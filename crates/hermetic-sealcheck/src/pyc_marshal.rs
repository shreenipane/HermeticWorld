use std::collections::HashSet;
use std::sync::Arc;

use crate::fingerprint::{sha256_u64, FingerprintSet, PycFunctionFingerprint};
use crate::scan::{Finding, ScanOptions, Severity};

// Aggregate per-stream limits cover parsing, reference expansion and extraction.
const MAX_MARSHAL_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_MARSHAL_ALLOC_BYTES: usize = 32 * 1024 * 1024;
const MAX_MARSHAL_PROCESSED_BYTES: usize = 32 * 1024 * 1024;
const MAX_MARSHAL_WORK: usize = 200_000;
const MAX_MARSHAL_GRAPH_DEPTH: usize = 64;
const MAX_NUMERIC_ALLOCATION_BYTES: usize = 2048;
const CONTAINER_ALLOCATION_FACTOR: usize = 2;

pub const MAX_MARSHAL_LONG_DIGITS: usize = 256;
pub const MAX_MARSHAL_LONG_ALLOCATION_BYTES: usize = 2048;
pub const MAX_MARSHAL_LONG_PROCESSING_STEPS: usize = 65536;

/// A parsed code object from a `.pyc` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PycCodeObject {
    pub name: String,
    pub qualname: Option<String>,
    pub symbols: HashSet<String>,
}

/// A code object with symbols hashed with `sha256_u64`, stored in a layer index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedPycCodeObject {
    pub name: String,
    pub symbols: HashSet<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MarshalError {
    Truncated,
    RecursionLimit,
    BudgetLimit,
    BadRef(usize),
    UnresolvedRef(usize),
    UnknownType(u8),
}

impl std::fmt::Display for MarshalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated marshal stream"),
            Self::BudgetLimit => write!(f, "marshal aggregate budget exceeded"),
            Self::RecursionLimit => write!(f, "marshal recursion limit exceeded"),
            Self::BadRef(idx) => write!(f, "bad marshal ref index: {idx}"),
            Self::UnresolvedRef(idx) => write!(f, "unresolved marshal ref index: {idx}"),
            Self::UnknownType(b) => write!(f, "unknown marshal type code: 0x{b:02x}"),
        }
    }
}

impl std::error::Error for MarshalError {}

#[derive(Debug, Clone)]
enum MarshalValue {
    Null,
    None,
    Bool,
    StopIteration,
    Ellipsis,
    Int(Arc<str>),
    Float(Arc<str>),
    String(Arc<str>),
    Bytes(Arc<[u8]>),
    Tuple(Arc<[MarshalValue]>, usize),
    FrozenSet(Arc<[MarshalValue]>, usize),
    List,
    Dict,
    /// A code object; the index of its entry in `MarshalParser::code_objects`.
    Code(usize),
    Other,
}

impl MarshalValue {
    fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            Self::Bytes(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    fn payload_len(&self) -> usize {
        match self {
            Self::Int(s) | Self::Float(s) | Self::String(s) => s.len(),
            Self::Bytes(b) => b.len(),
            _ => 0,
        }
    }
}

struct MarshalParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    magic: u16,
    depth: usize,
    work_budget: usize,
    allocation_budget: usize,
    byte_budget: usize,
    refs: Vec<Option<MarshalValue>>,
    code_objects: Vec<PycCodeObject>,
}

impl<'a> MarshalParser<'a> {
    fn new(bytes: &'a [u8], magic: u16) -> Self {
        Self {
            bytes,
            pos: 0,
            magic,
            depth: 0,
            work_budget: MAX_MARSHAL_WORK,
            allocation_budget: MAX_MARSHAL_ALLOC_BYTES,
            byte_budget: MAX_MARSHAL_PROCESSED_BYTES,
            refs: Vec::new(),
            code_objects: Vec::new(),
        }
    }

    fn charge_work(&mut self, count: usize) -> Result<(), MarshalError> {
        self.work_budget = self
            .work_budget
            .checked_sub(count)
            .ok_or(MarshalError::BudgetLimit)?;
        Ok(())
    }

    fn charge_bytes(&mut self, count: usize) -> Result<(), MarshalError> {
        self.byte_budget = self
            .byte_budget
            .checked_sub(count)
            .ok_or(MarshalError::BudgetLimit)?;
        Ok(())
    }

    fn charge_allocation(&mut self, count: usize) -> Result<(), MarshalError> {
        self.allocation_budget = self
            .allocation_budget
            .checked_sub(count)
            .ok_or(MarshalError::BudgetLimit)?;
        Ok(())
    }

    fn charge_entries<T>(&mut self, count: usize) -> Result<(), MarshalError> {
        let bytes = count
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|bytes| bytes.checked_mul(CONTAINER_ALLOCATION_FACTOR))
            .ok_or(MarshalError::BudgetLimit)?;
        self.charge_allocation(bytes)
    }

    fn read_tuple(&mut self, count: usize) -> Result<MarshalValue, MarshalError> {
        if count > self.remaining() {
            return Err(MarshalError::Truncated);
        }
        // Charge both the vector and its conversion to shared storage before allocating.
        self.charge_entries::<MarshalValue>(count)?;
        self.charge_entries::<MarshalValue>(count)?;
        let mut items = Vec::with_capacity(count);
        let mut graph_depth = 1usize;
        for _ in 0..count {
            let item = self.read_object()?;
            if let MarshalValue::Tuple(_, child_depth) | MarshalValue::FrozenSet(_, child_depth) =
                &item
            {
                graph_depth = graph_depth.max(child_depth.saturating_add(1));
            }
            if graph_depth > MAX_MARSHAL_GRAPH_DEPTH {
                return Err(MarshalError::RecursionLimit);
            }
            items.push(item);
        }
        Ok(MarshalValue::Tuple(items.into(), graph_depth))
    }

    fn read_frozenset(&mut self, count: usize) -> Result<MarshalValue, MarshalError> {
        if count > self.remaining() {
            return Err(MarshalError::Truncated);
        }
        self.charge_entries::<MarshalValue>(count)?;
        self.charge_entries::<MarshalValue>(count)?;
        let mut items = Vec::with_capacity(count);
        let mut graph_depth = 1usize;
        for _ in 0..count {
            let item = self.read_object()?;
            if let MarshalValue::Tuple(_, child_depth) | MarshalValue::FrozenSet(_, child_depth) =
                &item
            {
                graph_depth = graph_depth.max(child_depth.saturating_add(1));
            }
            if graph_depth > MAX_MARSHAL_GRAPH_DEPTH {
                return Err(MarshalError::RecursionLimit);
            }
            items.push(item);
        }
        Ok(MarshalValue::FrozenSet(items.into(), graph_depth))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, MarshalError> {
        if self.pos < self.bytes.len() {
            let b = *self.bytes.get(self.pos).ok_or(MarshalError::Truncated)?;
            self.pos = self.pos.saturating_add(1);
            Ok(b)
        } else {
            Err(MarshalError::Truncated)
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], MarshalError> {
        self.charge_bytes(len)?;
        if len > self.remaining() {
            return Err(MarshalError::Truncated);
        }
        let end = match self.pos.checked_add(len) {
            Some(e) => e,
            None => return Err(MarshalError::Truncated),
        };
        let slice = match self.bytes.get(self.pos..end) {
            Some(s) => s,
            None => return Err(MarshalError::Truncated),
        };
        self.pos = end;
        Ok(slice)
    }

    fn read_i32(&mut self) -> Result<i32, MarshalError> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_le_bytes(
            b.try_into().map_err(|_| MarshalError::Truncated)?,
        ))
    }

    fn read_u32(&mut self) -> Result<u32, MarshalError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(
            b.try_into().map_err(|_| MarshalError::Truncated)?,
        ))
    }

    fn read_object(&mut self) -> Result<MarshalValue, MarshalError> {
        if self.depth > MAX_MARSHAL_GRAPH_DEPTH {
            return Err(MarshalError::RecursionLimit);
        }
        self.charge_work(1)?;
        // Reserve scalar headers and per-value bookkeeping before creating a value.
        self.charge_allocation(64)?;
        self.depth = self.depth.saturating_add(1);
        let raw_type = self.read_u8()?;
        let flag_ref = (raw_type & 0x80) != 0;
        let type_code = raw_type & 0x7f;

        let is_composite = matches!(
            type_code,
            b'(' | b')' | b'[' | b'{' | b'}' | b'<' | b'>' | b':' | b'c'
        );
        let reserved_slot = if flag_ref {
            if self.refs.len() >= self.bytes.len() {
                return Err(MarshalError::Truncated);
            }
            if is_composite {
                let slot = self.refs.len();
                self.charge_entries::<Option<MarshalValue>>(1)?;
                self.refs.push(None);
                Some(slot)
            } else {
                None
            }
        } else {
            None
        };

        let val = match type_code {
            b'r' => {
                let idx = self.read_u32()? as usize;
                if idx >= self.refs.len() {
                    return Err(MarshalError::BadRef(idx));
                }
                let payload_len = self
                    .refs
                    .get(idx)
                    .and_then(Option::as_ref)
                    .ok_or(MarshalError::UnresolvedRef(idx))?
                    .payload_len();
                self.charge_bytes(payload_len)?;
                self.refs
                    .get(idx)
                    .and_then(Option::as_ref)
                    .cloned()
                    .ok_or(MarshalError::UnresolvedRef(idx))?
            }
            b'0' => MarshalValue::Null,
            b'N' => MarshalValue::None,
            b'T' | b'F' => MarshalValue::Bool,
            b'S' => MarshalValue::StopIteration,
            b'.' => MarshalValue::Ellipsis,
            b'i' => {
                self.charge_allocation(MAX_NUMERIC_ALLOCATION_BYTES)?;
                self.charge_bytes(MAX_NUMERIC_ALLOCATION_BYTES)?;
                let v = self.read_i32()?;
                MarshalValue::Int(v.to_string().into())
            }
            b'l' => {
                let n = self.read_i32()?;
                let count = n.unsigned_abs() as usize;
                if count > self.remaining() / 2 {
                    return Err(MarshalError::Truncated);
                }
                if count > MAX_MARSHAL_LONG_DIGITS {
                    let bytes_len = count.checked_mul(2).ok_or(MarshalError::BudgetLimit)?;
                    self.read_bytes(bytes_len)?;
                    MarshalValue::Other
                } else {
                    let bytes_len = count.checked_mul(2).ok_or(MarshalError::BudgetLimit)?;
                    let digits_bytes = self.read_bytes(bytes_len)?;
                    self.charge_bytes(bytes_len)?;
                    let alloc =
                        (count.saturating_mul(5) + 16).min(MAX_MARSHAL_LONG_ALLOCATION_BYTES);
                    self.charge_allocation(alloc)?;
                    let work = (count.saturating_mul(count).saturating_mul(5))
                        .min(MAX_MARSHAL_LONG_PROCESSING_STEPS);
                    self.charge_work(work)?;

                    if count == 0 {
                        MarshalValue::Int("0".into())
                    } else if count <= 8 {
                        let mut val: u128 = 0;
                        for (i, digit) in digits_bytes.as_chunks::<2>().0.iter().enumerate() {
                            let d = u16::from_le_bytes(*digit) as u128;
                            val = val.saturating_add(
                                d.checked_shl(15u32.saturating_mul(i as u32))
                                    .ok_or(MarshalError::BudgetLimit)?,
                            );
                        }
                        let s = if n < 0 {
                            format!("-{}", val)
                        } else {
                            val.to_string()
                        };
                        MarshalValue::Int(s.into())
                    } else {
                        let mut digits: Vec<u16> = digits_bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|chunk| u16::from_le_bytes(*chunk))
                            .collect();
                        let mut dec_digits: Vec<u8> = Vec::with_capacity(count.saturating_mul(5));
                        while !digits.is_empty() {
                            let mut rem: u32 = 0;
                            for d in digits.iter_mut().rev() {
                                let cur = (rem << 15) | (*d as u32);
                                *d = (cur / 10) as u16;
                                rem = cur % 10;
                            }
                            dec_digits.push(b'0' + rem as u8);
                            while digits.last() == Some(&0) {
                                digits.pop();
                            }
                        }
                        if dec_digits.is_empty() {
                            dec_digits.push(b'0');
                        }
                        dec_digits.reverse();
                        let mut s = String::with_capacity(dec_digits.len() + 1);
                        if n < 0 {
                            s.push('-');
                        }
                        s.push_str(std::str::from_utf8(&dec_digits).unwrap_or("0"));
                        MarshalValue::Int(s.into())
                    }
                }
            }
            b'f' => {
                let len = self.read_u8()? as usize;
                self.charge_allocation(len)?;
                let bytes = self.read_bytes(len)?;
                self.charge_bytes(len)?;
                let text =
                    std::str::from_utf8(bytes).map_err(|_| MarshalError::UnknownType(type_code))?;
                MarshalValue::Float(text.into())
            }
            b'g' => {
                self.charge_allocation(MAX_NUMERIC_ALLOCATION_BYTES)?;
                self.charge_bytes(MAX_NUMERIC_ALLOCATION_BYTES)?;
                let bytes = self.read_bytes(8)?;
                let f = f64::from_le_bytes(bytes.try_into().map_err(|_| MarshalError::Truncated)?);
                MarshalValue::Float(f.to_string().into())
            }
            b'x' => {
                let r_len = self.read_u8()? as usize;
                self.read_bytes(r_len)?;
                let i_len = self.read_u8()? as usize;
                self.read_bytes(i_len)?;
                MarshalValue::Other
            }
            b'y' => {
                self.read_bytes(16)?;
                MarshalValue::Other
            }
            b's' => {
                let len = self.read_u32()? as usize;
                self.charge_allocation(len)?;
                let bytes = self.read_bytes(len)?;
                MarshalValue::Bytes(bytes.into())
            }
            b't' | b'u' | b'a' | b'A' => {
                let len = self.read_u32()? as usize;
                self.charge_allocation(len)?;
                let bytes = self.read_bytes(len)?;
                self.charge_bytes(len)?;
                let text =
                    std::str::from_utf8(bytes).map_err(|_| MarshalError::UnknownType(type_code))?;
                MarshalValue::String(text.into())
            }
            b'z' | b'Z' => {
                let len = self.read_u8()? as usize;
                self.charge_allocation(len)?;
                let bytes = self.read_bytes(len)?;
                self.charge_bytes(len)?;
                let text =
                    std::str::from_utf8(bytes).map_err(|_| MarshalError::UnknownType(type_code))?;
                MarshalValue::String(text.into())
            }
            b'(' => {
                let count = self.read_u32()? as usize;
                self.read_tuple(count)?
            }
            b')' => {
                let count = self.read_u8()? as usize;
                self.read_tuple(count)?
            }
            b'[' => {
                let count = self.read_u32()? as usize;
                if count > self.remaining() {
                    return Err(MarshalError::Truncated);
                }
                for _ in 0..count {
                    self.read_object()?;
                }
                MarshalValue::List
            }
            b'{' | b'}' => {
                let max_pairs = (self.remaining() / 2).saturating_add(1);
                for _ in 0..max_pairs {
                    let key = self.read_object()?;
                    if matches!(key, MarshalValue::Null) {
                        break;
                    }
                    let _val = self.read_object()?;
                }
                MarshalValue::Dict
            }
            b'<' | b'>' => {
                let count = self.read_u32()? as usize;
                self.read_frozenset(count)?
            }
            b':' => {
                self.read_object()?;
                self.read_object()?;
                self.read_object()?;
                MarshalValue::Other
            }
            b'c' => MarshalValue::Code(self.read_code_object()?),
            unknown => return Err(MarshalError::UnknownType(unknown)),
        };

        if flag_ref {
            if let Some(slot) = reserved_slot {
                if let Some(entry) = self.refs.get_mut(slot) {
                    *entry = Some(val.clone());
                } else {
                    return Err(MarshalError::BadRef(slot));
                }
            } else {
                if self.refs.len() >= self.bytes.len() {
                    return Err(MarshalError::Truncated);
                }
                self.charge_entries::<Option<MarshalValue>>(1)?;
                self.refs.push(Some(val.clone()));
            }
        }

        self.depth = self.depth.saturating_sub(1);
        Ok(val)
    }

    /// Reads a code object and returns its index in `code_objects`.
    fn read_code_object(&mut self) -> Result<usize, MarshalError> {
        let magic = self.magic;
        if magic < 3410 {
            // Python 3.6 - 3.7
            let _argcount = self.read_i32()?;
            let _kwonlyargcount = self.read_i32()?;
            let _nlocals = self.read_i32()?;
            let _stacksize = self.read_i32()?;
            let _flags = self.read_i32()?;
            let _code = self.read_object()?;
            let consts = self.read_object()?;
            let names = self.read_object()?;
            let varnames = self.read_object()?;
            let freevars = self.read_object()?;
            let cellvars = self.read_object()?;
            let _filename = self.read_object()?;
            let name = self.read_object()?;
            let _firstlineno = self.read_i32()?;
            let _lnotab = self.read_object()?;

            self.build_code_object(name, None, consts, names, [varnames, freevars, cellvars])
        } else if magic < 3450 {
            // Python 3.8 - 3.10
            let _argcount = self.read_i32()?;
            let _posonlyargcount = self.read_i32()?;
            let _kwonlyargcount = self.read_i32()?;
            let _nlocals = self.read_i32()?;
            let _stacksize = self.read_i32()?;
            let _flags = self.read_i32()?;
            let _code = self.read_object()?;
            let consts = self.read_object()?;
            let names = self.read_object()?;
            let varnames = self.read_object()?;
            let freevars = self.read_object()?;
            let cellvars = self.read_object()?;
            let _filename = self.read_object()?;
            let name = self.read_object()?;
            let _firstlineno = self.read_i32()?;
            let _lnotab = self.read_object()?;

            self.build_code_object(name, None, consts, names, [varnames, freevars, cellvars])
        } else {
            // Python 3.11 - 3.13
            let _argcount = self.read_i32()?;
            let _posonlyargcount = self.read_i32()?;
            let _kwonlyargcount = self.read_i32()?;
            let _stacksize = self.read_i32()?;
            let _flags = self.read_i32()?;
            let _code = self.read_object()?;
            let consts = self.read_object()?;
            let names = self.read_object()?;
            let localsplusnames = self.read_object()?;
            let _localspluskinds = self.read_object()?;
            let _filename = self.read_object()?;
            let name = self.read_object()?;
            let qualname = self.read_object()?;
            let _firstlineno = self.read_i32()?;
            let _linetable = self.read_object()?;
            let _exceptiontable = self.read_object()?;

            self.build_code_object(name, Some(qualname), consts, names, [localsplusnames])
        }
    }

    fn copy_symbol(&mut self, text: &str) -> Result<String, MarshalError> {
        self.charge_work(1)?;
        // Includes hashing/validation and the owned output string plus set overhead.
        self.charge_bytes(text.len())?; // copying
        self.charge_bytes(text.len())?; // hashing
        self.charge_allocation(text.len())?;
        self.charge_allocation(64)?;
        Ok(text.to_string())
    }

    fn copy_value_string(&mut self, value: &MarshalValue) -> Result<Option<String>, MarshalError> {
        // Bytes require UTF-8 validation even when they produce no symbol.
        self.charge_bytes(value.payload_len())?;
        value
            .as_string()
            .map(|text| self.copy_symbol(text))
            .transpose()
    }

    fn build_code_object(
        &mut self,
        name_obj: MarshalValue,
        qualname_obj: Option<MarshalValue>,
        consts_obj: MarshalValue,
        names_obj: MarshalValue,
        var_tuples: impl IntoIterator<Item = MarshalValue>,
    ) -> Result<usize, MarshalError> {
        self.charge_work(1)?;
        self.charge_entries::<PycCodeObject>(1)?;
        let name = self.copy_value_string(&name_obj)?.unwrap_or_default();
        let qualname = qualname_obj
            .as_ref()
            .map(|q| self.copy_value_string(q))
            .transpose()?
            .flatten();
        let mut symbols = HashSet::new();
        let mut folded: HashSet<usize> = HashSet::new();

        for value in std::iter::once(names_obj).chain(var_tuples) {
            if let MarshalValue::Tuple(items, _) = value {
                for item in items.iter() {
                    self.charge_work(1)?;
                    if let Some(text) = self.copy_value_string(item)? {
                        symbols.insert(text);
                    }
                }
            }
        }

        if let MarshalValue::Tuple(items, _) | MarshalValue::FrozenSet(items, _) = consts_obj {
            self.charge_entries::<&MarshalValue>(items.len())?;
            let mut stack: Vec<&MarshalValue> = items.iter().collect();
            while let Some(value) = stack.pop() {
                self.charge_work(1)?;
                match value {
                    MarshalValue::String(s) | MarshalValue::Int(s) | MarshalValue::Float(s) => {
                        symbols.insert(self.copy_symbol(s)?);
                    }
                    MarshalValue::Bytes(b) => {
                        self.charge_bytes(b.len())?;
                        if let Ok(s) = std::str::from_utf8(b) {
                            symbols.insert(self.copy_symbol(s)?);
                        }
                    }
                    MarshalValue::Tuple(children, _) | MarshalValue::FrozenSet(children, _) => {
                        self.charge_entries::<&MarshalValue>(children.len())?;
                        stack.extend(children.iter().rev());
                    }
                    MarshalValue::Code(child) => {
                        self.fold_expression_scope(*child, &mut folded, &mut symbols)?;
                    }
                    _ => {}
                }
            }
        }
        let index = self.code_objects.len();
        self.code_objects.push(PycCodeObject {
            name,
            qualname,
            symbols,
        });
        Ok(index)
    }

    /// Adds the symbols of the nested code object `child` to `symbols` when the child is an
    /// expression scope (lambda, generator expression or, before CPython 3.12, a
    /// comprehension). The source fingerprint attributes such expressions to the enclosing
    /// function, so the bytecode side must too. Children are built before their parent, so
    /// a child's own expression scopes are already folded into it. Every copied symbol is
    /// charged to the aggregate budgets.
    fn fold_expression_scope(
        &mut self,
        child: usize,
        folded: &mut HashSet<usize>,
        symbols: &mut HashSet<String>,
    ) -> Result<(), MarshalError> {
        // A child referenced more than once is folded once.
        if !folded.insert(child) {
            return Ok(());
        }
        let Some(child_obj) = self.code_objects.get(child) else {
            return Ok(());
        };
        if !is_expression_scope_name(&child_obj.name) {
            return Ok(());
        }
        let count = child_obj.symbols.len();
        let bytes = child_obj
            .symbols
            .iter()
            .fold(0usize, |acc, sym| acc.saturating_add(sym.len()));
        // Charge before copying anything.
        self.charge_work(count)?;
        self.charge_bytes(bytes)?;
        self.charge_allocation(bytes.saturating_add(count.saturating_mul(64)))?;
        if let Some(child_obj) = self.code_objects.get(child) {
            symbols.extend(child_obj.symbols.iter().cloned());
        }
        Ok(())
    }
}

/// Names CPython gives the code objects of expression scopes nested in a function.
const EXPRESSION_SCOPE_NAMES: &[&str] = &[
    "<lambda>",
    "<genexpr>",
    "<listcomp>",
    "<setcomp>",
    "<dictcomp>",
];

fn is_expression_scope_name(name: &str) -> bool {
    EXPRESSION_SCOPE_NAMES.contains(&name)
}

/// Parse all code objects from the marshal stream of a `.pyc` file.
/// Unparseable input falls back silently to returning an empty `Vec`.
pub fn parse_pyc_code_objects(bytes: &[u8]) -> Vec<PycCodeObject> {
    if bytes.len() > MAX_MARSHAL_INPUT_BYTES {
        return Vec::new();
    }
    let magic = match crate::bytecode::pyc_magic(bytes) {
        Some(m) => m,
        None => return Vec::new(),
    };
    let header_len = crate::bytecode::pyc_header_len(magic);
    if bytes.len() <= header_len {
        return Vec::new();
    }
    let Some(body) = bytes.get(header_len..) else {
        return Vec::new();
    };
    let mut parser = MarshalParser::new(body, magic);
    if parser.read_object().is_err() {
        return Vec::new();
    }
    parser.code_objects
}

/// Match extracted code objects against FingerprintSet (D3b, channel `binary_pyc_function`).
pub fn match_pyc_code_objects(
    objects: &[PycCodeObject],
    fp: &FingerprintSet,
    opts: &ScanOptions,
    path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for hunk in &fp.hunks {
        let pyc_fps: Vec<&PycFunctionFingerprint> = if !hunk.pyc_fingerprints.is_empty() {
            hunk.pyc_fingerprints.iter().collect()
        } else if let Some(f) = &hunk.pyc_fingerprint {
            vec![f]
        } else {
            Vec::new()
        };

        for pyc_fp in pyc_fps {
            for co in objects {
                let matches_name = co.name == pyc_fp.function_name;
                if !matches_name {
                    continue;
                }

                let hit_added = pyc_fp
                    .added
                    .iter()
                    .filter(|s| co.symbols.contains(*s))
                    .count();
                let hit_removed_absent = pyc_fp
                    .removed
                    .iter()
                    .filter(|s| !co.symbols.contains(*s))
                    .count();
                let total = pyc_fp.added.len() + pyc_fp.removed.len();
                if total == 0 {
                    continue;
                }
                let confidence = (hit_added + hit_removed_absent) as f64 / total as f64;
                let rounded_conf = (confidence * 100.0).round() / 100.0;

                if !pyc_fp.added.is_empty() {
                    if confidence >= opts.binary_threshold && hit_added >= 1 {
                        let mut matched: Vec<&String> = pyc_fp
                            .added
                            .iter()
                            .filter(|s| co.symbols.contains(*s))
                            .collect();
                        matched.sort();
                        let mut evidence = Vec::new();
                        evidence.push(pyc_fp.function_name.clone());
                        for sym in matched.into_iter().take(5) {
                            evidence.push(sym.clone());
                        }
                        findings.push(Finding {
                            detector: "D3b".into(),
                            channel: "binary_pyc_function".into(),
                            path: path.to_string(),
                            visibility: opts.visibility,
                            severity: Severity::Gate,
                            confidence: rounded_conf,
                            hunk: Some(hunk.hunk_index),
                            evidence,
                        });
                    }
                } else {
                    // When added is empty (a pure deletion): report Review, not Gate, when confidence >= 0.60
                    if confidence >= opts.binary_threshold {
                        let mut absent: Vec<&String> = pyc_fp
                            .removed
                            .iter()
                            .filter(|s| !co.symbols.contains(*s))
                            .collect();
                        absent.sort();
                        let mut evidence = Vec::new();
                        evidence.push(pyc_fp.function_name.clone());
                        evidence.push("pure deletion: absence of names is weak evidence".into());
                        for sym in absent.into_iter().take(5) {
                            evidence.push(sym.clone());
                        }
                        findings.push(Finding {
                            detector: "D3b".into(),
                            channel: "binary_pyc_function".into(),
                            path: path.to_string(),
                            visibility: opts.visibility,
                            severity: Severity::Review,
                            confidence: rounded_conf,
                            hunk: Some(hunk.hunk_index),
                            evidence,
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Match hashed code objects from an index against FingerprintSet.
pub fn match_hashed_pyc_code_objects(
    objects: &[HashedPycCodeObject],
    fp: &FingerprintSet,
    opts: &ScanOptions,
    path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for hunk in &fp.hunks {
        let pyc_fps: Vec<&PycFunctionFingerprint> = if !hunk.pyc_fingerprints.is_empty() {
            hunk.pyc_fingerprints.iter().collect()
        } else if let Some(f) = &hunk.pyc_fingerprint {
            vec![f]
        } else {
            Vec::new()
        };

        for pyc_fp in pyc_fps {
            for co in objects {
                let matches_name = co.name == pyc_fp.function_name;
                if !matches_name {
                    continue;
                }

                let hit_added = pyc_fp
                    .added_u64
                    .iter()
                    .filter(|h| co.symbols.contains(h))
                    .count();
                let hit_removed_absent = pyc_fp
                    .removed_u64
                    .iter()
                    .filter(|h| !co.symbols.contains(h))
                    .count();
                let total = pyc_fp.added_u64.len() + pyc_fp.removed_u64.len();
                if total == 0 {
                    continue;
                }
                let confidence = (hit_added + hit_removed_absent) as f64 / total as f64;
                let rounded_conf = (confidence * 100.0).round() / 100.0;

                if !pyc_fp.added.is_empty() {
                    if confidence >= opts.binary_threshold && hit_added >= 1 {
                        let mut matched: Vec<&String> = pyc_fp
                            .added
                            .iter()
                            .filter(|s| {
                                let h = sha256_u64(s.as_bytes());
                                co.symbols.contains(&h)
                            })
                            .collect();
                        matched.sort();
                        let mut evidence = Vec::new();
                        evidence.push(pyc_fp.function_name.clone());
                        for sym in matched.into_iter().take(5) {
                            evidence.push(sym.clone());
                        }
                        findings.push(Finding {
                            detector: "D3b".into(),
                            channel: "binary_pyc_function".into(),
                            path: path.to_string(),
                            visibility: opts.visibility,
                            severity: Severity::Gate,
                            confidence: rounded_conf,
                            hunk: Some(hunk.hunk_index),
                            evidence,
                        });
                    }
                } else {
                    // When added is empty (a pure deletion): report Review, not Gate, when confidence >= 0.60
                    if confidence >= opts.binary_threshold {
                        let mut absent: Vec<&String> = pyc_fp
                            .removed
                            .iter()
                            .filter(|s| {
                                let h = sha256_u64(s.as_bytes());
                                !co.symbols.contains(&h)
                            })
                            .collect();
                        absent.sort();
                        let mut evidence = Vec::new();
                        evidence.push(pyc_fp.function_name.clone());
                        evidence.push("pure deletion: absence of names is weak evidence".into());
                        for sym in absent.into_iter().take(5) {
                            evidence.push(sym.clone());
                        }
                        findings.push(Finding {
                            detector: "D3b".into(),
                            channel: "binary_pyc_function".into(),
                            path: path.to_string(),
                            visibility: opts.visibility,
                            severity: Severity::Review,
                            confidence: rounded_conf,
                            hunk: Some(hunk.hunk_index),
                            evidence,
                        });
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod budget_regressions {
    use super::*;

    fn reference(index: u32) -> Vec<u8> {
        let mut value = vec![b'r'];
        value.extend_from_slice(&index.to_le_bytes());
        value
    }

    fn tuple(items: &[Vec<u8>]) -> Vec<u8> {
        let mut value = vec![b'('];
        value.extend_from_slice(&(items.len() as u32).to_le_bytes());
        for item in items {
            value.extend_from_slice(item);
        }
        value
    }

    fn large_scalar(tag: u8) -> Vec<u8> {
        let mut value = vec![tag | 0x80];
        value.extend_from_slice(&(1024u32 * 1024).to_le_bytes());
        value.resize(value.len() + 1024 * 1024, b'x');
        value
    }

    fn code(consts: &[u8], names: &[u8]) -> Vec<u8> {
        let mut value = vec![b'c'];
        value.extend_from_slice(&[0; 24]); // Python 3.8 integer fields
        value.extend_from_slice(b"s\0\0\0\0"); // bytecode
        value.extend_from_slice(consts);
        value.extend_from_slice(names);
        value.extend_from_slice(b")\0)\0)\0z\0z\x01f\0\0\0\0s\0\0\0\0");
        value
    }

    fn assert_budget_rejection(body: &[u8]) {
        for _ in 0..2 {
            let mut parser = MarshalParser::new(body, 3413);
            assert!(matches!(
                parser.read_object(),
                Err(MarshalError::BudgetLimit)
            ));
            let mut pyc = vec![0x55, 0x0d, 0x0d, 0x0a];
            pyc.extend_from_slice(&[0; 12]);
            pyc.extend_from_slice(body);
            assert!(parse_pyc_code_objects(&pyc).is_empty(), "no partial output");
        }
    }

    #[test]
    fn scalar_references_in_one_root_exhaust_aggregate_byte_budget() {
        for tag in *b"us" {
            let mut items = vec![code(b")\0", b")\0"), large_scalar(tag)];
            items.extend((0..10_000).map(|_| reference(0)));
            let body = tuple(&items);
            assert_budget_rejection(&body);
        }
    }

    #[test]
    fn shared_names_and_constants_exhaust_aggregate_extraction_budget() {
        for constants in [false, true] {
            let mut shared = tuple(&[large_scalar(b'u')]);
            shared[0] |= 0x80; // tuple ref 0, scalar ref 1
            let object = if constants {
                code(&reference(0), b")\0")
            } else {
                code(b")\0", &reference(0))
            };
            let small = tuple(&[shared.clone(), object.clone()]);
            let mut parser = MarshalParser::new(&small, 3413);
            assert!(parser.read_object().is_ok());
            assert_eq!(parser.code_objects.len(), 1);
            let mut items = vec![shared];
            items.extend((0..10_000).map(|_| object.clone()));
            assert_budget_rejection(&tuple(&items));
        }
    }

    #[test]
    fn shared_invalid_bytes_still_charge_validation_work() {
        let mut scalar = large_scalar(b's');
        *scalar.last_mut().expect("payload") = 0xff;
        let mut shared = tuple(&[scalar]);
        shared[0] |= 0x80;
        let mut items = vec![shared];
        items.extend((0..10_000).map(|_| code(b")\0", &reference(0))));
        assert_budget_rejection(&tuple(&items));
    }

    #[test]
    fn extraction_work_and_pending_entries_are_aggregate_and_fail_closed() {
        // A DAG expands exponentially during constant traversal, despite small input.
        let mut items = vec![vec![0x80 | b')', 0]];
        for i in 0..24 {
            let mut next = tuple(&[reference(i), reference(i)]);
            next[0] |= 0x80;
            items.push(next);
        }
        items.push(code(&tuple(&[reference(24)]), b")\0"));
        assert_budget_rejection(&tuple(&items));
    }
}
