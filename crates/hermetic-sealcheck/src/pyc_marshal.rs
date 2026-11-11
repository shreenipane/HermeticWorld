use std::collections::HashSet;
use std::sync::Arc;

use crate::fingerprint::{sha256_u64, FingerprintSet, PycFunctionFingerprint};
use crate::scan::{Finding, ScanOptions, Severity};

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
    BadRef(usize),
    UnresolvedRef(usize),
    UnknownType(u8),
}

impl std::fmt::Display for MarshalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated marshal stream"),
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
    Int(String),
    Float(String),
    String(String),
    Bytes(Vec<u8>),
    Tuple(Arc<[MarshalValue]>),
    List,
    Dict,
    Set,
    Code,
    Other,
}

impl MarshalValue {
    fn as_string(&self) -> Option<String> {
        match self {
            Self::String(s) => Some(s.clone()),
            Self::Bytes(b) => String::from_utf8(b.clone()).ok(),
            _ => None,
        }
    }
}

struct MarshalParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    magic: u16,
    depth: usize,
    work_budget: usize,
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
            work_budget: 100_000 + bytes.len().saturating_mul(10),
            refs: Vec::new(),
            code_objects: Vec::new(),
        }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, MarshalError> {
        if self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            Ok(b)
        } else {
            Err(MarshalError::Truncated)
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], MarshalError> {
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
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u32(&mut self) -> Result<u32, MarshalError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_object(&mut self) -> Result<MarshalValue, MarshalError> {
        if self.depth > 64 || self.work_budget == 0 {
            return Err(MarshalError::RecursionLimit);
        }
        self.work_budget -= 1;
        self.depth += 1;
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
                match &self.refs[idx] {
                    Some(v) => v.clone(),
                    None => return Err(MarshalError::UnresolvedRef(idx)),
                }
            }
            b'0' => MarshalValue::Null,
            b'N' => MarshalValue::None,
            b'T' | b'F' => MarshalValue::Bool,
            b'S' => MarshalValue::StopIteration,
            b'.' => MarshalValue::Ellipsis,
            b'i' => {
                let v = self.read_i32()?;
                MarshalValue::Int(v.to_string())
            }
            b'l' => {
                let n = self.read_i32()?;
                let count = n.unsigned_abs() as usize;
                if count > self.remaining() / 2 {
                    return Err(MarshalError::Truncated);
                }
                let digits_bytes = self.read_bytes(count * 2)?;
                if count == 0 {
                    MarshalValue::Int("0".to_string())
                } else if count == 1 {
                    let d0 = u16::from_le_bytes([digits_bytes[0], digits_bytes[1]]) as i64;
                    let val = if n < 0 { -d0 } else { d0 };
                    MarshalValue::Int(val.to_string())
                } else if count <= 4 {
                    let mut val: u128 = 0;
                    for i in 0..count {
                        let d = u16::from_le_bytes([digits_bytes[i * 2], digits_bytes[i * 2 + 1]])
                            as u128;
                        val += d << (15 * i);
                    }
                    let s = if n < 0 {
                        format!("-{}", val)
                    } else {
                        val.to_string()
                    };
                    MarshalValue::Int(s)
                } else {
                    MarshalValue::Other
                }
            }
            b'f' => {
                let len = self.read_u8()? as usize;
                let bytes = self.read_bytes(len)?;
                MarshalValue::Float(String::from_utf8_lossy(bytes).into_owned())
            }
            b'g' => {
                let bytes = self.read_bytes(8)?;
                let f = f64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                MarshalValue::Float(f.to_string())
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
                let bytes = self.read_bytes(len)?;
                MarshalValue::Bytes(bytes.to_vec())
            }
            b't' | b'u' | b'a' | b'A' => {
                let len = self.read_u32()? as usize;
                let bytes = self.read_bytes(len)?;
                MarshalValue::String(String::from_utf8_lossy(bytes).into_owned())
            }
            b'z' | b'Z' => {
                let len = self.read_u8()? as usize;
                let bytes = self.read_bytes(len)?;
                MarshalValue::String(String::from_utf8_lossy(bytes).into_owned())
            }
            b'(' => {
                let count = self.read_u32()? as usize;
                if count > self.remaining() {
                    return Err(MarshalError::Truncated);
                }
                let mut items = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    items.push(self.read_object()?);
                }
                MarshalValue::Tuple(items.into())
            }
            b')' => {
                let count = self.read_u8()? as usize;
                if count > self.remaining() {
                    return Err(MarshalError::Truncated);
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.read_object()?);
                }
                MarshalValue::Tuple(items.into())
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
                let max_pairs = self.remaining() / 2 + 1;
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
                if count > self.remaining() {
                    return Err(MarshalError::Truncated);
                }
                for _ in 0..count {
                    self.read_object()?;
                }
                MarshalValue::Set
            }
            b':' => {
                self.read_object()?;
                self.read_object()?;
                self.read_object()?;
                MarshalValue::Other
            }
            b'c' => {
                self.read_code_object()?;
                MarshalValue::Code
            }
            unknown => return Err(MarshalError::UnknownType(unknown)),
        };

        if flag_ref {
            if let Some(slot) = reserved_slot {
                self.refs[slot] = Some(val.clone());
            } else {
                if self.refs.len() >= self.bytes.len() {
                    return Err(MarshalError::Truncated);
                }
                self.refs.push(Some(val.clone()));
            }
        }

        self.depth -= 1;
        Ok(val)
    }

    fn read_code_object(&mut self) -> Result<(), MarshalError> {
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

            self.build_code_object(
                name,
                None,
                consts,
                names,
                vec![varnames, freevars, cellvars],
            );
            Ok(())
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

            self.build_code_object(
                name,
                None,
                consts,
                names,
                vec![varnames, freevars, cellvars],
            );
            Ok(())
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

            self.build_code_object(name, Some(qualname), consts, names, vec![localsplusnames]);
            Ok(())
        }
    }

    fn build_code_object(
        &mut self,
        name_obj: MarshalValue,
        qualname_obj: Option<MarshalValue>,
        consts_obj: MarshalValue,
        names_obj: MarshalValue,
        var_tuples: Vec<MarshalValue>,
    ) -> PycCodeObject {
        let name = name_obj.as_string().unwrap_or_default();
        let qualname = qualname_obj.and_then(|q| q.as_string());
        let mut symbols = HashSet::new();

        // 1. co_names
        if let MarshalValue::Tuple(items) = names_obj {
            for it in items.iter() {
                if let Some(s) = it.as_string() {
                    symbols.insert(s);
                }
            }
        }

        // 2. co_varnames / co_localsplusnames / co_freevars / co_cellvars
        for vt in var_tuples {
            if let MarshalValue::Tuple(items) = vt {
                for it in items.iter() {
                    if let Some(s) = it.as_string() {
                        symbols.insert(s);
                    }
                }
            }
        }

        // 3. co_consts
        if let MarshalValue::Tuple(items) = consts_obj {
            let mut stack: Vec<(&MarshalValue, usize)> = items.iter().map(|it| (it, 0)).collect();
            let mut walk_budget = 10_000usize;
            while let Some((val, depth)) = stack.pop() {
                if walk_budget == 0 || depth > 16 {
                    continue;
                }
                walk_budget -= 1;
                match val {
                    MarshalValue::String(s) => {
                        symbols.insert(s.clone());
                    }
                    MarshalValue::Bytes(b) => {
                        if let Ok(s) = std::str::from_utf8(b) {
                            symbols.insert(s.to_string());
                        }
                    }
                    MarshalValue::Int(s) => {
                        symbols.insert(s.clone());
                    }
                    MarshalValue::Float(s) => {
                        symbols.insert(s.clone());
                    }
                    MarshalValue::Tuple(sub_items) => {
                        for sub in sub_items.iter().rev() {
                            stack.push((sub, depth + 1));
                        }
                    }
                    MarshalValue::Code => {
                        // Nested code objects are collected separately when read
                    }
                    _ => {}
                }
            }
        }

        let co = PycCodeObject {
            name,
            qualname,
            symbols,
        };
        self.code_objects.push(co.clone());
        co
    }
}

/// Parse all code objects from the marshal stream of a `.pyc` file.
/// Unparseable input falls back silently to returning an empty `Vec`.
pub fn parse_pyc_code_objects(bytes: &[u8]) -> Vec<PycCodeObject> {
    let magic = match crate::bytecode::pyc_magic(bytes) {
        Some(m) => m,
        None => return Vec::new(),
    };
    let header_len = crate::bytecode::pyc_header_len(magic);
    if bytes.len() <= header_len {
        return Vec::new();
    }
    let body = &bytes[header_len..];
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
