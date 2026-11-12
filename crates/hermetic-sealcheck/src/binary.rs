use std::collections::HashSet;

use crate::fingerprint::FingerprintSet;
use crate::scan::{Finding, ScanOptions, Severity};
use crate::winnow::tokenize;

#[derive(Debug)]
pub struct BinaryMalformed(pub String);

pub struct BinaryStrings {
    pub exact_strings: HashSet<String>,
    pub printable_runs: Vec<String>,
}

/// Extract content from a string literal token without surrounding quotes and prefix.
pub fn extract_string_literal_content(tok_text: &str) -> Option<String> {
    let bytes = tok_text.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut quote_start = 0;
    while quote_start < bytes.len() && bytes[quote_start].is_ascii_alphabetic() {
        quote_start += 1;
    }
    if quote_start >= bytes.len() {
        return None;
    }
    let quote_char = bytes[quote_start];
    if quote_char != b'\'' && quote_char != b'"' {
        return None;
    }
    let rest = &tok_text[quote_start..];
    if rest.starts_with("\"\"\"") {
        let content = rest.strip_prefix("\"\"\"").unwrap_or(rest);
        let content = content.strip_suffix("\"\"\"").unwrap_or(content);
        Some(content.to_string())
    } else if rest.starts_with("'''") {
        let content = rest.strip_prefix("'''").unwrap_or(rest);
        let content = content.strip_suffix("'''").unwrap_or(content);
        Some(content.to_string())
    } else if rest.starts_with('"') {
        let content = rest.strip_prefix('"').unwrap_or(rest);
        let content = content.strip_suffix('"').unwrap_or(content);
        Some(content.to_string())
    } else if rest.starts_with('\'') {
        let content = rest.strip_prefix('\'').unwrap_or(rest);
        let content = content.strip_suffix('\'').unwrap_or(content);
        Some(content.to_string())
    } else {
        None
    }
}

pub fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => chars.all(|c| c.is_alphanumeric() || c == '_'),
        _ => false,
    }
}

/// Collect binary items from added text:
/// - identifiers of at least 8 characters
/// - string literals whose content, without quotes and prefix, is at least 8 characters
pub fn extract_binary_items(text: &str) -> Vec<String> {
    let tokens = tokenize(text);
    let mut items = Vec::new();
    for tok in tokens {
        if let Some(content) = extract_string_literal_content(&tok.text) {
            if content.len() >= 8 && !content.chars().any(char::is_control) {
                items.push(content);
            }
        } else if is_identifier(&tok.text) && tok.text.len() >= 8 {
            items.push(tok.text);
        }
    }
    items
}

/// Extract printable ASCII runs (0x20..=0x7E) of at least `min_len` bytes.
pub fn extract_printable_runs(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut runs = Vec::new();
    let mut current_run = Vec::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            current_run.push(b);
        } else {
            if current_run.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&current_run) {
                    runs.push(s.to_string());
                }
            }
            current_run.clear();
        }
    }
    if current_run.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&current_run) {
            runs.push(s.to_string());
        }
    }
    runs
}

/// Extract null-terminated strings from a byte slice.
pub fn extract_null_terminated_strings(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    for part in bytes.split(|&b| b == 0) {
        if !part.is_empty() {
            if let Ok(s) = std::str::from_utf8(part) {
                strings.push(s.to_string());
            }
        }
    }
    strings
}

fn read_u16(bytes: &[u8], offset: usize, is_le: bool) -> Result<u16, BinaryMalformed> {
    let slice = offset
        .checked_add(2)
        .and_then(|end| bytes.get(offset..end))
        .ok_or_else(|| BinaryMalformed("offset out of bounds reading u16".into()))?;
    Ok(if is_le {
        u16::from_le_bytes([slice[0], slice[1]])
    } else {
        u16::from_be_bytes([slice[0], slice[1]])
    })
}

fn read_u32(bytes: &[u8], offset: usize, is_le: bool) -> Result<u32, BinaryMalformed> {
    let slice = offset
        .checked_add(4)
        .and_then(|end| bytes.get(offset..end))
        .ok_or_else(|| BinaryMalformed("offset out of bounds reading u32".into()))?;
    Ok(if is_le {
        u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
    } else {
        u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
    })
}

fn read_u64(bytes: &[u8], offset: usize, is_le: bool) -> Result<u64, BinaryMalformed> {
    let slice = offset
        .checked_add(8)
        .and_then(|end| bytes.get(offset..end))
        .ok_or_else(|| BinaryMalformed("offset out of bounds reading u64".into()))?;
    let mut b = [0u8; 8];
    b.copy_from_slice(slice);
    Ok(if is_le {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    })
}

struct ElfSection {
    name_offset: usize,
    sh_type: u32,
    offset: usize,
    size: usize,
}

/// Parse ELF (32-bit and 64-bit, little and big endian).
/// Extracts null-terminated strings from .dynstr and .strtab,
/// and printable runs of 6 or more bytes from .rodata, .data, .comment.
pub fn parse_elf(bytes: &[u8]) -> Result<BinaryStrings, BinaryMalformed> {
    if bytes.len() < 52 {
        return Err(BinaryMalformed("ELF file too small for header".into()));
    }
    if !bytes.starts_with(b"\x7fELF") {
        return Err(BinaryMalformed("invalid ELF magic".into()));
    }

    let class = bytes[4];
    let is_64 = match class {
        1 => false,
        2 => true,
        _ => return Err(BinaryMalformed("unsupported ELF class".into())),
    };

    let data_encoding = bytes[5];
    let is_le = match data_encoding {
        1 => true,
        2 => false,
        _ => return Err(BinaryMalformed("unsupported ELF data encoding".into())),
    };

    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        if bytes.len() < 64 {
            return Err(BinaryMalformed(
                "ELF file too small for 64-bit header".into(),
            ));
        }
        let shoff = read_u64(bytes, 40, is_le)? as usize;
        let shentsize = read_u16(bytes, 58, is_le)? as usize;
        let shnum = read_u16(bytes, 60, is_le)? as usize;
        let shstrndx = read_u16(bytes, 62, is_le)? as usize;
        (shoff, shentsize, shnum, shstrndx)
    } else {
        let shoff = read_u32(bytes, 32, is_le)? as usize;
        let shentsize = read_u16(bytes, 46, is_le)? as usize;
        let shnum = read_u16(bytes, 48, is_le)? as usize;
        let shstrndx = read_u16(bytes, 50, is_le)? as usize;
        (shoff, shentsize, shnum, shstrndx)
    };

    let (e_shnum, e_shstrndx) =
        extended_section_counts(bytes, is_64, is_le, e_shoff, e_shnum, e_shstrndx)?;

    let min_shentsize = if is_64 { 64 } else { 40 };
    if e_shnum > 0 && e_shentsize < min_shentsize {
        return Err(BinaryMalformed("e_shentsize too small".into()));
    }

    let total_sh_bytes = e_shnum
        .checked_mul(e_shentsize)
        .ok_or_else(|| BinaryMalformed("section table size overflow".into()))?;
    let sh_end = e_shoff
        .checked_add(total_sh_bytes)
        .ok_or_else(|| BinaryMalformed("section table offset overflow".into()))?;
    if sh_end > bytes.len() {
        return Err(BinaryMalformed(
            "section header table exceeds file size".into(),
        ));
    }

    if e_shnum == 0 {
        // No section table (stripped of section headers): fall back to the whole file.
        return Ok(BinaryStrings {
            exact_strings: HashSet::new(),
            printable_runs: extract_printable_runs(bytes, 6),
        });
    }

    if e_shstrndx >= e_shnum {
        return Err(BinaryMalformed("e_shstrndx exceeds e_shnum".into()));
    }

    let mut sections = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let sh_start = e_shoff + i * e_shentsize;
        let (name_offset, sh_type, offset, size) = if is_64 {
            let name = read_u32(bytes, sh_start, is_le)? as usize;
            let stype = read_u32(bytes, sh_start + 4, is_le)?;
            let off = read_u64(bytes, sh_start + 24, is_le)? as usize;
            let sz = read_u64(bytes, sh_start + 32, is_le)? as usize;
            (name, stype, off, sz)
        } else {
            let name = read_u32(bytes, sh_start, is_le)? as usize;
            let stype = read_u32(bytes, sh_start + 4, is_le)?;
            let off = read_u32(bytes, sh_start + 16, is_le)? as usize;
            let sz = read_u32(bytes, sh_start + 20, is_le)? as usize;
            (name, stype, off, sz)
        };

        if sh_type != 8 {
            // SHT_NOBITS does not occupy file bytes
            let sec_end = offset
                .checked_add(size)
                .ok_or_else(|| BinaryMalformed("section offset overflow".into()))?;
            if sec_end > bytes.len() {
                return Err(BinaryMalformed("section exceeds file size".into()));
            }
        }
        sections.push(ElfSection {
            name_offset,
            sh_type,
            offset,
            size,
        });
    }

    let shstrtab_sec = &sections[e_shstrndx];
    // A NOBITS section has no file bytes, and its offset and size were never checked.
    if shstrtab_sec.sh_type == 8 {
        return Err(BinaryMalformed("shstrtab is a NOBITS section".into()));
    }
    let shstrtab_bytes = shstrtab_sec
        .offset
        .checked_add(shstrtab_sec.size)
        .and_then(|end| bytes.get(shstrtab_sec.offset..end))
        .ok_or_else(|| BinaryMalformed("shstrtab out of bounds".into()))?;

    let mut exact_strings = HashSet::new();
    let mut printable_runs = Vec::new();

    for sec in &sections {
        if sec.sh_type == 8 {
            continue;
        }
        if sec.name_offset >= shstrtab_bytes.len() {
            return Err(BinaryMalformed("section name index past .shstrtab".into()));
        }
        let name_slice = &shstrtab_bytes[sec.name_offset..];
        let null_pos = name_slice
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| BinaryMalformed("unterminated section name in shstrtab".into()))?;
        let sec_name = std::str::from_utf8(&name_slice[..null_pos])
            .map_err(|_| BinaryMalformed("non-utf8 section name".into()))?;

        let sec_bytes = &bytes[sec.offset..sec.offset + sec.size];
        if sec_name == ".dynstr" || sec_name == ".strtab" {
            for s in extract_null_terminated_strings(sec_bytes) {
                exact_strings.insert(s);
            }
        } else if sec_name.starts_with(".rodata")
            || sec_name.starts_with(".data")
            || sec_name == ".comment"
        {
            printable_runs.extend(extract_printable_runs(sec_bytes, 6));
        }
    }

    Ok(BinaryStrings {
        exact_strings,
        printable_runs,
    })
}

/// ELF stores a section count of 0xff00 or more in section 0's `sh_size`, and an
/// overflowing string-table index (`SHN_XINDEX`) in section 0's `sh_link`.
fn extended_section_counts(
    bytes: &[u8],
    is_64: bool,
    is_le: bool,
    e_shoff: usize,
    e_shnum: usize,
    e_shstrndx: usize,
) -> Result<(usize, usize), BinaryMalformed> {
    const SHN_XINDEX: usize = 0xffff;
    if e_shoff == 0 || (e_shnum != 0 && e_shstrndx != SHN_XINDEX) {
        return Ok((e_shnum, e_shstrndx));
    }
    let (size_off, link_off) = if is_64 { (32, 40) } else { (20, 24) };
    let at = |field: usize| {
        e_shoff
            .checked_add(field)
            .ok_or_else(|| BinaryMalformed("section 0 offset overflow".into()))
    };
    let shnum = if e_shnum != 0 {
        e_shnum
    } else if is_64 {
        read_u64(bytes, at(size_off)?, is_le)? as usize
    } else {
        read_u32(bytes, at(size_off)?, is_le)? as usize
    };
    let shstrndx = if e_shstrndx == SHN_XINDEX {
        read_u32(bytes, at(link_off)?, is_le)? as usize
    } else {
        e_shstrndx
    };
    Ok((shnum, shstrndx))
}

/// Parse Java .class file (magic 0xCAFEBABE).
/// Extracts UTF-8 constant pool entries, handling all tag sizes and the 2 slots of Long/Double.
pub fn parse_class(bytes: &[u8]) -> Result<BinaryStrings, BinaryMalformed> {
    if bytes.len() < 10 {
        return Err(BinaryMalformed("class file too small".into()));
    }
    if !bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        return Err(BinaryMalformed("invalid class magic".into()));
    }

    let cp_count = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
    if cp_count > bytes.len() {
        return Err(BinaryMalformed(
            "constant pool count larger than file".into(),
        ));
    }

    let mut exact_strings = HashSet::new();
    let mut offset = 10;
    let mut i = 1;

    while i < cp_count {
        if offset >= bytes.len() {
            return Err(BinaryMalformed("truncated constant pool".into()));
        }
        let tag = bytes[offset];
        offset += 1;

        match tag {
            1 => {
                // CONSTANT_Utf8
                if offset + 2 > bytes.len() {
                    return Err(BinaryMalformed("truncated utf8 entry length".into()));
                }
                let len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
                offset += 2;
                if offset + len > bytes.len() {
                    return Err(BinaryMalformed("truncated utf8 entry bytes".into()));
                }
                let s = String::from_utf8_lossy(&bytes[offset..offset + len]).to_string();
                offset += len;
                exact_strings.insert(s);
                i += 1;
            }
            3 | 4 => {
                // Integer, Float
                if offset + 4 > bytes.len() {
                    return Err(BinaryMalformed("truncated integer/float entry".into()));
                }
                offset += 4;
                i += 1;
            }
            5 | 6 => {
                // Long, Double: takes 2 slots in the constant pool!
                if offset + 8 > bytes.len() {
                    return Err(BinaryMalformed("truncated long/double entry".into()));
                }
                offset += 8;
                i += 2;
            }
            7 | 8 | 16 | 19 | 20 => {
                // Class, String, MethodType, Module, Package
                if offset + 2 > bytes.len() {
                    return Err(BinaryMalformed("truncated 2-byte tag entry".into()));
                }
                offset += 2;
                i += 1;
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                // Fieldref, Methodref, InterfaceMethodref, NameAndType, Dynamic, InvokeDynamic
                if offset + 4 > bytes.len() {
                    return Err(BinaryMalformed("truncated 4-byte tag entry".into()));
                }
                offset += 4;
                i += 1;
            }
            15 => {
                // MethodHandle
                if offset + 3 > bytes.len() {
                    return Err(BinaryMalformed("truncated method handle entry".into()));
                }
                offset += 3;
                i += 1;
            }
            _ => {
                return Err(BinaryMalformed(format!(
                    "unknown constant pool tag: {}",
                    tag
                )));
            }
        }
    }

    Ok(BinaryStrings {
        exact_strings,
        printable_runs: Vec::new(),
    })
}

fn read_varuint(bytes: &[u8], offset: &mut usize) -> Result<u32, BinaryMalformed> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        if *offset >= bytes.len() {
            return Err(BinaryMalformed("unexpected end of LEB128 varuint".into()));
        }
        let b = bytes[*offset];
        *offset += 1;
        result |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return Err(BinaryMalformed("LEB128 varuint overflow".into()));
        }
    }
    Ok(result)
}

fn read_wasm_string(bytes: &[u8], offset: &mut usize) -> Result<String, BinaryMalformed> {
    let len = read_varuint(bytes, offset)? as usize;
    if *offset + len > bytes.len() {
        return Err(BinaryMalformed("wasm string length out of bounds".into()));
    }
    let s = String::from_utf8_lossy(&bytes[*offset..*offset + len]).to_string();
    *offset += len;
    Ok(s)
}

/// Parse WebAssembly module (magic \0asm).
/// Extracts export and import names, name custom section, and printable runs from data section.
pub fn parse_wasm(bytes: &[u8]) -> Result<BinaryStrings, BinaryMalformed> {
    if bytes.len() < 8 {
        return Err(BinaryMalformed("wasm module too small".into()));
    }
    if !bytes.starts_with(b"\0asm") {
        return Err(BinaryMalformed("invalid wasm magic".into()));
    }

    let mut exact_strings = HashSet::new();
    let mut printable_runs = Vec::new();
    let mut offset = 8;

    while offset < bytes.len() {
        let section_id = bytes[offset];
        offset += 1;
        let payload_len = read_varuint(bytes, &mut offset)? as usize;
        let section_end = offset
            .checked_add(payload_len)
            .ok_or_else(|| BinaryMalformed("wasm section length overflow".into()))?;
        if section_end > bytes.len() {
            return Err(BinaryMalformed("wasm section length past the end".into()));
        }
        let payload = &bytes[offset..section_end];

        match section_id {
            0 => {
                // Custom section
                let mut sec_off = 0;
                if let Ok(name) = read_wasm_string(payload, &mut sec_off) {
                    if name == "name" {
                        let mut sub_off = sec_off;
                        while sub_off < payload.len() {
                            let sub_id = payload[sub_off];
                            sub_off += 1;
                            let sub_len = match read_varuint(payload, &mut sub_off) {
                                Ok(l) => l as usize,
                                Err(_) => break,
                            };
                            if sub_off + sub_len > payload.len() {
                                break;
                            }
                            let sub_end = sub_off + sub_len;
                            let sub_payload = &payload[sub_off..sub_end];

                            if sub_id == 0 {
                                let mut m_off = 0;
                                if let Ok(m_name) = read_wasm_string(sub_payload, &mut m_off) {
                                    exact_strings.insert(m_name);
                                }
                            } else if sub_id == 1 {
                                let mut f_off = 0;
                                if let Ok(count) = read_varuint(sub_payload, &mut f_off) {
                                    for _ in 0..count {
                                        if f_off >= sub_payload.len() {
                                            break;
                                        }
                                        let _ = read_varuint(sub_payload, &mut f_off);
                                        if let Ok(fname) = read_wasm_string(sub_payload, &mut f_off)
                                        {
                                            exact_strings.insert(fname);
                                        }
                                    }
                                }
                            } else if sub_id == 2 {
                                let mut l_off = 0;
                                if let Ok(count) = read_varuint(sub_payload, &mut l_off) {
                                    for _ in 0..count {
                                        if l_off >= sub_payload.len() {
                                            break;
                                        }
                                        let _ = read_varuint(sub_payload, &mut l_off);
                                        if let Ok(num_locals) =
                                            read_varuint(sub_payload, &mut l_off)
                                        {
                                            for _ in 0..num_locals {
                                                if l_off >= sub_payload.len() {
                                                    break;
                                                }
                                                let _ = read_varuint(sub_payload, &mut l_off);
                                                if let Ok(lname) =
                                                    read_wasm_string(sub_payload, &mut l_off)
                                                {
                                                    exact_strings.insert(lname);
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                let mut o_off = 0;
                                if let Ok(count) = read_varuint(sub_payload, &mut o_off) {
                                    for _ in 0..count {
                                        if o_off >= sub_payload.len() {
                                            break;
                                        }
                                        let _ = read_varuint(sub_payload, &mut o_off);
                                        if let Ok(s) = read_wasm_string(sub_payload, &mut o_off) {
                                            exact_strings.insert(s);
                                        }
                                    }
                                }
                            }
                            sub_off = sub_end;
                        }
                    }
                }
            }
            2 => {
                // Import section
                let mut imp_off = 0;
                if let Ok(count) = read_varuint(payload, &mut imp_off) {
                    for _ in 0..count {
                        if imp_off >= payload.len() {
                            break;
                        }
                        if let Ok(mod_name) = read_wasm_string(payload, &mut imp_off) {
                            exact_strings.insert(mod_name);
                        } else {
                            break;
                        }
                        if let Ok(field_name) = read_wasm_string(payload, &mut imp_off) {
                            exact_strings.insert(field_name);
                        } else {
                            break;
                        }
                        if imp_off >= payload.len() {
                            break;
                        }
                        let kind = payload[imp_off];
                        imp_off += 1;
                        match kind {
                            0 => {
                                let _ = read_varuint(payload, &mut imp_off);
                            }
                            1 => {
                                imp_off += 1;
                                if let Ok(flags) = read_varuint(payload, &mut imp_off) {
                                    let _ = read_varuint(payload, &mut imp_off);
                                    if flags == 1 {
                                        let _ = read_varuint(payload, &mut imp_off);
                                    }
                                }
                            }
                            2 => {
                                if let Ok(flags) = read_varuint(payload, &mut imp_off) {
                                    let _ = read_varuint(payload, &mut imp_off);
                                    if flags == 1 {
                                        let _ = read_varuint(payload, &mut imp_off);
                                    }
                                }
                            }
                            3 => {
                                imp_off += 2;
                            }
                            _ => {}
                        }
                    }
                }
            }
            7 => {
                // Export section
                let mut exp_off = 0;
                if let Ok(count) = read_varuint(payload, &mut exp_off) {
                    for _ in 0..count {
                        if exp_off >= payload.len() {
                            break;
                        }
                        if let Ok(exp_name) = read_wasm_string(payload, &mut exp_off) {
                            exact_strings.insert(exp_name);
                        } else {
                            break;
                        }
                        if exp_off >= payload.len() {
                            break;
                        }
                        let _kind = payload[exp_off];
                        exp_off += 1;
                        let _ = read_varuint(payload, &mut exp_off);
                    }
                }
            }
            11 => {
                // Data section
                printable_runs.extend(extract_printable_runs(payload, 6));
            }
            _ => {}
        }

        offset = section_end;
    }

    Ok(BinaryStrings {
        exact_strings,
        printable_runs,
    })
}

/// Detect minified JS or CSS bundle:
/// Text with a line of at least 5000 characters, or path ending .min.js, .min.css, .bundle.js
pub fn is_minified_bundle(path: &str, text: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".min.js") || lower.ends_with(".min.css") || lower.ends_with(".bundle.js") {
        return true;
    }
    text.lines().any(|l| l.len() >= 5000)
}

/// Extract tokens from minified text: runs of `[A-Za-z0-9_$]` and quoted-string contents.
/// `winnow::tokenize` can't be used here: it treats `#` as a comment to the end of the
/// line, and a minified bundle is one line, so CSS `#fff` or JS `this.#x` would hide the rest.
pub fn parse_minified(text: &str) -> BinaryStrings {
    let mut exact_strings = HashSet::new();
    let mut word = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_alphanumeric() || c == '_' || c == '$' {
            word.push(c);
            continue;
        }
        if !word.is_empty() {
            exact_strings.insert(std::mem::take(&mut word));
        }
        if c == '"' || c == '\'' || c == '`' {
            let mut content = String::new();
            while let Some(d) = chars.next() {
                if d == '\\' {
                    if let Some(escaped) = chars.next() {
                        content.push(escaped);
                    }
                } else if d == c {
                    break;
                } else {
                    content.push(d);
                }
            }
            for part in content.split(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '$'))
            {
                if !part.is_empty() {
                    exact_strings.insert(part.to_string());
                }
            }
            exact_strings.insert(content);
        }
    }
    if !word.is_empty() {
        exact_strings.insert(word);
    }
    BinaryStrings {
        exact_strings,
        printable_runs: Vec::new(),
    }
}

/// Check if item matches in printable run either by exact equality or as a whole-token substring
/// (characters around it are not [A-Za-z0-9_]).
fn matches_printable_run(run: &str, item: &str) -> bool {
    if run == item {
        return true;
    }
    let item_bytes = item.as_bytes();
    let run_bytes = run.as_bytes();
    if item_bytes.len() > run_bytes.len() {
        return false;
    }
    let mut start = 0;
    while let Some(pos) = run[start..].find(item) {
        let idx = start + pos;
        let before_ok = if idx == 0 {
            true
        } else {
            let b = run_bytes[idx - 1];
            !(b.is_ascii_alphanumeric() || b == b'_')
        };
        let after_idx = idx + item_bytes.len();
        let after_ok = if after_idx >= run_bytes.len() {
            true
        } else {
            let b = run_bytes[after_idx];
            !(b.is_ascii_alphanumeric() || b == b'_')
        };
        if before_ok && after_ok {
            return true;
        }
        start = idx + 1;
        if start >= run_bytes.len() {
            break;
        }
    }
    false
}

/// Match extracted binary strings against FingerprintSet binary tier.
pub fn match_binary_items(
    extracted: &BinaryStrings,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    channel: &str,
    path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for hunk in &fp.hunks {
        // Skip rule: A hunk with fewer than 2 surviving items isn't matched on this tier.
        if hunk.binary_items.len() < 2 {
            continue;
        }

        let mut matched_items = Vec::new();
        for item in &hunk.binary_items {
            let mut matched = extracted.exact_strings.contains(item);
            if !matched {
                for run in &extracted.printable_runs {
                    if matches_printable_run(run, item) {
                        matched = true;
                        break;
                    }
                }
            }
            if matched {
                matched_items.push(item.clone());
            }
        }

        let confidence = matched_items.len() as f64 / hunk.binary_items.len() as f64;
        if confidence >= opts.binary_threshold {
            findings.push(Finding {
                detector: "D3b".into(),
                channel: channel.into(),
                path: path.to_string(),
                visibility: opts.visibility,
                severity: Severity::Gate,
                confidence: (confidence * 100.0).round() / 100.0,
                hunk: Some(hunk.hunk_index),
                evidence: matched_items.into_iter().take(5).collect(),
            });
        }
    }

    findings
}

/// `0xCAFEBABE` starts both class files and Mach-O universal binaries. A class file's major
/// version (bytes 6-7) is 45 or more; a universal binary has a small architecture count there.
fn is_java_class(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && u16::from_be_bytes([bytes[6], bytes[7]]) >= 45
}

/// Strings a `.pyc` stores, read from marshal's length-prefixed string records without a
/// full unmarshal. Names and constants run straight into the next opcode byte, as in
/// `effective_hourss`, so a printable-run search can't find them as whole tokens.
///
/// Every position whose type code (the 0x80 ref flag masked off) is a string type, and
/// whose length prefix covers printable bytes only, yields a candidate. A false candidate
/// costs nothing: candidates are only compared for equality with the fix's items.
pub fn extract_pyc_strings(body: &[u8]) -> HashSet<String> {
    let printable = |s: &[u8]| s.iter().all(|&b| (0x20..=0x7e).contains(&b));
    let mut out = HashSet::new();
    for i in 0..body.len() {
        let (len, start) = match body[i] & 0x7f {
            // short ascii (interned): one-byte length
            b'z' | b'Z' => match body.get(i + 1) {
                Some(&l) => (l as usize, i + 2),
                None => continue,
            },
            // ascii, unicode, bytes, interned: four-byte little-endian length
            b'a' | b'A' | b'u' | b't' | b's' => match body.get(i + 1..i + 5) {
                Some(l) => (u32::from_le_bytes([l[0], l[1], l[2], l[3]]) as usize, i + 5),
                None => continue,
            },
            _ => continue,
        };
        if len < 8 {
            continue;
        }
        if let Some(s) = start.checked_add(len).and_then(|end| body.get(start..end)) {
            if printable(s) {
                if let Ok(text) = std::str::from_utf8(s) {
                    out.insert(text.to_string());
                }
            }
        }
    }
    out
}

/// The binary-tier strings of a `.pyc`: its marshal strings, matched exactly.
pub fn pyc_binary_strings(bytes: &[u8]) -> BinaryStrings {
    let header = crate::bytecode::pyc_magic(bytes)
        .map(crate::bytecode::pyc_header_len)
        .unwrap_or(0);
    let body = bytes.get(header..).unwrap_or(&[]);
    BinaryStrings {
        exact_strings: extract_pyc_strings(body),
        printable_runs: Vec::new(),
    }
}

/// D3b over a `.pyc` (channel `binary_pyc`): the binary tier on its marshal strings.
pub fn scan_pyc_strings(
    path: &str,
    bytes: &[u8],
    fp: &FingerprintSet,
    opts: &ScanOptions,
) -> Vec<Finding> {
    match_binary_items(&pyc_binary_strings(bytes), fp, opts, "binary_pyc", path)
}

/// A recognised binary (ELF, Java class, Mach-O universal, wasm): its D3b channel and its
/// parsed strings. `None` when `bytes` is none of these formats.
pub fn recognize_binary(
    bytes: &[u8],
) -> Option<(&'static str, Result<BinaryStrings, BinaryMalformed>)> {
    if bytes.starts_with(b"\x7fELF") {
        Some(("binary_elf", parse_elf(bytes)))
    } else if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) && is_java_class(bytes) {
        Some(("binary_class", parse_class(bytes)))
    } else if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        // Same magic as a class file: a Mach-O universal binary. Search its strings.
        Some((
            "binary_macho",
            Ok(BinaryStrings {
                exact_strings: HashSet::new(),
                printable_runs: extract_printable_runs(bytes, 6),
            }),
        ))
    } else if bytes.starts_with(b"\0asm") {
        Some(("binary_wasm", parse_wasm(bytes)))
    } else {
        None
    }
}

/// The info finding for a malformed binary. Its strings are still searched, through
/// `malformed_fallback_strings`.
pub fn malformed_binary_finding(
    path: &str,
    channel: &str,
    err: &str,
    opts: &ScanOptions,
) -> Finding {
    Finding {
        detector: "D3b".into(),
        channel: "binary_malformed".into(),
        path: path.to_string(),
        visibility: opts.visibility,
        severity: Severity::Info,
        confidence: 0.0,
        hunk: None,
        evidence: vec![format!("malformed {}: {}", channel, err)],
    }
}

/// The payload decoded as UTF-16LE from byte offset 0 and from byte offset 1 (the second
/// also reads UTF-16BE text), over its whole length. Control characters, unpaired
/// surrogates and a trailing odd byte become line breaks, so text keeps its lines.
pub fn utf16_text_views(bytes: &[u8]) -> [String; 2] {
    let decode = |offset: usize| -> String {
        let units = bytes
            .get(offset..)
            .unwrap_or(&[])
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair));
        char::decode_utf16(units)
            .map(|c| match c {
                Ok(ch) if !ch.is_control() || ch == '\t' || ch == '\n' => ch,
                _ => '\n',
            })
            .collect()
    };
    [decode(0), decode(1)]
}

/// A corrupted header must not hide the file's strings: search its printable runs.
pub fn malformed_fallback_strings(bytes: &[u8]) -> BinaryStrings {
    BinaryStrings {
        exact_strings: HashSet::new(),
        printable_runs: extract_printable_runs(bytes, 6),
    }
}

/// If `bytes` is a recognised binary (ELF, Class, wasm), parse and scan it for D3b.
/// Returns `Some(findings)` if recognised, or `None` if not a recognised binary format.
pub fn scan_binary_if_recognized(
    path: &str,
    bytes: &[u8],
    fp: &FingerprintSet,
    opts: &ScanOptions,
) -> Option<Vec<Finding>> {
    let (channel, res) = recognize_binary(bytes)?;
    match res {
        Ok(extracted) => Some(match_binary_items(&extracted, fp, opts, channel, path)),
        Err(BinaryMalformed(err)) => {
            let mut findings = vec![malformed_binary_finding(path, channel, &err, opts)];
            findings.extend(match_binary_items(
                &malformed_fallback_strings(bytes),
                fp,
                opts,
                channel,
                path,
            ));
            Some(findings)
        }
    }
}

/// True when every character of `s` is in `[A-Za-z0-9_]`, the characters that bound a
/// whole-token match inside a printable run.
pub fn is_word_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The maximal `[A-Za-z0-9_]+` pieces of a printable run. An item made only of those
/// characters matches the run as a whole token exactly when it equals one of these pieces.
pub fn word_tokens(run: &str) -> impl Iterator<Item = &str> {
    run.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
}

/// Binary-tier strings reduced to 64-bit hashes, as stored in a layer index.
///
/// `exact` holds every exact string and every whole printable run; `tokens` holds the
/// `[A-Za-z0-9_]+` pieces of the runs. An item that holds any other character can only
/// match a whole stored string, not a substring of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HashedBinaryStrings {
    pub exact: HashSet<u64>,
    pub tokens: HashSet<u64>,
}

impl HashedBinaryStrings {
    pub fn from_strings(strings: &BinaryStrings) -> Self {
        let h = |s: &str| crate::fingerprint::sha256_u64(s.as_bytes());
        let mut exact: HashSet<u64> = strings.exact_strings.iter().map(|s| h(s)).collect();
        let mut tokens = HashSet::new();
        for run in &strings.printable_runs {
            exact.insert(h(run));
            for t in word_tokens(run) {
                tokens.insert(h(t));
            }
        }
        Self { exact, tokens }
    }

    fn contains_item(&self, item: &str, item_hash: u64) -> bool {
        self.exact.contains(&item_hash) || (is_word_token(item) && self.tokens.contains(&item_hash))
    }
}

/// `match_binary_items` over hashed strings. Gives the same findings, except that an item
/// holding a character outside `[A-Za-z0-9_]` is not found as a substring of a run.
pub fn match_hashed_binary_items(
    extracted: &HashedBinaryStrings,
    fp: &FingerprintSet,
    opts: &ScanOptions,
    channel: &str,
    path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for hunk in &fp.hunks {
        if hunk.binary_items.len() < 2 {
            continue;
        }
        let matched_items: Vec<String> = hunk
            .binary_items
            .iter()
            .filter(|item| {
                extracted.contains_item(item, crate::fingerprint::sha256_u64(item.as_bytes()))
            })
            .cloned()
            .collect();
        let confidence = matched_items.len() as f64 / hunk.binary_items.len() as f64;
        if confidence >= opts.binary_threshold {
            findings.push(Finding {
                detector: "D3b".into(),
                channel: channel.into(),
                path: path.to_string(),
                visibility: opts.visibility,
                severity: Severity::Gate,
                confidence: (confidence * 100.0).round() / 100.0,
                hunk: Some(hunk.hunk_index),
                evidence: matched_items.into_iter().take(5).collect(),
            });
        }
    }
    findings
}

/// Scan a minified bundle for D3b (channel `binary_minified`).
pub fn scan_minified_bundle(
    path: &str,
    text: &str,
    fp: &FingerprintSet,
    opts: &ScanOptions,
) -> Vec<Finding> {
    let extracted = parse_minified(text);
    match_binary_items(&extracted, fp, opts, "binary_minified", path)
}
