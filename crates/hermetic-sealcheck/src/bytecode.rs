use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::scan::{Finding, Severity, Visibility};

/// Determine Python bytecode magic number if bytes match pyc signature.
/// Bytes 2 and 3 are `\r\n` and the little-endian u16 from bytes 0 and 1 is in `3000..=4095` or equals `62211`.
pub fn pyc_magic(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 4 {
        return None;
    }
    if bytes[2] != 0x0d || bytes[3] != 0x0a {
        return None;
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if (3000..=4095).contains(&magic) || magic == 62211 {
        Some(magic)
    } else {
        None
    }
}

/// Determine pyc header length based on magic number.
pub fn pyc_header_len(magic: u16) -> usize {
    if magic >= 3392 && magic != 62211 {
        16
    } else if (3210..=3391).contains(&magic) {
        12
    } else {
        8
    }
}

/// Locate the Python source file for a given .pyc file path.
/// - Strip `.pyc`, then an optional `.opt-N`, then the final `.tag`
/// - For `__pycache__/name.cpython-XY.pyc`, it is `../name.py`
/// - For a legacy `name.pyc`, it is `name.py` in the same directory.
pub fn locate_pyc_source(pyc_path: &Path) -> Option<PathBuf> {
    let parent = pyc_path.parent()?;
    let file_name = pyc_path.file_name()?.to_str()?;

    let without_pyc = file_name.strip_suffix(".pyc")?;
    let without_opt = if let Some(idx) = without_pyc.rfind(".opt-") {
        let suffix = &without_pyc[idx + 5..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            &without_pyc[..idx]
        } else {
            without_pyc
        }
    } else {
        without_pyc
    };

    if parent.file_name().is_some_and(|name| name == "__pycache__") {
        let stem = if let Some(idx) = without_opt.rfind('.') {
            &without_opt[..idx]
        } else {
            without_opt
        };
        let grand_parent = parent.parent()?;
        Some(grand_parent.join(format!("{}.py", stem)))
    } else {
        Some(parent.join(format!("{}.py", without_opt)))
    }
}

/// Check a loose .pyc file for D3 (PEP 552 bytecode freshness / orphan check).
pub fn check_pyc_bytecode(
    pyc_path: &Path,
    visibility: Visibility,
) -> Result<Vec<Finding>, std::io::Error> {
    let mut file = crate::safe_fs::open_regular(pyc_path)?;
    let mut buf = Vec::new();
    file.by_ref().take(16).read_to_end(&mut buf)?;
    let display_path = pyc_path.display().to_string();

    let magic = match pyc_magic(&buf) {
        Some(m) => m,
        None => {
            return Ok(vec![Finding {
                detector: "D3".into(),
                channel: "pyc_invalid".into(),
                path: display_path,
                visibility,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec!["invalid pyc magic number".into()],
            }]);
        }
    };

    let header_len = pyc_header_len(magic);
    if buf.len() < header_len {
        return Ok(vec![Finding {
            detector: "D3".into(),
            channel: "pyc_invalid".into(),
            path: display_path,
            visibility,
            severity: Severity::Info,
            confidence: 0.0,
            hunk: None,
            evidence: vec![format!(
                "pyc file too short for header: got {} bytes, expected {}",
                buf.len(),
                header_len
            )],
        }]);
    }

    let source_path = match locate_pyc_source(pyc_path) {
        Some(p) => p,
        None => {
            return Ok(vec![Finding {
                detector: "D3".into(),
                channel: "pyc_orphan".into(),
                path: display_path,
                visibility,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec!["unable to determine expected source path".into()],
            }]);
        }
    };

    let meta = match crate::safe_fs::metadata(&source_path) {
        Ok(meta) if meta.is_file() => meta,
        Ok(_) => return Err(std::io::Error::other("source is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(vec![Finding {
                detector: "D3".into(),
                channel: "pyc_orphan".into(),
                path: display_path,
                visibility,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!("missing source file: {}", source_path.display())],
            }]);
        }
        Err(error) => return Err(error),
    };
    let src_mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let src_size = (meta.len() & 0xFFFF_FFFF) as u32;

    if header_len == 16 {
        let flags = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if flags & 1 != 0 {
            return Ok(vec![Finding {
                detector: "D3".into(),
                channel: "pyc_hash_unchecked".into(),
                path: display_path,
                visibility,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec!["hash-based pyc unchecked".into()],
            }]);
        }
        let header_mtime = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let header_size = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if header_mtime != src_mtime || header_size != src_size {
            Ok(vec![Finding {
                detector: "D3".into(),
                channel: "pyc_stale".into(),
                path: display_path,
                visibility,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!(
                    "header mtime: {}, source mtime: {}; header size: {}, source size: {}",
                    header_mtime, src_mtime, header_size, src_size
                )],
            }])
        } else {
            Ok(Vec::new())
        }
    } else if header_len == 12 {
        let header_mtime = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let header_size = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if header_mtime != src_mtime || header_size != src_size {
            Ok(vec![Finding {
                detector: "D3".into(),
                channel: "pyc_stale".into(),
                path: display_path,
                visibility,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!(
                    "header mtime: {}, source mtime: {}; header size: {}, source size: {}",
                    header_mtime, src_mtime, header_size, src_size
                )],
            }])
        } else {
            Ok(Vec::new())
        }
    } else {
        // header_len == 8: source size isn't checked
        let header_mtime = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if header_mtime != src_mtime {
            Ok(vec![Finding {
                detector: "D3".into(),
                channel: "pyc_stale".into(),
                path: display_path,
                visibility,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!(
                    "header mtime: {}, source mtime: {}",
                    header_mtime, src_mtime
                )],
            }])
        } else {
            Ok(Vec::new())
        }
    }
}
