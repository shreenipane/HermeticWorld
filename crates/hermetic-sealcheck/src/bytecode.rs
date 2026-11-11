use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::scan::{Finding, Severity, Visibility};

/// Locate the Python source file for a given .pyc file path.
/// - For `__pycache__/name.cpython-XY.pyc` (any tag), it is `../name.py`
/// - For a legacy `name.pyc`, it is `name.py` in the same directory.
pub fn locate_pyc_source(pyc_path: &Path) -> Option<PathBuf> {
    let parent = pyc_path.parent()?;
    let file_name = pyc_path.file_name()?.to_str()?;

    if parent.file_name().is_some_and(|name| name == "__pycache__") {
        // e.g. foo.cpython-310.pyc -> foo.py in parent's parent
        let grand_parent = parent.parent()?;
        let stem = file_name.split('.').next()?;
        Some(grand_parent.join(format!("{}.py", stem)))
    } else {
        // legacy name.pyc -> name.py in same directory
        let stem = file_name.strip_suffix(".pyc")?;
        Some(parent.join(format!("{}.py", stem)))
    }
}

/// Check a loose .pyc file for D3 (PEP 552 bytecode freshness / orphan check).
pub fn check_pyc_bytecode(
    pyc_path: &Path,
    visibility: Visibility,
) -> Result<Vec<Finding>, std::io::Error> {
    let mut file = File::open(pyc_path)?;
    let mut header = [0u8; 16];
    let bytes_read = file.read(&mut header)?;

    if bytes_read < 16 {
        // Not a valid 16-byte PEP 552 pyc header
        return Ok(Vec::new());
    }

    let flags = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let display_path = pyc_path.display().to_string();

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

    if !source_path.exists() {
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

    // Source exists; check header kind
    if flags & 1 != 0 {
        // Bit 0 set: hash-based pyc
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

    // flags == 0: timestamp pyc
    let header_mtime = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let header_size = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);

    let meta = source_path.metadata()?;
    let src_mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let src_size = (meta.len() & 0xFFFF_FFFF) as u32;

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
        // Fresh timestamp pyc: no finding
        Ok(Vec::new())
    }
}
