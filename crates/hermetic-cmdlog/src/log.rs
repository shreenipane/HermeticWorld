//! Append-only, fsynced command log writer and full-chain verifier.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

use crate::entry::{Entry, EntryPayload, GENESIS_PREV};
use crate::{ChainError, MAX_LINE_BYTES, MAX_LOG_ENTRIES};

/// Verified head position of a command log chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub seq: u64,
    pub head: String,
}

/// Append-only writer holding an open, verified command log file descriptor.
#[derive(Debug)]
pub struct CmdLog {
    file: File,
    next_seq: u64,
    head_hash: String,
    has_entries: bool,
    /// Set when a write or `fsync` failed, leaving the file tail in an unknown state.
    poisoned: bool,
}

/// Extra `open(2)` flags: never follow a final symlink and never block opening a FIFO.
#[cfg(unix)]
const SAFE_OPEN_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;

fn safe_open_options() -> OpenOptions {
    #[allow(unused_mut)]
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    {
        opts.custom_flags(SAFE_OPEN_FLAGS);
    }
    opts
}

impl CmdLog {
    /// Opens an existing command log or atomically creates a new one (`0o600` on Unix).
    ///
    /// Refuses to open symlinks, non-regular files, or files writable by group or others, and
    /// verifies the entire existing chain before allowing any appends.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ChainError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.display().to_string();

        let mut file = match fs::symlink_metadata(path_ref) {
            Ok(lstat_meta) => {
                validate_lstat_metadata(&lstat_meta, &path_display)?;
                let opened = safe_open_options()
                    .read(true)
                    .append(true)
                    .open(path_ref)
                    .map_err(|source| ChainError::Io {
                        context: format!("opening existing log file '{path_display}'"),
                        source,
                    })?;
                let fstat_meta = opened.metadata().map_err(|source| ChainError::Io {
                    context: format!("inspecting opened log descriptor '{path_display}'"),
                    source,
                })?;
                validate_opened_matches_lstat(&lstat_meta, &fstat_meta, &path_display)?;
                opened
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let mut opts = safe_open_options();
                opts.read(true).write(true).create_new(true);
                #[cfg(unix)]
                {
                    opts.mode(0o600);
                }
                let created = opts.open(path_ref).map_err(|source| ChainError::Io {
                    context: format!("creating new log file '{path_display}'"),
                    source,
                })?;
                let fstat_meta = created.metadata().map_err(|source| ChainError::Io {
                    context: format!("inspecting newly created log '{path_display}'"),
                    source,
                })?;
                validate_fstat_metadata(&fstat_meta, &path_display)?;
                created.sync_all().map_err(|source| ChainError::Io {
                    context: format!("fsyncing newly created log '{path_display}'"),
                    source,
                })?;
                created
            }
            Err(source) => {
                return Err(ChainError::Io {
                    context: format!("statting log path '{path_display}'"),
                    source,
                });
            }
        };

        file.seek(SeekFrom::Start(0))
            .map_err(|source| ChainError::Io {
                context: format!("seeking to start of '{path_display}'"),
                source,
            })?;

        let verified = verify_reader(&mut file, &path_display)?;

        file.seek(SeekFrom::End(0))
            .map_err(|source| ChainError::Io {
                context: format!("seeking to end of '{path_display}'"),
                source,
            })?;

        match verified {
            Some(head) => {
                let next_seq = head
                    .seq
                    .checked_add(1)
                    .ok_or(ChainError::MaxEntriesExceeded {
                        max: MAX_LOG_ENTRIES,
                    })?;
                if next_seq > MAX_LOG_ENTRIES {
                    return Err(ChainError::MaxEntriesExceeded {
                        max: MAX_LOG_ENTRIES,
                    });
                }
                Ok(Self {
                    file,
                    next_seq,
                    head_hash: head.head,
                    has_entries: true,
                    poisoned: false,
                })
            }
            None => Ok(Self {
                file,
                next_seq: 0,
                head_hash: GENESIS_PREV.to_string(),
                has_entries: false,
                poisoned: false,
            }),
        }
    }

    /// Returns `(seq, hash)` of the current head entry.
    ///
    /// Before the first entry (`seq == 0`) is appended, returns `(0, GENESIS_PREV)`.
    /// Once at least one entry has been appended, returns `(last_seq, last_entry_hash)`.
    pub fn head(&self) -> (u64, String) {
        if self.has_entries {
            (self.next_seq.saturating_sub(1), self.head_hash.clone())
        } else {
            (0, GENESIS_PREV.to_string())
        }
    }

    /// Returns the sequence number that will be assigned to the next appended entry.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Returns `true` if no entries have been written to this log yet.
    pub fn is_empty(&self) -> bool {
        !self.has_entries
    }

    /// Appends a single canonical JSON entry line (`\n`-terminated) and `fsync`s the file.
    pub fn append(&mut self, payload: EntryPayload) -> Result<Head, ChainError> {
        if self.poisoned {
            return Err(ChainError::WriterPoisoned);
        }
        if self.next_seq >= MAX_LOG_ENTRIES {
            return Err(ChainError::MaxEntriesExceeded {
                max: MAX_LOG_ENTRIES,
            });
        }

        let seq = self.next_seq;
        let entry = payload.into_entry(seq, self.head_hash.clone());
        let canonical = entry.to_canonical_json()?;
        let entry_hash = entry.hash()?;

        let mut line_buf = Vec::with_capacity(canonical.len().saturating_add(1));
        line_buf.extend_from_slice(canonical.as_bytes());
        line_buf.push(b'\n');

        // A failed or partial write (or fsync) leaves an unknown tail on disk. Appending after
        // it would splice a new line onto a partial one, so the writer is poisoned instead.
        if let Err(source) = self.file.write_all(&line_buf) {
            self.poisoned = true;
            return Err(ChainError::Io {
                context: format!("appending entry seq {seq}"),
                source,
            });
        }

        if let Err(source) = self.file.sync_all() {
            self.poisoned = true;
            return Err(ChainError::Io {
                context: format!("fsyncing entry seq {seq}"),
                source,
            });
        }

        self.next_seq = seq.checked_add(1).ok_or(ChainError::MaxEntriesExceeded {
            max: MAX_LOG_ENTRIES,
        })?;
        self.head_hash = entry_hash.clone();
        self.has_entries = true;

        Ok(Head {
            seq,
            head: entry_hash,
        })
    }
}

/// Verifies an entire command log file on disk and returns its verified [`Head`].
///
/// Refuses symlinks, non-regular files, and files writable by group or others. Reports the
/// 1-based line number of the first broken line on any corruption.
pub fn verify<P: AsRef<Path>>(path: P) -> Result<Head, ChainError> {
    let path_ref = path.as_ref();
    let path_display = path_ref.display().to_string();

    let lstat_meta = fs::symlink_metadata(path_ref).map_err(|source| ChainError::Io {
        context: format!("statting log path '{path_display}'"),
        source,
    })?;
    validate_lstat_metadata(&lstat_meta, &path_display)?;

    let mut file = safe_open_options()
        .read(true)
        .open(path_ref)
        .map_err(|source| ChainError::Io {
            context: format!("opening log file '{path_display}' for verification"),
            source,
        })?;

    let fstat_meta = file.metadata().map_err(|source| ChainError::Io {
        context: format!("inspecting opened log descriptor '{path_display}'"),
        source,
    })?;
    validate_opened_matches_lstat(&lstat_meta, &fstat_meta, &path_display)?;

    match verify_reader(&mut file, &path_display)? {
        Some(head) => Ok(head),
        None => Ok(Head {
            seq: 0,
            head: GENESIS_PREV.to_string(),
        }),
    }
}

fn validate_lstat_metadata(meta: &Metadata, path_display: &str) -> Result<(), ChainError> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(ChainError::SymlinkNotAllowed {
            path: path_display.to_string(),
        });
    }
    if !ft.is_file() {
        return Err(ChainError::NotRegularFile {
            path: path_display.to_string(),
        });
    }
    validate_permissions(meta, path_display)
}

fn validate_fstat_metadata(meta: &Metadata, path_display: &str) -> Result<(), ChainError> {
    if !meta.file_type().is_file() {
        return Err(ChainError::NotRegularFile {
            path: path_display.to_string(),
        });
    }
    validate_permissions(meta, path_display)
}

fn validate_opened_matches_lstat(
    lstat_meta: &Metadata,
    fstat_meta: &Metadata,
    path_display: &str,
) -> Result<(), ChainError> {
    validate_fstat_metadata(fstat_meta, path_display)?;
    #[cfg(unix)]
    {
        if lstat_meta.dev() != fstat_meta.dev() || lstat_meta.ino() != fstat_meta.ino() {
            return Err(ChainError::SymlinkNotAllowed {
                path: path_display.to_string(),
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = lstat_meta;
    }
    Ok(())
}

fn validate_permissions(meta: &Metadata, path_display: &str) -> Result<(), ChainError> {
    #[cfg(unix)]
    {
        let mode = meta.permissions().mode();
        if (mode & 0o022) != 0 {
            return Err(ChainError::InsecurePermissions {
                path: path_display.to_string(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        let _ = path_display;
    }
    Ok(())
}

fn verify_reader<R: Read>(reader: R, path_display: &str) -> Result<Option<Head>, ChainError> {
    let mut buf_reader = BufReader::new(reader);
    let mut line_buf = Vec::new();
    let mut line_num: usize = 0;
    let mut expected_seq: u64 = 0;
    let mut expected_prev = GENESIS_PREV.to_string();
    let mut last_head: Option<Head> = None;

    // Bound line reads by MAX_LINE_BYTES + 1 so an arbitrarily long line cannot cause unbounded
    // allocation, and bound total iterations by MAX_LOG_ENTRIES + 1.
    let max_read_cap = (MAX_LINE_BYTES.saturating_add(1)) as u64;

    loop {
        line_num = line_num
            .checked_add(1)
            .ok_or(ChainError::MaxEntriesExceeded {
                max: MAX_LOG_ENTRIES,
            })?;
        line_buf.clear();

        let bytes_read = (&mut buf_reader)
            .take(max_read_cap)
            .read_until(b'\n', &mut line_buf)
            .map_err(|source| ChainError::Io {
                context: format!("reading line {line_num} of '{path_display}'"),
                source,
            })?;

        if bytes_read == 0 {
            break;
        }

        if expected_seq >= MAX_LOG_ENTRIES {
            return Err(ChainError::MaxEntriesExceeded {
                max: MAX_LOG_ENTRIES,
            });
        }

        if !line_buf.ends_with(b"\n") {
            if line_buf.len() > MAX_LINE_BYTES {
                return Err(ChainError::OversizedLine {
                    line: line_num,
                    max_bytes: MAX_LINE_BYTES,
                });
            }
            return Err(ChainError::TruncatedLine { line: line_num });
        }

        if line_buf.len() > MAX_LINE_BYTES {
            return Err(ChainError::OversizedLine {
                line: line_num,
                max_bytes: MAX_LINE_BYTES,
            });
        }

        let raw_line = &line_buf[..line_buf.len() - 1];
        let line_str = std::str::from_utf8(raw_line).map_err(|err| ChainError::BadJson {
            line: line_num,
            detail: format!("invalid UTF-8: {err}"),
        })?;

        let entry: Entry = serde_json::from_str(line_str).map_err(|err| {
            let detail = err.to_string();
            if detail.contains("unknown field") {
                ChainError::UnknownField {
                    line: line_num,
                    detail,
                }
            } else {
                ChainError::BadJson {
                    line: line_num,
                    detail,
                }
            }
        })?;

        entry.validate_at_line(Some(line_num))?;

        if entry.seq != expected_seq {
            return Err(ChainError::SeqGap {
                line: line_num,
                expected: expected_seq,
                actual: entry.seq,
            });
        }

        if entry.prev != expected_prev {
            return Err(ChainError::PrevMismatch {
                line: line_num,
                expected: expected_prev,
                actual: entry.prev.clone(),
            });
        }

        let canonical = entry.to_canonical_json_at_line(Some(line_num))?;
        if canonical != line_str {
            return Err(ChainError::NonCanonicalJson { line: line_num });
        }

        let entry_hash = entry.hash_at_line(Some(line_num))?;
        last_head = Some(Head {
            seq: entry.seq,
            head: entry_hash.clone(),
        });
        expected_prev = entry_hash;
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or(ChainError::MaxEntriesExceeded {
                max: MAX_LOG_ENTRIES,
            })?;
    }

    Ok(last_head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EMPTY_SHA256;

    fn status_payload() -> EntryPayload {
        EntryPayload::status(Some(0), EMPTY_SHA256, EMPTY_SHA256, 0, 0, false)
    }

    #[test]
    fn regression_failed_append_poisons_writer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cmdlog.jsonl");
        std::fs::write(&path, b"").expect("create log");
        // A read-only descriptor makes every write fail, standing in for a disk error that
        // may have left part of a line on disk.
        let file = File::open(&path).expect("open read-only");
        let mut log = CmdLog {
            file,
            next_seq: 0,
            head_hash: GENESIS_PREV.to_string(),
            has_entries: false,
            poisoned: false,
        };

        let first = log.append(status_payload()).expect_err("write must fail");
        assert!(matches!(first, ChainError::Io { .. }), "{first:?}");
        assert_eq!(log.head(), (0, GENESIS_PREV.to_string()));
        assert_eq!(log.next_seq(), 0);

        let second = log
            .append(status_payload())
            .expect_err("writer is poisoned");
        assert!(matches!(second, ChainError::WriterPoisoned), "{second:?}");
        assert!(!second.is_chain_corruption());
    }
}
