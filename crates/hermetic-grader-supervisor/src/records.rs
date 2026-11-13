use std::fmt;

use serde::{Deserialize, Serialize};

/// Stream header magic bytes (`b"HGR1"`).
pub const STREAM_MAGIC: &[u8; 4] = b"HGR1";

/// Fixed record frame header size in bytes: `type (1) + length u32 LE (4)`.
pub const RECORD_HEADER_BYTES: usize = 5;

/// Maximum JSON payload length for a single record frame (64 KiB).
pub const MAX_RECORD_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum number of records accepted in a single grading stream.
pub const MAX_RECORDS_PER_STREAM: usize = 100_000;

/// Maximum internal unread byte buffer size in [`RecordDecoder`].
pub const MAX_STREAM_BUFFER_BYTES: usize = 256 * 1024;

/// Maximum UTF-8 byte length of a test `nodeid`.
pub const MAX_NODEID_BYTES: usize = 1024;

/// Wire record type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    Start = 1,
    Finish = 2,
    End = 3,
}

impl RecordType {
    pub fn from_u8(tag: u8) -> Result<Self, RecordError> {
        match tag {
            1 => Ok(RecordType::Start),
            2 => Ok(RecordType::Finish),
            3 => Ok(RecordType::End),
            other => Err(RecordError::UnknownRecordType(other)),
        }
    }
}

/// Test outcome reported in a `FINISH` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordOutcome {
    Passed,
    Failed,
    Skipped,
    Error,
}

/// `START` record JSON payload (`type = 1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRecord {
    pub seq: u64,
    pub nodeid: String,
}

/// `FINISH` record JSON payload (`type = 2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishRecord {
    pub seq: u64,
    pub nodeid: String,
    pub outcome: RecordOutcome,
    pub duration_ms: u64,
}

/// `END` record JSON payload (`type = 3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndRecord {
    pub count: u64,
}

/// A validated record decoded from the `HGR1` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedRecord {
    Start(StartRecord),
    Finish(FinishRecord),
    End(EndRecord),
}

/// Errors produced during strict `HGR1` stream decoding or encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    InvalidMagic,
    TruncatedHeader,
    TruncatedRecord,
    UnknownRecordType(u8),
    RecordTooLarge {
        len: u32,
        max: usize,
    },
    BufferOverflow {
        buffered: usize,
        max: usize,
    },
    TooManyRecords {
        max: usize,
    },
    InvalidUtf8,
    InvalidJson(String),
    InvalidNodeId(String),
    NonMonotonicSeq {
        prev: u64,
        current: u64,
    },
    DuplicateStart(String),
    DuplicateTest(String),
    FinishWithoutStart(String),
    EndCountMismatch {
        reported: u64,
        tests_finished: u64,
        records_emitted: u64,
    },
    TrailingDataAfterEnd,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::InvalidMagic => write!(f, "invalid stream magic (expected HGR1)"),
            RecordError::TruncatedHeader => write!(f, "truncated stream header before HGR1 magic"),
            RecordError::TruncatedRecord => write!(f, "truncated record frame at EOF"),
            RecordError::UnknownRecordType(t) => write!(f, "unknown record type tag: {}", t),
            RecordError::RecordTooLarge { len, max } => {
                write!(f, "record length {} exceeds cap of {} bytes", len, max)
            }
            RecordError::BufferOverflow { buffered, max } => {
                write!(
                    f,
                    "stream buffer size {} exceeds cap of {} bytes",
                    buffered, max
                )
            }
            RecordError::TooManyRecords { max } => {
                write!(f, "stream exceeded maximum record count of {}", max)
            }
            RecordError::InvalidUtf8 => write!(f, "record payload is not valid UTF-8"),
            RecordError::InvalidJson(msg) => write!(f, "invalid record JSON: {}", msg),
            RecordError::InvalidNodeId(msg) => write!(f, "invalid nodeid: {}", msg),
            RecordError::NonMonotonicSeq { prev, current } => {
                write!(
                    f,
                    "non-monotonic sequence number: {} after {}",
                    current, prev
                )
            }
            RecordError::DuplicateStart(id) => write!(f, "duplicate START for test '{}'", id),
            RecordError::DuplicateTest(id) => {
                write!(f, "test '{}' started again after finishing", id)
            }
            RecordError::FinishWithoutStart(id) => {
                write!(f, "FINISH received without prior START for test '{}'", id)
            }
            RecordError::EndCountMismatch {
                reported,
                tests_finished,
                records_emitted,
            } => write!(
                f,
                "END count {} matched neither tests_finished ({}) nor records_emitted ({})",
                reported, tests_finished, records_emitted
            ),
            RecordError::TrailingDataAfterEnd => {
                write!(f, "unexpected trailing bytes or records after END")
            }
        }
    }
}

impl std::error::Error for RecordError {}

fn validate_nodeid(nodeid: &str) -> Result<(), RecordError> {
    if nodeid.is_empty() {
        return Err(RecordError::InvalidNodeId(
            "nodeid must not be empty".to_string(),
        ));
    }
    if nodeid.len() > MAX_NODEID_BYTES {
        return Err(RecordError::InvalidNodeId(format!(
            "nodeid length {} exceeds {} bytes",
            nodeid.len(),
            MAX_NODEID_BYTES
        )));
    }
    Ok(())
}

/// Incremental, strict decoder for the `HGR1` per-test record stream.
///
/// Any stream error locks the decoder into an error state while returning all
/// valid records decoded prior to the error (preserving the valid prefix).
#[derive(Debug, Clone)]
pub struct RecordDecoder {
    buf: Vec<u8>,
    header_seen: bool,
    end_seen: bool,
    records_decoded: usize,
    sticky_error: Option<RecordError>,
}

impl RecordDecoder {
    /// Creates an empty `RecordDecoder`.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            header_seen: false,
            end_seen: false,
            records_decoded: 0,
            sticky_error: None,
        }
    }

    /// Returns whether the `END` record was cleanly decoded.
    pub fn end_seen(&self) -> bool {
        self.end_seen
    }

    /// Returns the sticky stream error, if any occurred.
    pub fn error(&self) -> Option<&RecordError> {
        self.sticky_error.as_ref()
    }

    /// Pushes a chunk of bytes from the pipe and decodes as many complete, valid records
    /// as possible.
    ///
    /// Returns `(valid_records_from_this_chunk, optional_stream_error)`. If an error occurs
    /// partway through `chunk`, all valid records preceding the error are still returned.
    pub fn push(&mut self, chunk: &[u8]) -> (Vec<DecodedRecord>, Option<RecordError>) {
        if let Some(err) = &self.sticky_error {
            return (Vec::new(), Some(err.clone()));
        }

        let new_len = self.buf.len().saturating_add(chunk.len());
        if new_len > MAX_STREAM_BUFFER_BYTES {
            let err = RecordError::BufferOverflow {
                buffered: new_len,
                max: MAX_STREAM_BUFFER_BYTES,
            };
            self.sticky_error = Some(err.clone());
            return (Vec::new(), Some(err));
        }

        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();

        for _ in 0..=MAX_RECORDS_PER_STREAM {
            if !self.header_seen {
                let Some(magic_slice) = self.buf.get(..STREAM_MAGIC.len()) else {
                    break;
                };
                if magic_slice != STREAM_MAGIC {
                    let err = RecordError::InvalidMagic;
                    self.sticky_error = Some(err.clone());
                    return (out, Some(err));
                }
                self.buf.drain(..STREAM_MAGIC.len());
                self.header_seen = true;
            }

            if self.end_seen {
                if !self.buf.is_empty() {
                    let err = RecordError::TrailingDataAfterEnd;
                    self.sticky_error = Some(err.clone());
                    return (out, Some(err));
                }
                break;
            }

            let Some(header_slice) = self.buf.get(..RECORD_HEADER_BYTES) else {
                break;
            };

            let tag = match header_slice.first().copied() {
                Some(b) => b,
                None => break,
            };
            let rec_type = match RecordType::from_u8(tag) {
                Ok(t) => t,
                Err(err) => {
                    self.sticky_error = Some(err.clone());
                    return (out, Some(err));
                }
            };

            let len_bytes = match (
                header_slice.get(1).copied(),
                header_slice.get(2).copied(),
                header_slice.get(3).copied(),
                header_slice.get(4).copied(),
            ) {
                (Some(b0), Some(b1), Some(b2), Some(b3)) => [b0, b1, b2, b3],
                _ => break,
            };
            let payload_len_u32 = u32::from_le_bytes(len_bytes);
            let payload_len = payload_len_u32 as usize;

            if payload_len > MAX_RECORD_PAYLOAD_BYTES {
                let err = RecordError::RecordTooLarge {
                    len: payload_len_u32,
                    max: MAX_RECORD_PAYLOAD_BYTES,
                };
                self.sticky_error = Some(err.clone());
                return (out, Some(err));
            }

            if self.records_decoded >= MAX_RECORDS_PER_STREAM {
                let err = RecordError::TooManyRecords {
                    max: MAX_RECORDS_PER_STREAM,
                };
                self.sticky_error = Some(err.clone());
                return (out, Some(err));
            }

            let Some(frame_end) = RECORD_HEADER_BYTES.checked_add(payload_len) else {
                let err = RecordError::RecordTooLarge {
                    len: payload_len_u32,
                    max: MAX_RECORD_PAYLOAD_BYTES,
                };
                self.sticky_error = Some(err.clone());
                return (out, Some(err));
            };

            let Some(payload_bytes) = self.buf.get(RECORD_HEADER_BYTES..frame_end) else {
                break;
            };

            match decode_payload(rec_type, payload_bytes) {
                Ok(record) => {
                    if matches!(record, DecodedRecord::End(_)) {
                        self.end_seen = true;
                    }
                    self.buf.drain(..frame_end);
                    self.records_decoded = self.records_decoded.saturating_add(1);
                    out.push(record);
                }
                Err(err) => {
                    self.sticky_error = Some(err.clone());
                    return (out, Some(err));
                }
            }
        }

        (out, None)
    }

    /// Signals EOF on the pipe and checks for mid-header or mid-frame truncation.
    ///
    /// Note: Reaching EOF cleanly at a record boundary without an `END` record (for example,
    /// when a test calls `os._exit`) is NOT a mid-frame stream corruption error; the caller
    /// checks [`RecordDecoder::end_seen`] to classify the supervisor exit as `"crash"` while
    /// preserving `"missing"` for unstarted tests.
    pub fn finish_eof(&mut self) -> Result<(), RecordError> {
        if let Some(err) = &self.sticky_error {
            return Err(err.clone());
        }
        if !self.header_seen {
            if self.buf.is_empty() {
                return Ok(());
            }
            let err = RecordError::TruncatedHeader;
            self.sticky_error = Some(err.clone());
            return Err(err);
        }
        if !self.buf.is_empty() {
            let err = RecordError::TruncatedRecord;
            self.sticky_error = Some(err.clone());
            return Err(err);
        }
        Ok(())
    }
}

impl Default for RecordDecoder {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_payload(rec_type: RecordType, bytes: &[u8]) -> Result<DecodedRecord, RecordError> {
    let text = std::str::from_utf8(bytes).map_err(|_| RecordError::InvalidUtf8)?;
    match rec_type {
        RecordType::Start => {
            let rec: StartRecord =
                serde_json::from_str(text).map_err(|e| RecordError::InvalidJson(e.to_string()))?;
            validate_nodeid(&rec.nodeid)?;
            Ok(DecodedRecord::Start(rec))
        }
        RecordType::Finish => {
            let rec: FinishRecord =
                serde_json::from_str(text).map_err(|e| RecordError::InvalidJson(e.to_string()))?;
            validate_nodeid(&rec.nodeid)?;
            Ok(DecodedRecord::Finish(rec))
        }
        RecordType::End => {
            let rec: EndRecord =
                serde_json::from_str(text).map_err(|e| RecordError::InvalidJson(e.to_string()))?;
            Ok(DecodedRecord::End(rec))
        }
    }
}

/// Helper for encoding valid `HGR1` wire streams (used by tests and harness tools).
pub struct RecordEncoder;

impl RecordEncoder {
    /// Returns the 4-byte `HGR1` stream magic header.
    pub fn stream_header() -> [u8; 4] {
        *STREAM_MAGIC
    }

    /// Encodes a single `START`, `FINISH`, or `END` record frame.
    pub fn encode_record(record: &DecodedRecord) -> Result<Vec<u8>, RecordError> {
        let (tag, payload) = match record {
            DecodedRecord::Start(r) => {
                validate_nodeid(&r.nodeid)?;
                let json =
                    serde_json::to_vec(r).map_err(|e| RecordError::InvalidJson(e.to_string()))?;
                (RecordType::Start as u8, json)
            }
            DecodedRecord::Finish(r) => {
                validate_nodeid(&r.nodeid)?;
                let json =
                    serde_json::to_vec(r).map_err(|e| RecordError::InvalidJson(e.to_string()))?;
                (RecordType::Finish as u8, json)
            }
            DecodedRecord::End(r) => {
                let json =
                    serde_json::to_vec(r).map_err(|e| RecordError::InvalidJson(e.to_string()))?;
                (RecordType::End as u8, json)
            }
        };

        if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
            let len_u32 = u32::try_from(payload.len()).unwrap_or(u32::MAX);
            return Err(RecordError::RecordTooLarge {
                len: len_u32,
                max: MAX_RECORD_PAYLOAD_BYTES,
            });
        }

        let len_u32 = u32::try_from(payload.len()).map_err(|_| RecordError::RecordTooLarge {
            len: u32::MAX,
            max: MAX_RECORD_PAYLOAD_BYTES,
        })?;

        let mut frame = Vec::with_capacity(RECORD_HEADER_BYTES.saturating_add(payload.len()));
        frame.push(tag);
        frame.extend_from_slice(&len_u32.to_le_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }
}
