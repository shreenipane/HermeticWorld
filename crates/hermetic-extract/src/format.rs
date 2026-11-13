#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

use crate::error::{ExtractError, FormatError};

pub const STREAM_MAGIC: [u8; 4] = *b"HEXT";
pub const STREAM_VERSION: u32 = 1;
pub const RECORD_HEADER_SIZE: usize = 60;
pub const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB bounded chunk

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    RegularFile = 1,
    Directory = 2,
    Deletion = 3,
    EndOfStream = 4,
}

impl RecordType {
    pub fn from_u8(v: u8) -> Result<Self, FormatError> {
        match v {
            1 => Ok(Self::RegularFile),
            2 => Ok(Self::Directory),
            3 => Ok(Self::Deletion),
            4 => Ok(Self::EndOfStream),
            5 => Err(FormatError::UnsupportedRecordType {
                record_type: 5,
                name: "symlink",
            }),
            6 => Err(FormatError::UnsupportedRecordType {
                record_type: 6,
                name: "device",
            }),
            7 => Err(FormatError::UnsupportedRecordType {
                record_type: 7,
                name: "fifo",
            }),
            8 => Err(FormatError::UnsupportedRecordType {
                record_type: 8,
                name: "socket",
            }),
            9 => Err(FormatError::UnsupportedRecordType {
                record_type: 9,
                name: "hardlink",
            }),
            other => Err(FormatError::UnknownRecordType(other)),
        }
    }
}

/// Raw decoded fixed-width record header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeader {
    pub record_type: RecordType,
    pub flags: u8,
    pub reserved: [u8; 2],
    pub path_len: u32,
    pub mode: u32,
    pub size: u64,
    pub record_count: u64,
    pub sha256: [u8; 32],
}

impl RecordHeader {
    pub fn parse(buf: &[u8; RECORD_HEADER_SIZE]) -> Result<Self, FormatError> {
        let record_type = RecordType::from_u8(buf[0])?;
        let flags = buf[1];
        if flags != 0 {
            return Err(FormatError::InvalidPayloadForType("unknown flags"));
        }
        let reserved = [buf[2], buf[3]];
        if reserved != [0, 0] {
            return Err(FormatError::InvalidReservedBytes(reserved));
        }

        let path_len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mode = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let size = u64::from_le_bytes([
            buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
        ]);
        let record_count = u64::from_le_bytes([
            buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
        ]);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&buf[28..60]);

        // Validation by record type
        match record_type {
            RecordType::EndOfStream => {
                if path_len != 0 {
                    return Err(FormatError::InvalidPayloadForType("end-of-stream"));
                }
                if mode != 0 {
                    return Err(FormatError::InvalidPayloadForType(
                        "end-of-stream mode must be 0",
                    ));
                }
                if sha256 != [0u8; 32] {
                    return Err(FormatError::InvalidPayloadForType(
                        "end-of-stream sha256 must be zeroed",
                    ));
                }
            }
            RecordType::Directory => {
                if size != 0 {
                    return Err(FormatError::InvalidPayloadForType(
                        "directory size must be 0",
                    ));
                }
                if record_count != 0 {
                    return Err(FormatError::InvalidPayloadForType(
                        "directory record_count must be 0",
                    ));
                }
                if sha256 != [0u8; 32] {
                    return Err(FormatError::InvalidPayloadForType(
                        "directory sha256 must be zeroed",
                    ));
                }
            }
            RecordType::Deletion => {
                if size != 0 {
                    return Err(FormatError::InvalidPayloadForType(
                        "deletion size must be 0",
                    ));
                }
                if mode != 0 {
                    return Err(FormatError::InvalidPayloadForType(
                        "deletion mode must be 0",
                    ));
                }
                if record_count != 0 {
                    return Err(FormatError::InvalidPayloadForType(
                        "deletion record_count must be 0",
                    ));
                }
                if sha256 != [0u8; 32] {
                    return Err(FormatError::InvalidPayloadForType(
                        "deletion sha256 must be zeroed",
                    ));
                }
            }
            RecordType::RegularFile => {
                if record_count != 0 {
                    return Err(FormatError::InvalidPayloadForType(
                        "regular file record_count must be 0",
                    ));
                }
            }
        }

        Ok(Self {
            record_type,
            flags,
            reserved,
            path_len,
            mode,
            size,
            record_count,
            sha256,
        })
    }

    pub fn to_bytes(&self) -> [u8; RECORD_HEADER_SIZE] {
        let mut buf = [0u8; RECORD_HEADER_SIZE];
        buf[0] = self.record_type as u8;
        buf[1] = self.flags;
        buf[2] = self.reserved[0];
        buf[3] = self.reserved[1];
        buf[4..8].copy_from_slice(&self.path_len.to_le_bytes());
        buf[8..12].copy_from_slice(&self.mode.to_le_bytes());
        buf[12..20].copy_from_slice(&self.size.to_le_bytes());
        buf[20..28].copy_from_slice(&self.record_count.to_le_bytes());
        buf[28..60].copy_from_slice(&self.sha256);
        buf
    }
}

/// Arguments for writing arbitrary (possibly malformed) raw records in tests.
#[derive(Debug, Clone)]
pub struct RawRecordArgs<'a> {
    pub record_type: u8,
    pub flags: u8,
    pub reserved: [u8; 2],
    pub path: &'a [u8],
    pub mode: u32,
    pub size: u64,
    pub record_count: u64,
    pub sha256: [u8; 32],
    pub payload: &'a [u8],
}

/// Helper to serialize records to an output stream.
pub struct StreamEncoder;

impl StreamEncoder {
    pub fn write_stream_header(writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&STREAM_MAGIC)?;
        writer.write_all(&STREAM_VERSION.to_le_bytes())?;
        Ok(())
    }

    pub fn write_file(
        writer: &mut impl Write,
        path: &str,
        mode: u32,
        data: &[u8],
    ) -> io::Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash: [u8; 32] = hasher.finalize().into();

        let header = RecordHeader {
            record_type: RecordType::RegularFile,
            flags: 0,
            reserved: [0, 0],
            path_len: path.len() as u32,
            mode,
            size: data.len() as u64,
            record_count: 0,
            sha256: hash,
        };

        writer.write_all(&header.to_bytes())?;
        writer.write_all(path.as_bytes())?;
        writer.write_all(data)?;
        Ok(())
    }

    pub fn write_directory(writer: &mut impl Write, path: &str, mode: u32) -> io::Result<()> {
        let header = RecordHeader {
            record_type: RecordType::Directory,
            flags: 0,
            reserved: [0, 0],
            path_len: path.len() as u32,
            mode,
            size: 0,
            record_count: 0,
            sha256: [0u8; 32],
        };

        writer.write_all(&header.to_bytes())?;
        writer.write_all(path.as_bytes())?;
        Ok(())
    }

    pub fn write_deletion(writer: &mut impl Write, path: &str) -> io::Result<()> {
        let header = RecordHeader {
            record_type: RecordType::Deletion,
            flags: 0,
            reserved: [0, 0],
            path_len: path.len() as u32,
            mode: 0,
            size: 0,
            record_count: 0,
            sha256: [0u8; 32],
        };

        writer.write_all(&header.to_bytes())?;
        writer.write_all(path.as_bytes())?;
        Ok(())
    }

    pub fn write_end(
        writer: &mut impl Write,
        record_count: u64,
        total_bytes: u64,
    ) -> io::Result<()> {
        let header = RecordHeader {
            record_type: RecordType::EndOfStream,
            flags: 0,
            reserved: [0, 0],
            path_len: 0,
            mode: 0,
            size: total_bytes,
            record_count,
            sha256: [0u8; 32],
        };

        writer.write_all(&header.to_bytes())?;
        Ok(())
    }

    /// Write an arbitrary (possibly hostile) raw record.
    pub fn write_raw_record(writer: &mut impl Write, args: &RawRecordArgs<'_>) -> io::Result<()> {
        let mut buf = [0u8; RECORD_HEADER_SIZE];
        buf[0] = args.record_type;
        buf[1] = args.flags;
        buf[2] = args.reserved[0];
        buf[3] = args.reserved[1];
        buf[4..8].copy_from_slice(&(args.path.len() as u32).to_le_bytes());
        buf[8..12].copy_from_slice(&args.mode.to_le_bytes());
        buf[12..20].copy_from_slice(&args.size.to_le_bytes());
        buf[20..28].copy_from_slice(&args.record_count.to_le_bytes());
        buf[28..60].copy_from_slice(&args.sha256);

        writer.write_all(&buf)?;
        writer.write_all(args.path)?;
        writer.write_all(args.payload)?;
        Ok(())
    }
}

pub fn format_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Streaming payload consumer that streams bytes in bounded chunks.
pub struct PayloadStreamer;

impl PayloadStreamer {
    /// Streams `size` bytes from `reader` into `writer`, hashing chunk-by-chunk.
    /// Checks that actual bytes read match `size` and resulting hash matches `declared_sha256`.
    pub fn stream_to_writer<R: Read, W: Write>(
        reader: &mut R,
        size: u64,
        declared_sha256: [u8; 32],
        writer: &mut W,
        path: &str,
    ) -> Result<[u8; 32], ExtractError> {
        let mut hasher = Sha256::new();
        let mut remaining = size;
        let mut buf = [0u8; CHUNK_SIZE];

        while remaining > 0 {
            let to_read = (remaining.min(CHUNK_SIZE as u64)) as usize;
            match reader.read_exact(&mut buf[..to_read]) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(FormatError::Truncated("file payload truncated").into());
                }
                Err(e) => return Err(ExtractError::Io(e)),
            }

            hasher.update(&buf[..to_read]);
            writer
                .write_all(&buf[..to_read])
                .map_err(ExtractError::Io)?;
            remaining -= to_read as u64;
        }

        let actual_hash: [u8; 32] = hasher.finalize().into();
        if actual_hash != declared_sha256 {
            return Err(FormatError::HashMismatch {
                path: path.to_string(),
                declared: format_hex(&declared_sha256),
                actual: format_hex(&actual_hash),
            }
            .into());
        }

        Ok(actual_hash)
    }

    /// Discards and hashes `size` bytes from `reader`.
    pub fn discard_and_hash<R: Read>(
        reader: &mut R,
        size: u64,
        declared_sha256: [u8; 32],
        path: &str,
    ) -> Result<[u8; 32], ExtractError> {
        let mut sink = io::sink();
        Self::stream_to_writer(reader, size, declared_sha256, &mut sink, path)
    }
}
