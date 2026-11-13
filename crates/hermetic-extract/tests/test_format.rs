#![forbid(unsafe_code)]

use std::io::Cursor;

use hermetic_extract::error::FormatError;
use hermetic_extract::format::{
    RawRecordArgs, RecordHeader, RecordType, StreamEncoder, RECORD_HEADER_SIZE, STREAM_MAGIC,
    STREAM_VERSION,
};

#[test]
fn test_stream_header_validation() {
    // Valid header
    let mut buf = Vec::new();
    StreamEncoder::write_stream_header(&mut buf).unwrap();
    assert_eq!(&buf[0..4], &STREAM_MAGIC);
    assert_eq!(
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        STREAM_VERSION
    );

    // Bad magic
    let bad_magic = *b"BAD!";
    let mut header = [0u8; 8];
    header[0..4].copy_from_slice(&bad_magic);
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    let magic = [header[0], header[1], header[2], header[3]];
    assert_eq!(magic, bad_magic);

    // Bad version
    let bad_version = 2u32;
    header[0..4].copy_from_slice(&STREAM_MAGIC);
    header[4..8].copy_from_slice(&bad_version.to_le_bytes());
    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    assert_ne!(version, STREAM_VERSION);
}

#[test]
fn test_record_types_recognition_and_rejection() {
    assert_eq!(RecordType::from_u8(1).unwrap(), RecordType::RegularFile);
    assert_eq!(RecordType::from_u8(2).unwrap(), RecordType::Directory);
    assert_eq!(RecordType::from_u8(3).unwrap(), RecordType::Deletion);
    assert_eq!(RecordType::from_u8(4).unwrap(), RecordType::EndOfStream);

    // Hostile types
    assert_eq!(
        RecordType::from_u8(5).unwrap_err(),
        FormatError::UnsupportedRecordType {
            record_type: 5,
            name: "symlink",
        }
    );
    assert_eq!(
        RecordType::from_u8(6).unwrap_err(),
        FormatError::UnsupportedRecordType {
            record_type: 6,
            name: "device",
        }
    );
    assert_eq!(
        RecordType::from_u8(7).unwrap_err(),
        FormatError::UnsupportedRecordType {
            record_type: 7,
            name: "fifo",
        }
    );
    assert_eq!(
        RecordType::from_u8(8).unwrap_err(),
        FormatError::UnsupportedRecordType {
            record_type: 8,
            name: "socket",
        }
    );
    assert_eq!(
        RecordType::from_u8(9).unwrap_err(),
        FormatError::UnsupportedRecordType {
            record_type: 9,
            name: "hardlink",
        }
    );

    // Unknown type
    assert_eq!(
        RecordType::from_u8(42).unwrap_err(),
        FormatError::UnknownRecordType(42)
    );
}

#[test]
fn test_record_header_reserved_bytes() {
    let mut raw = [0u8; RECORD_HEADER_SIZE];
    raw[0] = 1; // RegularFile
    raw[2] = 1; // non-zero reserved
    let err = RecordHeader::parse(&raw).unwrap_err();
    assert_eq!(err, FormatError::InvalidReservedBytes([1, 0]));
}

#[test]
fn test_record_header_invalid_payload_for_type() {
    // Directory with non-zero size
    let mut raw = [0u8; RECORD_HEADER_SIZE];
    raw[0] = 2; // Directory
    raw[12] = 10; // size = 10
    assert!(matches!(
        RecordHeader::parse(&raw).unwrap_err(),
        FormatError::InvalidPayloadForType(_)
    ));

    // Deletion with non-zero mode
    let mut raw = [0u8; RECORD_HEADER_SIZE];
    raw[0] = 3; // Deletion
    raw[8..12].copy_from_slice(&0o755u32.to_le_bytes()); // mode
    assert!(matches!(
        RecordHeader::parse(&raw).unwrap_err(),
        FormatError::InvalidPayloadForType(_)
    ));

    // EndOfStream with non-zero path_len
    let mut raw = [0u8; RECORD_HEADER_SIZE];
    raw[0] = 4; // EndOfStream
    raw[4] = 5; // path_len
    assert!(matches!(
        RecordHeader::parse(&raw).unwrap_err(),
        FormatError::InvalidPayloadForType(_)
    ));
}

#[test]
fn test_encoder_and_decoder_round_trip() {
    let mut buf = Vec::new();
    StreamEncoder::write_stream_header(&mut buf).unwrap();
    StreamEncoder::write_file(&mut buf, "hello.txt", 0o644, b"Hello world!").unwrap();
    StreamEncoder::write_directory(&mut buf, "subdir", 0o755).unwrap();
    StreamEncoder::write_deletion(&mut buf, "old.txt").unwrap();
    StreamEncoder::write_end(&mut buf, 3, 12).unwrap();

    let mut cursor = Cursor::new(buf);

    let mut magic_ver = [0u8; 8];
    cursor.set_position(0);
    std::io::Read::read_exact(&mut cursor, &mut magic_ver).unwrap();
    assert_eq!(&magic_ver[0..4], &STREAM_MAGIC);
    assert_eq!(
        u32::from_le_bytes([magic_ver[4], magic_ver[5], magic_ver[6], magic_ver[7]]),
        STREAM_VERSION
    );

    let mut rec1 = [0u8; RECORD_HEADER_SIZE];
    std::io::Read::read_exact(&mut cursor, &mut rec1).unwrap();
    let h1 = RecordHeader::parse(&rec1).unwrap();
    assert_eq!(h1.record_type, RecordType::RegularFile);
    assert_eq!(h1.path_len, 9);
    assert_eq!(h1.size, 12);
}

#[test]
fn test_raw_record_encoder() {
    let mut buf = Vec::new();
    let args = RawRecordArgs {
        record_type: 5, // symlink
        flags: 0,
        reserved: [0, 0],
        path: b"link.txt",
        mode: 0o777,
        size: 0,
        record_count: 0,
        sha256: [0u8; 32],
        payload: b"",
    };
    StreamEncoder::write_raw_record(&mut buf, &args).unwrap();
    assert_eq!(buf[0], 5);
}
