#![forbid(unsafe_code)]

use std::io::Cursor;
use tempfile::tempdir;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::error::{ExtractError, QuotaError};
use hermetic_extract::format::StreamEncoder;
use hermetic_extract::validator::validate_stream;

#[test]
fn test_per_file_bytes_quota_boundary() {
    let cap = 100u64;

    // Exactly at cap passes
    {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_file_bytes: cap,
            ..Default::default()
        };

        let data = vec![b'x'; cap as usize];
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_file(&mut stream, "file.txt", 0o644, &data).unwrap();
        StreamEncoder::write_end(&mut stream, 1, cap).unwrap();

        let mut cursor = Cursor::new(stream);
        let res = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        );
        assert!(res.is_ok());
    }

    // Exactly one over cap fails
    {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_file_bytes: cap,
            ..Default::default()
        };

        let data = vec![b'x'; (cap + 1) as usize];
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_file(&mut stream, "file.txt", 0o644, &data).unwrap();
        StreamEncoder::write_end(&mut stream, 1, cap + 1).unwrap();

        let mut cursor = Cursor::new(stream);
        let err = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtractError::Quota(QuotaError::FileBytesExceeded { .. })
        ));
    }
}

#[test]
fn test_total_bytes_quota_boundary() {
    let total_cap = 200u64;

    // Exactly at total cap passes (two files of 100 bytes)
    {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_total_bytes: total_cap,
            max_file_bytes: 150,
            ..Default::default()
        };

        let data1 = vec![b'a'; 100];
        let data2 = vec![b'b'; 100];
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_file(&mut stream, "file1.txt", 0o644, &data1).unwrap();
        StreamEncoder::write_file(&mut stream, "file2.txt", 0o644, &data2).unwrap();
        StreamEncoder::write_end(&mut stream, 2, 200).unwrap();

        let mut cursor = Cursor::new(stream);
        let res = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        );
        assert!(res.is_ok());
    }

    // Exactly one over total cap fails (100 + 101 = 201 bytes)
    {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_total_bytes: total_cap,
            max_file_bytes: 150,
            ..Default::default()
        };

        let data1 = vec![b'a'; 100];
        let data2 = vec![b'b'; 101];
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_file(&mut stream, "file1.txt", 0o644, &data1).unwrap();
        StreamEncoder::write_file(&mut stream, "file2.txt", 0o644, &data2).unwrap();
        StreamEncoder::write_end(&mut stream, 2, 201).unwrap();

        let mut cursor = Cursor::new(stream);
        let err = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtractError::Quota(QuotaError::TotalBytesExceeded { .. })
        ));
    }
}

#[test]
fn test_file_count_quota_boundary() {
    let file_count_cap = 3u64;

    // Exactly at cap (3 files) passes
    {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_file_count: file_count_cap,
            ..Default::default()
        };

        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_file(&mut stream, "f1.txt", 0o644, b"1").unwrap();
        StreamEncoder::write_file(&mut stream, "f2.txt", 0o644, b"2").unwrap();
        StreamEncoder::write_file(&mut stream, "f3.txt", 0o644, b"3").unwrap();
        StreamEncoder::write_end(&mut stream, 3, 3).unwrap();

        let mut cursor = Cursor::new(stream);
        let res = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        );
        assert!(res.is_ok());
    }

    // Exactly one over cap (4 files) fails
    {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_file_count: file_count_cap,
            ..Default::default()
        };

        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_file(&mut stream, "f1.txt", 0o644, b"1").unwrap();
        StreamEncoder::write_file(&mut stream, "f2.txt", 0o644, b"2").unwrap();
        StreamEncoder::write_file(&mut stream, "f3.txt", 0o644, b"3").unwrap();
        StreamEncoder::write_file(&mut stream, "f4.txt", 0o644, b"4").unwrap();
        StreamEncoder::write_end(&mut stream, 4, 4).unwrap();

        let mut cursor = Cursor::new(stream);
        let err = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtractError::Quota(QuotaError::FileCountExceeded { .. })
        ));
    }
}

#[test]
fn test_dir_count_quota_boundary() {
    let dir_count_cap = 2u64;

    // Exactly at cap (2 directories) passes
    {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_dir_count: dir_count_cap,
            ..Default::default()
        };

        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_directory(&mut stream, "d1", 0o755).unwrap();
        StreamEncoder::write_directory(&mut stream, "d2", 0o755).unwrap();
        StreamEncoder::write_end(&mut stream, 2, 0).unwrap();

        let mut cursor = Cursor::new(stream);
        let res = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        );
        assert!(res.is_ok());
    }

    // Exactly one over cap (3 directories) fails
    {
        let base = tempdir().unwrap();
        let out = tempdir().unwrap();
        let config = ExtractConfig {
            max_dir_count: dir_count_cap,
            ..Default::default()
        };

        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_directory(&mut stream, "d1", 0o755).unwrap();
        StreamEncoder::write_directory(&mut stream, "d2", 0o755).unwrap();
        StreamEncoder::write_directory(&mut stream, "d3", 0o755).unwrap();
        StreamEncoder::write_end(&mut stream, 3, 0).unwrap();

        let mut cursor = Cursor::new(stream);
        let err = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtractError::Quota(QuotaError::DirCountExceeded { .. })
        ));
    }
}
