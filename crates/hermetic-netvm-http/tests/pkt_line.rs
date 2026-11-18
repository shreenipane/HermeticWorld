#![forbid(unsafe_code)]

use hermetic_netvm_http::pkt_line::{
    parse_pkt_line, write_delim, write_flush, write_pkt_line, write_response_end,
    write_sideband_chunk, write_sideband_data, PktLine, PktLineError, BAND_DATA, BAND_ERROR,
    BAND_PROGRESS, MAX_PKT_LINE_BYTES, MAX_SIDEBAND_PAYLOAD,
};

#[test]
fn test_parse_valid_lines() {
    assert_eq!(parse_pkt_line(b"0000"), Ok((PktLine::Flush, 4)));
    assert_eq!(parse_pkt_line(b"0001"), Ok((PktLine::Delimiter, 4)));
    assert_eq!(parse_pkt_line(b"0002"), Ok((PktLine::ResponseEnd, 4)));

    // Empty data line
    assert_eq!(parse_pkt_line(b"0004"), Ok((PktLine::Data(b""), 4)));

    // Typical data lines
    assert_eq!(
        parse_pkt_line(b"000ahello\n"),
        Ok((PktLine::Data(b"hello\n"), 10))
    );
    assert_eq!(
        parse_pkt_line(b"000eversion 2\n"),
        Ok((PktLine::Data(b"version 2\n"), 14))
    );
}

#[test]
fn test_write_and_roundtrip() {
    let mut out = Vec::new();
    write_flush(&mut out);
    write_delim(&mut out);
    write_response_end(&mut out);
    write_pkt_line(&mut out, b"command=ls-refs\n").unwrap();

    let (p1, n1) = parse_pkt_line(&out).unwrap();
    assert_eq!(p1, PktLine::Flush);
    let (p2, n2) = parse_pkt_line(&out[n1..]).unwrap();
    assert_eq!(p2, PktLine::Delimiter);
    let (p3, n3) = parse_pkt_line(&out[n1 + n2..]).unwrap();
    assert_eq!(p3, PktLine::ResponseEnd);
    let (p4, _) = parse_pkt_line(&out[n1 + n2 + n3..]).unwrap();
    assert_eq!(p4, PktLine::Data(b"command=ls-refs\n"));
}

#[test]
fn test_sideband_chunking_and_channels() {
    let mut out = Vec::new();
    write_sideband_chunk(&mut out, BAND_DATA, b"PACKDATA").unwrap();
    write_sideband_chunk(&mut out, BAND_PROGRESS, b"Counting...").unwrap();
    write_sideband_chunk(&mut out, BAND_ERROR, b"fatal error").unwrap();

    let (p1, n1) = parse_pkt_line(&out).unwrap();
    match p1 {
        PktLine::Data(d) => {
            assert_eq!(d[0], BAND_DATA);
            assert_eq!(&d[1..], b"PACKDATA");
        }
        _ => panic!("expected Data"),
    }

    let (p2, n2) = parse_pkt_line(&out[n1..]).unwrap();
    match p2 {
        PktLine::Data(d) => {
            assert_eq!(d[0], BAND_PROGRESS);
            assert_eq!(&d[1..], b"Counting...");
        }
        _ => panic!("expected Data"),
    }

    let (p3, _) = parse_pkt_line(&out[n1 + n2..]).unwrap();
    match p3 {
        PktLine::Data(d) => {
            assert_eq!(d[0], BAND_ERROR);
            assert_eq!(&d[1..], b"fatal error");
        }
        _ => panic!("expected Data"),
    }

    // Invalid channel byte rejected
    assert_eq!(
        write_sideband_chunk(&mut Vec::new(), 0, b"bad"),
        Err(PktLineError::InvalidChannel(0))
    );
    assert_eq!(
        write_sideband_chunk(&mut Vec::new(), 4, b"bad"),
        Err(PktLineError::InvalidChannel(4))
    );
}

#[test]
fn test_sideband_large_payload_chunking() {
    // 150_000 bytes spanning multiple maximum sideband chunks
    let large_data = vec![0x42u8; 150_000];
    let mut out = Vec::new();
    write_sideband_data(&mut out, BAND_DATA, &large_data).unwrap();

    let mut remaining = &out[..];
    let mut reconstructed = Vec::new();
    while !remaining.is_empty() {
        let (pkt, consumed) = parse_pkt_line(remaining).unwrap();
        match pkt {
            PktLine::Data(d) => {
                assert_eq!(d[0], BAND_DATA);
                assert!(d.len() - 1 <= MAX_SIDEBAND_PAYLOAD);
                reconstructed.extend_from_slice(&d[1..]);
            }
            _ => panic!("expected Data"),
        }
        remaining = &remaining[consumed..];
    }
    assert_eq!(reconstructed, large_data);
}

#[test]
fn test_hostile_truncated_inputs() {
    for trunc in [&b""[..], &b"0"[..], &b"00"[..], &b"000"[..]] {
        assert_eq!(parse_pkt_line(trunc), Err(PktLineError::Truncated));
    }

    // Declares 16 bytes (0010) but provides only 8
    assert_eq!(parse_pkt_line(b"0010abcdef"), Err(PktLineError::Truncated));
}

#[test]
fn test_hostile_invalid_hex() {
    for bad_hex in [b"000g", b"00-1", b"    ", b"\0\0\0\0", b"00z0", b"xxxx"] {
        assert!(matches!(
            parse_pkt_line(bad_hex),
            Err(PktLineError::InvalidHex(_))
        ));
    }
}

#[test]
fn test_hostile_invalid_lengths() {
    // 0003 is reserved/invalid
    assert_eq!(parse_pkt_line(b"0003"), Err(PktLineError::InvalidLength(3)));
}

#[test]
fn test_hostile_oversized_packets() {
    // Max packet length is 65520 (0xfff0)
    let max_len = MAX_PKT_LINE_BYTES;
    let mut max_pkt = format!("{:04x}", max_len).into_bytes();
    max_pkt.resize(max_len, b'a');
    let (parsed, consumed) = parse_pkt_line(&max_pkt).unwrap();
    assert_eq!(consumed, max_len);
    match parsed {
        PktLine::Data(d) => assert_eq!(d.len(), max_len - 4),
        _ => panic!("expected data"),
    }

    // Over length: 65521 (0xfff1)
    let over_len = MAX_PKT_LINE_BYTES + 1;
    let over_pkt = format!("{:04x}", over_len).into_bytes();
    assert_eq!(
        parse_pkt_line(&over_pkt),
        Err(PktLineError::LineTooLong(over_len))
    );

    // Write oversized packet rejected
    let huge_data = vec![b'x'; MAX_PKT_LINE_BYTES];
    let mut out = Vec::new();
    assert!(matches!(
        write_pkt_line(&mut out, &huge_data),
        Err(PktLineError::LineTooLong(_))
    ));
}

#[test]
fn test_hostile_byte_mutations_never_panic() {
    let mut valid = b"0014command=fetch\n0001".to_vec();
    for i in 0..valid.len() {
        for bit in 0..8 {
            valid[i] ^= 1 << bit;
            let _ = parse_pkt_line(&valid);
            valid[i] ^= 1 << bit;
        }
    }
}
