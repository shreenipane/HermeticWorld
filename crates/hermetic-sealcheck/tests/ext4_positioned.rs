use hermetic_sealcheck::ext4::{scan_ext4_image, scan_ext4_slice, MAX_IMAGE_BYTES};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use time::macros::datetime;

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

// Fixed metadata, no formatter, host timestamps, or image-size allocation.
fn metadata(blocks: u32) -> Vec<u8> {
    let mut data = vec![0; 5 * 4096];
    let groups = blocks.div_ceil(32768);
    put32(&mut data, 1024, groups);
    put32(&mut data, 1028, blocks);
    put32(&mut data, 1024 + 0x18, 2);
    put32(&mut data, 1024 + 0x20, 32768);
    put32(&mut data, 1024 + 0x28, 1);
    put16(&mut data, 1024 + 0x38, 0xef53);
    put16(&mut data, 1024 + 0x58, 128);
    put32(&mut data, 1024 + 0x60, 0x40);
    put32(&mut data, 4096 + 4, 3);
    put32(&mut data, 4096 + 8, 4);
    for group in 1..groups as usize {
        put16(&mut data, 4096 + group * 32 + 0x12, 1);
    }
    data[3 * 4096] = 1;
    // Allocated regular inode with an empty extent tree (a sparse file).
    put16(&mut data, 4 * 4096, 0x81a4);
    put32(&mut data, 4 * 4096 + 0x20, 0x80000);
    put16(&mut data, 4 * 4096 + 0x28, 0xf30a);
    put16(&mut data, 4 * 4096 + 0x2c, 4);
    data
}

#[test]
fn sparse_two_gib_image_uses_bounded_positioned_reads_and_matches_slice() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sparse.img");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut data = metadata(524288);
    // A known-answer violation must survive the streaming path.
    put32(&mut data, 4 * 4096 + 0x10, 1_704_153_601);
    file.write_all_at(&data, 0).unwrap();
    file.set_len(2 * 1024 * 1024 * 1024).unwrap();
    let findings = scan_ext4_image(&path, datetime!(2024-01-02 00:00 UTC)).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "sparse.img#inode/1");
    assert_eq!(
        findings[0].evidence,
        ["i_mtime 2024-01-02T00:00:01Z > T_clock 2024-01-02T00:00:00Z"]
    );
    let small = metadata(5);
    fs::write(&path, &small).unwrap();
    assert_eq!(
        serde_json::to_value(scan_ext4_image(&path, datetime!(2024-01-02 00:00 UTC)).unwrap())
            .unwrap(),
        serde_json::to_value(
            scan_ext4_slice("sparse.img", &small, datetime!(2024-01-02 00:00 UTC)).unwrap()
        )
        .unwrap()
    );
}

#[test]
fn oversized_sparse_image_is_refused_before_reading() {
    assert_eq!(MAX_IMAGE_BYTES, 8 * 1024 * 1024 * 1024);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large.img");
    let file = fs::File::create(&path).unwrap();
    file.write_all_at(&metadata((MAX_IMAGE_BYTES / 4096) as u32), 0)
        .unwrap();
    file.set_len(MAX_IMAGE_BYTES).unwrap();
    assert!(scan_ext4_image(&path, datetime!(2024-01-02 00:00 UTC))
        .unwrap()
        .is_empty());
    file.set_len(MAX_IMAGE_BYTES + 1).unwrap();
    let error = scan_ext4_image(&path, datetime!(2024-01-02 00:00 UTC)).unwrap_err();
    assert!(error.to_string().contains("image byte cap exceeded"));
}

#[test]
fn truncated_image_and_inode_table_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("short.img");
    let data = metadata(5);
    for end in [1500, 4096, data.len() - 1] {
        fs::write(&path, &data[..end]).unwrap();
        assert!(scan_ext4_image(&path, datetime!(2024-01-02 00:00 UTC)).is_err());
    }
    let mut data = data;
    put32(&mut data, 4096 + 8, 5);
    fs::write(&path, &data).unwrap();
    assert!(scan_ext4_image(&path, datetime!(2024-01-02 00:00 UTC)).is_err());
}

#[test]
fn extent_data_and_index_past_eof_are_refused() {
    for depth in [0, 1, 6] {
        let mut data = metadata(5);
        put16(&mut data, 4 * 4096 + 0x2a, 1);
        put16(&mut data, 4 * 4096 + 0x2e, depth);
        if depth == 0 {
            put16(&mut data, 4 * 4096 + 0x38, 1);
            put32(&mut data, 4 * 4096 + 0x3c, 5);
        } else {
            put32(&mut data, 4 * 4096 + 0x38, 5);
        }
        assert!(
            scan_ext4_slice("extent.img", &data, datetime!(2024-01-02 00:00 UTC)).is_err(),
            "depth {depth}"
        );
    }
}

#[test]
fn cyclic_extent_index_is_refused_without_unbounded_reads() {
    let mut data = metadata(6);
    data.resize(6 * 4096, 0);
    put16(&mut data, 4 * 4096 + 0x2a, 1);
    put16(&mut data, 4 * 4096 + 0x2e, 1);
    put32(&mut data, 4 * 4096 + 0x38, 5);
    put16(&mut data, 5 * 4096, 0xf30a);
    put16(&mut data, 5 * 4096 + 2, 1);
    put16(&mut data, 5 * 4096 + 4, 340);
    put16(&mut data, 5 * 4096 + 6, 1);
    put32(&mut data, 5 * 4096 + 16, 5);
    assert!(scan_ext4_slice("cycle.img", &data, datetime!(2024-01-02 00:00 UTC)).is_err());
}

#[test]
fn sparse_image_descriptor_remains_pinned_after_path_replacement() {
    use std::io::{Seek, SeekFrom};
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("held.img");
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all_at(&metadata(524288), 0).unwrap();
    file.set_len(2 * 1024 * 1024 * 1024).unwrap();
    file.seek(SeekFrom::Start(123)).unwrap();
    fs::rename(&path, dir.path().join("original.img")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    let inherited = std::path::PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    assert!(scan_ext4_image(&inherited, datetime!(2024-01-02 00:00 UTC))
        .unwrap()
        .is_empty());
    assert_eq!(file.stream_position().unwrap(), 123);
}
