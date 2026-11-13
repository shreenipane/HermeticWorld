#![forbid(unsafe_code)]
use hermetic_grader_supervisor::{label::*, *};
use std::path::Path;

fn config() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "argv":["pytest"], "cwd":"/work/repo", "deadline_seconds":10,
        "expected_test_ids":[], "variant_set":"00".repeat(32)
    }))
    .unwrap()
}

#[test]
fn run_label_known_answer_strict_format_and_bounds() {
    for run in [RunName::R0, RunName::R1, RunName::R2, RunName::R3] {
        let image = encode_run_label(run);
        assert_eq!(image.len(), RESULT_DISK_BYTES);
        assert_eq!(&image[..6], b"HGRL\0\x01");
        assert_eq!(&image[6..8], format!("{run:?}").as_bytes());
        assert!(image[8..].iter().all(|b| *b == 0));
        assert_eq!(decode_run_label(&image), Some(run));
    }
    let image = encode_run_label(RunName::R0);
    for len in (0..8).chain([RESULT_DISK_BYTES - 1]) {
        assert_eq!(decode_run_label(&image[..len]), None);
    }
    let mut long = image.clone();
    long.push(0);
    assert_eq!(decode_run_label(&long), None);
    for at in 0..8 {
        let mut bad = image.clone();
        bad[at] = 0xff;
        assert_eq!(decode_run_label(&bad), None);
    }
    let mut nonce = image;
    nonce[RESULT_DISK_BYTES - 1] = 1;
    assert_eq!(decode_run_label(&nonce), None);
}

#[test]
fn only_supervisor_receives_label_and_sandbox_input_is_identical() {
    let config_path = Path::new("/config");
    let disk = Path::new("/dev/vdb");
    let mut inputs = Vec::new();
    for run in [RunName::R0, RunName::R1, RunName::R2] {
        let mut os = FakeOs::new();
        os.insert_file(config_path, config());
        os.insert_file(disk, encode_run_label(run));
        os.push_child_script(FakeChildScript::new(vec![
            FakeStep::EmitBytes(b"HGR1".to_vec()),
            FakeStep::ExitTree(ExitKind::Clean),
        ]));
        let report = run_supervisor(&mut os, config_path, disk).unwrap();
        assert_eq!(report.payload.run, run);
        assert_eq!(
            decode_result_disk(os.written_file(disk).unwrap())
                .unwrap()
                .run,
            run
        );
        let spec = os
            .events()
            .iter()
            .find_map(|event| match event {
                OsEvent::Spawn(spec) => Some(spec.clone()),
                _ => None,
            })
            .unwrap();
        inputs.push((
            serde_json::to_vec(&spec).unwrap(),
            sandbox::build_plan(&spec).unwrap(),
        ));
    }
    assert!(inputs.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn missing_malformed_or_image_embedded_label_fails_before_spawn_or_write() {
    let config_path = Path::new("/config");
    let disk = Path::new("/result");
    for image in [
        None,
        Some(vec![]),
        Some(vec![0; RESULT_DISK_BYTES]),
        Some(b"HGRL\0\x01R9".to_vec()),
    ] {
        let mut os = FakeOs::new();
        os.insert_file(config_path, config());
        if let Some(image) = image {
            os.insert_file(disk, image);
        }
        assert!(run_supervisor(&mut os, config_path, disk).is_err());
        assert!(!os
            .events()
            .iter()
            .any(|e| matches!(e, OsEvent::Spawn(_) | OsEvent::WriteFileAtomic { .. })));
    }
    for key in ["run", "run_name"] {
        let mut cfg: serde_json::Value = serde_json::from_slice(&config()).unwrap();
        cfg[key] = "R1".into();
        let mut os = FakeOs::new();
        os.insert_file(config_path, serde_json::to_vec(&cfg).unwrap());
        os.insert_file(disk, encode_run_label(RunName::R1));
        assert!(run_supervisor(&mut os, config_path, disk).is_err());
        assert_eq!(os.events(), &[OsEvent::ReadFile(config_path.into())]);
    }
}

#[test]
fn real_label_reader_rejects_links_special_files_and_oversized_input() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("input");
    std::fs::write(&image, encode_run_label(RunName::R2)).unwrap();
    let mut os = RealOs::new();
    assert_eq!(os.read_run_label(&image).unwrap(), RunName::R2);
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&image, &link).unwrap();
    let parent = temp.path().join("parent");
    std::os::unix::fs::symlink(temp.path(), &parent).unwrap();
    let fifo = temp.path().join("fifo");
    rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, rustix::fs::Mode::RUSR).unwrap();
    for path in [
        link,
        parent.join("input"),
        fifo,
        "/dev/zero".into(),
        "/dev/null".into(),
    ] {
        assert!(os.read_run_label(&path).is_err());
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&image)
        .unwrap();
    file.set_len((RESULT_DISK_BYTES as u64) + 1).unwrap();
    assert!(os.read_run_label(&image).is_err());
    file.set_len(7).unwrap();
    assert!(os.read_run_label(&image).is_err());
}
