use std::fs;
use tempfile::tempdir;
use time::macros::datetime;

use hermetic_sealcheck::d8_image::{
    check_cpu_identity, check_cpu_template, check_kernel_image_bytes, MAX_KERNEL_IMAGES,
    MAX_KERNEL_IMAGE_BYTES,
};
use hermetic_sealcheck::{check_d8, Visibility};

const VIS: Visibility = Visibility::AgentVisible;

fn image(banner: &str) -> Vec<u8> {
    let mut bytes = b"\x7fELF\x02\x01\x00\x00".to_vec();
    bytes.extend_from_slice(banner.as_bytes());
    bytes.extend_from_slice(b"\x00\xff\x00");
    bytes
}

#[test]
fn kernel_image_build_string_after_t_clock_is_reported() {
    let img = image("Linux version 6.6.1 (gcc 2024-01-05) #1 SMP 2024-02-10");
    let f = check_kernel_image_bytes(
        "boot/vmlinuz-6.6",
        &img,
        datetime!(2024-01-31 12:00 UTC),
        VIS,
    );
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].channel, "kernel_image");
    assert_eq!(f[0].path, "boot/vmlinuz-6.6");
    assert!(f[0]
        .evidence
        .contains(&"build-string date: 2024-02-10".to_string()));
    assert!(!f[0].evidence.iter().any(|e| e.contains("2024-01-05")));
    assert!(check_kernel_image_bytes("k", &img, datetime!(2024-02-10 00:00 UTC), VIS).is_empty());
}

#[test]
fn kernel_image_without_dates_fails_closed() {
    let f = check_kernel_image_bytes(
        "boot/vmlinuz",
        b"\x1f\x8b\x08\x00compressed",
        datetime!(2024-01-01 0:00 UTC),
        VIS,
    );
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].channel, "d8_error");
}

#[test]
fn kernel_image_date_flood_fails_closed() {
    let mut text = String::new();
    for y in 2000..2020 {
        for m in 1..=12 {
            for d in 1..=28 {
                text.push_str(&format!("{y:04}-{m:02}-{d:02} "));
            }
        }
    }
    let f = check_kernel_image_bytes("k", &image(&text), datetime!(2030-01-01 0:00 UTC), VIS);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].channel, "d8_error");
}

#[test]
fn check_d8_scans_boot_images_relative_and_no_follow() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("root");
    let boot = root.join("boot");
    fs::create_dir_all(&boot).unwrap();
    fs::write(
        boot.join("vmlinuz-6.6"),
        image("Linux version 6.6 2026-10-21"),
    )
    .unwrap();
    fs::write(boot.join("System.map"), "2099-01-01").unwrap();
    let outside = dir.path().join("outside");
    fs::write(&outside, image("Linux version 9 2099-01-01")).unwrap();
    std::os::unix::fs::symlink(&outside, boot.join("vmlinux-link")).unwrap();

    let f = check_d8(&root, datetime!(2025-01-01 0:00 UTC), VIS);
    let img: Vec<_> = f.iter().filter(|f| f.path.starts_with("boot/")).collect();
    assert_eq!(img.len(), 2, "{img:?}");
    let hit = img.iter().find(|f| f.channel == "kernel_image").unwrap();
    assert_eq!(hit.path, "boot/vmlinuz-6.6");
    let link = img.iter().find(|f| f.path == "boot/vmlinux-link").unwrap();
    assert_eq!(link.channel, "d8_error");
    let json = serde_json::to_string(&f).unwrap();
    assert!(!json.contains(dir.path().to_str().unwrap()));
    assert!(!json.contains("2099"));
}

#[test]
fn oversized_and_excess_kernel_images_are_capped() {
    let dir = tempdir().unwrap();
    let boot = dir.path().join("boot");
    fs::create_dir_all(&boot).unwrap();
    let big = fs::File::create(boot.join("vmlinuz-big")).unwrap();
    big.set_len(MAX_KERNEL_IMAGE_BYTES + 1).unwrap();
    let f = check_d8(dir.path(), datetime!(2025-01-01 0:00 UTC), VIS);
    assert!(f
        .iter()
        .any(|f| f.path == "boot/vmlinuz-big" && f.channel == "d8_error"));

    fs::remove_file(boot.join("vmlinuz-big")).unwrap();
    for i in 0..=MAX_KERNEL_IMAGES {
        fs::write(
            boot.join(format!("vmlinuz-{i:02}")),
            image("Linux 2020-01-01"),
        )
        .unwrap();
    }
    let f = check_d8(dir.path(), datetime!(2025-01-01 0:00 UTC), VIS);
    assert!(f
        .iter()
        .any(|f| f.path == "boot" && f.evidence.iter().any(|e| e.contains("count cap"))));
}

#[test]
fn cpu_template_baseline_is_coherent_after_its_sale_date() {
    assert!(check_cpu_template(datetime!(2009-03-30 0:00 UTC), VIS).is_empty());
    let f = check_cpu_template(datetime!(2008-06-01 0:00 UTC), VIS);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].channel, "cpu_template");
    assert_eq!(f[0].path, "<cpu-template>");
    let f = check_d8(
        tempdir().unwrap().path(),
        datetime!(2008-06-01 0:00 UTC),
        VIS,
    );
    assert!(f.iter().any(|f| f.channel == "cpu_template"));
}

#[test]
fn unknown_or_mismatched_cpu_identity_is_reported() {
    let t = datetime!(2024-01-01 0:00 UTC);
    let f = check_cpu_identity("AMD Ryzen 9 9950X", 0x00b4_0f40, t, VIS);
    assert_eq!(f.len(), 1);
    assert!(f[0].evidence[0].contains("not in the historical CPU policy"));
    let f = check_cpu_identity("Intel(R) Xeon(R) CPU E5504 @ 2.00GHz", 0x000a_06a4, t, VIS);
    assert_eq!(f.len(), 1);
    assert!(f[0].evidence[0].contains("does not match"));
}
