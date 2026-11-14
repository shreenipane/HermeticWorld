mod support;
use hermetic_vmm::{plan::*, spec::*};
use serde_json::{json, Value};

#[test]
fn frequency_resolution_rejects_non_unicode_and_out_of_range_cpuid() {
    use std::os::unix::ffi::OsStrExt;
    assert!(resolve_tsc_khz_os(
        Some(2_688_000),
        Some(std::ffi::OsStr::from_bytes(b"secret\xff"))
    )
    .is_err());
    for khz in [0, 99_999, 10_000_001, u64::MAX] {
        assert!(resolve_tsc_khz(Some(khz), Some("2688000")).is_err());
    }
    assert_eq!(
        tsc_khz_from_leaf15(u32::MAX, u32::MAX, u32::MAX),
        Some(4_294_967)
    );
}

#[test]
fn tsc_append_rejects_duplicate_aliases_malformed_requests_and_cap_overflow() {
    let base = "clocksource=tsc tsc=reliable hermetic.t=1700000000 ro";
    for arg in [
        "tsc_early_khz",
        "tsc-early-khz=2688000",
        "tsc_early-khz=2688000",
        "tsc_early_khz=2688000",
    ] {
        let mut s = support::spec(Role::Agent);
        s.boot_args.push_str(&format!(" {arg}"));
        assert!(s.validate().is_err(), "{arg}");
        assert!(calibrated_boot_args(&format!("{base} {arg}"), 2_000_000).is_err());
    }
    let mut s = support::spec(Role::Agent);
    s.boot_args
        .push_str(&" ".repeat(MAX_BOOT_ARGS - s.boot_args.len()));
    assert!(s.validate().is_err());
    for (body, khz) in [
        (json!({}), 2_000_000),
        (json!({"boot_args":12}), 2_000_000),
        (json!({"boot_args":base}), 0),
    ] {
        assert!(with_tsc_khz(
            ApiRequest {
                method: "PUT".into(),
                path: "/boot-source".into(),
                body
            },
            khz
        )
        .is_err());
    }
}

#[test]
fn all_launch_roles_boot_without_a_tsc_frequency_argument() {
    for role in [Role::Agent, Role::Net, Role::Extractor, Role::Grader] {
        let s = support::spec(role).validate().unwrap();
        let requests = calibrated_api_requests(&s, 2_000_000).unwrap();
        let boot = requests.iter().find(|r| r.path == "/boot-source").unwrap();
        let args = boot.body["boot_args"].as_str().unwrap();
        // No role may pass a frequency that would bypass CPUID leaf 0x15.
        assert_eq!(args.matches("tsc_early_khz").count(), 0);
        assert!(args.contains("clocksource=tsc"));
    }
}

fn word(template: &Value, leaf: u32, subleaf: u32, reg: &str, original: u32) -> u32 {
    let entry = template["cpuid_modifiers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            u32::from_str_radix(e["leaf"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
                == leaf
                && u32::from_str_radix(e["subleaf"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap()
                    == subleaf
        })
        .unwrap();
    let bitmap = entry["modifiers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["register"] == reg)
        .unwrap()["bitmap"]
        .as_str()
        .unwrap();
    assert_eq!(bitmap.len(), 34);
    bitmap[2..]
        .bytes()
        .rev()
        .enumerate()
        .fold(original, |v, (i, b)| match b {
            b'0' => v & !(1 << i),
            b'1' => v | (1 << i),
            b'x' => v,
            _ => panic!("invalid bitmap"),
        })
}

#[test]
fn active_template_masks_pv_frequency_pmu_and_baseline_identity() {
    let t = cpu_template();
    assert_eq!(t, serde_json::from_str::<Value>(CPU_TEMPLATE).unwrap());
    assert_eq!(word(&t, 1, 0, "eax", u32::MAX), 0x0001_06a5);
    assert_eq!(word(&t, 1, 0, "ecx", u32::MAX) & (1 << 31), 0);
    for leaf in [0xa, 0x40000000, 0x40000001] {
        for reg in ["eax", "ebx", "ecx", "edx"] {
            assert_eq!(word(&t, leaf, 0, reg, u32::MAX), 0, "{leaf:x}:{reg}");
        }
    }
    for reg in ["eax", "ebx", "ecx", "edx"] {
        assert_eq!(word(&t, 7, 1, reg, u32::MAX), 0);
    }
    let mut brand = Vec::new();
    for leaf in 0x80000002..=0x80000004 {
        for reg in ["eax", "ebx", "ecx", "edx"] {
            brand.extend(word(&t, leaf, 0, reg, u32::MAX).to_le_bytes());
        }
    }
    assert_eq!(
        String::from_utf8(brand).unwrap().trim_end_matches('\0'),
        "Intel(R) Xeon(R) CPU E5504 @ 2.00GHz"
    );
    assert_eq!(t["msr_modifiers"], json!([]));
}

#[test]
fn amd_and_nested_leaf15_require_operator_calibration() {
    let intel = [0x756e6547, 0x49656e69, 0x6c65746e];
    assert_eq!(
        tsc_khz_from_host_leaf15(intel, false, 2, 140, 38_400_000),
        Some(2_688_000)
    );
    for (vendor, nested) in [(intel, true), ([0x68747541, 0x69746e65, 0x444d4163], false)] {
        let cpuid = tsc_khz_from_host_leaf15(vendor, nested, 2, 140, 38_400_000);
        assert_eq!(cpuid, None);
        assert!(resolve_tsc_khz(cpuid, None).is_err());
        assert_eq!(resolve_tsc_khz(cpuid, Some("3000000")).unwrap(), 3_000_000);
    }
}
