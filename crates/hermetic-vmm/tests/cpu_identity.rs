use hermetic_vmm::plan::{calibrated_boot_args, cpu_template};

#[path = "../../../vmm/cpu-baseline.rs"]
mod baseline;

#[test]
fn executable_frequency_is_constant_without_host_calibration() {
    // The test process has no need to query or publish the physical frequency.
    let base = "ro clocksource=tsc tsc=reliable hermetic.t=1700000000";
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-vmm"))
        .args(["boot-args", base])
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    // The VMM confirms the fixed rate and returns the arguments unchanged.
    assert_eq!(baseline::TSC_KHZ, 2_000_000);
    assert_eq!(output.stdout, format!("{base}\n").as_bytes());
    for khz in [100_000, 2_400_000, 2_688_000, 10_000_000] {
        assert!(calibrated_boot_args(base, khz).is_err());
    }
}

#[test]
fn template_contains_only_complete_fixed_registers() {
    let template = cpu_template();
    for leaf in template["cpuid_modifiers"].as_array().unwrap() {
        let number =
            u32::from_str_radix(leaf["leaf"].as_str().unwrap().trim_start_matches("0x"), 16)
                .unwrap();
        let subleaf = u32::from_str_radix(
            leaf["subleaf"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let expected = baseline::registers(number, subleaf, 0, 1).unwrap();
        let modifiers = leaf["modifiers"].as_array().unwrap();
        assert_eq!(modifiers.len(), 4, "{number:x}");
        for (reg, value) in ["eax", "ebx", "ecx", "edx"].into_iter().zip(expected) {
            let bitmap = modifiers.iter().find(|r| r["register"] == reg).unwrap()["bitmap"]
                .as_str()
                .unwrap();
            assert_eq!(
                bitmap,
                format!("0b{value:032b}"),
                "{number:x}:{subleaf}:{reg}"
            );
        }
    }
    assert!(template["cpuid_modifiers"].as_array().unwrap().len() >= 20);
    assert!(hermetic_vmm::plan::CPU_TEMPLATE.len() as u64 <= hermetic_vmm::fs::MAX_TEMPLATE_BYTES);
    assert!(
        serde_json::to_vec(&template).unwrap().len() + 512 <= hermetic_vmm::api::MAX_REQUEST_BYTES
    );
}

#[test]
fn profile_is_bounded_and_nehalem_with_v2_features() {
    assert!(baseline::queries().count() <= baseline::MAX_CPUID_ENTRIES);
    assert_eq!(baseline::registers(1, 0, 0, 0), None);
    assert_eq!(baseline::registers(1, 0, 32, 32), None);
    assert_eq!(baseline::registers(1, 0, 0, 33), None);
    assert_eq!(baseline::registers(7, u32::MAX, 0, 1), Some([0; 4]));
    assert_eq!(
        baseline::registers(0x15, 0, 0, 1),
        Some([1, 80, 25_000_000, 0])
    );
    assert_eq!(
        baseline::FEATURES_ECX & ((1 << 26) | (1 << 28) | (1 << 31)),
        0
    );
    for (leaf, subleaf, expected) in [
        (0, 0, [0x16, 0x756e6547, 0x6c65746e, 0x49656e69]),
        (1, 0, [0x106a5, 0x10800, 0x982201, 0x78bfbff]),
        (4, 0, [0x121, 0x1c0003f, 63, 0]),
        (4, 1, [0x122, 0x1c0003f, 63, 0]),
        (4, 2, [0x143, 0x1c0003f, 511, 0]),
        (4, 3, [0; 4]),
        (0x80000001, 0, [0, 0, 1, 0x20100800]),
        (0x80000007, 0, [0, 0, 0, 256]),
        (0x80000008, 0, [0x3024, 0, 0, 0]),
    ] {
        assert_eq!(baseline::registers(leaf, subleaf, 0, 1), Some(expected));
    }
    assert_eq!(baseline::registers(0xb, 1, 1, 4), Some([2, 4, 0x201, 1]));
}
