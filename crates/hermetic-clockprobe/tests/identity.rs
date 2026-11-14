use hermetic_clockprobe::{baseline, classify::*, identity};

fn profile(index: u8, count: u8) -> Vec<CpuidLeafDump> {
    baseline::queries()
        .map(|(leaf, subleaf)| {
            let [eax, ebx, ecx, edx] = identity::expected(leaf, subleaf, index, count).unwrap();
            CpuidLeafDump {
                leaf,
                subleaf,
                eax,
                ebx,
                ecx,
                edx,
            }
        })
        .collect()
}

#[test]
fn exact_profile_all_cpus_and_each_register_mutation() {
    for count in [1, 2, 3, 32] {
        for index in 0..count {
            let good = profile(index, count);
            assert_eq!(
                identity::inspect(&good, Some(baseline::BRAND)).result,
                ProbeResult::Blocked
            );
            for pos in 0..good.len() {
                for register in 0..4 {
                    let mut bad = good.clone();
                    match register {
                        0 => bad[pos].eax ^= 1,
                        1 => bad[pos].ebx ^= 1,
                        2 => bad[pos].ecx ^= 1,
                        _ => bad[pos].edx ^= 1,
                    }
                    let result = identity::inspect(&bad, Some(baseline::BRAND));
                    assert_ne!(result.result, ProbeResult::Blocked);
                    assert!(result.value.is_none());
                }
            }
        }
    }
}

#[test]
fn partial_duplicate_brand_and_caps_cannot_pass() {
    let good = profile(0, 1);
    for pos in 0..good.len() {
        let mut bad = good.clone();
        bad.remove(pos);
        assert_eq!(
            identity::inspect(&bad, Some(baseline::BRAND)).result,
            ProbeResult::Error
        );
    }
    let mut bad = good.clone();
    bad.push(good[0]);
    assert_eq!(
        identity::inspect(&bad, Some(baseline::BRAND)).result,
        ProbeResult::Error
    );
    assert_eq!(identity::inspect(&good, None).result, ProbeResult::Error);
    assert_eq!(
        identity::inspect(&good, Some("host-secret")).result,
        ProbeResult::Leak
    );
    assert_eq!(
        identity::inspect(&vec![good[0]; 129], Some(baseline::BRAND)).result,
        ProbeResult::Error
    );
    assert_eq!(baseline::TSC_KHZ, 2_000_000);
}

#[test]
fn cpuinfo_rejects_features_above_the_fixed_v2_ceiling() {
    for flag in [
        "avx2",
        "avx",
        "aes",
        "rdrand",
        "rdseed",
        "xsave",
        "hypervisor",
        "pdpe1gb",
    ] {
        let text = format!("model name: {}\nflags: fpu tsc {flag}\n", baseline::BRAND);
        assert_eq!(
            classify_cpuinfo(Some(&text)).result,
            ProbeResult::Leak,
            "{flag}"
        );
    }
    let baseline_leaves = profile(0, 1);
    assert_eq!(
        classify_cpuid(&baseline_leaves, Some(baseline::BRAND)).result,
        ProbeResult::Blocked
    );
}

#[test]
fn documented_cpu_register_baseline_matches_guest_checker() {
    let guide = include_str!("../../../docs/clock-3b-analysis.md");
    for row in [
        format!("| CPUID.1 EAX | `0x{:08x}` |", baseline::SIGNATURE),
        format!("| CPUID.1 ECX | `0x{:08x}` |", baseline::FEATURES_ECX),
        format!(
            "| CPUID.1 EDX (one vCPU) | `0x{:08x}` |",
            baseline::FEATURES_EDX
        ),
    ] {
        assert!(guide.contains(&row), "documented baseline differs: {row}");
    }
}

/// CPUID as read inside the nested lockdown guest (patched Firecracker, vCPU 1 of
/// 2, 2026-11-14). Leaf 0xD.0 EBX is KVM's runtime x87 save-area size, which
/// the probe once reported as a leak; every value must classify as blocked.
#[test]
fn nested_guest_dump_with_kvm_xsave_size_is_the_fixed_profile() {
    let dump: &[(u32, u32, [u32; 4])] = &[
        (
            0x00000000,
            0,
            [0x00000016, 0x756e6547, 0x6c65746e, 0x49656e69],
        ),
        (
            0x00000001,
            0,
            [0x000106a5, 0x01020800, 0x00982201, 0x178bfbff],
        ),
        (
            0x00000002,
            0,
            [0x00000001, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000003,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000004,
            0,
            [0x04000121, 0x01c0003f, 0x0000003f, 0x00000000],
        ),
        (
            0x00000004,
            1,
            [0x04000122, 0x01c0003f, 0x0000003f, 0x00000000],
        ),
        (
            0x00000004,
            2,
            [0x04000143, 0x01c0003f, 0x000001ff, 0x00000000],
        ),
        (
            0x00000004,
            3,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000005,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000006,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000007,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000007,
            1,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000007,
            2,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000007,
            3,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000008,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000009,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x0000000a,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x0000000b,
            0,
            [0x00000000, 0x00000001, 0x00000100, 0x00000001],
        ),
        (
            0x0000000b,
            1,
            [0x00000001, 0x00000002, 0x00000201, 0x00000001],
        ),
        (
            0x0000000b,
            2,
            [0x00000000, 0x00000000, 0x00000002, 0x00000001],
        ),
        (
            0x0000000b,
            3,
            [0x00000000, 0x00000000, 0x00000003, 0x00000001],
        ),
        (
            0x0000000c,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x0000000d,
            0,
            [0x00000000, 0x00000240, 0x00000000, 0x00000000],
        ),
        (
            0x0000000d,
            1,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x0000000d,
            2,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x0000000d,
            3,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x0000000e,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x0000000f,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000010,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000011,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000012,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000013,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000014,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x00000015,
            0,
            [0x00000001, 0x00000050, 0x017d7840, 0x00000000],
        ),
        (
            0x00000016,
            0,
            [0x000007d0, 0x000007d0, 0x00000064, 0x00000000],
        ),
        (
            0x40000000,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x40000001,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x80000000,
            0,
            [0x80000008, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x80000001,
            0,
            [0x00000000, 0x00000000, 0x00000001, 0x20100800],
        ),
        (
            0x80000002,
            0,
            [0x65746e49, 0x2952286c, 0x6f655820, 0x2952286e],
        ),
        (
            0x80000003,
            0,
            [0x55504320, 0x35354520, 0x40203430, 0x302e3220],
        ),
        (
            0x80000004,
            0,
            [0x7a484730, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x80000005,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x80000006,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
        ),
        (
            0x80000007,
            0,
            [0x00000000, 0x00000000, 0x00000000, 0x00000100],
        ),
        (
            0x80000008,
            0,
            [0x00003024, 0x00000000, 0x00000000, 0x00000000],
        ),
    ];
    let leaves: Vec<CpuidLeafDump> = baseline::queries()
        .map(|(leaf, subleaf)| {
            let [eax, ebx, ecx, edx] = dump
                .iter()
                .find(|(l, s, _)| (*l, *s) == (leaf, subleaf))
                .map(|(_, _, r)| *r)
                .unwrap_or_else(|| identity::expected(leaf, subleaf, 1, 2).unwrap());
            CpuidLeafDump {
                leaf,
                subleaf,
                eax,
                ebx,
                ecx,
                edx,
            }
        })
        .collect();
    assert_eq!(
        identity::inspect(&leaves, Some(baseline::BRAND)).result,
        ProbeResult::Blocked
    );
    // The template itself still installs zero; only KVM's runtime value is accepted.
    assert_eq!(baseline::registers(0xd, 0, 1, 2).unwrap()[1], 0);
    let mut stale = leaves.clone();
    let d = stale
        .iter_mut()
        .find(|r| (r.leaf, r.subleaf) == (0xd, 0))
        .unwrap();
    d.ebx = 0;
    assert_eq!(
        identity::inspect(&stale, Some(baseline::BRAND)).result,
        ProbeResult::Leak
    );
}
