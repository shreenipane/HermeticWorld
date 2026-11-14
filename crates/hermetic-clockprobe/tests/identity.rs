use hermetic_clockprobe::{baseline, classify::*, identity};

fn profile(index: u8, count: u8) -> Vec<CpuidLeafDump> {
    baseline::queries()
        .map(|(leaf, subleaf)| {
            let [eax, ebx, ecx, edx] = baseline::registers(leaf, subleaf, index, count).unwrap();
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
