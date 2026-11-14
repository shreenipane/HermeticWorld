//! Exact pre-handoff CPUID check against the profile installed by the VMM.
use crate::baseline;
use crate::classify::{CpuidLeafDump, ProbeRecord, ProbeResult};
use std::collections::BTreeSet;

pub fn inspect(leaves: &[CpuidLeafDump], brand: Option<&str>) -> ProbeRecord {
    let record = |result, detail| ProbeRecord::new("cpuid", result, None, detail);
    if leaves.len() > baseline::MAX_CPUID_ENTRIES {
        return record(ProbeResult::Error, "CPU profile item cap exceeded");
    }
    let Some(cpu) = leaves.iter().find(|r| r.leaf == 1 && r.subleaf == 0) else {
        return record(ProbeResult::Error, "CPU profile evidence incomplete");
    };
    let index = (cpu.ebx >> 24) as u8;
    let count = ((cpu.ebx >> 16) & 0xff) as u8;
    let mut seen = BTreeSet::new();
    for leaf in leaves {
        if !seen.insert((leaf.leaf, leaf.subleaf)) {
            return record(ProbeResult::Error, "Duplicate CPU profile evidence");
        }
        if baseline::registers(leaf.leaf, leaf.subleaf, index, count)
            != Some([leaf.eax, leaf.ebx, leaf.ecx, leaf.edx])
        {
            return record(ProbeResult::Leak, "CPUID differs from fixed CPU profile");
        }
    }
    if baseline::queries().any(|query| !seen.contains(&query)) || brand.is_none() {
        return record(ProbeResult::Error, "CPU profile evidence incomplete");
    }
    if brand != Some(baseline::BRAND) {
        return record(
            ProbeResult::Leak,
            "CPU brand differs from fixed CPU profile",
        );
    }
    record(
        ProbeResult::Blocked,
        "Exact CPU profile and fixed 2 GHz CPUID frequency verified",
    )
}
