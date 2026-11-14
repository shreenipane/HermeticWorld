//! Exact pre-handoff CPUID check against the profile installed by the VMM.
use crate::baseline;
use crate::classify::{CpuidLeafDump, ProbeRecord, ProbeResult};
use std::collections::BTreeSet;

/// KVM recomputes CPUID.0xD.0:EBX on every XCR0 change as the save-area size of
/// the enabled state. The template advertises no XSAVE, so the guest keeps the
/// reset XCR0 (x87 only) and KVM reports the legacy area plus header, 0x240,
/// on every host. All other registers must equal the installed template.
pub const KVM_XSAVE_LEGACY_SIZE: u32 = 0x240;

pub fn expected(leaf: u32, subleaf: u32, index: u8, count: u8) -> Option<[u32; 4]> {
    let mut r = baseline::registers(leaf, subleaf, index, count)?;
    if (leaf, subleaf) == (0xd, 0) {
        r[1] = KVM_XSAVE_LEGACY_SIZE;
    }
    Some(r)
}

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
        if expected(leaf.leaf, leaf.subleaf, index, count)
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
