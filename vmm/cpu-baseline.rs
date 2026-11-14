//! Fixed Intel Nehalem-era identity with an x86-64-v2 feature ceiling.
//! Only vCPU index/count vary, and both come from the bounded machine spec.
pub const BRAND: &str = "Intel(R) Xeon(R) CPU E5504 @ 2.00GHz";
pub const TSC_KHZ: u32 = 2_000_000;
pub const MAX_VCPUS: u8 = 32;
pub const MAX_CPUID_ENTRIES: usize = 128;
pub const SIGNATURE: u32 = 0x0001_06a5;
pub const FEATURES_ECX: u32 = 0x0098_2201;
pub const FEATURES_EDX: u32 = 0x078b_fbff;

/// A total function, including invalid topology and unadvertised leaf queries.
pub fn registers(leaf: u32, subleaf: u32, index: u8, count: u8) -> Option<[u32; 4]> {
    if count == 0 || count > MAX_VCPUS || index >= count {
        return None;
    }
    let id = u32::from(index);
    let cpus = u32::from(count);
    let width = cpus.next_power_of_two().trailing_zeros();
    let r = match (leaf, subleaf) {
        (0, 0) => [0x16, 0x756e6547, 0x6c65746e, 0x49656e69],
        (1, 0) => [
            SIGNATURE,
            (id << 24) | (cpus << 16) | (8 << 8),
            FEATURES_ECX,
            FEATURES_EDX | if count > 1 { 1 << 28 } else { 0 },
        ],
        // No legacy cache descriptors: enumerate the fixed geometry in leaf 4.
        (2, 0) => [1, 0, 0, 0],
        (4, 0..=2) => {
            let (kind, level, ways, sets) = match subleaf {
                0 => (1, 1, 8, 64),
                1 => (2, 1, 8, 64),
                _ => (3, 2, 8, 512),
            };
            [
                kind | (level << 5) | (1 << 8) | ((cpus - 1) << 26),
                ((ways - 1) << 22) | 63,
                sets - 1,
                0,
            ]
        }
        (0xb, 0) => [0, 1, 1 << 8, id],
        (0xb, 1) => [width, cpus, (2 << 8) | 1, id],
        (0xb, _) => [0, 0, subleaf & 0xff, id],
        // 25 MHz crystal * 80 = the fixed 2 GHz virtual TSC.
        (0x15, 0) => [1, 80, 25_000_000, 0],
        (0x16, 0) => [2000, 2000, 100, 0],
        (0x8000_0000, 0) => [0x8000_0008, 0, 0, 0],
        (0x8000_0001, 0) => [0, 0, 1, (1 << 11) | (1 << 20) | (1 << 29)],
        (0x8000_0002..=0x8000_0004, 0) => {
            let offset = usize::try_from(leaf - 0x8000_0002).ok()?.checked_mul(16)?;
            let mut words = [0u32; 4];
            for (word_index, word) in words.iter_mut().enumerate() {
                for byte_index in 0..4 {
                    let pos = offset.checked_add(word_index * 4 + byte_index)?;
                    *word |=
                        u32::from(*BRAND.as_bytes().get(pos).unwrap_or(&0)) << (byte_index * 8);
                }
            }
            words
        }
        (0x8000_0007, 0) => [0, 0, 0, 1 << 8],
        (0x8000_0008, 0) => [36 | (48 << 8), 0, 0, 0],
        _ => [0; 4],
    };
    Some(r)
}

/// Exactly the entries installed in KVM; unknown inputs are never copied.
pub fn queries() -> impl Iterator<Item = (u32, u32)> {
    (0..=0x16)
        .flat_map(|leaf| {
            let subleaves = match leaf {
                4 => 4,
                7 => 2,
                0xb => 3,
                _ => 1,
            };
            (0..subleaves).map(move |subleaf| (leaf, subleaf))
        })
        .chain((0x8000_0000..=0x8000_0008).map(|leaf| (leaf, 0)))
        .chain((0x4000_0000..=0x4000_0010).map(|leaf| (leaf, 0)))
}
