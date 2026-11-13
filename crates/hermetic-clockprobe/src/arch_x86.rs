//! The only unsafe module: CPUID and RDTSC via core::arch, with no memory
//! operands, MSR instructions, hypercalls, port I/O, or writable guest pages.
//! Run only in the intended x86_64 guest with CR4.TSD clear (the sealed kernel
//! default). A hostile kernel can forbid RDTSC; this diagnostic cannot attest
//! to a kernel that actively falsifies its observations.
#![allow(unsafe_code)]

pub fn read_tsc() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: x86_64 provides RDTSC. It has no memory side effects; the
        // required guest execution environment leaves userspace TSC enabled.
        Some(unsafe { core::arch::x86_64::_rdtsc() })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

pub fn read_cpuid(leaf: u32, subleaf: u32) -> Option<(u32, u32, u32, u32)> {
    #[cfg(target_arch = "x86_64")]
    {
        // The safe intrinsic returns register values and accepts no memory.
        let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
        Some((r.eax, r.ebx, r.ecx, r.edx))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (leaf, subleaf);
        None
    }
}
