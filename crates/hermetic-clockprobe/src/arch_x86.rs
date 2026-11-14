//! The only unsafe module: CPUID and RDTSC via core::arch, with no memory
//! operands, MSR instructions, hypercalls, port I/O, or writable guest pages.
//! A separate zero-length init_module syscall checks compiled-out module support.
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

/// Probe only the absence of init_module with a zero-length image. This cannot
/// load executable code. Return the raw Linux syscall result without errno text.
pub fn empty_module_calls() -> Option<(i64, i64)> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let result: i64;
        // SAFETY: syscall 175 is init_module on Linux x86_64. Both pointers
        // are null and the length is zero; there are no valid memory operands
        // or module bytes. The kernel returns an error without installing code.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 175_i64 => result,
                in("rdi") 0_usize,
                in("rsi") 0_usize,
                in("rdx") 0_usize,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        let finit_result: i64;
        // SAFETY: finit_module (313) with fd=-1 can never identify a module
        // file. The parameter pointer is null and flags are zero. No code or
        // writable userspace memory is supplied.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 313_i64 => finit_result,
                in("rdi") -1_i64,
                in("rsi") 0_usize,
                in("rdx") 0_usize,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        Some((result, finit_result))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        None
    }
}
