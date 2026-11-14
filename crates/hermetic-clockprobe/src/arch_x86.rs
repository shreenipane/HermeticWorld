//! The only unsafe module: CPUID and RDTSC via core::arch, with no
//! MSR instructions, hypercalls, port I/O, or writable guest pages.
//! A separate zero-length init_module syscall checks compiled-out module support.
//! Bounded Linux affinity wrappers keep a CPUID sample on one vCPU.
//! A read-only clock_gettime wrapper samples the guest's POSIX clocks.
//! Run only in the intended x86_64 guest with CR4.TSD clear (the sealed kernel
//! default). A hostile kernel can forbid RDTSC; this diagnostic cannot attest
//! to a kernel that actively falsifies its observations.
#![allow(unsafe_code)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod affinity {
    use std::io;

    // Covers up to 8192 logical CPUs; larger kernel masks fail closed.
    const MAX_AFFINITY_WORDS: usize = 128;
    type Mask = [u64; MAX_AFFINITY_WORDS];

    unsafe extern "C" {
        fn sched_getaffinity(pid: i32, size: usize, mask: *mut Mask) -> i32;
        fn sched_setaffinity(pid: i32, size: usize, mask: *const Mask) -> i32;
    }

    fn invalid() -> io::Error {
        io::ErrorKind::Other.into()
    }
    fn get() -> io::Result<Mask> {
        let mut mask = [0; MAX_AFFINITY_WORDS];
        // SAFETY: pid 0 selects this thread. The aligned buffer is writable
        // for exactly the bounded size passed to the Linux libc wrapper.
        if unsafe { sched_getaffinity(0, size_of::<Mask>(), &mut mask) } != 0 {
            return Err(invalid());
        }
        Ok(mask)
    }
    fn set(mask: &Mask) -> io::Result<()> {
        // SAFETY: pid 0 selects this thread; mask is an initialized aligned
        // buffer readable for the supplied size. No other thread is changed.
        if unsafe { sched_setaffinity(0, size_of::<Mask>(), mask) } != 0 {
            return Err(invalid());
        }
        Ok(())
    }

    struct Restore<F: FnMut(&Mask) -> io::Result<()>> {
        original: Mask,
        set: F,
        active: bool,
    }
    impl<F: FnMut(&Mask) -> io::Result<()>> Restore<F> {
        fn restore(&mut self) -> io::Result<()> {
            self.active = false;
            (self.set)(&self.original)
        }
    }
    impl<F: FnMut(&Mask) -> io::Result<()>> Drop for Restore<F> {
        fn drop(&mut self) {
            if self.active {
                let _ = self.restore();
            }
        }
    }

    fn inspect_with<T>(
        get: impl FnOnce() -> io::Result<Mask>,
        set: impl FnMut(&Mask) -> io::Result<()>,
        inspect: impl FnOnce() -> T,
    ) -> io::Result<T> {
        let original = get()?;
        let (index, word) = original
            .iter()
            .enumerate()
            .find(|(_, word)| **word != 0)
            .ok_or_else(invalid)?;
        let mut selected = [0; MAX_AFFINITY_WORDS];
        *selected.get_mut(index).ok_or_else(invalid)? = word & word.wrapping_neg();
        let mut restore = Restore {
            original,
            set,
            active: true,
        };
        (restore.set)(&selected)?;
        let result = inspect();
        restore.restore()?;
        Ok(result)
    }

    pub(super) fn inspect<T>(inspect: impl FnOnce() -> T) -> io::Result<T> {
        inspect_with(get, set, inspect)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::RefCell;

        #[test]
        fn cpuid_sampling_pins_one_cpu_and_restores_the_original_mask() {
            let mut original = [0; MAX_AFFINITY_WORDS];
            original[2] = 0b1010;
            let current = RefCell::new(original);
            let result = inspect_with(
                || Ok(original),
                |mask| {
                    *current.borrow_mut() = *mask;
                    Ok(())
                },
                || {
                    for _ in crate::baseline::queries() {
                        // Model arbitrary scheduling between CPUID queries:
                        // only the selected CPU is eligible for every query.
                        assert_eq!(
                            current.borrow().iter().map(|w| w.count_ones()).sum::<u32>(),
                            1
                        );
                        assert_eq!(current.borrow()[2], 0b10);
                    }
                    42
                },
            );
            assert_eq!(result.unwrap(), 42);
            assert_eq!(*current.borrow(), original);
        }

        #[test]
        fn affinity_failures_do_not_sample_or_report_success() {
            assert!(inspect_with(|| Err(invalid()), |_| Ok(()), || panic!("sampled")).is_err());
            assert!(inspect_with(
                || Ok([0; MAX_AFFINITY_WORDS]),
                |_| Ok(()),
                || panic!("sampled")
            )
            .is_err());
            let mut original = [0; MAX_AFFINITY_WORDS];
            original[0] = 3;
            assert!(
                inspect_with(|| Ok(original), |_| Err(invalid()), || panic!("sampled")).is_err()
            );
            let mut calls = 0;
            assert!(inspect_with(
                || Ok(original),
                |_| {
                    calls += 1;
                    if calls == 1 {
                        Ok(())
                    } else {
                        Err(invalid())
                    }
                },
                || ()
            )
            .is_err());
        }

        #[test]
        fn linux_affinity_wrapper_pins_and_restores_the_calling_thread() {
            let before = get().unwrap();
            inspect(|| {
                for _ in crate::baseline::queries() {
                    assert_eq!(
                        get().unwrap().iter().map(|w| w.count_ones()).sum::<u32>(),
                        1
                    );
                    std::thread::yield_now();
                }
            })
            .unwrap();
            assert_eq!(get().unwrap(), before);
        }
    }
}

pub fn with_pinned_cpu<T>(inspect: impl FnOnce() -> T) -> std::io::Result<T> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        affinity::inspect(inspect)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = inspect;
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

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

/// Linux clock ids read by the POSIX clock probe.
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_BOOTTIME: i32 = 7;
pub const CLOCK_TAI: i32 = 11;

/// Seconds on `clock` via the libc vDSO/syscall wrapper; None on failure or for
/// any other id. It only reads the clock into a local timespec.
#[cfg(target_os = "linux")]
pub fn clock_seconds(clock: i32) -> Option<f64> {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, ts: *mut Timespec) -> i32;
    }
    if ![CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_TAI].contains(&clock) {
        return None;
    }
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a valid, aligned, writable timespec owned by this frame, and
    // only the four allowlisted clock ids reach libc.
    if unsafe { clock_gettime(clock, &mut ts) } != 0 {
        return None;
    }
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return None;
    }
    Some(ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9)
}

#[cfg(not(target_os = "linux"))]
pub fn clock_seconds(_clock: i32) -> Option<f64> {
    None
}
