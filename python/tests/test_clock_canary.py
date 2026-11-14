"""Compile and execute the real test-only initializer with simulated KVM operations."""
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'images/kernel/canary/hermetic-clock-canary.c'

STUB = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef uintptr_t phys_addr_t;
#define __init
#define early_param(a,b)
#define late_initcall(a)
#define GFP_KERNEL 0
#define PAGE_SIZE 4096
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define pr_info printf
static unsigned char storage[PAGE_SIZE];
static bool pinned, registered, freed;
static int cpu, registered_cpu;
static void migrate_disable(void) { assert(!pinned); pinned = true; }
static void migrate_enable(void) { assert(pinned); pinned = false; }
static unsigned long __get_free_page(int flags) { (void)flags; return (unsigned long)storage; }
static phys_addr_t virt_to_phys(void *page) { return (uintptr_t)page; }
static void free_page(unsigned long page) {
    assert(page == (unsigned long)storage && !registered && !pinned);
    freed = true;
}
static void *memchr_inv(const void *p, int byte, size_t n) {
    const unsigned char *s = p;
    for (size_t i = 0; i < n; ++i) if (s[i] != byte) return (void *)(s+i);
    return NULL;
}
static int rdmsrl_safe(u32 msr, u64 *value) { (void)msr; *value = 0; return MODE ? 0 : -1; }
static int wrmsrl_safe(u32 msr, u64 value) {
    if (!pinned) cpu++; /* model migration between MSR instructions */
    if (!MODE) return -1;
    if (msr == 0x12 || msr == 0x4b564d01) {
        if (value) { registered = true; registered_cpu = cpu; }
        else if (MODE == 2) return -1;
        else if (cpu == registered_cpu) registered = false;
    }
    return 0;
}
'''


@pytest.mark.parametrize('mode', [0, 1, 2])
def test_canary_compiles_and_matches_vmm_result_without_freeing_registered_pages(tmp_path, mode):
    # These macros live in linux/kvm_para.h, not asm/kvm_para.h, in Linux 6.6.
    headers = {
        'linux/kvm_para.h': '#include <asm/kvm_para.h>\n#define KVM_HC_CLOCK_PAIRING 9\n#define KVM_ENOSYS 1000\n',
        'linux/errno.h': '#define ENOSYS 38\n',
        'asm/kvm_para.h': '''#define KVM_CLOCK_PAIRING_WALLCLOCK 0
static long kvm_hypercall2(unsigned int nr, unsigned long p1, unsigned long p2) {
    assert(nr == 9 && p1 == (unsigned long)storage && p2 == 0);
    return -38; /* the VMM's fixed Xen exit result */
}
''',
    }
    for name in ['linux/init.h', 'linux/mm.h', 'linux/slab.h', 'linux/string.h',
                 'linux/printk.h', 'linux/sched.h', 'asm/io.h', 'asm/msr.h']:
        headers[name] = ''
    for name, text in headers.items():
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    harness = tmp_path / 'canary.c'
    harness.write_text(f'#define MODE {mode}\n' + STUB + f'\n#include "{SOURCE}"\n' + r'''
int main(void) {
    hermetic_clock_canary(); /* no opt-in must do nothing */
    assert(!freed);
    canary_opt_in("nested-vm");
    hermetic_clock_canary();
    assert(!pinned);
    assert(freed == (MODE != 2));
    return 0;
}
''')
    binary = tmp_path / 'canary'
    compiled = subprocess.run(['cc', '-std=c11', '-I', str(tmp_path), str(harness), '-o', str(binary)],
                              capture_output=True, timeout=15)
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert len(lines) == 6
    assert lines[-2] == 'hermetic-canary/v1 hypercall=9 ret=enosys page=unchanged'
    assert lines[-1] == f'hermetic-canary/v1 result={"pass" if mode == 0 else "fail"}'
    for msr, line in zip(['00000011', '00000012', '4b564d00', '4b564d01'], lines):
        status = 'gp' if mode == 0 else 'accepted'
        assert line == f'hermetic-canary/v1 msr={msr} rd={status} wr={status} page=unchanged'
