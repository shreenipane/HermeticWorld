"""Apply the shipping patch to upstream inputs and validate its security wiring."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / 'fixtures/firecracker-filter/upstream-v1.18.0.json.gz'


def test_patch_applies_once_and_preserves_seccomp_rules(tmp_path):
    original = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    for name, source in original.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    patch = ROOT / 'vmm/firecracker-patches/0001-host-pv-clock-filter.patch'
    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                            cwd=tmp_path, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    lock = json.loads((ROOT / 'vmm/firecracker.lock.json').read_bytes())
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == lock['patch_sha256']
    policy_path = 'resources/seccomp/x86_64-unknown-linux-musl.json'
    before = json.loads(original[policy_path])
    after = json.loads((tmp_path / policy_path).read_text())
    assert after['vcpu'] == before['vcpu']
    assert after['api'] == before['api']
    old_rules = before['vmm']['filter']
    new_rules = after['vmm']['filter']
    assert new_rules[:len(old_rules)] == old_rules
    # Seccompiler's argument schema cannot accept nested syscall rules.
    additions = new_rules[len(old_rules):]
    assert len(additions) == 3
    assert {rule['args'][0]['val'] for rule in additions} == {0x4188aec6, 0x4038ae7a, 0x4068aea3}
    for rule in additions:
        assert rule['syscall'] == 'ioctl' and len(rule['args']) == 1
        arg = rule['args'][0]
        assert set(arg) == {'index', 'type', 'op', 'val', 'comment'}
        assert (arg['index'], arg['type'], arg['op']) == (1, 'dword', 'eq')
    arch = tmp_path / 'src/vmm/src/arch/x86_64'
    assert (arch / 'mod.rs').read_text().count('pub mod clock_filter;') == 1
    vm = (arch / 'vm.rs').read_text()
    assert vm.count('ClockFilter(kvm_ioctls::Error),') == 1
    assert vm.count('clock_filter::install(&common.fd)') == 1
    vcpu = (arch / 'vcpu.rs').read_text()
    assert vcpu.count('clock_filter::enforce_pv(&self.fd)') == 2  # boot and restore
    loop = (tmp_path / 'src/vmm/src/vstate/vcpu.rs').read_text()
    assert loop.count('Ok(VcpuExit::Unsupported(kvm_bindings::KVM_EXIT_XEN))') == 1


def test_cpu_identity_is_replaced_after_normalization_on_boot_and_restore(tmp_path):
    original = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    for name, source in original.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    patch = ROOT / 'vmm/firecracker-patches/0001-host-pv-clock-filter.patch'
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                   cwd=tmp_path, check=True, capture_output=True, timeout=10)
    arch = tmp_path / 'src/vmm/src/arch/x86_64'
    assert (arch / 'cpu_baseline.rs').read_bytes() == (ROOT / 'vmm/cpu-baseline.rs').read_bytes()
    vcpu = (arch / 'vcpu.rs').read_text()
    assert vcpu.index('cpuid.normalize(') < vcpu.index('clock_filter::sealed_cpuid(self.index, vcpu_count)') < vcpu.index('.set_cpuid2(&kvm_cpuid)')
    assert '.set_cpuid2(&state.cpuid)' not in vcpu
    assert 'clock_filter::restore_cpuid(&state.cpuid, self.index, state.tsc_khz)' in vcpu
    assert vcpu.count('clock_filter::fixed_tsc(&self.fd)') == 3
    vm = (arch / 'vm.rs').read_text()
    assert 'clock_filter::host_supported(&common.kvm.supported_cpuid)' in vm
    host = (arch / 'clock_filter.rs').read_text()
    assert 'vm.check_extension_int(Cap::TscControl) != 1' in host
    assert 'vcpu.set_tsc_khz(khz)' in host
    assert 'set(baseline::TSC_KHZ)?' in host
    assert 'vcpu.get_tsc_khz()' in host
    assert 'get()? != baseline::TSC_KHZ' in host


def test_filter_seccomp_ioctl_values_match_linux_uapi(tmp_path):
    # Compute the ABI from system headers, independently of patch constants.
    code = tmp_path / 'ioctls.c'
    code.write_text('''#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <stdio.h>
int main(void) {
    printf("%lu %lu %lu\\n", (unsigned long)KVM_X86_SET_MSR_FILTER,
           (unsigned long)KVM_XEN_HVM_CONFIG, (unsigned long)KVM_ENABLE_CAP);
    return 0;
}
''')
    binary = tmp_path / 'ioctls'
    subprocess.run(['cc', '-o', str(binary), str(code)], check=True, capture_output=True, timeout=30)
    actual = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=10)
    values = {int(value) for value in actual.stdout.split()}
    original = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    for name, source in original.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                    str(ROOT / 'vmm/firecracker-patches/0001-host-pv-clock-filter.patch')],
                   cwd=tmp_path, check=True, capture_output=True, timeout=10)
    policy_path = 'resources/seccomp/x86_64-unknown-linux-musl.json'
    before = json.loads(original[policy_path])['vmm']['filter']
    after = json.loads((tmp_path / policy_path).read_bytes())['vmm']['filter']
    assert {rule['args'][0]['val'] for rule in after[len(before):]} == values
