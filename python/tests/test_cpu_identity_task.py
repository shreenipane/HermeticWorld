import json
from pathlib import Path

import pytest
from hermetic_slice import guest_kernel as k

ROOT = Path(__file__).resolve().parents[2]
APPROVED = '29ad57ab16edc3ddcb8b44de77061336a4cabc6812243bedac48e815529da238'


def test_kernel_builder_requires_the_approved_digest():
    lock = json.loads((ROOT / 'images/kernel/kernel.lock.json').read_bytes())
    assert lock['builder_image'] == 'hermetic/kernel-builder:6.6-v1@sha256:' + APPROVED
    assert k.validate_lock(lock, for_build=True) == lock
    assert k.docker_arguments(lock, Path('/private/in'), Path('/private/out'))[-2] == 'sha256:' + APPROVED
    for image in ['sha256:' + 'a' * 64, 'hermetic/kernel-builder:6.6-v1@sha256:' + k.PLACEHOLDER]:
        for building in (False, True):
            with pytest.raises(k.KernelError):
                k.validate_lock({**lock, 'builder_image': image}, for_build=building)


def test_unapproved_local_builder_is_refused_before_kernel_build(tmp_path, monkeypatch):
    source = tmp_path / 'source.tar.xz'
    source.write_bytes(b'source')
    import hashlib
    kernel = tmp_path / 'inputs'
    kernel.mkdir()
    lock = k.load_lock(ROOT / 'images/kernel/kernel.lock.json')
    lock['sha256'] = hashlib.sha256(b'source').hexdigest()
    (kernel / 'kernel.lock.json').write_text(json.dumps(lock))
    for name in ('Dockerfile', 'build.sh', 'base-x86_64.config', 'hermetic.config'):
        (kernel / name).write_bytes((ROOT / 'images/kernel' / name).read_bytes())
    monkeypatch.setattr(k, 'DEFAULT_KERNEL_DIR', kernel)
    def build_image(argv, **kwargs):
        Path(argv[argv.index('--iidfile') + 1]).write_text('sha256:' + 'a' * 64)
    monkeypatch.setattr(k, '_run', build_image)
    monkeypatch.setattr(k, 'build_kernel', lambda *args, **kwargs: pytest.fail('unapproved builder used'))
    output = tmp_path / 'output'
    with pytest.raises(k.KernelError, match='builder_image'):
        k.integration_build(source, output)
    assert list(output.iterdir()) == []
