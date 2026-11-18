#![forbid(unsafe_code)]

mod support;

use hermetic_world_server::{DirStore, Store};
use std::path::Path;
use std::process::Command;

#[test]
fn offline_mirror_is_served_by_dirstore_and_excluded_routes_miss() {
    let temp = support::private_tempdir().expect("private fixture directory");
    let python_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../python");
    let script = r#"
import hashlib, json, pathlib, sys
from hermetic_ecosystem_cut.mirror import build_mirror_files

root = pathlib.Path(sys.argv[1])
blob_root = root / 'blobs'
blob_root.mkdir()
encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def blob(body):
    digest = hashlib.sha256(body).hexdigest()
    (blob_root / digest).write_bytes(body)
    return digest
body = b'offline artifact'
digest = blob(body)
cutoff = '2023-04-01T00:00:00Z'
future = '2024-01-01T00:00:00Z'
packages = []
records = [dict(name='demo', vers=version, deps=[], features={}, cksum=digest,
                yanked=False, pubtime=date)
           for version, date in [('1.0.0', cutoff), ('2.0.0', future)]]
packages.append(dict(ecosystem='crates', name='demo',
    metadata=blob(b'\n'.join(encode(row) for row in records)), artifacts={'1.0.0': digest}))
packages.append(dict(ecosystem='go', name='example.org/demo',
    metadata=blob(b'v1.0.0\nv2.0.0\n'),
    infos={version: blob(encode(dict(Version=version, Time=date)))
           for version, date in [('v1.0.0', cutoff), ('v2.0.0', future)]},
    artifacts={'v1.0.0.mod': digest, 'v1.0.0.zip': digest}))
packages.append(dict(ecosystem='npm', name='demo', metadata=blob(encode(dict(
    name='demo', time={'1.0.0': cutoff, '2.0.0': future}, versions={
        version: dict(name='demo', version=version, dist={'shasum': hashlib.sha1(body).hexdigest()})
        for version in ['1.0.0', '2.0.0']}))), artifacts={'1.0.0': digest}))
packages.append(dict(ecosystem='pypi-simple', name='demo', metadata=blob(encode({
    'meta': {'api-version': '1.1'}, 'name': 'demo', 'files': [
        {'filename': 'demo-' + version + '.tar.gz', 'hashes': {'sha256': digest},
         'size': len(body), 'upload-time': date}
        for version, date in [('1.0.0', cutoff), ('2.0.0', future)]]})),
    artifacts={'demo-1.0.0.tar.gz': digest}))
recipe = root / 'recipe.json'
recipe.write_bytes(encode(dict(cutoff=cutoff, packages=packages)))
build_mirror_files(recipe, blob_root, root / 'world')
print(digest)
"#;
    let output = support::output_bounded(
        Command::new("python3")
            .args(["-c", script])
            .arg(temp.path())
            .env("PYTHONPATH", python_root)
            .env("PYTHONDONTWRITEBYTECODE", "1"),
    );
    assert!(output.status.success(), "offline fixture build failed");
    let digest = String::from_utf8(output.stdout).expect("digest UTF-8");
    let digest = digest.trim();
    let store = DirStore::new(temp.path().join("world/store"));
    let artifact_paths = [
        ("static.crates.io", "/crates/demo/demo-1.0.0.crate"),
        ("proxy.golang.org", "/example.org/demo/@v/v1.0.0.zip"),
        ("registry.npmjs.org", "/demo/-/demo-1.0.0.tgz"),
    ];
    for (authority, path) in artifact_paths {
        assert_eq!(
            store.get(authority, path).expect("admitted download").body,
            b"offline artifact"
        );
        assert!(store
            .get(authority, &path.replace("1.0.0", "2.0.0"))
            .is_none());
    }
    let pypi_path = format!("/files/{digest}/demo-1.0.0.tar.gz");
    assert_eq!(
        store
            .get("pypi.org", &pypi_path)
            .expect("PyPI download")
            .body,
        b"offline artifact"
    );
    assert!(store
        .get("pypi.org", &pypi_path.replace("1.0.0", "2.0.0"))
        .is_none());
    for (authority, path, content_type) in [
        ("index.crates.io", "/de/mo/demo", "text/plain"),
        ("registry.npmjs.org", "/demo", "application/json"),
        ("registry.npmjs.org", "/demo/1.0.0", "application/json"),
        (
            "proxy.golang.org",
            "/example.org/demo/@latest",
            "application/json",
        ),
        ("pypi.org", "/simple/demo/", "text/html"),
    ] {
        let object = store.get(authority, path).expect("admitted metadata");
        assert_eq!(object.content_type.as_deref(), Some(content_type));
        assert!(!object.body.windows(5).any(|window| window == b"2.0.0"));
    }
    for authority in [
        "pypi.org",
        "index.crates.io",
        "registry.npmjs.org",
        "proxy.golang.org",
    ] {
        for path in ["/manifest.json", "/reports.json", "/../reports.json"] {
            assert!(store.get(authority, path).is_none());
        }
    }
    assert!(store.get("registry.npmjs.org", "/demo/2.0.0").is_none());
    assert!(store
        .get("proxy.golang.org", "/example.org/demo/@v/v2.0.0.info")
        .is_none());
}

#[test]
fn test_offline_mirrors_phase2_pypi_conda_apt_git() {
    let temp = support::private_tempdir().expect("private fixture directory");
    let python_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../python");
    let script = r#"
import hashlib, json, pathlib, sys
from hermetic_ecosystem_cut.mirror import build_mirror_files

root = pathlib.Path(sys.argv[1])
blob_root = root / 'blobs'
blob_root.mkdir()
encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def blob(body):
    digest = hashlib.sha256(body).hexdigest()
    (blob_root / digest).write_bytes(body)
    return digest

body = b'offline pkg artifact'
digest = blob(body)
cutoff = '2023-04-01T00:00:00Z'
cutoff_ms = 1680307200000
future_ms = 1704067200000
future_date = '2024-01-01T00:00:00Z'

packages = []

# 1. PyPI
packages.append({
    'ecosystem': 'pypi-simple',
    'name': 'demo-pkg',
    'metadata': blob(encode({
        'meta': {'api-version': '1.1'},
        'name': 'demo-pkg',
        'files': [
            {'filename': 'demo_pkg-1.0.0.tar.gz', 'hashes': {'sha256': digest}, 'size': len(body), 'upload-time': cutoff},
            {'filename': 'demo_pkg-2.0.0.tar.gz', 'hashes': {'sha256': digest}, 'size': len(body), 'upload-time': future_date},
        ]
    })),
    'artifacts': {'demo_pkg-1.0.0.tar.gz': digest}
})

# 2. Conda
packages.append({
    'ecosystem': 'conda',
    'name': 'conda.anaconda.org/conda-forge/linux-64',
    'metadata': blob(encode({
        'info': {'subdir': 'linux-64'},
        'repodata_version': 1,
        'packages': {
            'demo-1.0.0.tar.bz2': {'name': 'demo', 'version': '1.0.0', 'build': '0', 'timestamp': cutoff_ms, 'sha256': digest},
            'demo-2.0.0.tar.bz2': {'name': 'demo', 'version': '2.0.0', 'build': '0', 'timestamp': future_ms, 'sha256': digest},
        },
        'packages.conda': {}
    })),
    'artifacts': {'demo-1.0.0.tar.bz2': digest}
})

# 3. Apt (Ubuntu and Debian)
packages.append({
    'ecosystem': 'apt',
    'name': 'snapshot.ubuntu.com/ubuntu/20230301T000000Z',
    'metadata': blob(encode({
        'dist': 'ubuntu',
        'suite': 'jammy',
        'snapshot_id': '20230301T000000Z',
        'files': {
            'dists/jammy/InRelease': {'sha256': digest, 'content_type': 'text/plain'},
            'pool/main/d/demo/demo_1.0.0_amd64.deb': {'sha256': digest, 'content_type': 'application/vnd.debian.binary-package'}
        }
    })),
    'artifacts': {
        'dists/jammy/InRelease': digest,
        'pool/main/d/demo/demo_1.0.0_amd64.deb': digest
    }
})

packages.append({
    'ecosystem': 'apt',
    'name': 'snapshot.debian.org/archive/debian/20230301T000000Z',
    'metadata': blob(encode({
        'dist': 'debian',
        'suite': 'bookworm',
        'snapshot_id': '20230301T000000Z',
        'files': {
            'dists/bookworm/Release': {'sha256': digest, 'content_type': 'text/plain'},
            'pool/main/d/demo/demo_1.0.0_amd64.deb': {'sha256': digest, 'content_type': 'application/vnd.debian.binary-package'}
        }
    })),
    'artifacts': {
        'dists/bookworm/Release': digest,
        'pool/main/d/demo/demo_1.0.0_amd64.deb': digest
    }
})

# 4. Git static mirror (dumb HTTP)
packages.append({
    'ecosystem': 'git',
    'name': 'github.com/example/demo.git',
    'metadata': blob(b'1111111111111111111111111111111111111111\trefs/heads/main\n'),
    'artifacts': {
        'HEAD': blob(b'ref: refs/heads/main\n'),
        'info/refs': blob(b'1111111111111111111111111111111111111111\trefs/heads/main\n'),
        'objects/info/packs': blob(b'P pack-1111111111111111111111111111111111111111.pack\n'),
        'objects/pack/pack-1111111111111111111111111111111111111111.pack': digest,
        'objects/pack/pack-1111111111111111111111111111111111111111.idx': digest,
    }
})

recipe = root / 'recipe.json'
recipe.write_bytes(encode(dict(cutoff=cutoff, packages=packages)))
build_mirror_files(recipe, blob_root, root / 'world')
print(digest)
"#;
    let output = support::output_bounded(
        Command::new("python3")
            .args(["-c", script])
            .arg(temp.path())
            .env("PYTHONPATH", python_root)
            .env("PYTHONDONTWRITEBYTECODE", "1"),
    );
    assert!(
        output.status.success(),
        "phase2 offline fixture build failed: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let digest = String::from_utf8(output.stdout).expect("digest UTF-8");
    let digest = digest.trim();
    let store = DirStore::new(temp.path().join("world/store"));

    // 1. PyPI served by WorldServer
    let pypi_file = format!("/files/{digest}/demo_pkg-1.0.0.tar.gz");
    assert_eq!(
        store.get("pypi.org", &pypi_file).expect("pypi wheel").body,
        b"offline pkg artifact"
    );
    assert!(store
        .get("pypi.org", &pypi_file.replace("1.0.0", "2.0.0"))
        .is_none());
    let pypi_index = store
        .get("pypi.org", "/simple/demo-pkg/index.html")
        .expect("pypi index");
    assert_eq!(pypi_index.content_type.as_deref(), Some("text/html"));
    assert!(pypi_index.body.windows(5).any(|w| w == b"1.0.0"));
    assert!(!pypi_index.body.windows(5).any(|w| w == b"2.0.0"));

    // 2. Conda served by WorldServer
    let conda_repodata = store
        .get("conda.anaconda.org", "/conda-forge/linux-64/repodata.json")
        .expect("conda repodata");
    assert_eq!(
        conda_repodata.content_type.as_deref(),
        Some("application/json")
    );
    assert!(conda_repodata.body.windows(5).any(|w| w == b"1.0.0"));
    assert!(!conda_repodata.body.windows(5).any(|w| w == b"2.0.0"));
    assert_eq!(
        store
            .get(
                "conda.anaconda.org",
                "/conda-forge/linux-64/demo-1.0.0.tar.bz2"
            )
            .expect("conda package")
            .body,
        b"offline pkg artifact"
    );
    assert!(store
        .get(
            "conda.anaconda.org",
            "/conda-forge/linux-64/demo-2.0.0.tar.bz2"
        )
        .is_none());

    // 3. Apt (Ubuntu & Debian) served by WorldServer
    let ub_inrelease = store
        .get(
            "snapshot.ubuntu.com",
            "/ubuntu/20230301T000000Z/dists/jammy/InRelease",
        )
        .expect("ubuntu InRelease");
    assert_eq!(ub_inrelease.content_type.as_deref(), Some("text/plain"));
    let ub_deb = store
        .get(
            "snapshot.ubuntu.com",
            "/ubuntu/20230301T000000Z/pool/main/d/demo/demo_1.0.0_amd64.deb",
        )
        .expect("ubuntu deb");
    assert_eq!(
        ub_deb.content_type.as_deref(),
        Some("application/vnd.debian.binary-package")
    );
    assert_eq!(ub_deb.body, b"offline pkg artifact");

    let deb_release = store
        .get(
            "snapshot.debian.org",
            "/archive/debian/20230301T000000Z/dists/bookworm/Release",
        )
        .expect("debian Release");
    assert_eq!(deb_release.content_type.as_deref(), Some("text/plain"));
    let deb_deb = store
        .get(
            "snapshot.debian.org",
            "/archive/debian/20230301T000000Z/pool/main/d/demo/demo_1.0.0_amd64.deb",
        )
        .expect("debian deb");
    assert_eq!(
        deb_deb.content_type.as_deref(),
        Some("application/vnd.debian.binary-package")
    );

    // Excluded or non-existent apt files miss cleanly
    assert!(store
        .get(
            "snapshot.ubuntu.com",
            "/ubuntu/20230301T000000Z/pool/main/d/demo/missing.deb"
        )
        .is_none());

    // 4. Git static mirror (dumb HTTP) served by WorldServer
    let git_head = store
        .get("github.com", "/example/demo.git/HEAD")
        .expect("git HEAD");
    assert_eq!(git_head.content_type.as_deref(), Some("text/plain"));
    assert_eq!(git_head.body, b"ref: refs/heads/main\n");

    let git_refs = store
        .get("github.com", "/example/demo.git/info/refs")
        .expect("git info/refs");
    assert_eq!(git_refs.content_type.as_deref(), Some("text/plain"));
    assert!(git_refs
        .body
        .starts_with(b"1111111111111111111111111111111111111111"));

    let git_packs = store
        .get("github.com", "/example/demo.git/objects/info/packs")
        .expect("git objects/info/packs");
    assert_eq!(git_packs.content_type.as_deref(), Some("text/plain"));

    let git_pack = store
        .get(
            "github.com",
            "/example/demo.git/objects/pack/pack-1111111111111111111111111111111111111111.pack",
        )
        .expect("git packfile");
    assert_eq!(
        git_pack.content_type.as_deref(),
        Some("application/x-git-packed-objects")
    );
    assert_eq!(git_pack.body, b"offline pkg artifact");

    let git_idx = store
        .get(
            "github.com",
            "/example/demo.git/objects/pack/pack-1111111111111111111111111111111111111111.idx",
        )
        .expect("git pack idx");
    assert_eq!(
        git_idx.content_type.as_deref(),
        Some("application/x-git-packed-objects-toc")
    );
    assert_eq!(git_idx.body, b"offline pkg artifact");

    // Traversal or missing routes miss
    assert!(store
        .get("github.com", "/example/demo.git/../demo.git/HEAD")
        .is_none());
    assert!(store
        .get("github.com", "/example/demo.git/objects/missing")
        .is_none());
}
