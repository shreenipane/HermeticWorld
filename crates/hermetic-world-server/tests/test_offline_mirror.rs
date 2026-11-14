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
