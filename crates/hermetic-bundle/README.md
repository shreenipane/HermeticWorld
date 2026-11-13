# hermetic-bundle

Deterministic sealing and third-party verification for Hermetic World directory bundles.

## 1. Bundle Layout and Manifest Schema

A sealed bundle is a directory tree containing a canonical UTF-8 JSON file named `bundle.manifest.json` at the bundle root. The manifest file itself is never listed as an entry inside `entries`.

Canonical manifest JSON format (compact UTF-8 JSON with no extra whitespace, fields in exact schema declaration order):

```json
{"format":"hermetic-bundle/v1","entries":[...],"root":"sha256:<64-char-lowercase-hex>"}
```

Each element of `entries` is ordered lexicographically by the raw UTF-8 bytes of its `path` field (`path_a.as_bytes() < path_b.as_bytes()`) and serialized in compact UTF-8 JSON with keys in exact declaration order:

* Regular file entry:
```json
{"path":"<relative-path>","kind":"file","mode":"0644"|"0755","size":<u64>,"sha256":"<64-char-lowercase-hex>"}
```
* Directory entry:
```json
{"path":"<relative-path>","kind":"dir","mode":"0755"}
```

Mode normalization:
* Regular files receive `"0755"` if any POSIX execute bit (`mode & 0o111 != 0`) is set, and `"0644"` otherwise.
* Directories always receive `"0755"`.

## 2. Path and Object Rules

* Paths are relative to the bundle root, valid UTF-8, separated by `/`.
* Empty paths, leading or trailing `/`, empty components (`//`), `.`, `..`, NUL bytes, and `\` are refused.
* NFC Unicode normalization is not required, but any two paths in the bundle that differ only in ASCII case (`to_ascii_lowercase()`) are refused. The root manifest name also participates in this rule and cannot be used as a directory prefix.
* Symlinks, hard-linked regular files (`st_nlink > 1`), FIFOs, sockets, block devices, and character devices are refused.
* Bounded caps:
  * `MAX_ENTRIES` = 1,000,000
  * `MAX_PATH_BYTES` = 4,096
  * `MAX_COMPONENT_BYTES` = 255
  * `MAX_DEPTH` = 128
  * `MAX_TOTAL_FILE_BYTES` = 64 GiB (68,719,476,736 bytes)
  * `MAX_MANIFEST_BYTES` = 512 MiB (536,870,912 bytes)
  * `MAX_JSON_STRING_BYTES` = 4,096 decoded bytes; `MAX_JSON_OBJECT_KEYS` = 6
  * `MAX_ROOT_PATH_BYTES` = 8,192; `MAX_ROOT_COMPONENTS` = 4,096

Parsing checks string lengths and array/object counts before schema deserialization.
Noncanonical encodings (including extra whitespace, reordered fields, and null
file fields on directories) are refused. Every entry's parent must be a listed
directory. Serialization checks the byte cap while writing.

Filesystem operations use Linux x86_64 flags and require a trusted procfs at
`/proc/self/fd`. Root components and child directories are opened with
`O_DIRECTORY | O_NOFOLLOW` after lstat, then checked by descriptor identity.
Enumeration and child lookups use those pinned descriptors. Pending siblings
share parent handles, bounding distinct directory handles by the active depth.
Regular files are pinned with `O_PATH | O_NOFOLLOW`, checked for type and identity,
then opened through their pinned descriptor; a substituted FIFO cannot block and
a substituted device is never opened for data. Files are checked again after
hashing for changes in identity, size, mode, link count, and modification metadata.
The excluded manifest is still checked for refused object types before sealing.
Manifest reads, temporary creation, rename, and directory fsync all use the same
root handle, so replacing the root pathname cannot redirect them.

Sealing and verification are not filesystem snapshots. An actor able to write
the tree concurrently can change an already inspected entry or replace a named
temporary file before publication. The caller must exclude concurrent writers
while sealing or verifying, including privileged writers; enforcing that ownership
boundary belongs to the caller. Detected changes fail closed, but metadata checks
cannot provide snapshot isolation.

## 3. Root Hash Definition

Let $E = [e_0, e_1, \ldots, e_{n-1}]$ be the manifest entries sorted in strictly ascending order of $e_i.\text{path.as\_bytes}()$.

For each entry $e_i$, let $C(e_i)$ be the canonical compact UTF-8 JSON byte string of $e_i$ as defined in Section 1, and let $H(e_i) = \text{SHA-256}(C(e_i))$ be its 32-byte raw SHA-256 digest.

The bundle root digest is defined as:

$$\text{root} = \text{"sha256:"} \parallel \text{lowercase\_hex}(\text{SHA-256}(H(e_0) \parallel H(e_1) \parallel \ldots \parallel H(e_{n-1})))$$

where $\parallel$ denotes byte concatenation. For an empty bundle ($n = 0$), SHA-256 of the empty byte string is taken, yielding:

`sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

For a bundle containing regular file `a.txt` (`"abc"`, mode `0644`) and directory `sub` (mode `0755`):
* `C(e_0)`: `{"path":"a.txt","kind":"file","mode":"0644","size":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}`
* `C(e_1)`: `{"path":"sub","kind":"dir","mode":"0755"}`
* `root`: `sha256:3f4874b7911d5aaafcd47fb763d4ff38e7fc17abe8b6c4e8724a6b8b0bb9af53`

## 4. CLI Usage

* Seal a directory and print its root hash:
```sh
hermetic-bundle seal DIR
```
* Verify a directory against its `bundle.manifest.json` (and optional expected root) and print the JSON report:
```sh
hermetic-bundle verify DIR [--root sha256:HEX]
```

Exit codes:
* `0`: success / verdict `"ok"`
* `2`: verification completed with verdict `"mismatch"`
* `1`: error (invalid arguments, I/O failure, refused object during seal, or malformed manifest)
