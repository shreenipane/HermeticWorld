# hermetic_pkgrec

Layer 1 recording index proxy and frozen world-root generator for Hermetic World.

## Overview

`hermetic_pkgrec` implements requirements TR-PKG-1 and TR-PKG-2:
1. Sits between package resolvers (`uv`, `pip`) and an upstream simple index during setup and oracle runs.
2. Honours the package cutoff $T_{\text{pkg}}$:
   - Evaluates PEP 700 `upload-time` against $T_{\text{pkg}}$. Files with `upload-time <= T_pkg` are served; files with `upload-time > T_pkg` are dropped. Files without upload-time are refused and listed.
   - Evaluates yank status per TR-PKG-2 and `hermetic_yank`: releases yanked after the cutoff are served as not yanked; releases with an unknown yank date are served as not yanked and listed.
3. Content-addressed storage: saves fetched files verified against index SHA-256 into a directory structure compatible with `hermetic_pkgindex`.
4. Canonical JSON manifest: records `(project, filename, sha256, upload-time, yank_decision)` deterministically.
5. Freeze command: compiles the recorded task closure into a frozen root that `hermetic_pkgindex` can serve. 404 misses are redirected to a misses file and never added to a frozen root (TR-PKG-6).

## CLI Usage

### Recording Proxy

```bash
python -m hermetic_pkgrec record \
  --cutoff 2023-01-01T00:00:00Z \
  --upstream https://pypi.org/simple/ \
  --store /path/to/store \
  --manifest /path/to/manifest.json \
  --listen 127.0.0.1:8080
```

### Freezing Recorded World

```bash
python -m hermetic_pkgrec freeze \
  --store /path/to/store \
  --manifest /path/to/manifest.json \
  --out /path/to/frozen_root
```
