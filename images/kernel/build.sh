#!/bin/bash
# T3.2: fixed container entrypoint. No ambient build variables are accepted.
set -euo pipefail
umask 022
exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC HOME=/build \
    /usr/bin/python3 -I -B /inputs/guest_kernel.py
