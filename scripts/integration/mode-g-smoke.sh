#!/usr/bin/env bash
# Nested VM evaluation smoke test for Mode G (TR-CLI, TR-GW, TR-NET-3, TR-EXT).
# Runs an end-to-end Mode G evaluation with a local fake model upstream and scripted agent.
# Run by the manager in the nested VM with /dev/kvm.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"

smoke_main() {
  WORK="${HERMETIC_SMOKE_WORK:?}"

  # 1. Resolve inputs with readlink -f as required
  FC="$(readlink -f "${HERMETIC_FC_BIN:?set HERMETIC_FC_BIN}")"
  FC_LOCK="$(readlink -f "${HERMETIC_FIRECRACKER_LOCK:?set HERMETIC_FIRECRACKER_LOCK}")"
  KERNEL="$(readlink -f "${HERMETIC_KERNEL:?set HERMETIC_KERNEL}")"

  export HERMETIC_FC_BIN="$FC"
  export HERMETIC_FIRECRACKER_LOCK="$FC_LOCK"
  export HERMETIC_KERNEL="$KERNEL"

  if [ -n "${HERMETIC_ROOTFS:-}" ]; then
    export HERMETIC_ROOTFS="$(readlink -f "$HERMETIC_ROOTFS")"
  fi

  # 2. Build release CLI
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/.review/cargo-target}"
  export CARGO_TARGET_DIR
  cargo build --release -q -p hermetic-cli
  CLI="$CARGO_TARGET_DIR/release/hermetic"

  # 3. Setup work directories with mode 0700
  RUN_DIR="$WORK/run"
  WORLD_DIR="$WORK/world"
  mkdir -m 0700 -p "$RUN_DIR" "$WORLD_DIR"

  # 4. Create fake upstream server (loopback only, never reaches any remote network)
  FAKE_PORT=18443
  FAKE_SERVER_PID=""
  cleanup_fake_server() {
    if [ -n "$FAKE_SERVER_PID" ]; then
      kill "$FAKE_SERVER_PID" 2>/dev/null || true
      wait "$FAKE_SERVER_PID" 2>/dev/null || true
    fi
  }
  trap cleanup_fake_server EXIT

  python3 -u -c '
import http.server
import json
import socketserver
import sys

class FakeHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        reply = {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "created": 1000000000,
            "model": "gpt-oss-test",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "ok"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15
            }
        }
        body = json.dumps(reply).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

port = int(sys.argv[1])
with socketserver.TCPServer(("127.0.0.1", port), FakeHandler) as httpd:
    httpd.serve_forever()
' "$FAKE_PORT" >/dev/null 2>&1 &
  FAKE_SERVER_PID=$!
  sleep 0.5

  # 5. Create fake API key file with strict mode 0600
  FAKE_KEY_FILE="$WORK/fake_upstream.key"
  echo "test-fake-key-secret-12345" > "$FAKE_KEY_FILE"
  chmod 0600 "$FAKE_KEY_FILE"

  # 6. Generate Ed25519 signing key pair for attestation
  SIGNING_KEY="$WORK/signing.pkcs8"
  PUB_KEY="$WORK/signing.pub"
  python3 -c '
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
key = ed25519.Ed25519PrivateKey.generate()
with open("'"$SIGNING_KEY"'", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("'"$PUB_KEY"'", "wb") as f:
    f.write(key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))
'
  chmod 0600 "$SIGNING_KEY"

  # 7. Prepare fixture world
  FIXTURE_SRC="$top/scripts/integration/fixtures/grader-task/repo"
  TASK_ID="mode-g-smoke-task"
  cp -r "$FIXTURE_SRC"/* "$WORLD_DIR/" 2>/dev/null || true

  # 8. Run Mode G evaluation flow
  echo "mode-g-smoke: running Mode G evaluation..."
  "$CLI" run \
    --world "$WORLD_DIR" \
    --task "$TASK_ID" \
    --mode g \
    --run-dir "$RUN_DIR" \
    --key "$SIGNING_KEY" \
    --out "$WORK/record.json" \
    --model "gpt-oss-test" \
    --upstream-url "http://127.0.0.1:$FAKE_PORT/v1" \
    --upstream-key-file "$FAKE_KEY_FILE"

  # 9. Verify record was signed and verifies against public key
  echo "mode-g-smoke: verifying signed attestation..."
  "$CLI" verify \
    --record "$WORK/record.json" \
    --key "$PUB_KEY"

  echo "mode-g-smoke: ok"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/mode-g-smoke.sh" "$@"
fi
