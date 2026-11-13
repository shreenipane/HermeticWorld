# Mode H host harness

The harness runs outside AgentVM. Every action goes to execd over Firecracker's
Unix vsock socket, port 5000. Model requests go only to an explicit numeric
loopback hermetic-gateway endpoint. Neither the guest nor this package reads a
provider key. The sealing pipeline has no dependency on this package's extras.

Install on the staging host with `pip install './python/hermetic_agent[mini]'`.
The optional dependency is exactly **mini-swe-agent 1.17.4**, MIT. The inspected
[released wheel](https://files.pythonhosted.org/packages/de/11/34b8223f13e7b5344945f04ed97f327b89a1cfa56cc7e805393b5087d113/mini_swe_agent-1.17.4-py3-none-any.whl)
has SHA-256 `a8df18447d51210007420588512355013aaaecb95001727f3cb86d9847ff85c8`.
Its `minisweagent/__init__.py` defines Environment.execute(command, cwd) and
get_template_vars, and Model.query(messages), config, cost, n_calls and
get_template_vars. `ExecdEnvironment.execute` additionally supports a bounded
keyword timeout. `runner.run` subclasses the actual release's DefaultAgent;
it replaces add_message's host timestamp with the manifest's T_clock and bounds
history, steps and elapsed time. Global dotenv configuration is replaced with
an empty file in a fresh private directory before importing the optional agent.
The model, tokenizer, Hub and telemetry integrations are never imported.

`swebench.json` contains the release's SWE-bench agent templates, with the world
clock added, the working directory supplied by the task, and submission reduced
to its sentinel command. The upstream MIT notice is in `MINI_LICENSE.txt`.
The single tool is the release's fenced bash text protocol. There are no local
shell or file tools. An observation always comes from execd. Commands use bash
without startup files; cwd changes are shell quoted. Task inputs, output files,
commands and responses are validated before execution. Every command must first
be recorded in an atomic 0600 journal. RPC transport errors contain fixed text.

```sh
mkdir -m 0700 run-config
PYTHONPATH=python python -m hermetic_agent \
  --manifest world.json --task issue.txt --vsock /run/world/vsock \
  --cwd /testbed --config-dir run-config --trajectory trajectory.json \
  --command-log commands.jsonl --gateway http://127.0.0.1:8080 --model PINNED
```

The manifest must supply `cutoffs.t_clock`, a UTC RFC3339 second. There is no
clock fallback. The gateway must pin the requested model and receive the same
manifest clock. `--script commands.json` replaces `--gateway` for offline smoke
runs. Each script is a finite list of bash commands; exhaustion fails the run.

Caps are named in `protocol.py`, `model.py`, `runner.py` and `journal.py`:
execd frames 4 MiB + 64 KiB, observations 64 KiB, run output 16 MiB, gateway
responses 4 MiB, history 8 MiB, journals 16 MiB, at most 250 steps, and a
5400-second run deadline. A command timeout is at most 300 seconds. Each
transport has an absolute deadline, including slow headers and partial frames.
`wire-vectors.json` is asserted against Rust's real execd encoder and consumed
by the Python tests; these are execd's u32-LE JSON frames, distinct from the
WorldServer HTTP frames in hermetic-common.

## Offline checks and owner-run VM smoke

`python/tests/test_hermetic_agent.py` uses local fake execd and gateway servers.
Its optional real-runner test runs when the pinned harness extra is installed;
the adapter tests require only the standard library and pytest. Gateway tests
in `test_openai_adapter.rs` use a local fake upstream and a fake 0600 key.

`bash scripts/integration/agent-h-smoke.sh FRESH_WORK_DIR` boots a development
AgentVM with no network, runs the real harness with a scripted command source,
edits calc.py, collects untrusted HEXT through execd, destroys the VM, validates
the stream against the sealed fixture, and invokes the existing clean GraderVM
smoke for empty and submitted trees. It performs no provider call. It requires:

- `HERMETIC_FC_BIN`, `HERMETIC_KERNEL`: staged pinned Firecracker and kernel.
- `HERMETIC_AGENT_PYTHON`: interpreter with the pinned optional extra installed.
- `HERMETIC_ROOTFS`: a D4-checked fixture AgentVM image containing the trusted
  execd/init binaries, `/bin/bash` and its runtime, cat, sed, and the static
  `/sbin/hermetic-extract-agent`. `/testbed` and `/smoke/base` must both contain
  exactly `scripts/integration/fixtures/grader-task/repo`. Its run spec uses
  `/testbed` and a PATH containing the supplied shell utilities. This image is
  an input, like the other owner-run VM tests; the script never downloads one.
- `HERMETIC_AGENT_MANIFEST`: that fixture's world manifest. The existing grader
  fixture uses `2023-11-14T22:13:20Z`; the agent clock is read from the manifest.
- The same local Docker image, grader runtime, pytest packages and e2fsprogs as
  `grader-vm-smoke.sh`. The harness script does not need NetVM for this fixture.

The KVM smoke is an explicit ignored test and must be run by the manager on the
prepared VM host. A missing input fails; it cannot produce a successful skip.

## Open protocol decision: requests/httpbin

The httpbin requirement remains open. At requests base commit
`091991be0da19de9108dbe5e3752917fea3d7fdc`, test_requests.py uses POST, PUT,
DELETE, arbitrary request headers, cookies, auth, uploads and redirects.
`hermetic_common::RequestFrame` transports only GET/HEAD, authority, path/query
and byte ranges. It carries neither headers nor a body; NetVM enforces that
surface. A stand-in behind it cannot implement those tests. A protocol-version
and ingress-policy decision is required before extending it, including body
caps, header allowlists and deterministic state. No httpbin service is advertised
in a manifest until it is actually reachable through the sealed network.
