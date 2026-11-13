
# hermetic-grader-sandbox

Pure data planner for executing pytest suites inside the Hermetic World grader VM (`TR-GR-3`, `TR-GR-4`).

## Guarantees
- `#![forbid(unsafe_code)]`, zero syscalls, zero host environment or clock reads.
- Strips `CAP_MKNOD` and all administrative capabilities from Docker's default set; forces `no_new_privileges = true` and empty `inheritable` and `ambient` sets.
- Enables new PID, mount, IPC, UTS, and empty network namespaces while keeping user namespaces disabled (documenting why the hypervisor VM boundary is used instead).
- Emits exact device nodes (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`), `/dev/pts`, `/dev/shm`, and ordered cgroup v2 BPF device rules.
- Rewrites validated pytest invocations to `python -s -m pytest -p <plugin> ...` with deterministic sorted plugins and a sealed environment.


