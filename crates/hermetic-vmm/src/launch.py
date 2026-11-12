# Isolated stdlib-only exec trampoline; receives no guest-controlled source code.
# Safe Rust cannot close arbitrary inherited raw descriptors before exec.
import os
import resource
import sys

MAX_FDS = 1048576
MAX_OPEN_DESCRIPTORS = 4096
try:
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if maximum == resource.RLIM_INFINITY or maximum > MAX_FDS:
        raise ValueError()
    executable = os.open(sys.argv[1], os.O_RDONLY | os.O_CLOEXEC)
    identity = os.fstat(executable)
    if (identity.st_dev, identity.st_ino) != (int(sys.argv[2]), int(sys.argv[3])):
        raise ValueError()
    # Existing descriptors can exceed a subsequently lowered rlimit.
    with os.scandir("/proc/self/fd") as entries:
        for count, entry in enumerate(entries, 1):
            if count > MAX_OPEN_DESCRIPTORS or int(entry.name) >= MAX_FDS:
                raise ValueError()
    resource.setrlimit(resource.RLIMIT_FSIZE, (int(sys.argv[4]), int(sys.argv[4])))
    resource.setrlimit(resource.RLIMIT_NOFILE, (int(sys.argv[5]), int(sys.argv[5])))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.closerange(3, executable)
    os.closerange(executable + 1, MAX_FDS)
    os.execve(executable, sys.argv[6:], {})
except BaseException:
    os.write(2, b"VM launcher refused execution\n")
    os._exit(1)
