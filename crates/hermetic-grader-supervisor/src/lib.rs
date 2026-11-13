#![forbid(unsafe_code)]

//! Hermetic World grader supervisor library.
//!
//! Runs untrusted benchmark test suites behind an abstract [`os::Os`] boundary,
//! decodes the strict `HGR1` per-test record stream, enforces bounded reads,
//! counts, loops, and deadlines, waits for the entire child process tree to
//! terminate, and atomically writes a deterministic 1 MiB `HGRD` result disk.

pub mod disk;
pub mod os;
pub mod records;
pub mod run;

pub use disk::{
    canonical_payload_json, decode_result_disk, encode_result_disk, DiskError, FinalTestOutcome,
    ResultPayload, RunName, SupervisorExit, SupervisorSummary, MAX_RESULT_PAYLOAD_BYTES,
    RESULT_DISK_BYTES, RESULT_DISK_FLAGS, RESULT_DISK_HEADER_BYTES, RESULT_DISK_MAGIC,
    RESULT_DISK_VERSION,
};
pub use os::{
    ExitKind, FakeChildScript, FakeOs, FakeStep, Os, OsError, OsEvent, PipeRead, RealOs, SpawnSpec,
    TreeStatus, MAX_FILE_READ_BYTES, MAX_PIPE_CHUNK_BYTES, MAX_READ_STEPS, POLL_INTERVAL_MS,
    REAL_OS_PIPE_CHANNEL_BOUND,
};
pub use records::{
    DecodedRecord, EndRecord, FinishRecord, RecordDecoder, RecordEncoder, RecordError,
    RecordOutcome, RecordType, StartRecord, MAX_NODEID_BYTES, MAX_RECORDS_PER_STREAM,
    MAX_RECORD_PAYLOAD_BYTES, MAX_STREAM_BUFFER_BYTES, RECORD_HEADER_BYTES, STREAM_MAGIC,
};
pub use run::{
    run_supervisor, ConfigError, RunConfig, RunReport, SupervisorError, KILL_GRACE_SECONDS,
    MAX_ARGV_ITEMS, MAX_ARG_BYTES, MAX_CONFIG_BYTES, MAX_CWD_BYTES, MAX_DEADLINE_SECONDS,
    MAX_ENV_ENTRY_BYTES, MAX_ENV_VARS, MAX_EXPECTED_TESTS, MAX_SUPERVISOR_ITERATIONS,
    POLL_SLICE_MS,
};
