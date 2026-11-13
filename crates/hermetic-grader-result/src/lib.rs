#![forbid(unsafe_code)]

pub mod disk;
pub mod verdict;

pub use disk::{
    encode_disk, parse_disk_bytes, read_bounded_regular_file, read_disk, sha256_bytes, sha256_hex,
    validate_run_result, write_disk, DiskError, InvalidFileType, RunId, RunResult, SupervisorExit,
    SupervisorSummary, TamperReason, TestStatus, DISK_BYTES, FORMAT_VERSION, HEADER_BYTES, MAGIC,
    MAX_NODE_ID_BYTES, MAX_TESTS, PAYLOAD_CAP, SHA256_BYTES, SHA256_HEX_LEN,
};
pub use verdict::{
    verdict, GradingPlan, RunMetrics, Verdict, VerdictStatus, MAX_EQUIVALENT_PAIRS, MAX_PLAN_BYTES,
    MAX_PLAN_TESTS,
};
