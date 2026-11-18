//! `hermetic-cli run` must fail closed until real microVM orchestration is wired:
//! it may never fabricate VM, extraction or grading results.

use hermetic_cli::args::{AgentMode, ClockMode, RunRequest};
use hermetic_cli::backend::RUN_NOT_WIRED;
use hermetic_cli::dispatch::BackendError;

fn request(world: std::path::PathBuf, run_dir: std::path::PathBuf, mode: AgentMode) -> RunRequest {
    RunRequest {
        world,
        task: "fixture-task".into(),
        agent_mode: mode,
        clock: ClockMode::Faked,
        json: false,
        key: None,
        out: None,
        run_dir: Some(run_dir),
        entrypoint: None,
        model: None,
        upstream_url: None,
        upstream_key_file: None,
    }
}

#[test]
fn run_with_real_infra_fails_closed_and_fabricates_nothing() {
    let temp = tempfile::tempdir().unwrap();
    for mode in [AgentMode::H, AgentMode::G] {
        let run_dir = temp.path().join(format!("run-{}", mode.as_str()));
        let req = request(temp.path().join("world"), run_dir.clone(), mode);
        let res = hermetic_cli::run_flow::run_with_real_infra(req);
        assert!(
            matches!(&res, Err(BackendError::Unavailable(m)) if *m == RUN_NOT_WIRED),
            "run must fail closed until real VM orchestration is wired, got {res:?}"
        );
        assert!(
            !run_dir.exists(),
            "a refused run must not write any run artifacts"
        );
    }
}
