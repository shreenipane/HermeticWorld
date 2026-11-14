#![forbid(unsafe_code)]
use hermetic_vmm::{fs::open_image, jail_plan, spec::VmSpec, Error};
use std::io::Write;
fn run() -> hermetic_vmm::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next();
    if command.as_deref() == Some(std::ffi::OsStr::new("boot-args")) {
        let base = args
            .next()
            .and_then(|s| s.into_string().ok())
            .ok_or(Error::Validation("missing boot arguments"))?;
        if args.next().is_some() {
            return Err(Error::Validation("unexpected argument"));
        }
        let calibrated = hermetic_vmm::plan::calibrated_boot_args(
            &base,
            hermetic_vmm::plan::configured_tsc_khz()?,
        )?;
        writeln!(std::io::stdout().lock(), "{calibrated}")?;
        return Ok(());
    }
    if command.as_deref() != Some(std::ffi::OsStr::new("plan")) {
        return Err(Error::Validation(
            "usage: hermetic-vmm plan SPEC.json (or - for stdin)",
        ));
    }
    let path = args
        .next()
        .ok_or(Error::Validation("missing spec"))?
        .into_string()
        .map_err(|_| Error::Validation("argument encoding"))?;
    if args.next().is_some() {
        return Err(Error::Validation("unexpected argument"));
    }
    let spec = if path == "-" {
        VmSpec::read(std::io::stdin().lock())?
    } else {
        VmSpec::read(open_image(&path)?)?
    }
    .validate()?;
    let requests = hermetic_vmm::plan::calibrated_api_requests(
        &spec,
        hermetic_vmm::plan::configured_tsc_khz()?,
    )?;
    let result = serde_json::json!({"api_requests":requests,"jail_plan":jail_plan(&spec)});
    let mut output = serde_json::to_vec_pretty(&result).map_err(|_| Error::Io)?;
    output.push(b'\n');
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(if matches!(error, Error::Validation(_)) {
            2
        } else {
            1
        });
    }
}
