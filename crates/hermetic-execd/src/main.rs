#![deny(unsafe_code)]
use hermetic_execd::{
    boot::{self, Effect, Sys},
    real::{self, Linux},
    rpc::Server,
    Error, Result,
};

fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    if let Some(arg) = args.next() {
        if arg == "--child" {
            let payload = args.next().ok_or(Error::InvalidInput)?;
            if args.next().is_some() {
                return Err(Error::InvalidInput);
            }
            return real::child_main(payload.to_str().ok_or(Error::InvalidInput)?);
        }
        return Err(Error::InvalidInput);
    }
    // Refuse all privileged work when accidentally invoked on the host.
    if rustix::process::getpid().as_raw_nonzero().get() != 1 {
        return Err(Error::Boot);
    }
    let mut sys = Linux::default();
    let cmdline = match std::fs::File::open("/proc/cmdline") {
        Ok(file) => file,
        Err(_) => {
            let _ = sys.effect(Effect::PowerOff(Error::InvalidClock));
            return Err(Error::InvalidClock);
        }
    };
    let boot = boot::start(&mut sys, cmdline)?;
    let mut listener = sys.listener.take().ok_or(Error::Boot)?;
    let mut server = Server::new(sys, boot);
    let result = server.run(&mut listener);
    if result.is_err() {
        let _ = server.sys.effect(Effect::PowerOff(Error::Io));
    }
    result
}
fn main() {
    if let Err(error) = run() {
        // No raw OS errors or input can escape, and no pre-clock logging.
        std::process::exit(if error == Error::InvalidClock { 2 } else { 1 });
    }
}
