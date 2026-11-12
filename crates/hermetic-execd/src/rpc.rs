use crate::{
    boot::{self, Booted, Effect, Sys},
    *,
};
use serde::de::DeserializeOwned;
use std::io::{Read, Write};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Exec {
        argv: Vec<String>,
        tty: bool,
        timeout_ms: u64,
    },
    Upload {
        path: String,
        data: Vec<u8>,
    },
    Download {
        path: String,
    },
    Status {},
    Shutdown {},
    /// Only the trusted host may release an initramfs boot.
    Authorize {},
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Exec {
                argv, timeout_ms, ..
            } => {
                spec::args(argv, false)?;
                if *timeout_ms == 0 || *timeout_ms > MAX_TIMEOUT_MS {
                    return Err(Error::InvalidInput);
                }
            }
            Self::Upload { path, data } => {
                spec::path(path)?;
                if data.len() > MAX_TRANSFER {
                    return Err(Error::Limit);
                }
            }
            Self::Download { path } => spec::path(path)?,
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecReply {
    pub code: Option<i32>,
    pub output: Vec<u8>,
    pub truncated: bool,
    pub timed_out: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Ok,
    Status { locked: bool, output_bytes: usize },
    Exec(ExecReply),
    Download { data: Vec<u8> },
    Frozen,
    Error { reason: Error },
}

/// u32 little endian length then strict JSON; lengths checked before allocation.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(Error::Limit);
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)
}
pub fn write_frame(value: &impl Serialize, writer: &mut impl Write) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::InvalidInput)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub trait Listener {
    type Stream: Read + Write;
    /// Nonblocking accept. Stream must enforce FRAME_TIMEOUT_MS for reads/writes.
    fn accept(&mut self) -> Result<Option<Self::Stream>>;
}

pub struct Server<S: Sys> {
    pub sys: S,
    pub boot: Booted<S::FreezeHandle>,
    output: usize,
    stopped: bool,
}
impl<S: Sys> Server<S> {
    pub fn new(sys: S, boot: Booted<S::FreezeHandle>) -> Self {
        Self {
            sys,
            boot,
            output: 0,
            stopped: false,
        }
    }
    fn dispatch(&mut self, request: Request) -> Result<Reply> {
        request.validate()?;
        if self.stopped {
            return Err(Error::Shutdown);
        }
        match request {
            Request::Status {} => Ok(Reply::Status {
                locked: self.boot.locked,
                output_bytes: self.output,
            }),
            Request::Authorize {} => {
                if self.boot.locked {
                    if !self.boot.spec.initial_argv().is_empty() {
                        self.sys.start_entrypoint(&self.boot.spec)?;
                    }
                    self.boot.locked = false;
                }
                Ok(Reply::Ok)
            }
            Request::Exec {
                argv,
                tty,
                timeout_ms,
            } => {
                if self.boot.locked {
                    return Err(Error::Locked);
                }
                let cap = MAX_COMMAND_OUTPUT.min(MAX_RUN_OUTPUT.saturating_sub(self.output));
                let result = self
                    .sys
                    .execute(&self.boot.spec, &argv, tty, timeout_ms, cap);
                if matches!(result, Err(Error::ChildStuck)) {
                    self.stopped = true;
                }
                let mut reply = result?;
                if reply.output.len() > cap {
                    reply.output.truncate(cap);
                    reply.truncated = true;
                }
                self.output = self.output.saturating_add(reply.output.len());
                Ok(Reply::Exec(reply))
            }
            Request::Upload { path, data } => {
                self.sys.upload(&path, &data)?;
                Ok(Reply::Ok)
            }
            Request::Download { path } => {
                let data = self.sys.download(&path)?;
                if data.len() > MAX_TRANSFER {
                    return Err(Error::Limit);
                }
                Ok(Reply::Download { data })
            }
            Request::Shutdown {} => {
                self.stopped = true;
                boot::shutdown(&mut self.sys, &self.boot.upper)?;
                Ok(Reply::Frozen)
            }
        }
    }
    /// One request per connection bounds both connection and command concurrency.
    /// Always power off after a shutdown attempt, even if the reply disconnects.
    pub fn serve_one(&mut self, stream: &mut (impl Read + Write)) -> Result<()> {
        let reply = read_frame::<Request>(stream)
            .and_then(|r| self.dispatch(r))
            .unwrap_or_else(|reason| Reply::Error { reason });
        let written = write_frame(&reply, stream);
        if self.stopped {
            self.sys.effect(Effect::PowerOff(Error::Shutdown))?;
        }
        written
    }
    pub fn run(&mut self, listener: &mut impl Listener) -> Result<()> {
        while !self.stopped {
            self.sys.maintain()?;
            if let Some(mut stream) = listener.accept()? {
                let result = self.serve_one(&mut stream);
                if self.stopped {
                    return result;
                }
            }
        }
        Ok(())
    }
}
