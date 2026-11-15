use std::io::Result as IoResult;
use std::io::{Read, Write};

use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use std::mem;

pub struct SequentialReaderBuilder<R>
where
    R: Read + Send,
{
    inner: SequentialReaderBuilderInner<R>,
}

enum SequentialReaderBuilderInner<R>
where
    R: Read + Send,
{
    First(R),
    NotFirst(Receiver<R>),
}

pub struct SequentialReader<R>
where
    R: Read + Send,
{
    inner: SequentialReaderInner<R>,
    next: Sender<R>,
    on_start: Option<StartCallback<R>>,
}

type StartCallback<R> = Box<dyn FnOnce(&mut R) + Send>;

enum SequentialReaderInner<R>
where
    R: Read + Send,
{
    MyTurn(R),
    Waiting(Receiver<R>),
    Empty,
}

pub struct SequentialWriterBuilder<W>
where
    W: Write + Send,
{
    writer: Arc<Mutex<W>>,
    next_trigger: Option<Receiver<()>>,
}

pub struct SequentialWriter<W>
where
    W: Write + Send,
{
    trigger: Option<Receiver<()>>,
    writer: Arc<Mutex<W>>,
    on_finish: Sender<()>,
}

impl<R: Read + Send> SequentialReaderBuilder<R> {
    pub fn new(reader: R) -> SequentialReaderBuilder<R> {
        SequentialReaderBuilder {
            inner: SequentialReaderBuilderInner::First(reader),
        }
    }
}

impl<W: Write + Send> SequentialWriterBuilder<W> {
    pub fn new(writer: W) -> SequentialWriterBuilder<W> {
        SequentialWriterBuilder {
            writer: Arc::new(Mutex::new(writer)),
            next_trigger: None,
        }
    }
}

impl<R: Read + Send> Iterator for SequentialReaderBuilder<R> {
    type Item = SequentialReader<R>;

    fn next(&mut self) -> Option<SequentialReader<R>> {
        let (tx, rx) = channel();

        let inner = mem::replace(&mut self.inner, SequentialReaderBuilderInner::NotFirst(rx));

        match inner {
            SequentialReaderBuilderInner::First(reader) => Some(SequentialReader {
                inner: SequentialReaderInner::MyTurn(reader),
                next: tx,
                on_start: None,
            }),

            SequentialReaderBuilderInner::NotFirst(previous) => Some(SequentialReader {
                inner: SequentialReaderInner::Waiting(previous),
                next: tx,
                on_start: None,
            }),
        }
    }
}

impl<W: Write + Send> Iterator for SequentialWriterBuilder<W> {
    type Item = SequentialWriter<W>;
    fn next(&mut self) -> Option<SequentialWriter<W>> {
        let (tx, rx) = channel();
        let mut next_next_trigger = Some(rx);
        ::std::mem::swap(&mut next_next_trigger, &mut self.next_trigger);

        Some(SequentialWriter {
            trigger: next_next_trigger,
            writer: self.writer.clone(),
            on_finish: tx,
        })
    }
}

impl<R: Read + Send> SequentialReader<R> {
    /// Runs once, after acquiring the stream and before reading its first byte.
    pub(crate) fn on_start(&mut self, callback: impl FnOnce(&mut R) + Send + 'static) {
        self.on_start = Some(Box::new(callback));
    }
}

impl<R: Read + Send> Read for SequentialReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if let SequentialReaderInner::Waiting(recv) = &self.inner {
            let reader = recv.recv().map_err(|_| std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted, "previous reader disconnected"
            ))?;
            self.inner = SequentialReaderInner::MyTurn(reader);
        }
        match &mut self.inner {
            SequentialReaderInner::MyTurn(reader) => {
                if let Some(callback) = self.on_start.take() {
                    callback(reader);
                }
                reader.read(buf)
            }
            _ => Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "reader unavailable")),
        }
    }
}

impl<W: Write + Send> Write for SequentialWriter<W> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.wait_turn()?;
        self.writer
            .lock()
            .map_err(|_| aborted("writer poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.wait_turn()?;
        self.writer
            .lock()
            .map_err(|_| aborted("writer poisoned"))?
            .flush()
    }
}

impl<R> Drop for SequentialReader<R>
where
    R: Read + Send,
{
    fn drop(&mut self) {
        let inner = mem::replace(&mut self.inner, SequentialReaderInner::Empty);

        match inner {
            SequentialReaderInner::MyTurn(reader) => {
                self.next.send(reader).ok();
            }
            // HERMETIC PATCH: a predecessor that went away without handing the
            // stream on leaves nothing to forward; never panic while dropping.
            SequentialReaderInner::Waiting(recv) => {
                if let Ok(reader) = recv.recv() {
                    self.next.send(reader).ok();
                }
            }
            SequentialReaderInner::Empty => (),
        }
    }
}

impl<W> Drop for SequentialWriter<W>
where
    W: Write + Send,
{
    fn drop(&mut self) {
        self.on_finish.send(()).ok();
    }
}

fn aborted(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, message)
}

impl<W: Write + Send> SequentialWriter<W> {
    /// HERMETIC PATCH: wait for the previous response to finish; a predecessor
    /// that disappeared without signalling is an I/O error, not a panic.
    fn wait_turn(&mut self) -> IoResult<()> {
        // On failure the trigger is kept, so every later write fails too.
        if let Some(v) = self.trigger.as_mut() {
            v.recv()
                .map_err(|_| aborted("previous writer disconnected"))?;
        }
        self.trigger = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::mpsc::channel;

    #[test]
    fn writer_whose_predecessor_vanished_fails_without_panicking_and_stays_failed() {
        let (trigger_tx, trigger_rx) = channel();
        let (finish_tx, _finish_rx) = channel();
        let mut writer = SequentialWriter {
            trigger: Some(trigger_rx),
            writer: Arc::new(Mutex::new(Vec::<u8>::new())),
            on_finish: finish_tx,
        };
        drop(trigger_tx);
        for _ in 0..2 {
            let err = writer.write(b"late").unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
            assert_eq!(writer.flush().unwrap_err().kind(), std::io::ErrorKind::ConnectionAborted);
        }
        assert!(writer.writer.lock().unwrap().is_empty());
    }

    #[test]
    fn dropping_a_waiting_reader_whose_predecessor_vanished_does_not_panic() {
        let (prev_tx, prev_rx) = channel::<Cursor<Vec<u8>>>();
        let (next_tx, next_rx) = channel();
        let reader = SequentialReader {
            inner: SequentialReaderInner::Waiting(prev_rx),
            next: next_tx,
            on_start: None,
        };
        drop(prev_tx);
        drop(reader);
        assert!(next_rx.try_recv().is_err());
    }

    #[test]
    fn dropping_a_waiting_reader_forwards_the_stream_once_it_arrives() {
        let (prev_tx, prev_rx) = channel();
        let (next_tx, next_rx) = channel();
        let reader = SequentialReader {
            inner: SequentialReaderInner::Waiting(prev_rx),
            next: next_tx,
            on_start: None,
        };
        prev_tx.send(Cursor::new(b"stream".to_vec())).unwrap();
        drop(reader);
        assert_eq!(next_rx.try_recv().unwrap().into_inner(), b"stream");
    }
}
