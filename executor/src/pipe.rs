//! Named-pipe server side of the zendo protocol. The payload attaches as a
//! client to `\\.\pipe\zendo-dev`; we host the pipe and answer each RDY line
//! with the next command (or a chunk).

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use std::ffi::c_void;
use std::io::{self, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

pub type Handle = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn CreateNamedPipeW(name: *const u16, open_mode: u32, pipe_mode: u32,
                        max_instances: u32, out_buf: u32, in_buf: u32,
                        timeout: u32, sec: *mut c_void) -> Handle;
    fn ConnectNamedPipe(h: Handle, overlapped: *mut c_void) -> i32;
    fn ReadFile(h: Handle, buf: *mut c_void, len: u32, read: *mut u32,
                overlapped: *mut c_void) -> i32;
    fn WriteFile(h: Handle, buf: *const c_void, len: u32, written: *mut u32,
                 overlapped: *mut c_void) -> i32;
    fn DisconnectNamedPipe(h: Handle) -> i32;
    fn CloseHandle(h: Handle) -> i32;
    fn GetLastError() -> u32;
    fn OpenMutexA(access: u32, inherit: i32, name: *const i8) -> Handle;
    fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
    fn ReleaseMutex(h: Handle) -> i32;
}

/// True while a payload thread is parked in the client **and owns** the
/// `zendo-live` mutex. Ownership is the part that matters: the payload thread
/// takes the mutex and never releases it, so the kernel marks it abandoned as
/// soon as that thread dies even though a stale handle keeps the object alive.
/// A dead payload therefore reads as no session instead of blocking every
/// later inject forever.
pub fn payload_live() -> bool {
    let name = b"zendo-live\0";
    // SYNCHRONIZE | MUTEX_MODIFY_STATE: enough to wait on it and take it.
    let h = unsafe { OpenMutexA(0x0010_0001, 0, name.as_ptr() as *const i8) };
    if h.is_null() {
        return false;
    }
    let r = unsafe { WaitForSingleObject(h, 0) };
    eprintln!("[probe] wait=0x{r:x}");
    if r == 0x102 {
        // Still owned by a running thread.
        unsafe { CloseHandle(h) };
        return true;
    }
    // Free or abandoned: nobody is serving. Hand ownership back so the next
    // payload starts clean.
    unsafe {
        ReleaseMutex(h);
        CloseHandle(h);
    }
    false
}

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const PIPE_ACCESS_DUPLEX: u32 = 0x3;
const PIPE_TYPE_BYTE: u32 = 0x0;
const PIPE_WAIT: u32 = 0x0;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const ERROR_PIPE_CONNECTED: u32 = 535;

pub struct Pipe {
    h: Handle,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl Pipe {
    pub fn create(name: &str) -> io::Result<Pipe> {
        let n = wide(name);
        let h = unsafe {
            CreateNamedPipeW(n.as_ptr(), PIPE_ACCESS_DUPLEX,
                             PIPE_TYPE_BYTE | PIPE_WAIT,
                             PIPE_UNLIMITED_INSTANCES, 1 << 16, 1 << 16, 0,
                             std::ptr::null_mut())
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Pipe { h })
    }

    pub fn accept(&self) -> io::Result<()> {
        let ok = unsafe { ConnectNamedPipe(self.h, std::ptr::null_mut()) };
        if ok == 0 {
            let e = unsafe { GetLastError() };
            if e != ERROR_PIPE_CONNECTED {
                return Err(io::Error::from_raw_os_error(e as i32));
            }
        }
        Ok(())
    }

    /// Start waiting for a client without blocking the caller. The wait runs on
    /// a helper thread so the UI can decide whether a session is already alive
    /// (a payload parked in its reconnect loop) before spending an injection.
    pub fn begin_accept(&self) -> Pending {
        let h = self.h as usize;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let handle = h as Handle;
            let ok = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
            let res = if ok != 0 {
                Ok(())
            } else {
                let e = unsafe { GetLastError() };
                if e == ERROR_PIPE_CONNECTED {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(e as i32))
                }
            };
            let _ = tx.send(res);
        });
        Pending { rx }
    }

    pub fn write_all(&self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let mut w: u32 = 0;
            let n = buf.len().min(1 << 20) as u32;
            let ok = unsafe {
                WriteFile(self.h, buf.as_ptr() as *const c_void, n, &mut w,
                          std::ptr::null_mut())
            };
            if ok == 0 || w == 0 {
                return Err(io::Error::last_os_error());
            }
            buf = &buf[w as usize..];
        }
        Ok(())
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut got: u32 = 0;
        let ok = unsafe {
            ReadFile(self.h, buf.as_mut_ptr() as *mut c_void, buf.len() as u32,
                     &mut got, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(got as usize)
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            DisconnectNamedPipe(self.h);
            CloseHandle(self.h);
        }
    }
}

/// One unit of work handed to the payload at successive RDYs.
pub enum Step<'a> {
    Cmd(u8),
    Chunk(&'a [u8]),
    /// Same blob as `Chunk`, sent as `i`: the payload runs it synchronously on
    /// the borrowed thread with the given identity, then restores the old one.
    Ident(&'a [u8], u8),
}

/// A connection attempt started by `Pipe::begin_accept`.
pub struct Pending {
    rx: mpsc::Receiver<io::Result<()>>,
}

impl Pending {
    /// Wait up to `ms` for the client to connect. `false` means nobody did yet;
    /// the accept thread stays parked and a later `wait` picks up the same
    /// connection, so the caller can inject and then keep waiting on it.
    pub fn wait(&self, ms: u64) -> io::Result<bool> {
        match self.rx.recv_timeout(Duration::from_millis(ms)) {
            Ok(Ok(())) => Ok(true),
            Ok(Err(e)) => Err(e),
            Err(RecvTimeoutError::Timeout) => Ok(false),
            Err(RecvTimeoutError::Disconnected) => {
                Err(io::Error::new(io::ErrorKind::Other, "accept thread gone"))
            }
        }
    }
}

/// Streams payload output into `sink` and answers RDY lines with `steps` in
/// order, then `q` once the list is drained. Lines the payload marks with a
/// leading `P` are script output and reach the sink with a `» ` prefix so the
/// UI can tell them apart from protocol chatter.
pub fn drive(pipe: &Pipe, steps: &[Step], mut sink: impl Write) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    let mut acc = Vec::new();
    let mut idx = 0usize;
    let mut sent_quit = false;
    let mut seen_end = false;
    loop {
        let n = match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        acc.extend_from_slice(&buf[..n]);
        while let Some(pos) = acc.iter().position(|&c| c == b'\n') {
            let line: Vec<u8> = acc.drain(..=pos).collect();
            let body = &line[..line.len() - 1];
            if body == b"RDY" {
                if idx < steps.len() {
                    match steps[idx] {
                        Step::Cmd(c) => {
                            eprintln!("[pipe] sending cmd {}", c as char);
                            pipe.write_all(&[c])?;
                        }
                        Step::Chunk(chunk) => {
                            eprintln!("[pipe] sending chunk {} bytes", chunk.len());
                            pipe.write_all(b"L")?;
                            pipe.write_all(&(chunk.len() as u32).to_le_bytes())?;
                            pipe.write_all(chunk)?;
                        }
                        Step::Ident(chunk, id) => {
                            eprintln!("[pipe] sending ident chunk {} bytes id {}", chunk.len(), id);
                            pipe.write_all(b"i")?;
                            pipe.write_all(&[id])?;                            pipe.write_all(&(chunk.len() as u32).to_le_bytes())?;
                            pipe.write_all(chunk)?;
                        }
                    }
                    idx += 1;
                } else if !sent_quit {
                    eprintln!("[pipe] sending quit");
                    pipe.write_all(b"q")?;
                    sent_quit = true;
                }
            } else if body == b"END" {
                seen_end = true;
            } else if body.first() == Some(&b'P') {
                sink.write_all("\u{bb} ".as_bytes())?;
                sink.write_all(&body[1..])?;
                sink.write_all(b"\n")?;
            } else {
                sink.write_all(&line)?;
            }
            sink.flush()?;
        }
        if seen_end && sent_quit {
            break;
        }
    }
    Ok(())
}
