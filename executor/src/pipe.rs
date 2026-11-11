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
    fn PeekNamedPipe(h: Handle, buf: *mut c_void, len: u32, read: *mut u32,
                     avail: *mut u32, left: *mut u32) -> i32;
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

    /// Bytes already buffered on the pipe. Polling this instead of blocking in
    /// ReadFile is what lets the driver give up on a script that never signals
    /// done without writing a stray byte into a reply the payload is waiting for.
    pub fn available(&self) -> io::Result<u32> {
        let mut avail: u32 = 0;
        let ok = unsafe {
            PeekNamedPipe(self.h, std::ptr::null_mut(), 0, std::ptr::null_mut(),
                          &mut avail, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(avail)
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

/// A Luau string literal for arbitrary bytes. Everything outside printable
/// ASCII goes out as a three digit decimal escape, which the parser turns back
/// into the exact byte; three digits is why a following literal digit cannot be
/// swallowed by the escape.
fn luau_literal(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push('"');
    for &b in bytes {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\{:03}", b)),
        }
    }
    s.push('"');
    s
}

/// Everything a script names lives under one directory. A path that climbs out
/// with `..` is rejected rather than resolved: the client is not a shell.
fn fs_path(raw: &[u8]) -> Option<std::path::PathBuf> {
    let text = std::str::from_utf8(raw).ok()?;
    if text.is_empty() || text.contains("..") {
        return None;
    }
    let root = std::path::PathBuf::from(r"D:\zendo\work\fs");
    let joined = root.join(text.trim_start_matches(['/', '\\']));
    Some(joined)
}

/// A request header and its body travel together, so a single read can pull
/// part of the body into the line buffer before the header is parsed.
fn take_bytes(pipe: &Pipe, acc: &mut Vec<u8>, dst: &mut [u8]) -> io::Result<()> {
    let mut off = 0usize;
    while off < dst.len() && !acc.is_empty() {
        let n = (dst.len() - off).min(acc.len());
        dst[off..off + n].copy_from_slice(&acc[..n]);
        acc.drain(..n);
        off += n;
    }
    while off < dst.len() {
        let n = pipe.read(&mut dst[off..])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short body"));
        }
        off += n;
    }
    Ok(())
}

/// Streams payload output into `sink` and answers RDY lines with `steps` in
/// order, then `q` once the list is drained. Lines the payload marks with a
/// leading `P` are script output and reach the sink with a `» ` prefix so the
/// UI can tell them apart from protocol chatter.
pub fn drive(pipe: &Pipe, steps: &[Step], mut sink: impl Write) -> io::Result<()> {
    drive_wait(pipe, steps, &mut sink, false)
}

/// `wait_done` keeps the session open after the last step until the payload
/// signals END. A wrapped chunk runs on a scheduler thread and only touches the
/// pipe later; closing it early is what made `loadstring` return nil. A raw
/// chunk runs inside the step itself, so there is nothing left to wait for.
pub fn drive_wait(pipe: &Pipe, steps: &[Step], mut sink: impl Write,
                  wait_done: bool) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    let mut acc = Vec::new();
    let mut idx = 0usize;
    let mut sent_quit = false;
    let mut seen_end = false;
    let mut idle = Duration::ZERO;
    // How long the host stays quiet waiting for the script's done signal. A
    // deferred body can sit in the scheduler for seconds before it runs, so a
    // short window is what kills the session mid-script.
    let wait_limit = std::env::var("ZENDO_DONE_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60));
    loop {
        // Poll: a blocking read hands the timeout decision to the client, and
        // any byte written to break the wait would land inside a reply the
        // payload is still assembling (a loadstring header, for example).
        let avail = match pipe.available() {
            Ok(v) => v,
            Err(_) => break,
        };
        if avail == 0 {
            if wait_done && !sent_quit && idx >= steps.len() && idle >= wait_limit {
                eprintln!("[pipe] no done signal, detaching");
                pipe.write_all(b"x")?;
                sent_quit = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
            idle += Duration::from_millis(20);
            continue;
        }
        idle = Duration::ZERO;
        let n = match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        acc.extend_from_slice(&buf[..n]);
        while let Some(pos) = acc.iter().position(|&c| c == b'\n') {
            let line: Vec<u8> = acc.drain(..=pos).collect();
            let body = &line[..line.len() - 1];
            if body.starts_with(b"C ") {
                // Live loadstring: the script is blocked inside the client
                // waiting for these bytes, so compile now and answer on the
                // same stream. Nothing else is pending; the next line is RDY.
                let want: usize = std::str::from_utf8(&body[2..])
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                let mut src = vec![0u8; want.min(262144)];
                if want == 0 || want > 262144 {
                    pipe.write_all(b"E 0\n")?;
                } else {
                    take_bytes(pipe, &mut acc, &mut src)?;
                    match crate::compile_str(&String::from_utf8_lossy(&src)) {
                        Ok(blob) => {
                            eprintln!("[pipe] loadstring {} bytes -> {} bytes", want, blob.len());
                            pipe.write_all(format!("K {}\n", blob.len()).as_bytes())?;
                            pipe.write_all(&blob)?;
                        }
                        Err(e) => {
                            eprintln!("[pipe] loadstring failed: {e}");
                            let msg = e.into_bytes();
                            pipe.write_all(format!("E {}\n", msg.len()).as_bytes())?;
                            pipe.write_all(&msg)?;
                        }
                    }
                }
                sink.flush()?;
                continue;
            }
            if body.first() == Some(&b'F') || body.first() == Some(&b'G')
                || body.first() == Some(&b'S') || body.first() == Some(&b'L')
            {
                // Filesystem request from inside the client. The payload cannot
                // build a Luau string, so the answer is not raw bytes: it is a
                // chunk that returns the bytes as a literal, which the VM turns
                // into a real string on the other side.
                let cmd = body[0];
                let fields: Vec<&[u8]> = body[1..]
                    .split(|&c| c == b' ')
                    .filter(|f| !f.is_empty())
                    .collect();
                let num = |i: usize| -> usize {
                    fields.get(i).and_then(|f| std::str::from_utf8(f).ok())
                        .and_then(|s| s.trim().parse().ok()).unwrap_or(0)
                };
                let plen = num(0);
                let dlen = if cmd == b'G' { num(1) } else { 0 };
                let mut path = vec![0u8; plen.min(4096)];
                let mut data = vec![0u8; dlen.min(1 << 20)];
                if plen == 0 || plen > 4096 || dlen > (1 << 20) {
                    pipe.write_all(b"E 0\n")?;
                } else {
                    take_bytes(pipe, &mut acc, &mut path)?;
                    if dlen > 0 {
                        take_bytes(pipe, &mut acc, &mut data)?;
                    }
                    let target = fs_path(&path);
                    let mut reply: Option<String> = None;
                    let mut blob_src: Option<String> = None;
                    let mut ok = 0u8;
                    match (cmd, target) {
                        (_, None) => {
                            reply = Some("E bad path\n".to_string());
                        }
                        (b'F', Some(p)) => match std::fs::read(&p) {
                            Ok(bytes) => blob_src = Some(format!("return {}", luau_literal(&bytes))),
                            Err(e) => reply = Some(format!("E {}\n", e.to_string().replace('\n', " "))),
                        },
                        (b'S', Some(p)) => ok = if p.is_file() { 1 } else { 0 },
                        (b'L', Some(p)) => match std::fs::read_dir(&p) {
                            Ok(rd) => {
                                let mut names: Vec<String> = Vec::new();
                                for ent in rd.flatten() {
                                    let name = ent.file_name().to_string_lossy().to_string();
                                    let is_dir = ent.path().is_dir();
                                    names.push(format!("{{\"{}\",{}}}", name.replace('\\', "\\\\").replace('"', "\\\""),
                                                        if is_dir { "true" } else { "false" }));
                                }
                                blob_src = Some(format!("return {{{}}}", names.join(",")));
                            }
                            Err(e) => reply = Some(format!("E {}\n", e.to_string().replace('\n', " "))),
                        },
                        (b'G', Some(p)) => {
                            if let Some(parent) = p.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                            ok = if std::fs::write(&p, &data).is_ok() { 1 } else { 0 };
                        }
                        _ => reply = Some("E bad cmd\n".to_string()),
                    }
                    if let Some(src) = blob_src {
                        match crate::compile_str(&src) {
                            Ok(blob) => {
                                eprintln!("[pipe] fs reply {} bytes", blob.len());
                                pipe.write_all(format!("K {}\n", blob.len()).as_bytes())?;
                                pipe.write_all(&blob)?;
                            }
                            Err(e) => {
                                let msg = e.into_bytes();
                                pipe.write_all(format!("E {}\n", msg.len()).as_bytes())?;
                                pipe.write_all(&msg)?;
                            }
                        }
                    } else if let Some(line) = reply {
                        pipe.write_all(line.as_bytes())?;
                    } else {
                        pipe.write_all(format!("A {}\n", ok).as_bytes())?;
                    }
                }
                sink.flush()?;
                continue;
            }
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
                    if wait_done && !seen_end {
                        // The script is still running on a scheduler thread and
                        // may call loadstring any moment. Stay silent.
                    } else {
                        eprintln!("[pipe] detaching");
                        pipe.write_all(b"x")?;
                        sent_quit = true;
                    }
                }
            } else if body == b"END" {
                seen_end = true;
                if wait_done && !sent_quit {
                    eprintln!("[pipe] script done, detaching");
                    pipe.write_all(b"x")?;
                    sent_quit = true;
                }
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
