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

#[link(name = "winhttp")]
extern "system" {
    fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16,
                   bypass: *const u16, flags: u32) -> *mut c_void;
    fn WinHttpConnect(session: *mut c_void, host: *const u16, port: u16,
                      reserved: u32) -> *mut c_void;
    fn WinHttpOpenRequest(connect: *mut c_void, verb: *const u16, path: *const u16,
                          version: *const u16, referrer: *const u16,
                          accept: *const u16, flags: u32) -> *mut c_void;
    fn WinHttpSendRequest(req: *mut c_void, headers: *const u16, headers_len: u32,
                          body: *const c_void, body_len: u32, total_len: u32,
                          context: usize) -> i32;
    fn WinHttpReceiveResponse(req: *mut c_void, reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(req: *mut c_void, info: u32, name: *const u16,
                           buf: *mut c_void, len: *mut u32, index: *mut u32) -> i32;
    fn WinHttpReadData(req: *mut c_void, buf: *mut c_void, len: u32,
                       read: *mut u32) -> i32;
    fn WinHttpQueryDataAvailable(req: *mut c_void, avail: *mut u32) -> i32;
    fn WinHttpSetTimeouts(session: *mut c_void, resolve: i32, connect: i32,
                          send: i32, receive: i32) -> i32;
    fn WinHttpSetOption(h: *mut c_void, option: u32, buf: *mut c_void, len: u32) -> i32;
    fn WinHttpCloseHandle(h: *mut c_void) -> i32;
}

const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
const WINHTTP_QUERY_STATUS_TEXT: u32 = 20;
const WINHTTP_QUERY_RAW_HEADERS_CRLF: u32 = 22;
const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;

pub struct HttpResponse {
    pub status: u32,
    pub reason: String,
    pub headers: String,
    pub body: Vec<u8>,
}

/// `http[s]://host[:port]/path?query` -> (secure, host, port, path).
fn split_url(url: &str) -> Option<(bool, String, u16, String)> {
    let (secure, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return None;
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest[i..].starts_with('/') => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') => (
            h.to_string(),
            p.parse::<u16>().ok()?,
        ),
        _ => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    if host.is_empty() {
        return None;
    }
    Some((secure, host, port, path))
}

fn query_text(req: *mut c_void, info: u32) -> Option<String> {
    let mut len = 0u32;
    unsafe {
        WinHttpQueryHeaders(req, info, std::ptr::null(), std::ptr::null_mut(),
                            &mut len, std::ptr::null_mut());
    }
    if len == 0 {
        return Some(String::new());
    }
    let mut buf = vec![0u16; (len as usize / 2) + 2];
    let ok = unsafe {
        WinHttpQueryHeaders(req, info, std::ptr::null(), buf.as_mut_ptr() as *mut c_void,
                            &mut len, std::ptr::null_mut())
    };
    if ok == 0 {
        return None;
    }
    let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..nul]))
}

/// One HTTP round trip through WinHTTP. WinHTTP owns TLS, proxy discovery and
/// redirects, so nothing here has to know about certificates or chunked
/// encoding. Errors are strings because they end up in the log, not in Lua.
pub fn http_perform(url: &str, method: &str, headers: &str, body: &[u8]) -> Result<HttpResponse, String> {
    let (secure, host, port, path) = split_url(url).ok_or_else(|| format!("bad url: {url}"))?;
    let agent = wide("zendo/1.0");
    unsafe {
        let session = WinHttpOpen(agent.as_ptr(), 0, std::ptr::null(), std::ptr::null(), 0);
        if session.is_null() {
            return Err("WinHttpOpen".into());
        }
        // A script that hangs must not hang the whole session: every phase gets
        // a ceiling, and the pipe is synchronous while a request is in flight.
        WinHttpSetTimeouts(session, 10_000, 10_000, 30_000, 30_000);
        let hostw = wide(&host);
        let conn = WinHttpConnect(session, hostw.as_ptr(), port, 0);
        if conn.is_null() {
            WinHttpCloseHandle(session);
            return Err(format!("WinHttpConnect {host}:{port}"));
        }
        let verb_src = if method.is_empty() { "GET" } else { method };
        let verb = wide(verb_src);
        let pathw = wide(&path);
        let flags = if secure { WINHTTP_FLAG_SECURE } else { 0 };
        let req = WinHttpOpenRequest(conn, verb.as_ptr(), pathw.as_ptr(),
                                     std::ptr::null(), std::ptr::null(),
                                     std::ptr::null(), flags);
        if req.is_null() {
            WinHttpCloseHandle(conn);
            WinHttpCloseHandle(session);
            return Err("WinHttpOpenRequest".into());
        }
        let hdrw: Vec<u16> = headers.encode_utf16().chain(std::iter::once(0)).collect();
        // gzip | deflate: WinHTTP adds Accept-Encoding itself and hands back
        // decoded bytes. A script that sets its own Accept-Encoding still gets
        // what it asked for; the option only removes the manual inflate step.
        let decomp: u32 = 3;
        WinHttpSetOption(req, 118, &decomp as *const u32 as *mut c_void, 4);
        let (hp, hl) = if headers.is_empty() {
            (std::ptr::null(), 0u32)
        } else {
            (hdrw.as_ptr(), u32::MAX)
        };
        let (bp, bl) = if body.is_empty() {
            (std::ptr::null(), 0u32)
        } else {
            (body.as_ptr() as *const c_void, body.len() as u32)
        };
        let sent = WinHttpSendRequest(req, hp, hl, bp, bl, bl, 0);
        if sent == 0 {
            let e = std::io::Error::last_os_error();
            WinHttpCloseHandle(req);
            WinHttpCloseHandle(conn);
            WinHttpCloseHandle(session);
            return Err(format!("send: {e}"));
        }
        if WinHttpReceiveResponse(req, std::ptr::null_mut()) == 0 {
            let e = std::io::Error::last_os_error();
            WinHttpCloseHandle(req);
            WinHttpCloseHandle(conn);
            WinHttpCloseHandle(session);
            return Err(format!("receive: {e}"));
        }
        let mut status = 0u32;
        let mut slen = 4u32;
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            std::ptr::null(), &mut status as *mut u32 as *mut c_void,
                            &mut slen, std::ptr::null_mut());
        let reason = query_text(req, WINHTTP_QUERY_STATUS_TEXT).unwrap_or_default();
        let raw_headers = query_text(req, WINHTTP_QUERY_RAW_HEADERS_CRLF).unwrap_or_default();
        let mut data: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 1 << 16];
        // Query first, then read the advertised count. A bare ReadData can
        // return zero bytes while the body is still arriving (http/2 and
        // chunked responses both do this), which is how an example.com page
        // came back as a 200 with an empty body.
        loop {
            let mut avail = 0u32;
            if WinHttpQueryDataAvailable(req, &mut avail) == 0 || avail == 0 {
                break;
            }
            let want = (avail as usize).min(chunk.len());
            let mut got = 0u32;
            let ok = WinHttpReadData(req, chunk.as_mut_ptr() as *mut c_void,
                                     want as u32, &mut got);
            if ok == 0 || got == 0 {
                break;
            }
            data.extend_from_slice(&chunk[..got as usize]);
            if data.len() > (8 << 20) {
                break;
            }
        }
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        Ok(HttpResponse { status, reason, headers: raw_headers, body: data })
    }
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
                || body.first() == Some(&b'T') || body.first() == Some(&b'M')
                || body.first() == Some(&b'D')
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
                        (b'T', Some(p)) => ok = if p.is_dir() { 1 } else { 0 },
                        (b'M', Some(p)) => {
                            ok = if std::fs::create_dir_all(&p).is_ok() { 1 } else { 0 };
                        }
                        (b'D', Some(p)) => {
                            ok = if p.is_dir() {
                                std::fs::remove_dir_all(&p).is_ok() as u8
                            } else {
                                std::fs::remove_file(&p).is_ok() as u8
                            };
                        }
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
            if body.first() == Some(&b'Q') {
                // HTTP request forwarded from the payload. The socket lives
                // here, not in the client: WinHTTP handles TLS, proxies and
                // redirects. The response body and header block are written to
                // two sandbox files, and the script reads them back with
                // readfile - the payload cannot build a Luau string.
                const CAPS: [usize; 6] = [8192, 16, 65536, 8 << 20, 512, 512];
                let fields: Vec<usize> = body[1..]
                    .split(|&c| c == b' ')
                    .filter(|f| !f.is_empty())
                    .filter_map(|f| std::str::from_utf8(f).ok()?.trim().parse().ok())
                    .collect();
                if fields.len() != 6 || fields.iter().zip(CAPS).any(|(n, cap)| *n > cap) {
                    pipe.write_all(b"R 0 0\n")?;
                } else {
                    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(6);
                    for n in &fields {
                        let mut v = vec![0u8; *n];
                        take_bytes(pipe, &mut acc, &mut v)?;
                        parts.push(v);
                    }
                    let url = String::from_utf8_lossy(&parts[0]).to_string();
                    let method = String::from_utf8_lossy(&parts[1]).to_string();
                    let headers = String::from_utf8_lossy(&parts[2]).to_string();
                    let body_path = String::from_utf8_lossy(&parts[4]).to_string();
                    let hdr_path = String::from_utf8_lossy(&parts[5]).to_string();
                    let mut ok = 0u8;
                    let mut status = 0u32;
                    match http_perform(&url, &method, &headers, &parts[3]) {
                        Ok(resp) => {
                            status = resp.status;
                            let write_into = |raw: &str, bytes: &[u8]| -> bool {
                                match fs_path(raw.as_bytes()) {
                                    Some(p) => {
                                        if let Some(parent) = p.parent() {
                                            let _ = std::fs::create_dir_all(parent);
                                        }
                                        std::fs::write(&p, bytes).is_ok()
                                    }
                                    None => false,
                                }
                            };
                            let mut text = resp.headers.clone();
                            if !text.ends_with("\r\n") {
                                text.push_str("\r\n");
                            }
                            let body_ok = write_into(&body_path, &resp.body);
                            let hdr_ok = write_into(&hdr_path, text.as_bytes());
                            if body_ok && hdr_ok {
                                ok = 1;
                            }
                            eprintln!("[pipe] http {} {} -> {} ({} bytes)",
                                      method, url, resp.status, resp.body.len());
                        }
                        Err(e) => eprintln!("[pipe] http failed: {e}"),
                    }
                    pipe.write_all(format!("R {} {}\n", status, ok).as_bytes())?;
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
