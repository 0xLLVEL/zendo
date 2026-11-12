#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use std::ffi::c_void;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use zendo_core::pipe;

// DWM's acrylic backdrop carries an ~80% tint on Windows 11, which is what
// turned the window into a flat dark sheet. The undocumented accent policy
// gives the same blur with a tint alpha we choose; CSS keeps the rest.
mod glass {
    use std::ffi::c_void;

    #[repr(C)]
    struct AccentPolicy {
        state: i32,
        flags: i32,
        gradient_color: u32,
        animation_id: i32,
    }

    #[repr(C)]
    struct WinCompAttrData {
        attribute: i32,
        data: *mut c_void,
        size_of_data: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    type SetWindowCompositionAttributeFn =
        unsafe extern "system" fn(*mut c_void, *mut WinCompAttrData) -> i32;

    const WCA_ACCENT_POLICY: i32 = 19;
    const ACCENT_ENABLE_ACRYLICBLURBEHIND: i32 = 4;
    const ACCENT_FLAG_DRAW_BORDERS: i32 = 2;

    fn resolve() -> Option<SetWindowCompositionAttributeFn> {
        let name: [u16; 11] = [
            'u' as u16, 's' as u16, 'e' as u16, 'r' as u16, '3' as u16, '2' as u16,
            '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
        ];
        unsafe {
            let module = GetModuleHandleW(name.as_ptr());
            if module.is_null() {
                return None;
            }
            let proc = GetProcAddress(
                module,
                b"SetWindowCompositionAttribute\0".as_ptr(),
            );
            if proc.is_null() {
                return None;
            }
            Some(std::mem::transmute::<
                *mut c_void,
                SetWindowCompositionAttributeFn,
            >(proc))
        }
    }

    pub fn acrylic(hwnd: *mut c_void, alpha: u8, tint: u32) {
        let Some(set) = resolve() else { return };
        let mut policy = AccentPolicy {
            state: ACCENT_ENABLE_ACRYLICBLURBEHIND,
            flags: ACCENT_FLAG_DRAW_BORDERS,
            gradient_color: ((alpha as u32) << 24) | (tint & 0x00ff_ffff),
            animation_id: 0,
        };
        let mut data = WinCompAttrData {
            attribute: WCA_ACCENT_POLICY,
            data: &mut policy as *mut _ as *mut c_void,
            size_of_data: std::mem::size_of::<AccentPolicy>(),
        };
        unsafe {
            set(hwnd, &mut data);
        }
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Process32FirstW(snap: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snap: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn TerminateProcess(handle: *mut c_void, code: u32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(token: *mut c_void, class: u32, info: *mut c_void, len: u32,
                           out_len: *mut u32) -> i32;
}

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION: u32 = 20;

/// The client runs elevated on this machine, so a medium-integrity UI can see
/// the pid but cannot inject into it. Saying that in the status strip is the
/// difference between a clear error and a run that hangs for thirty seconds.
fn is_elevated() -> bool {
    unsafe {
        let mut token: *mut c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut on: u32 = 0;
        let mut got: u32 = 0;
        let ok = GetTokenInformation(token, TOKEN_ELEVATION, &mut on as *mut u32 as *mut c_void,
                                     4, &mut got);
        CloseHandle(token);
        ok != 0 && on != 0
    }
}

#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

const TH32CS_SNAPPROCESS: u32 = 0x2;

fn processes_named(name: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap as isize == -1 {
            return pids;
        }
        let mut e: ProcessEntry32W = std::mem::zeroed();
        e.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let end = e.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(0);
                if String::from_utf16_lossy(&e.sz_exe_file[..end]).eq_ignore_ascii_case(name) {
                    pids.push(e.th32_process_id);
                }
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    pids
}

fn find_process(name: &str) -> Option<u32> {
    processes_named(name).into_iter().next()
}

/// Everything the payload prints is relayed to the UI as it arrives and kept
/// for the final result.
struct Tap {
    app: AppHandle,
    buf: Arc<Mutex<Vec<u8>>>,
}

impl Write for Tap {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let _ = self.app.emit("zendo://out", String::from_utf8_lossy(b).to_string());
        self.buf.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct RunOut {
    output: String,
    ms: u128,
    chunk: usize,
    path: String,
}

fn temp_script(source: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("zendo");
    std::fs::create_dir_all(&dir).map_err(|e| format!("temp dir: {e}"))?;
    let path = dir.join("script.luau");
    std::fs::write(&path, source).map_err(|e| format!("write script: {e}"))?;
    Ok(path)
}

/// Newest Player log and its length. CrashHandler logs are excluded: they never
/// carry script output and are usually the newest file in the directory.
fn player_log() -> Option<(PathBuf, u64)> {
    let dir = PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("Roblox").join("logs");
    let mut best: Option<(std::time::SystemTime, PathBuf, u64)> = None;
    for entry in std::fs::read_dir(&dir).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.contains("_Player_") || name.contains("CrashHandler") || !name.ends_with(".log") {
            continue;
        }
        let meta = entry.metadata().ok()?;
        let mtime = meta.modified().ok()?;
        let len = meta.len();
        if best.as_ref().map(|(t, _, _)| mtime > *t).unwrap_or(true) {
            best = Some((mtime, entry.path(), len));
        }
    }
    let (_, path, len) = best?;
    Some((path, len))
}

/// Script output as the client recorded it: `print` lands in CreatorOutput and
/// `warn` in CreatorWarning. Everything else in the log is engine noise.
fn tail(snap: Option<(PathBuf, u64)>) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Some((path, mut off)) = snap else { return String::new() };
    let Ok(mut f) = std::fs::File::open(&path) else { return String::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len < off {
        off = 0;
    }
    if f.seek(SeekFrom::Start(off)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if f.read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    // The client writes bytes that are not UTF-8 (script prints carry whatever
    // the chunk emitted), and `read_to_string` rejects the whole file on one bad
    // byte. That is why every run showed zero lines: the tail was empty, not the
    // log.
    let buf = String::from_utf8_lossy(&bytes);
    let mut out = String::new();
    for line in buf.lines() {
        if let Some(i) = line.find("[FLog::CreatorOutput] ") {
            out.push_str(&line[i + 22..]);
            out.push('\n');
        } else if let Some(i) = line.find("[FLog::CreatorWarning] Warning: ") {
            out.push_str("warn: ");
            out.push_str(&line[i + 31..]);
            out.push('\n');
        }
    }
    out
}

/// Drops the completion line the deferred wrapper prints. The client writes it
/// into CreatorOutput like any other script line, and it is protocol, not
/// script output.
fn strip_sentinel(text: &str) -> String {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if line.trim() == zendo_core::DONE_SENTINEL {
            continue;
        }
        out.push_str(line);
    }
    out
}

fn steps_of<'a>(spec: &str, chunk: &'a [u8]) -> Result<Vec<pipe::Step<'a>>, String> {
    let mut v: Vec<pipe::Step> = Vec::new();
    let spec = if spec.trim().is_empty() { "defer" } else { spec };
    for tok in spec.split(',') {
        match tok.trim() {
            "c" | "C" => v.push(pipe::Step::Cmd(b'C')),
            "chunk" | "L" => v.push(pipe::Step::Chunk(chunk)),
            "defer" | "d" => v.push(pipe::Step::Defer(chunk)),
            "none" => {}
            other => return Err(format!("unknown step '{other}'")),
        }
    }
    Ok(v)
}

fn runlog(msg: &str) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"D:\zendo\work\ui-run.log")
    {
        let _ = writeln!(f, "{ms} {msg}");
    }
}

/// True while `work/loop.bin` is fresh. The seek loop rewrites it once a
/// second, so a fresh stamp is evidence that a payload thread is hunting for a
/// server right now. It is a hint, never a gate: the stamp freezes the moment
/// the client kills or suspends that thread, and a stale stamp that still reads
/// "fresh" cost four seconds of dead air on the second Execute. Nothing is
/// decided on it alone - if the resident does not connect in 1.5 s, injecting
/// is the next step either way.
fn payload_seeking() -> bool {
    std::fs::metadata(r"D:\zendo\work\loop.bin")
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|age| age.as_secs() < 6)
        .unwrap_or(false)
}

fn run_blocking(app: AppHandle, source: String, spec: String) -> Result<RunOut, String> {
    let t0 = Instant::now();
    // A deferred run completes on the client's scheduler, so the only proof it
    // ran is the sentinel in the client's own log. `END` on the pipe means the
    // payload finished handing the body over, not that the body ran.
    let deferred = spec.trim().is_empty()
        || spec.split(',').any(|t| matches!(t.trim(), "defer" | "d"));
    let path = temp_script(&source)?;
    // Deferred on purpose: the body is handed to the client's scheduler, so the
    // VM is never entered from the payload thread while the client runs it. A
    // raw chunk here is what made the client stutter and then freeze.
    let t_compile = Instant::now();
    let chunk = match zendo_core::compile_deferred(&source) {
        Ok(c) => c,
        Err(e) => {
            // Without this line a compile failure left no trace anywhere: the
            // console showed the message and the log jumped from nothing to
            // nothing, so there was no way to tell a typo from a broken
            // wrapper after the fact.
            runlog(&format!(
                "compile failed src={} ms={} err={}",
                source.len(),
                t_compile.elapsed().as_millis(),
                e.replace('\n', " | ")
            ));
            return Err(e);
        }
    };
    runlog(&format!(
        "start src={} chunk={} spec={} compile={}ms",
        source.len(),
        chunk.len(),
        spec,
        t_compile.elapsed().as_millis()
    ));

    let server =
        pipe::Pipe::create(r"\\.\pipe\zendo-dev").map_err(|e| format!("pipe: {e}"))?;

    // This client kills new threads at TLS init, so the borrow path is the one
    // that actually works. Go straight to it.
    let pending = server.begin_accept();
    let mut injector: Option<std::process::Child> = None;
    // Snapshot the client's own Player log before injecting. A deferred chunk
    // outlives this pipe session, so print/warn never reach us as bytes; the
    // only lasting record is the log line the client writes itself.
    let log_start = player_log();

    // A payload now serves exactly one session and returns, so a fresh connect
    // is the normal case. The hint only covers the narrow window where the
    // previous injection is still polling for its server: its seek loop writes
    // loop.bin every second, and it answers a new pipe in 50 ms.
    let seeking = payload_seeking();
    let mut connected = false;
    if seeking {
        let until = Instant::now() + std::time::Duration::from_millis(300);
        while Instant::now() < until {
            if pending.wait(100).map_err(|e| format!("accept: {e}"))? {
                connected = true;
                break;
            }
        }
    }
    runlog(&format!("accept connected={connected} seeking={seeking}"));
    if !connected {
        let _ = app.emit("zendo://stage", "injecting");
        match zendo_core::spawn_inject(&["--hijack"]) {
            Ok(c) => injector = Some(c),
            Err(e) => return Err(e),
        }
        runlog("injected");
        // A fresh image connects in about a second. Eight seconds is the
        // difference between "slow" and "will never answer", and a UI that
        // waits thirty is indistinguishable from a hung one.
        connected = pending.wait(8_000).map_err(|e| format!("accept: {e}"))?;
        if !connected {
            return Err("payload injected but no session connected within 8s".into());
        }
    }
    runlog("attached");
    let _ = app.emit("zendo://stage", "payload attached");

    let _ = app.emit("zendo://stage", "running");

    let buf = Arc::new(Mutex::new(Vec::new()));
    let steps = steps_of(&spec, &chunk)?;
    let tap = Tap { app: app.clone(), buf: buf.clone() };

    // print/warn never reach the pipe: the client writes them to its own
    // CreatorOutput log. Watch that log for the whole session so the UI shows a
    // line when the client writes it, not after a 60 s teardown. The watcher
    // returns what it has already relayed, so the final read below can finish
    // the tail without repeating a line.
    let live = Arc::new(AtomicBool::new(true));
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let app = app.clone();
        let buf = buf.clone();
        let live = live.clone();
        let done = done.clone();
        let snap = log_start.clone();
        std::thread::spawn(move || {
            let mut seen_raw = String::new();
            let mut seen = String::new();
            let mut gone = 0u32;
            while live.load(Ordering::Relaxed) {
                let raw = tail(snap.clone());
                if raw.contains(zendo_core::DONE_SENTINEL) {
                    if !done.swap(true, Ordering::Relaxed) {
                        runlog("sentinel seen");
                    }
                }
                if raw.len() > seen_raw.len() && raw.starts_with(&seen_raw) {
                    let clean = strip_sentinel(&raw);
                    if clean.len() > seen.len() && clean.starts_with(&seen) {
                        let delta = clean[seen.len()..].to_string();
                        let _ = app.emit("zendo://out", delta.clone());
                        buf.lock().unwrap().extend_from_slice(delta.as_bytes());
                        seen = clean;
                    }
                    seen_raw = raw;
                } else if !raw.is_empty() && !raw.starts_with(&seen_raw) {
                    // The log was rotated or truncated under us; adopt it whole.
                    seen_raw = raw.clone();
                    seen = strip_sentinel(&raw);
                }
                gone = if find_process("RobloxPlayerBeta.exe").is_none() { gone + 1 } else { 0 };
                if gone == 1 {
                    runlog("client gone");
                }
                if gone >= 5 {
                    runlog("watcher exit: client absent");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            seen
        })
    };

    // A UI run must never park the strip for a minute: the payload answers END
    // when the chunk finishes, and 15 s is long enough for a slow body. The
    // library entry point keeps its 60 s default.
    if std::env::var_os("ZENDO_DONE_TIMEOUT").is_none() {
        std::env::set_var("ZENDO_DONE_TIMEOUT", "15");
    }
    runlog(&format!("drive start steps={} bytes={}", steps.len(), chunk.len()));

    let driven = pipe::drive_until(&server, &steps, tap, true,
                                   Some(Instant::now() + std::time::Duration::from_secs(30)),
                                   Some(done.as_ref()));
    let ended = matches!(&driven, Ok(true));
    runlog(&format!("drive returned ok={} ended={} elapsed={}ms sentinel={}",
                    driven.is_ok(), ended, t0.elapsed().as_millis(),
                    done.load(Ordering::Relaxed)));
    live.store(false, Ordering::Relaxed);
    let mut seen = watcher.join().unwrap_or_default();
    runlog(&format!("watcher joined out={}B", seen.len()));
    // The payload restores the borrowed thread once the pipe closes, so there is
    // no ack to wait for. The injector is only reaped when this run borrowed one.
    if let Some(inj) = injector {
        runlog("injector wait");
        let inj = inj.wait_with_output().map_err(|e| format!("injector: {e}"))?;
        runlog(&format!("injector exited {}", inj.status));
        if !inj.status.success() {
            return Err(format!(
                "injector exited with {}\n{}{}",
                inj.status,
                String::from_utf8_lossy(&inj.stdout),
                String::from_utf8_lossy(&inj.stderr)
            ));
        }
    }

    let _ = app.emit("zendo://stage", "tail");

    // One last look for lines the client flushes as the session closes. The
    // sentinel is written by a scheduler thread, so it can land after the pipe
    // is already gone; a run that has it must not be reported as a failure just
    // because the payload got to CloseHandle first. A run that never reports
    // pays the longer wait exactly once.
    let polls = if done.load(Ordering::Relaxed) {
        2
    } else if deferred {
        // The payload gives the borrowed thread back one second after queueing
        // the body, so the log line can land after the pipe is already gone.
        // Fifteen seconds is the engine's own patience with a script before it
        // starts complaining, and it is still inside the watchdog.
        60
    } else {
        24
    };
    for i in 0..polls {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let raw = tail(log_start.clone());
        if !done.load(Ordering::Relaxed) && raw.contains(zendo_core::DONE_SENTINEL) {
            done.store(true, Ordering::Relaxed);
            runlog("sentinel seen late");
        }
        let clean = strip_sentinel(&raw);
        if clean.len() > seen.len() && clean.starts_with(&seen) {
            let delta = clean[seen.len()..].to_string();
            let _ = app.emit("zendo://out", delta.clone());
            buf.lock().unwrap().extend_from_slice(delta.as_bytes());
            seen = clean;
        }
        if done.load(Ordering::Relaxed) && i >= 1 {
            break;
        }
    }

    if let Err(e) = &driven {
        if done.load(Ordering::Relaxed) || ended {
            // ERROR_NO_DATA (232) is the payload closing the pipe after END,
            // racing the host's last control byte. The run itself completed.
            runlog(&format!("pipe closed early ({e}); completion already seen"));
        } else if deferred {
            // The payload went home without the host's closing byte. That is
            // expected now: it hands the body over and leaves within a second.
            // The client log is the only completion signal left, so wait for it
            // instead of calling this a broken pipe.
            runlog(&format!("pipe closed early ({e}); waiting on the client log"));
        } else {
            return Err(format!("pipe: {e}"));
        }
    }
    if !done.load(Ordering::Relaxed) && (deferred || !ended) {
        // A deferred run is complete when the client writes the sentinel, not
        // when the payload returns from its hand-off.
        runlog(if deferred {
            "deferred run never reported completion"
        } else {
            "session ended without END or sentinel"
        });
        return Err(if deferred {
            "script did not report completion (no zendo://done in the client log)".into()
        } else {
            "session ended before the script reported completion".into()
        });
    }

    let output = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    runlog(&format!("done ms={} out={}B", t0.elapsed().as_millis(), output.len()));
    Ok(RunOut { output, ms: t0.elapsed().as_millis(), chunk: chunk.len(), path: path.display().to_string() })
}

#[derive(Serialize)]
struct Bit {
    text: String,
    age: u64,
}

#[derive(Serialize)]
struct LogBit {
    name: String,
    age: u64,
    size: u64,
}

#[derive(Serialize)]
struct Telemetry {
    stage: Option<Bit>,
    // `loop` is a Rust keyword; the wire still names it `loop` for the frontend.
    #[serde(rename = "loop")]
    loop_mark: Option<Bit>,
    mutex: Option<Bit>,
    log: Option<LogBit>,
    work: String,
}

fn work_dir() -> PathBuf {
    std::env::var_os("ZENDO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\zendo"))
        .join("work")
}

// ── session identity ────────────────────────────────────────────────────────
// The client's own log names the player on every script error, and the public
// users/thumbnails endpoints turn that name into an id and a headshot. WinHTTP is
// already on the machine; a reqwest dependency would cost a rustls rebuild for
// two GETs and one POST.

#[derive(Serialize, Clone)]
struct Profile {
    name: String,
    display: String,
    id: u64,
    /// data:image/png;base64,… — the webview can paint it without a fetch.
    avatar: String,
}

#[link(name = "winhttp")]
extern "system" {
    fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16,
                   bypass: *const u16, flags: u32) -> *mut c_void;
    fn WinHttpConnect(session: *mut c_void, server: *const u16, port: u16,
                      reserved: u32) -> *mut c_void;
    fn WinHttpOpenRequest(connect: *mut c_void, verb: *const u16, object: *const u16,
                          version: *const u16, referrer: *const u16,
                          accept: *const *const u16, flags: u32) -> *mut c_void;
    fn WinHttpSetOption(handle: *mut c_void, option: u32, buffer: *mut c_void,
                        len: u32) -> i32;
    fn WinHttpSendRequest(request: *mut c_void, headers: *const u16, headers_len: i32,
                          optional: *const c_void, optional_len: u32,
                          total_len: u32, context: usize) -> i32;
    fn WinHttpReceiveResponse(request: *mut c_void, reserved: *mut c_void) -> i32;
    fn WinHttpReadData(request: *mut c_void, buffer: *mut c_void, to_read: u32,
                       read: *mut u32) -> i32;
    fn WinHttpSetTimeouts(session: *mut c_void, resolve: i32, connect: i32,
                          send: i32, receive: i32) -> i32;
    fn WinHttpCloseHandle(handle: *mut c_void) -> i32;
}

const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;
const WINHTTP_OPTION_REDIRECT_POLICY: u32 = 110;
const WINHTTP_OPTION_REDIRECT_POLICY_ALLOW: u32 = 6;
const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn http(host: &str, path: &str, method: &str, body: Option<&[u8]>,
        headers: Option<&str>) -> Result<Vec<u8>, String> {
    unsafe {
        let session = WinHttpOpen(wide("zendo/4080").as_ptr(), WINHTTP_ACCESS_TYPE_NO_PROXY,
                                  std::ptr::null(), std::ptr::null(), 0);
        if session.is_null() {
            return Err("winhttp open".into());
        }
        // The poller runs every two seconds; a dead network must not park a
        // request thread for the default sixty seconds.
        WinHttpSetTimeouts(session, 3000, 3000, 3000, 5000);
        let connect = WinHttpConnect(session, wide(host).as_ptr(), 443, 0);
        let request = if connect.is_null() {
            std::ptr::null_mut()
        } else {
            WinHttpOpenRequest(connect, wide(method).as_ptr(), wide(path).as_ptr(),
                               std::ptr::null(), std::ptr::null(), std::ptr::null(),
                               WINHTTP_FLAG_SECURE)
        };
        if request.is_null() {
            WinHttpCloseHandle(session);
            return Err("winhttp request".into());
        }
        let mut policy = WINHTTP_OPTION_REDIRECT_POLICY_ALLOW;
        WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY,
                         &mut policy as *mut u32 as *mut c_void, 4);

        let (opt, opt_len, total) = match body {
            Some(b) => (b.as_ptr() as *const c_void, b.len() as u32, b.len() as u32),
            None => (std::ptr::null(), 0, 0),
        };
        // Roblox rejects a JSON POST that does not declare its type: the body is
        // parsed before the route runs, so a missing header reads as a bad
        // request and the profile never resolves.
        let head = headers.map(wide);
        let (hptr, hlen) = match head.as_ref() {
            Some(h) => (h.as_ptr(), -1i32),
            None => (std::ptr::null(), 0),
        };
        let sent = WinHttpSendRequest(request, hptr, hlen, opt, opt_len, total, 0);
        let ok = sent != 0 && WinHttpReceiveResponse(request, std::ptr::null_mut()) != 0;
        let mut out = Vec::new();
        if ok {
            let mut chunk = [0u8; 8192];
            loop {
                let mut read: u32 = 0;
                if WinHttpReadData(request, chunk.as_mut_ptr() as *mut c_void,
                                   chunk.len() as u32, &mut read) == 0 || read == 0 {
                    break;
                }
                out.extend_from_slice(&chunk[..read as usize]);
            }
        }
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        if !ok {
            return Err("winhttp receive".into());
        }
        Ok(out)
    }
}

fn base64(bytes: &[u8]) -> String {
    const SET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for part in bytes.chunks(3) {
        let n = (part[0] as u32) << 16
            | (*part.get(1).unwrap_or(&0) as u32) << 8
            | *part.get(2).unwrap_or(&0) as u32;
        out.push(SET[(n >> 18) as usize & 63] as char);
        out.push(SET[(n >> 12) as usize & 63] as char);
        out.push(if part.len() > 1 { SET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if part.len() > 2 { SET[n as usize & 63] as char } else { '=' });
    }
    out
}

/// The log names the player two ways: `Players.<name>.` on every script error,
/// and `local player: <name>` from the client's own creator output. The newest
/// occurrence wins: a rejoined account overwrites the old one.
fn log_username() -> Option<String> {
    let (path, _) = player_log()?;
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let mut found = None;
    let mut fallback = None;
    for line in text.lines() {
        let mut from = 0;
        while let Some(at) = line[from..].find("Players.") {
            let start = from + at + 8;
            let rest = &line[start..];
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(0);
            if (3..=20).contains(&end) {
                found = Some(rest[..end].to_string());
                break;
            }
            from = start;
        }
        if let Some(i) = line.find("local player: ") {
            let rest = &line[i + 14..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            if (3..=20).contains(&end) {
                fallback = Some(rest[..end].to_string());
            }
        }
    }
    found.or(fallback)
}

const JSON_HEAD: &str = "Content-Type: application/json\r\nAccept: application/json\r\n";

fn fetch_profile(name: &str) -> Option<Profile> {
    let body = format!(
        r#"{{"usernames":["{}"],"excludeBannedUsers":false}}"#,
        name.replace('"', "")
    );
    let json = http("users.roblox.com", "/v1/usernames/users", "POST",
                    Some(body.as_bytes()), Some(JSON_HEAD)).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&json).ok()?;
    let first = v.get("data")?.as_array()?.first()?.clone();
    let id = first.get("id")?.as_u64()?;
    let name = first.get("name")?.as_str()?.to_string();
    let display = first.get("displayName").and_then(|d| d.as_str()).unwrap_or(&name).to_string();

    let thumb_path = format!(
        "/v1/users/avatar-headshot?userIds={id}&size=150x150&format=Png&isCircular=false"
    );
    let mut avatar = String::new();
    if let Ok(tj) = http("thumbnails.roblox.com", &thumb_path, "GET", None, None) {
        if let Ok(tv) = serde_json::from_slice::<serde_json::Value>(&tj) {
            if let Some(url) = tv["data"][0]["imageUrl"].as_str() {
                let host_and_path = url.split("://").nth(1).unwrap_or("");
                let (host, path) = host_and_path.split_once('/').unwrap_or((host_and_path, ""));
                if let Ok(png) = http(host, &format!("/{path}"), "GET", None, None) {
                    if !png.is_empty() {
                        avatar = format!("data:image/png;base64,{}", base64(&png));
                    }
                }
            }
        }
    }
    Some(Profile { name, display, id, avatar })
}

static PROFILE_CACHE: OnceLock<Mutex<Option<(u32, std::time::Instant, Option<Profile>)>>> =
    OnceLock::new();

/// Cached per pid: a hit for a minute, a miss for ten seconds. The strip polls
/// this every two seconds, and a miss that is not cached turns a slow network
/// into a request every tick.
fn profile_blocking() -> Option<Profile> {
    let pid = find_process("RobloxPlayerBeta.exe").unwrap_or(0);
    if pid == 0 {
        return None;
    }
    let cache = PROFILE_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((cached_pid, at, p)) = guard.as_ref() {
            if *cached_pid == pid {
                let ttl = if p.is_some() { 60 } else { 10 };
                if at.elapsed().as_secs() < ttl {
                    return p.clone();
                }
            }
        }
    }
    // The name is in the client's own log even when the network is not: an
    // offline or rate-limited lookup must not degrade the header to "guest".
    let p = log_username().map(|name| {
        fetch_profile(&name).unwrap_or_else(|| Profile {
            name: name.clone(),
            display: name,
            id: 0,
            avatar: String::new(),
        })
    });
    if let Ok(mut guard) = cache.lock() {
        *guard = Some((pid, std::time::Instant::now(), p.clone()));
    }
    p
}

fn age_ms(time: std::io::Result<std::time::SystemTime>) -> u64 {
    time.ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One of the payload's proof files. The bytes are ASCII by construction; a
/// short trim keeps a stray NUL from rendering as a box in the rail.
fn read_bit(path: PathBuf) -> Option<Bit> {
    let meta = std::fs::metadata(&path).ok()?;
    let age = age_ms(meta.modified());
    let bytes = std::fs::read(&path).ok()?;
    let text: String = String::from_utf8_lossy(&bytes)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace() || c == '\n')
        .chars()
        .take(64)
        .collect();
    Some(Bit { text, age })
}

/// The wire, as the payload writes it. Everything here is a file the C++ side
/// already touches, so the UI adds no new probe and cannot disturb a session.
#[tauri::command]
fn telemetry() -> Telemetry {
    let work = work_dir();
    let log = player_log().and_then(|(path, size)| {
        let name = path.file_name()?.to_string_lossy().to_string();
        let age = age_ms(std::fs::metadata(&path).ok()?.modified());
        Some(LogBit { name, age, size })
    });
    Telemetry {
        stage: read_bit(work.join("repl_stage.bin")),
        loop_mark: read_bit(work.join("loop.bin")),
        mutex: read_bit(work.join("mutex.bin")),
        log,
        work: work.display().to_string(),
    }
}

/// Ctrl+S writes the buffer somewhere real instead of leaving it in a textarea.
/// No dialog plugin: one known path is enough until the script library exists.
#[tauri::command]
fn save_script(code: String) -> Result<String, String> {
    let path = work_dir().join("ui-script.luau");
    std::fs::create_dir_all(work_dir()).map_err(|e| format!("work dir: {e}"))?;
    std::fs::write(&path, code).map_err(|e| format!("write: {e}"))?;
    Ok(path.display().to_string())
}

#[tauri::command]
async fn run_script(app: AppHandle, code: String, steps: String) -> Result<RunOut, String> {
    tauri::async_runtime::spawn_blocking(move || run_blocking(app, code, steps))
        .await
        .map_err(|e| format!("join: {e}"))?
}

#[derive(Serialize, Clone)]
struct RunEvent {
    id: u64,
    ok: bool,
    timeout: bool,
    output: String,
    ms: u128,
    chunk: usize,
    error: String,
}

static RUN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// id of the run that already emitted its terminal event. 0 means none yet.
static RUN_TERM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static RUN_ACTIVE: AtomicBool = AtomicBool::new(false);

fn emit_terminal(app: &AppHandle, id: u64, ev: RunEvent) {
    if RUN_TERM
        .compare_exchange(0, id, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        RUN_ACTIVE.store(false, Ordering::SeqCst);
        runlog(&format!("terminal id={} ok={} timeout={}", ev.id, ev.ok, ev.timeout));
        let _ = app.emit("zendo://run", ev);
    }
}

/// Start a run and return at once. The webview never awaits the session: the
/// button is released by `zendo://run`, and a watchdog emits that event even
/// when the pipe driver is wedged. Awaiting the command is what left the strip
/// on "running" while the client had already printed and moved on.
#[tauri::command]
async fn start_run(app: AppHandle, code: String, steps: String) -> Result<u64, String> {
    if RUN_ACTIVE.load(Ordering::SeqCst) {
        return Err("a run is already in flight".into());
    }
    let id = RUN_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
    RUN_TERM.store(0, Ordering::SeqCst);
    RUN_ACTIVE.store(true, Ordering::SeqCst);

    let worker = app.clone();
    std::thread::spawn(move || {
        let started = Instant::now();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_blocking(worker.clone(), code, steps)
        }));
        let ev = match res {
            Ok(Ok(out)) => RunEvent {
                id,
                ok: true,
                timeout: false,
                output: out.output,
                ms: out.ms,
                chunk: out.chunk,
                error: String::new(),
            },
            Ok(Err(e)) => RunEvent {
                id,
                ok: false,
                timeout: false,
                output: String::new(),
                ms: started.elapsed().as_millis(),
                chunk: 0,
                error: e,
            },
            Err(_) => RunEvent {
                id,
                ok: false,
                timeout: false,
                output: String::new(),
                ms: started.elapsed().as_millis(),
                chunk: 0,
                error: "run panicked".into(),
            },
        };
        emit_terminal(&worker, id, ev);
    });

    let watchdog = app.clone();
    std::thread::spawn(move || {
        for _ in 0..400 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if RUN_TERM.load(Ordering::SeqCst) == id || !RUN_ACTIVE.load(Ordering::SeqCst) {
                return;
            }
        }
        emit_terminal(
            &watchdog,
            id,
            RunEvent {
                id,
                ok: false,
                timeout: true,
                output: String::new(),
                ms: 40_000,
                chunk: 0,
                error: "run did not finish within 40s".into(),
            },
        );
    });

    Ok(id)
}

/// Reads the game's pid without launching a helper, so the poller never
/// flashes a console window on the player's screen.
#[tauri::command]
async fn client_pid() -> Option<u32> {
    tauri::async_runtime::spawn_blocking(|| find_process("RobloxPlayerBeta.exe"))
        .await
        .ok()
        .flatten()
}

const PROCESS_TERMINATE: u32 = 0x0001;

fn kill_clients() -> Vec<u32> {
    let mut killed = Vec::new();
    for name in ["RobloxPlayerBeta.exe", "RobloxCrashHandler.exe"] {
        for pid in processes_named(name) {
            unsafe {
                let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
                if h.is_null() {
                    continue;
                }
                if TerminateProcess(h, 1) != 0 {
                    killed.push(pid);
                }
                CloseHandle(h);
            }
        }
    }
    killed
}

/// A payload that dies mid-borrow can leave a windowless client holding the
/// singleton, and the next launch silently joins a process that will never show
/// a window. Nothing else can clear it: the client's own protection strips
/// PROCESS_TERMINATE from every handle but the one this elevated app can open.
#[tauri::command]
async fn kill_client() -> Vec<u32> {
    tauri::async_runtime::spawn_blocking(kill_clients)
        .await
        .unwrap_or_default()
}

/// Snapshot lookups, a WinHTTP round trip and a log scan all block. A sync
/// command runs on the webview's thread, so a slow network used to freeze the
/// strip - including the paint that shows the run badge.
#[tauri::command]
async fn profile() -> Option<Profile> {
    tauri::async_runtime::spawn_blocking(profile_blocking)
        .await
        .ok()
        .flatten()
}

#[tauri::command]
fn elevated() -> bool {
    is_elevated()
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            if let Some(w) = app.get_webview_window("main") {
                // The webview paints an opaque white sheet by default, which
                // sits on top of the DWM acrylic and cancels it. Clearing the
                // controller background is what lets the veil blend.
                let _ = w.set_background_color(Some(tauri::window::Color(0, 0, 0, 0)));
                if let Ok(hwnd) = w.hwnd() {
                    glass::acrylic(hwnd.0 as *mut c_void, 0x10, 0x141210);
                }
                let _ = w.set_focus();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            run_script,
            start_run,
            client_pid,
            telemetry,
            elevated,
            save_script,
            profile,
            kill_client
        ])
        .run(tauri::generate_context!())
        .expect("zendo ui");
}
