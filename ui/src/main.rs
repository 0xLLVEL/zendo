#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use std::ffi::c_void;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use zendo_core::{build, pipe};

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Process32FirstW(snap: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snap: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
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

fn find_process(name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap as isize == -1 {
            return None;
        }
        let mut e: ProcessEntry32W = std::mem::zeroed();
        e.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut found = None;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let end = e.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(0);
                if String::from_utf16_lossy(&e.sz_exe_file[..end]).eq_ignore_ascii_case(name) {
                    found = Some(e.th32_process_id);
                    break;
                }
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
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
    let mut buf = String::new();
    if f.read_to_string(&mut buf).is_err() {
        return String::new();
    }
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

fn steps_of<'a>(spec: &str, chunk: &'a [u8]) -> Result<Vec<pipe::Step<'a>>, String> {
    let mut v: Vec<pipe::Step> = Vec::new();
    let spec = if spec.trim().is_empty() { "chunk" } else { spec };
    for tok in spec.split(',') {
        match tok.trim() {
            "c" | "C" => v.push(pipe::Step::Cmd(b'C')),
            "chunk" | "L" => v.push(pipe::Step::Chunk(chunk)),
            "none" => {}
            other => return Err(format!("unknown step '{other}'")),
        }
    }
    Ok(v)
}

fn run_blocking(app: AppHandle, source: String, spec: String) -> Result<RunOut, String> {
    let t0 = Instant::now();
    let path = temp_script(&source)?;
    // A script that talks to the native surface has to run synchronously on the
    // borrowed thread: `zendo:loadstring` blocks inside the client until the
    // executor answers on the session pipe, and the deferred wrapper would move
    // the body onto a scheduler thread that outlives the pipe. Everything else
    // keeps the wrapper, so yielding stays legal for ordinary scripts.
    let chunk = if source.contains("zendo:") {
        zendo_core::compile_str(&source)?
    } else {
        build(&path)?
    };

    let server =
        pipe::Pipe::create(r"\\.\pipe\zendo-dev").map_err(|e| format!("pipe: {e}"))?;

    // This client kills new threads at TLS init, so the borrow path is the one
    // that actually works. Go straight to it: the thread path costs a 10 s
    // timeout on every run and never succeeds.
    // A payload only lives for one session: it restores the borrowed thread when
    // the pipe closes, so the 900 ms window is there to avoid racing a dying
    // server, not to find a reusable one.
    let pending = server.begin_accept();
    let mut injector: Option<std::process::Child> = None;
    // Snapshot the client's own Player log before injecting. A deferred chunk
    // outlives this pipe session, so print/warn never reach us as bytes; the
    // only lasting record is the log line the client writes itself.
    let log_start = player_log();
    let mut connected = pending.wait(900).map_err(|e| format!("accept: {e}"))?;
    if !connected {
        let _ = app.emit("zendo://stage", "injecting");
        match zendo_core::spawn_inject(&["--hijack"]) {
            Ok(c) => injector = Some(c),
            Err(e) => return Err(e),
        }
        match pending.wait(30_000) {
            Ok(true) => {}
            Ok(false) => return Err("payload never connected".into()),
            Err(e) => return Err(format!("accept: {e}")),
        }
    }
    let _ = app.emit("zendo://stage", "payload attached");

    let buf = Arc::new(Mutex::new(Vec::new()));
    let steps = steps_of(&spec, &chunk)?;
    let tap = Tap { app: app.clone(), buf: buf.clone() };
    let driven = pipe::drive(&server, &steps, tap);
    // The payload restores the borrowed thread once the pipe closes, so there is
    // no ack to wait for. The injector is only reaped when this run borrowed one.
    if let Some(inj) = injector {
        let inj = inj.wait_with_output().map_err(|e| format!("injector: {e}"))?;
        if !inj.status.success() {
            return Err(format!(
                "injector exited with {}\n{}{}",
                inj.status,
                String::from_utf8_lossy(&inj.stdout),
                String::from_utf8_lossy(&inj.stderr)
            ));
        }
    }
    driven.map_err(|e| format!("pipe: {e}"))?;

    // The chunk is deferred: the pipe session ends before Lua runs. Give the
    // client a moment to log the script's own print/warn lines, then relay them.
    let mut logged = String::new();
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        logged = tail(log_start.clone());
        if !logged.is_empty() {
            break;
        }
    }
    if !logged.is_empty() {
        let _ = app.emit("zendo://out", logged.clone());
        buf.lock().unwrap().extend_from_slice(logged.as_bytes());
    }

    let output = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    Ok(RunOut { output, ms: t0.elapsed().as_millis(), chunk: chunk.len(), path: path.display().to_string() })
}

#[tauri::command]
async fn run_script(app: AppHandle, code: String, steps: String) -> Result<RunOut, String> {
    tauri::async_runtime::spawn_blocking(move || run_blocking(app, code, steps))
        .await
        .map_err(|e| format!("join: {e}"))?
}

/// Reads the game's pid without launching a helper, so the poller never
/// flashes a console window on the player's screen.
#[tauri::command]
fn client_pid() -> Option<u32> {
    find_process("RobloxPlayerBeta.exe")
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![run_script, client_pid])
        .run(tauri::generate_context!())
        .expect("zendo ui");
}
