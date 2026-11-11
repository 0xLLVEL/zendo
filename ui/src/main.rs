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
    let chunk = build(&path)?;

    let server =
        pipe::Pipe::create(r"\\.\pipe\zendo-dev").map_err(|e| format!("pipe: {e}"))?;

    // This client kills new threads at TLS init, so the borrow path is the one
    // that actually works. Go straight to it: the thread path costs a 10 s
    // timeout on every run and never succeeds.
    let _ = app.emit("zendo://stage", "injecting");
    let injector = zendo_core::spawn_inject(&["--hijack"])?;

    server.accept().map_err(|e| format!("accept: {e}"))?;
    let _ = app.emit("zendo://stage", "payload attached");

    let buf = Arc::new(Mutex::new(Vec::new()));
    let steps = steps_of(&spec, &chunk)?;
    let tap = Tap { app: app.clone(), buf: buf.clone() };
    let driven = pipe::drive(&server, &steps, tap);
    // The payload waits for this ack before leaving DllMain. Without it the
    // borrowed thread never returns and its context is never restored.
    let _ = server.write_all(b"ZEND1 ack\n");
    std::thread::sleep(std::time::Duration::from_millis(400));
    let inj = injector.wait_with_output().map_err(|e| format!("injector: {e}"))?;
    if !inj.status.success() {
        return Err(format!(
            "injector exited with {}\n{}{}",
            inj.status,
            String::from_utf8_lossy(&inj.stdout),
            String::from_utf8_lossy(&inj.stderr)
        ));
    }
    driven.map_err(|e| format!("pipe: {e}"))?;

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
