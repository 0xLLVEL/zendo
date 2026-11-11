use std::io::Write;
use std::path::PathBuf;
use std::process::Child;

use zendo_core::{build, pipe, spawn_inject};

fn echo(out: &std::process::Output) {
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        println!("{}", line);
    }
    for line in String::from_utf8_lossy(&out.stderr).lines() {
        eprintln!("{}", line);
    }
}

/// Borrow a thread of the game. `pick_thread` prefers one parked inside an
/// ntdll wait and falls back to any thread if none is parked.
fn inject() -> Result<Child, String> {
    spawn_inject(&["--hijack"])
}

/// The client already writes every `print` into its own Player log, and a chunk
/// handed to the scheduler outlives our pipe. Tail that file for the session.
fn player_log() -> Option<PathBuf> {
    let dir = std::path::Path::new(&std::env::var_os("LOCALAPPDATA")?).join("Roblox").join("logs");
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for e in std::fs::read_dir(dir).ok()? {
        let Ok(e) = e else { continue };
        let p = e.path();
        let Some(name) = p.file_name().map(|n| n.to_string_lossy().to_string()) else { continue };
        if !name.ends_with("_last.log") || name.contains("CrashHandler") {
            continue;
        }
        let Ok(mt) = e.metadata().and_then(|m| m.modified()) else { continue };
        if best.as_ref().map_or(true, |(t, _)| mt > *t) {
            best = Some((mt, p));
        }
    }
    best.map(|(_, p)| p)
}

fn tail(path: &PathBuf, offset: u64, secs: u64) {
    use std::io::{Read, Seek, SeekFrom};
    let mut pos = offset;
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let out = std::io::stdout();
    while std::time::Instant::now() < end {
        std::thread::sleep(std::time::Duration::from_millis(120));
        let Ok(mut f) = std::fs::File::open(path) else { continue };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len <= pos {
            continue;
        }
        let mut buf = Vec::new();
        if f.seek(SeekFrom::Start(pos)).is_err() || (&mut f).take(len - pos).read_to_end(&mut buf).is_err() {
            continue;
        }
        pos = len;
        let mut w = out.lock();
        for line in String::from_utf8_lossy(&buf).lines() {
            if let Some((_, r)) = line.split_once("[FLog::CreatorOutput] ") {
                let _ = writeln!(w, "» {r}");
            } else if let Some((_, r)) = line.split_once("[FLog::CreatorWarning] Warning: ") {
                let _ = writeln!(w, "» warn: {r}");
            }
        }
        let _ = w.flush();
    }
}

fn usage() -> ! {
    eprintln!("usage: zendo-exec <run|build|serve> <script.luau|blob.bin> [out.bin]");
    std::process::exit(2);
}

fn serve(src: &PathBuf) -> ! {
    let chunk = std::fs::read(src).unwrap_or_else(|e| {
        eprintln!("read failed: {e}");
        std::process::exit(1);
    });
    let server = match pipe::Pipe::create(r"\\.\pipe\zendo-dev") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pipe create failed: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = server.accept() {
        eprintln!("accept failed: {e}");
        std::process::exit(1);
    }
    let stdout = std::io::stdout();
    if let Err(e) = pipe::drive(&server, &[pipe::Step::Chunk(&chunk)], stdout.lock()) {
        eprintln!("pipe error: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "probe" {
        println!("live={}", pipe::payload_live());
        return;
    }
    if args.len() < 3 {
        usage();
    }
    let src = PathBuf::from(&args[2]);
    if args[1] == "serve" {
        serve(&src);
    }
    let chunk = match build(&src) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("build failed: {e}");
            std::process::exit(1);
        }
    };
    if args[1] == "build" {
        let dst = PathBuf::from(
            args.get(3)
                .cloned()
                .unwrap_or_else(|| format!("{}.bin", src.display())),
        );
        if let Err(e) = std::fs::write(&dst, &chunk) {
            eprintln!("write failed: {e}");
            std::process::exit(1);
        }
        println!("{}: {} bytes -> {}", src.display(), chunk.len(), dst.display());
        return;
    }
    if args[1] != "run" {
        usage();
    }
    println!("chunk {} bytes, injecting", chunk.len());

    let server = match pipe::Pipe::create(r"\\.\pipe\zendo-dev") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pipe create failed: {e} (already running?)");
            std::process::exit(1);
        }
    };
    // Reuse a payload that is already listening; otherwise borrow a thread.
    // A live mutex means the previous payload may still be in its one second
    // tail, so wait briefly before deciding. When nothing answers we inject
    // anyway: the payload-side mutex guard turns a duplicate into a no-op
    // instead of a second image.
    let pending = server.begin_accept();
    let mut hijack_child: Option<Child> = None;
    let mut connected = match pending.wait(600) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("accept failed: {e}");
            std::process::exit(1);
        }
    };
    if connected {
        eprintln!("[z] live session, reusing");
    } else {
        // A held mutex only means the previous payload thread never let go of
        // it after returning from DllMain. The pipe is the only session that
        // matters: inject a fresh image and let this injection own the pipe.
        eprintln!("[z] no session, injecting");
        match zendo_core::spawn_inject_stream(&["--hijack"]) {
            Ok(c) => hijack_child = Some(c),
            Err(e) => {
                eprintln!("inject failed: {e}");
                std::process::exit(1);
            }
        }
        match pending.wait(30_000) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("[z] payload never connected");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("accept failed: {e}");
                std::process::exit(1);
            }
        }
    }
    eprintln!("[z] payload connected");
    let stdout = std::io::stdout();
    let mode = std::env::var("ZENDO_STEPS").unwrap_or_default();
    let mut steps: Vec<pipe::Step> = Vec::new();
    if mode.is_empty() {
        steps.push(pipe::Step::Cmd(b'C'));
        steps.push(pipe::Step::Chunk(&chunk));
    } else {
        for tok in mode.split(',') {
            match tok.trim() {
                "c" | "C" => steps.push(pipe::Step::Cmd(b'C')),
                "chunk" | "L" => steps.push(pipe::Step::Chunk(&chunk)),
                "none" | "" => {}
                t if t.len() == 1 => steps.push(pipe::Step::Cmd(t.as_bytes()[0])),
                other => eprintln!("unknown step {other}"),
            }
        }
    }
    let log = player_log();
    let log_pos = log.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(0);
    let driven = pipe::drive(&server, &steps, stdout.lock());
    // The payload parks itself after `END` and waits for the next server, so
    // there is no ack to send. Only a payload that finished the session (no
    // live one was reused) leaves the injector to reap.
    if let Some(child) = hijack_child {
        match child.wait_with_output() {
            Ok(out) => echo(&out),
            Err(e) => eprintln!("injector wait failed: {e}"),
        }
    }
    if let Err(e) = driven {
        eprintln!("pipe error: {e}");
        std::process::exit(1);
    }
    let _ = std::io::stdout().flush();
    if let Some(p) = log {
        let secs = std::env::var("ZENDO_TAIL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(8);
        if secs > 0 {
            tail(&p, log_pos, secs);
        }
    }
}
