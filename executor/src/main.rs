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

fn tail(path: &PathBuf, offset: u64, secs: u64) -> bool {
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
                if r.trim() == zendo_core::DONE_SENTINEL {
                    let _ = w.flush();
                    return true;
                }
                if r.trim_start().starts_with("zendo://") {
                    continue;
                }
                let _ = writeln!(w, "» {r}");
            } else if let Some((_, r)) = line.split_once("[FLog::CreatorWarning] Warning: ") {
                let _ = writeln!(w, "» warn: {r}");
            }
        }
        let _ = w.flush();
    }
    false
}

fn usage() -> ! {
    eprintln!("usage: zendo-exec <run|defer|build|serve> <script.luau|blob.bin> [out.bin]");
    eprintln!("  run <file>    raw chunk on the borrowed thread (prelude + script)");
    eprintln!("  defer <file>  same wrapper the UI uses: body on the client scheduler,");
    eprintln!("                place-gated, waits for the log sentinel and prints output");
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
    // Ask a parked payload to unwind for good. Without this a payload thread
    // stays inside the client between runs, and a process in that state cannot
    // be terminated - the window goes away, the pid keeps answering.
    if args.len() >= 2 && args[1] == "detach" {
        let server = match pipe::Pipe::create(r"\\.\pipe\zendo-dev") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("pipe create failed: {e}");
                std::process::exit(1);
            }
        };
        let pending = server.begin_accept();
        let ms = std::env::var("ZENDO_ACCEPT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3000);
        match pending.wait(ms) {
            Ok(true) => {
                if let Err(e) = server.write_all(b"x") {
                    eprintln!("detach write failed: {e}");
                    std::process::exit(1);
                }
                println!("detached");
            }
            Ok(false) => {
                eprintln!("no payload parked");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("accept failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() < 3 {
        usage();
    }
    let src = PathBuf::from(&args[2]);
    if args[1] == "serve" {
        serve(&src);
    }
    let deferred = args[1] == "defer";
    let chunk = if deferred {
        let text = match std::fs::read_to_string(&src) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("read {}: {e}", src.display());
                std::process::exit(1);
            }
        };
        match zendo_core::compile_deferred(&text) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("build failed: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match build(&src) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("build failed: {e}");
                std::process::exit(1);
            }
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
    if args[1] != "run" && args[1] != "defer" {
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
    // An idle payload parks in its reconnect loop for twenty minutes, so a run
    // that finds one should join it instead of mapping another image into the
    // same client. The wait is only paid in full when there is no payload;
    // ZENDO_ACCEPT_MS covers a slow client without rebuilding.
    let accept_ms = std::env::var("ZENDO_ACCEPT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2000);
    let mut connected = match pending.wait(accept_ms) {
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
    let mode = std::env::var("ZENDO_STEPS").unwrap_or_else(|_| {
        if deferred { "place,defer".to_string() } else { String::new() }
    });
    let mut steps: Vec<pipe::Step> = Vec::new();
    if mode.is_empty() {
        steps.push(pipe::Step::Cmd(b'C'));
        steps.push(pipe::Step::Chunk(&chunk));
    } else {
        for tok in mode.split(',') {
            match tok.trim() {
                "c" | "C" => steps.push(pipe::Step::Cmd(b'C')),
                // print-hook probe: payload swaps print for its own C closure
                // and calls it from the Luau VM, which is an indirect call into
                // our image - the CFG test in one command.
                "probe" | "h" => steps.push(pipe::Step::Cmd(b'h')),
                // page type + CFG registration + mitigation policy probe
                "mitig" | "g" => steps.push(pipe::Step::Cmd(b'g')),
                // native loadstring via a C closure whose c.f is our luau_load
                // wrapper: the direct test of VM -> payload indirect calls.
                "native" | "k" => steps.push(pipe::Step::Cmd(b'k')),
                // ntdll CFG dispatch stub patch, then the same native test
                "guard" | "x" => steps.push(pipe::Step::Cmd(b'x')),
                // read GuardCFDispatchFunctionPointer from the client load config
                "loadcfg" | "y" => steps.push(pipe::Step::Cmd(b'y')),
                "chunk" | "L" => steps.push(pipe::Step::Chunk(&chunk)),
                "defer" | "d" => steps.push(pipe::Step::Defer(&chunk)),
                // The same gate the UI sends: the place the client says it
                // joined, so the payload can refuse a chunk that belongs to a
                // DataModel the transition is still building.
                "place" | "G" => match zendo_core::place_hint() {
                    Ok(Some(id)) => {
                        eprintln!("[z] place {id}");
                        steps.push(pipe::Step::Place(id));
                    }
                    Ok(None) => eprintln!("[z] no place in the log tail"),
                    Err(why) => {
                        eprintln!("[z] {why}");
                        std::process::exit(1);
                    }
                },
                "ident" => {
                    let id: u8 = std::env::var("ZENDO_IDENT")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(7);
                    steps.push(pipe::Step::Ident(&chunk, id));
                }
                "none" | "" => {}
                t if t.len() == 1 => steps.push(pipe::Step::Cmd(t.as_bytes()[0])),
                other => eprintln!("unknown step {other}"),
            }
        }
    }
    let log = player_log();
    let log_pos = log.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(0);
    let driven = pipe::drive_wait(&server, &steps, stdout.lock(),
                                  std::env::var_os("ZENDO_RAW").is_none());
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
            .unwrap_or(if deferred { 20 } else { 8 });
        if secs > 0 {
            let seen = tail(&p, log_pos, secs);
            if deferred && !seen {
                eprintln!("[z] no completion sentinel in {}s", secs);
                std::process::exit(1);
            }
        }
    }
}
