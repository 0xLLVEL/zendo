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
    // A thread of our own dies at TLS init in this client, so borrow a parked
    // thread instead. The failed attempt is not tried first any more: it left a
    // second payload image behind and broke the borrow that followed.
    eprintln!("[z] pipe up, hijacking");
    let hijack_child = match zendo_core::spawn_inject_stream(&["--hijack"]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("inject failed: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[z] waiting for payload");
    if let Err(e) = server.accept() {
        eprintln!("accept failed: {e}");
        std::process::exit(1);
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
    let driven = pipe::drive(&server, &steps, stdout.lock());
    // The payload waits for this ack before leaving DllMain. Without it the
    // borrowed thread never returns and its context can never be restored.
    let _ = server.write_all(b"ZEND1 ack\n");
    std::thread::sleep(std::time::Duration::from_millis(400));
    match hijack_child.wait_with_output() {
        Ok(out) => echo(&out),
        Err(e) => eprintln!("injector wait failed: {e}"),
    }
    if let Err(e) = driven {
        eprintln!("pipe error: {e}");
        std::process::exit(1);
    }
    let _ = std::io::stdout().flush();
}
