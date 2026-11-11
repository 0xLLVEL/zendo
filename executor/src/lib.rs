//! Shared core for every zendo front end: bytecode build, named-pipe transport
//! and process injection. The CLI and the gUI both sit on this.

pub mod lbc;
pub mod pipe;
pub mod remap;
pub mod tables;

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// A GUI parent has no console. Without this flag every helper we start flashes
/// an empty console window on the player's screen.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn quiet(cmd: &mut Command) -> &mut Command {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
}

pub fn compiler() -> PathBuf {
    std::env::var_os("ZENDO_COMPILER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\zend\test\luau\luau-compile.exe"))
}

pub fn injector() -> PathBuf {
    std::env::var_os("ZENDO_INJECTOR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\zendo\injector\target\release\zendo-inject.exe"))
}

pub fn payload_dll() -> PathBuf {
    std::env::var_os("ZENDO_PAYLOAD")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\zendo\payload\build\zendo.dll"))
}

pub fn compile(src: &Path) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new(compiler());
    cmd.args(["-O0", "-g0", "--binary"]).arg(src);
    let out = quiet(&mut cmd)
        .output()
        .map_err(|e| format!("spawn compiler: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(out.stdout)
}

/// A chunk executed straight from the borrowed thread cannot yield: the C frame
/// it would resume into belongs to a thread the game has already taken back.
/// Hand the work to the scheduler and let our frame unwind, so `task.wait` and
/// `task.spawn` run on the client's own thread where yielding is legal.
fn wrap(src: &str) -> String {
    format!(
        "task.defer(function()\n\
         local __znd_ok, __znd_err = pcall(function()\n\
         {src}\n\
         end)\n\
         if not __znd_ok then warn(tostring(__znd_err)) end\n\
         end)\n"
    )
}

/// Compile a Luau source file and remap its opcodes to the client's runtime
/// numbering. The result is the exact blob the payload's `L` command expects.
pub fn build(src: &Path) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    let tmp = std::env::temp_dir().join(format!("zendo-chunk-{}.luau", std::process::id()));
    // The deferred wrapper is what makes yielding legal, but it also moves the
    // body onto a scheduler thread. A synchronous experiment needs the source
    // exactly as written.
    let body = if std::env::var_os("ZENDO_RAW").is_some() {
        text
    } else {
        wrap(&text)
    };
    std::fs::write(&tmp, body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let blob = compile(&tmp);
    let _ = std::fs::remove_file(&tmp);
    let blob = blob?;
    let out = remap::remap(&blob).map_err(|e| format!("remap: {e}"))?;
    Ok(out.blob)
}

/// Start the injector beside a pipe that is already being served. The payload
/// hosts a long-lived REPL, so the injector must not wait for DllMain to end.
pub fn spawn_inject(extra: &[&str]) -> Result<Child, String> {
    let mut cmd = Command::new(injector());
    cmd.args(["--name", "RobloxPlayerBeta.exe", "--dll"])
        .arg(payload_dll())
        .args(extra);
    quiet(&mut cmd)
        .spawn()
        .map_err(|e| format!("spawn injector: {e}"))
}

/// Same, but the injector writes straight into our console. Diagnostics must
/// never wait behind a pipe that may never connect.
pub fn spawn_inject_stream(extra: &[&str]) -> Result<Child, String> {
    let mut cmd = Command::new(injector());
    cmd.args(["--name", "RobloxPlayerBeta.exe", "--dll"])
        .arg(payload_dll())
        .args(extra);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("spawn injector: {e}"))
}

pub fn inject_blocking(extra: &[&str]) -> Result<std::process::Output, String> {
    spawn_inject(extra)?
        .wait_with_output()
        .map_err(|e| format!("injector wait: {e}"))
}
