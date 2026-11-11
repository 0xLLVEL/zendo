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

/// The Lua layer every chunk starts with. It is written to be safe to run any
/// number of times: the marker in the shared env short-circuits the whole body
/// after the first pass, and every name is installed only when it is still
/// absent. That second rule is what keeps the payload's own bindings
/// (`loadstring`, `read`, `write`, `dm`, ...) untouched - gbind owns those, and
/// a prelude that overwrote them would replace a working door with a shim.
///
/// Nothing here invents a function the client does not have. `getgc`, `getreg`
/// and `getconnections` are only reported; a fake version would hand a script a
/// function that lies about what it can see.
fn prelude() -> &'static str {
    r#"do
local __znd_env = (getfenv and getfenv()) or _G or {}
local __znd_mark = rawget(__znd_env, "__zendo_api")
if type(__znd_mark) ~= "table" or __znd_mark.version ~= 1 then
local api = { version = 1, missing = {} }
local function put(name, value)
    if rawget(__znd_env, name) == nil then __znd_env[name] = value end
end
local function call(name, ...)
    if type(zendo) ~= "function" then return nil end
    return zendo(name, ...)
end

put("getgenv", function() return __znd_env end)
put("getrenv", function() return __znd_env end)
put("_G", __znd_env)
put("identifyexecutor", function() return "zendo", "4080" end)

put("getsenv", function(f)
    local ok, e = pcall(getfenv, f)
    if ok and type(e) == "table" then return e end
    return nil
end)

local readonly = setmetatable({}, { __mode = "k" })
put("setreadonly", function(t, v)
    if t == nil then return false end
    readonly[t] = v ~= false
    return true
end)
put("isreadonly", function(t)
    return readonly[t] == true
end)

put("getrawmetatable", function(v)
    local ok, mt = pcall(getmetatable, v)
    if ok and type(mt) == "table" then return mt end
    return nil
end)
put("setrawmetatable", function(v, mt)
    local ok, err = pcall(setmetatable, v, mt)
    if ok then return true end
    return false, tostring(err)
end)

put("hookmetamethod", function(obj, method, hook)
    local ok, mt = pcall(getmetatable, obj)
    if not ok or type(mt) ~= "table" then
        return nil, "metatable locked (" .. type(mt) .. ")"
    end
    local orig = rawget(mt, method)
    mt[method] = hook
    return orig
end)

put("hookfunction", function(old, new)
    local oc, oe, oc_exec = call("zendo:probe", old)
    local nc, ne, nc_exec = call("zendo:probe", new)
    if oc == nil or nc == nil then return nil, "not a function" end
    if oc_exec ~= 1 or nc_exec ~= 1 then
        return nil, "luau closure has no entry point to swap"
    end
    if not oe or oe == 0 or not ne or ne == 0 then
        return nil, "entry point unreadable"
    end
    if call("zendo:fnset", old, ne) ~= 1 then
        return nil, "patch rejected"
    end
    local done = false
    return old, function()
        if done then return false end
        done = true
        return call("zendo:fnset", old, oe) == 1
    end
end)

-- What a closure IS, decided by where its entry point lives rather than by a
-- byte in the header. A C closure's entry is inside an executable image; a Luau
-- closure has no callable entry at all, only a Proto at +0x18.
put("iscclosure", function(f)
    local _, _, exec = call("zendo:probe", f)
    return exec == 1
end)
put("islclosure", function(f)
    local _, _, exec = call("zendo:probe", f)
    return exec == 0
end)

put("fireclickdetector", function(cd, dist)
    local ok, sig = pcall(function() return cd and cd.MouseClick end)
    if not ok or sig == nil then return false, "no MouseClick" end
    local fired, err = pcall(function() return sig:Fire(dist or 0) end)
    if fired then return true end
    return false, tostring(err)
end)

for _, name in ipairs({ "getgc", "getreg", "getconnections" }) do
    if rawget(__znd_env, name) == nil then
        api.missing[#api.missing + 1] = name
    end
end
__znd_env.__zendo_api = api
end
end
"#
}

/// A chunk executed straight from the borrowed thread cannot yield: the C frame
/// it would resume into belongs to a thread the game has already taken back.
/// Hand the work to the scheduler and let our frame unwind, so `task.wait` and
/// `task.spawn` run on the client's own thread where yielding is legal.
fn wrap(src: &str) -> String {
    // The vararg is the native door the payload binds into every chunk it
    // loads. A wrapped script is deferred, so it runs after exec returns and
    // may still need the session pipe (loadstring, dynamic loading). Signalling
    // done is what tells the host the scheduler thread finished with it.
    format!(
        "{}\
         local __znd = ...\n\
         task.defer(function()\n\
         local __znd_ok, __znd_err = pcall(function()\n\
         {src}\n\
         end)\n\
         if not __znd_ok then warn(tostring(__znd_err)) end\n\
         if __znd then pcall(__znd, \"zendo:done\") end\n\
         end)\n",
        prelude()
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
        format!("{}\n{}", prelude(), text)
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

/// Compile Luau source text with the same offline pipeline `build` uses. This is
/// the other half of `zendo:loadstring`: the client has no compiler, so every
/// live loadstring call lands here while the script is waiting for it.
pub fn compile_str(src: &str) -> Result<Vec<u8>, String> {
    let tmp = std::env::temp_dir().join(format!("zendo-ls-{}.luau", std::process::id()));
    std::fs::write(&tmp, src).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let blob = compile(&tmp);
    let _ = std::fs::remove_file(&tmp);
    let blob = blob?;
    remap::remap(&blob).map(|o| o.blob).map_err(|e| format!("remap: {e}"))
}

/// Compile a script that will run raw, straight on the borrowed thread. Raw is
/// the only path that can call `loadstring` (the session pipe stays reachable),
/// so this is where the Lua layer has to be present. `compile_str` stays pure:
/// a `loadstring` body is a fragment, not a script, and giving it the prelude
/// would change what it returns.
pub fn compile_script(src: &str) -> Result<Vec<u8>, String> {
    compile_str(&format!("{}\n{}", prelude(), src))
}

/// Start the injector beside a pipe that is already being served. The payload
/// hosts a long-lived REPL, so the injector must not wait for DllMain to end.
pub fn spawn_inject(extra: &[&str]) -> Result<Child, String> {
    let mut cmd = Command::new(injector());
    match std::env::var("ZENDO_PID") {
        Ok(pid) if !pid.trim().is_empty() => {
            cmd.arg(pid.trim()).arg("--dll");
        }
        _ => {
            cmd.args(["--name", "RobloxPlayerBeta.exe", "--dll"]);
        }
    }
    cmd.arg(payload_dll())
        .args(extra);
    quiet(&mut cmd)
        .spawn()
        .map_err(|e| format!("spawn injector: {e}"))
}

/// Same, but the injector writes straight into our console. Diagnostics must
/// never wait behind a pipe that may never connect.
pub fn spawn_inject_stream(extra: &[&str]) -> Result<Child, String> {
    let mut cmd = Command::new(injector());
    match std::env::var("ZENDO_PID") {
        Ok(pid) if !pid.trim().is_empty() => {
            cmd.arg(pid.trim()).arg("--dll");
        }
        _ => {
            cmd.args(["--name", "RobloxPlayerBeta.exe", "--dll"]);
        }
    }
    cmd.arg(payload_dll())
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
