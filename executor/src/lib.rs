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
if type(__znd_mark) ~= "table" or __znd_mark.version ~= 6 then
local api = { version = 6, missing = {} }
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

-- A thread the session gate lifted carries identity 8; a callback the game
-- invokes on its own runs at its own level. That is the whole test.
put("checkcaller", function()
    return call("zendo:caller") == 1
end)

-- Filesystem lives on the host. The payload cannot build a Luau string, so the
-- answer arrives as a chunk that returns the bytes; `call` runs it and the VM
-- hands back a real string.
put("readfile", function(path)
    if type(path) ~= "string" then return nil end
    return call("zendo:file", path)
end)

put("writefile", function(path, data)
    if type(path) ~= "string" then return nil, "bad path" end
    return call("zendo:filew", path, tostring(data or "")) == 1
end)

put("appendfile", function(path, data)
    if type(path) ~= "string" then return nil, "bad path" end
    local old = call("zendo:file", path)
    local body = (type(old) == "string" and old or "") .. tostring(data or "")
    return call("zendo:filew", path, body) == 1
end)

put("isfile", function(path)
    if type(path) ~= "string" then return false end
    return call("zendo:isfile", path) == 1
end)

put("isfolder", function(path)
    if type(path) ~= "string" then return false end
    local list = call("zendo:listfiles", path)
    return type(list) == "table"
end)

put("makefolder", function(path)
    if type(path) ~= "string" then return nil end
    if call("zendo:listfiles", path) ~= nil then return true end
    return call("zendo:filew", path .. "/.keep", "") == 1
end)

put("delfile", function(path)
    if type(path) ~= "string" then return nil, "bad path" end
    return call("zendo:filew", path, "") == 1
end)

put("listfiles", function(path)
    local raw = call("zendo:listfiles", type(path) == "string" and path or "")
    local out = {}
    if type(raw) ~= "table" then return out end
    for _, entry in ipairs(raw) do
        out[#out + 1] = entry[1]
    end
    return out
end)

-- Instance helpers are plain Luau: the client already hands us real Instances
-- through game:GetService, so none of this needs a new native door.
put("gethui", function()
    local ok, cg = pcall(function() return game:GetService("CoreGui") end)
    if ok then return cg end
    return nil
end)

put("compareinstances", function(a, b)
    return a == b
end)

-- A constant already lives in the VM heap as a TValue, so it can be moved onto
-- the stack as-is: no string constructor needed, and the value keeps its type.
put("getconstants", function(f)
    local w = table.pack(call("zendo:proto", f, 160))
    local sizek = w[4]
    if type(sizek) ~= "number" then return {} end
    local out = {}
    for i = 0, sizek - 1 do
        out[#out + 1] = call("zendo:kget", f, i)
    end
    return out
end)

put("getinfo", function(f)
    local w = table.pack(call("zendo:proto", f, 160))
    return {
        linedefined = w[2],
        maxstacksize = w[3],
        numk = w[4],
    }
end)

put("cloneref", function(ref)
    return ref
end)

-- Encoding runs in plain Luau, not in the client's memory. There is no string
-- constructor reachable from the payload yet, so a native base64 would have
-- nothing to hand back; a Lua implementation returns real strings today and
-- costs nothing a script can measure.
local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local b64map = {}
for i = 1, #b64chars do b64map[string.byte(b64chars, i)] = i - 1 end

put("base64encode", function(data)
    data = tostring(data or "")
    local out = {}
    local n = #data
    local i = 1
    while i <= n do
        local a = string.byte(data, i) or 0
        local b = string.byte(data, i + 1)
        local c = string.byte(data, i + 2)
        local v = a * 65536 + (b or 0) * 256 + (c or 0)
        local c1 = math.floor(v / 262144) % 64
        local c2 = math.floor(v / 4096) % 64
        local c3 = math.floor(v / 64) % 64
        local c4 = v % 64
        out[#out + 1] = string.sub(b64chars, c1 + 1, c1 + 1)
        out[#out + 1] = string.sub(b64chars, c2 + 1, c2 + 1)
        out[#out + 1] = b and string.sub(b64chars, c3 + 1, c3 + 1) or "="
        out[#out + 1] = c and string.sub(b64chars, c4 + 1, c4 + 1) or "="
        i += 3
    end
    return table.concat(out)
end)

put("base64decode", function(data)
    data = tostring(data or ""):gsub("[^%w%+/=]", "")
    local out = {}
    local n = #data
    local i = 1
    while i <= n do
        local v = 0
        local pad = 0
        for k = 0, 3 do
            local ch = string.byte(data, i + k)
            if ch == nil or ch == 61 then
                pad += 1
                v *= 64
            else
                local d = b64map[ch]
                if d == nil then pad += 1; v *= 64 else v = v * 64 + d end
            end
        end
        out[#out + 1] = string.char(math.floor(v / 65536) % 256)
        if pad < 2 then out[#out + 1] = string.char(math.floor(v / 256) % 256) end
        if pad < 1 then out[#out + 1] = string.char(v % 256) end
        i += 4
    end
    return table.concat(out)
end)

-- LZ4 block format. The compressor emits literal-only sequences, which is a
-- valid block - a decompressor reads it without knowing it never matched -
-- and the decompressor handles the full token grammar so a block produced by
-- any real LZ4 lands back as the original bytes.
put("lz4compress", function(data)
    data = tostring(data or "")
    local out = {}
    local n = #data
    local i = 1
    while i <= n do
        local len = math.min(65535, n - i + 1)
        local token = len >= 15 and 240 or len * 16
        out[#out + 1] = string.char(token)
        if len >= 15 then
            local rest = len - 15
            while rest >= 255 do out[#out + 1] = string.char(255); rest -= 255 end
            out[#out + 1] = string.char(rest)
        end
        out[#out + 1] = string.sub(data, i, i + len - 1)
        i += len
    end
    return table.concat(out)
end)

put("lz4decompress", function(data)
    data = tostring(data or "")
    local out = {}
    local n = #data
    local i = 1
    while i <= n do
        local token = string.byte(data, i)
        i += 1
        local lit = math.floor(token / 16)
        if lit == 15 then
            while true do
                local b = string.byte(data, i)
                if b == nil then return table.concat(out) end
                i += 1
                lit += b
                if b ~= 255 then break end
            end
        end
        if lit > 0 then
            out[#out + 1] = string.sub(data, i, i + lit - 1)
            i += lit
        end
        if i > n then break end
        local lo = string.byte(data, i) or 0
        local hi = string.byte(data, i + 1) or 0
        i += 2
        local buf = table.concat(out)
        local offset = lo + hi * 256
        if offset == 0 or offset > #buf then break end
        local mlen = (token % 16) + 4
        if token % 16 == 15 then
            while true do
                local b = string.byte(data, i)
                if b == nil then return table.concat(out) end
                i += 1
                mlen += b
                if b ~= 255 then break end
            end
        end
        local start = #buf - offset + 1
        local piece = string.sub(buf, start, start + mlen - 1)
        while #piece < mlen do piece ..= piece end
        out[#out + 1] = string.sub(piece, 1, mlen)
    end
    return table.concat(out)
end)

put("fireclickdetector", function(cd, dist)    local ok, sig = pcall(function() return cd and cd.MouseClick end)
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
-- Announce the state this prelude is running on, so checkcaller can tell our
-- threads from the client's own.
if type(zendo) == "function" then pcall(zendo, "zendo:mark") end
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
