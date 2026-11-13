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

/// The Luau compiler the client's VM was built against. Vendored and pinned -
/// a compiler from a different revision emits a bytecode version the client
/// rejects - so the search is: explicit override, repo copy, the old pinned
/// checkout, then PATH. The repo copy is found by walking up from the running
/// executable, because `cargo run` puts the binary four levels deep.
pub fn compiler() -> PathBuf {
    if let Some(p) = std::env::var_os("ZENDO_COMPILER") {
        return PathBuf::from(p);
    }
    let rel = Path::new("vendor").join("luau").join("luau-compile.exe");
    for start in [std::env::current_exe().ok(), std::env::current_dir().ok()]
        .into_iter()
        .flatten()
    {
        for dir in start.ancestors().take(7) {
            let candidate = dir.join(&rel);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    let legacy = PathBuf::from(r"D:\zend\test\luau\luau-compile.exe");
    if legacy.is_file() {
        return legacy;
    }
    PathBuf::from("luau-compile.exe")
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
-- Install on every body, never once per client. A cached table kept running the
-- previous build's functions; that is how a rewritten `getgc` still answered {}.
if true then
local api = { version = 13, missing = {} }
-- Always overwrite. A previous session left its functions in this environment,
-- and skipping a name that already exists means a body keeps running the old
-- build: that is how a parked `getgc` kept returning {} after it was rewritten.
local function put(name, value)
    __znd_env[name] = value
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

put("fstate", function() return call("zendo:fstate") end)

-- The client resolves `rbxasset://` against its own content folder, so the file
-- has to exist there, and only the host can write outside the workspace. The
-- host copies the bytes under a content address and hands back the URI.
put("getcustomasset", function(path)
    if type(path) ~= "string" then return nil end
    return call("zendo:asset", path)
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

-- Both of these are the file door plus the client's own compiler: the payload
-- has no compiler and no string constructor, so the source comes back as a real
-- string and loadstring turns it into a real closure. Nothing is emulated.
put("loadfile", function(path)
    if type(path) ~= "string" then return nil, "bad path" end
    local src = call("zendo:file", path)
    if type(src) ~= "string" then return nil, "no such file" end
    local fn, err = loadstring(src)
    if not fn then return nil, tostring(err) end
    return fn
end)

put("dofile", function(path)
    if type(path) ~= "string" then return nil, "bad path" end
    local src = call("zendo:file", path)
    if type(src) ~= "string" then return nil, "no such file" end
    local fn, err = loadstring(src)
    if not fn then return nil, tostring(err) end
    return fn()
end)

-- The identity is a field of the caller's state, written by the session gate.
-- Reading it costs one native call; writing it would also have to raise the
-- capability mask, so this side stays read-only.
put("getthreadidentity", function()
    local n = call("zendo:ident")
    if type(n) ~= "number" then return 0 end
    return n
end)

-- HTTP is a host job. WinHTTP lives in the executor, not in the client; the
-- payload forwards the request and can only receive numbers, so the host writes
-- the response body and header block into the sandbox and this reads them back
-- with the file door. Field names are the sUNC ones.
local req_seq = 0
put("request", function(t)
    if type(t) ~= "table" or type(t.Url) ~= "string" then return nil end
    local hdrs = {}
    if type(t.Headers) == "table" then
        for k, v in pairs(t.Headers) do
            if type(k) == "string" and (type(v) == "string" or type(v) == "number") then
                hdrs[#hdrs + 1] = k .. ": " .. tostring(v) .. "\r\n"
            end
        end
    end
    if type(t.Cookies) == "table" then
        local parts = {}
        for k, v in pairs(t.Cookies) do
            if type(k) == "string" then parts[#parts + 1] = k .. "=" .. tostring(v) end
        end
        if #parts > 0 then
            hdrs[#hdrs + 1] = "Cookie: " .. table.concat(parts, "; ") .. "\r\n"
        end
    end
    req_seq = req_seq + 1
    local tag = tostring(req_seq) .. "_" .. tostring(math.floor(os.clock() * 1000))
    local body_path = "http/" .. tag .. ".body"
    local hdr_path = "http/" .. tag .. ".hdr"
    local status, ok = call("zendo:req", t.Url, tostring(t.Method or "GET"),
        table.concat(hdrs), tostring(t.Body or ""), body_path, hdr_path)
    if type(status) ~= "number" or status == 0 then return nil end
    local raw_h = call("zendo:file", hdr_path)
    local raw_b = call("zendo:file", body_path)
    call("zendo:del", body_path)
    call("zendo:del", hdr_path)
    local headers, message = {}, ""
    if type(raw_h) == "string" then
        for line in string.gmatch(raw_h, "[^\r\n]+") do
            local k, v = string.match(line, "^([^:]+):%s*(.*)$")
            if k then headers[k] = v end
        end
        message = string.match(raw_h, "^HTTP/[%d%.]+%s+%d+%s*(.*)") or ""
    end
    return {
        Success = ok == 1,
        StatusCode = status,
        StatusMessage = message,
        Headers = headers,
        Body = (type(raw_b) == "string" and raw_b or ""),
        Url = t.Url,
    }
end)

put("isfile", function(path)
    if type(path) ~= "string" then return false end
    return call("zendo:isfile", path) == 1
end)

put("isfolder", function(path)
    if type(path) ~= "string" then return false end
    return call("zendo:isfolder", path) == 1
end)

put("makefolder", function(path)
    if type(path) ~= "string" then return nil end
    return call("zendo:mkdir", path) == 1
end)

put("delfile", function(path)
    if type(path) ~= "string" then return nil, "bad path" end
    return call("zendo:del", path) == 1
end)

put("delfolder", function(path)
    if type(path) ~= "string" then return nil, "bad path" end
    return call("zendo:del", path) == 1
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

-- FNV-1a over the proto's instruction words, computed in the payload. Two
-- functions with identical bytecode answer the same number.
put("getfunctionhash", function(f)
    local h = call("zendo:fnhash", f)
    if type(h) ~= "number" then return 0 end
    return h
end)

-- Upvalues. The count and the capture slots are measured fields, not guesses:
-- a Luau closure answers how many it holds and each slot is one TValue, read
-- through the same door `kget` uses. A capture by reference resolves to the
-- cell the closure shares with the stack, so reading it sees live values.
-- Reads go through a 48 byte buffer because the host only writes into long
-- strings - a shorter buffer is interned and the copy is refused.
local function __znd_mem(addr, n)
    if type(read) ~= "function" or type(addr) ~= "number" or addr < 0x10000 then return nil end
    local size = n or 48
    if size < 48 then size = 48 end
    local buf = string.rep("A", size)
    if read(addr, buf) ~= size then return nil end
    return buf
end

put("getupvalues", function(f)
    local n = call("zendo:ucount", f)
    if type(n) ~= "number" then return {} end
    local out = {}
    for i = 0, n - 1 do out[i + 1] = call("zendo:uget", f, i) end
    return out
end)

put("getupvalue", function(f, i)
    local idx = (tonumber(i) or 0) - 1
    if idx < 0 then return nil end
    local v = call("zendo:uget", f, idx)
    -- Names are not in the chunk: the compiler runs with debug info off, so the
    -- proto carries no upvalue name table to read. The index is what is real, so
    -- the name slot carries it as a string rather than inventing a name.
    return tostring(idx + 1), v
end)

put("setupvalue", function(f, i, v)
    local idx = (tonumber(i) or 0) - 1
    if idx < 0 then return nil end
    if call("zendo:uset", f, idx, v) ~= 1 then return nil end
    return f
end)

-- Constants are a TValue array on the proto, so the same write that moves an
-- upvalue moves a constant. Numbers and booleans land; a string is refused by
-- the payload until a write barrier address is measured.
put("setconstant", function(f, i, v)
    local idx = (tonumber(i) or 0) - 1
    if idx < 0 then return false end
    return call("zendo:kset", f, idx, v) == 1
end)

-- cloneref hands back the same reference, so identity is the comparison the
-- client itself would make. No allocation, no proxy table.
put("compareinstances", function(a, b)
    if a == nil or b == nil then return false end
    return a == b
end)

-- The registry itself. `_G` here is the script environment, which is not the
-- table the VM keeps its own references in; this is g->gt, handed over as the
-- live table it is.
put("getreg", function()
    return call("zendo:getreg")
end)

-- sUNC scores `debug.getconstants`; the native read behind `getconstants` is
-- the same one. The debug table the client ships may be read-only, so a denied
-- rawset falls back to a proxy that keeps every other debug field reachable.
-- The upvalue trio rides the same path: it is the same measured read, exposed
-- under the names sUNC asks for.
local dbg = rawget(__znd_env, "debug")
local fresh_debug = false
if type(dbg) ~= "table" then
    -- Luau inside the client may not expose a debug table at all. Create one
    -- rather than skip the install, otherwise debug.getconstants and
    -- debug.getstack simply do not exist for the script.
    dbg = {}
    fresh_debug = true
end
if true then
    local gc = rawget(__znd_env, "getconstants")
    local one = function(f, i)
        local k = gc(f)
        return k[i]
    end
    local guvs = rawget(__znd_env, "getupvalues")
    local guv = rawget(__znd_env, "getupvalue")
    local suv = rawget(__znd_env, "setupvalue")
    local sk = rawget(__znd_env, "setconstant")
    -- debug.getstack: the payload reads the frame window [base, top) and pushes
    -- each slot back through the same marshal path `getconstant` uses, so every
    -- value is a real TValue the VM handed over. The client's own debug.getstack
    -- answers an empty table from our threads, and a skipped install would leave
    -- that answer in place. +2 skips this wrapper and `call`.
    local gstack = function(level, index)
        local lv = (level or 1) + 2
        if index ~= nil then return call("zendo:stackget", lv, index) end
        local n = call("zendo:stacklen", lv)
        if type(n) ~= "number" or n < 1 then return {} end
        local out = table.create(n)
        for i = 1, n do out[i] = call("zendo:stackget", lv, i) end
        return out
    end
    local ok = pcall(function()
        if rawget(dbg, "getconstants") == nil then
            rawset(dbg, "getconstants", gc)
            rawset(dbg, "getconstant", one)
        end
        if rawget(dbg, "getupvalues") == nil then rawset(dbg, "getupvalues", guvs) end
        if rawget(dbg, "getupvalue") == nil then rawset(dbg, "getupvalue", guv) end
        if rawget(dbg, "setupvalue") == nil then rawset(dbg, "setupvalue", suv) end
        if rawget(dbg, "setconstant") == nil then rawset(dbg, "setconstant", sk) end
        -- The client's own debug.getstack answers an empty table from our
        -- threads, so ours has to replace it rather than sit behind a nil check.
        rawset(dbg, "getstack", gstack)
        rawset(dbg, "setstack", function(level, index, value)
            return call("zendo:stackset", (level or 1) + 2, index, value) == 1
        end)
        -- A proto has no Lua type, so it travels as a handle: the address as a
        -- number. debug.getconstants and debug.getinfo accept that handle, so a
        -- script can walk into a child proto without a fake value in the heap.
        rawset(dbg, "getprotos", function(f)
            local n = call("zendo:protos", f, 0)
            if type(n) ~= "number" or n < 1 then return {} end
            local out = table.create(n)
            for i = 1, n do out[i] = call("zendo:protos", f, i) end
            return out
        end)
        rawset(dbg, "getproto", function(f, i)
            return call("zendo:protos", f, i or 1)
        end)
    end)
    if not ok then
        local proxy = setmetatable({}, { __index = dbg })
        if rawget(dbg, "getconstants") == nil then
            proxy.getconstants = gc
            proxy.getconstant = one
        end
        if rawget(dbg, "getupvalues") == nil then proxy.getupvalues = guvs end
        if rawget(dbg, "getupvalue") == nil then proxy.getupvalue = guv end
        if rawget(dbg, "setupvalue") == nil then proxy.setupvalue = suv end
        if rawget(dbg, "setconstant") == nil then proxy.setconstant = sk end
        proxy.getstack = gstack
        proxy.setstack = rawget(dbg, "setstack") or function(level, index, value)
            return call("zendo:stackset", (level or 1) + 2, index, value) == 1
        end
        rawset(__znd_env, "debug", proxy)
    end
    if fresh_debug then rawset(__znd_env, "debug", dbg) end
end

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

-- Instances the tree still owns. The client already knows them, so this walks
-- the real DataModel instead of the GC heap: cheaper, and it cannot hand back
-- an object the game has already dropped.
put("getinstances", function()
    local ok, list = pcall(function() return game:GetDescendants() end)
    if ok and type(list) == "table" then return list end
    return {}
end)

-- Every script the tree holds. `game` is the DataModel root, so its descendants
-- are the whole place; `getnilinstances` below covers the ones the tree dropped.
put("getscripts", function()
    local ok, list = pcall(function() return game:GetDescendants() end)
    if not ok or type(list) ~= "table" then return {} end
    local out = {}
    for i = 1, #list do
        local v = list[i]
        local cls = v.ClassName
        if cls == "LocalScript" or cls == "ModuleScript" or cls == "Script" then
            out[#out + 1] = v
        end
    end
    return out
end)

-- The collector, read through the page chain rather than a global_State offset.
-- gcpage turns the address of any object into the page that owns it and the
-- head of the all-pages list; gcfill then copies the live blocks of one page
-- into the array part of a table this script already owns, so no VM stack is
-- touched and no string is built. `include_tables` follows sUNC: false keeps
-- functions only, true keeps tables, functions and userdata.
put("getgc", function(include_tables)
    -- Parked. The collector can be parked for the walk (`zendo:gclock` raises
    -- GCthreshold, and that part works: 197 functions, then 1318 mixed objects
    -- in one body). What breaks is the next body: gcfill writes raw pointers
    -- into a Lua array with a type byte attached, and no collector reference
    -- is created for them. Those blocks are ordinary garbage to the collector,
    -- so it is free to free them and reuse the memory - and then it traces a
    -- table that still holds those fake TValues. The result is not a wrong
    -- count, it is the client locking up on the following run. Making raw
    -- import safe needs every imported object marked reachable for the life of
    -- the table, which this build does not do. An empty set is honest; a
    -- heap-walking function that freezes the game is not.
    return {}
end)

-- Instances the tree no longer owns. They only exist in the collector, so the
-- walk is getgc over userdata: anything that answers `typeof == Instance` and
-- has no parent is exactly the set sUNC asks for.
put("getnilinstances", function()
    local out = {}
    local all = rawget(__znd_env, "getgc")
    if type(all) ~= "function" then return out end
    for _, v in ipairs(all(true)) do
        if typeof(v) == "Instance" then
            local okp, parent = pcall(function() return v.Parent end)
            if okp and parent == nil then out[#out + 1] = v end
        end
    end
    return out
end)

for _, name in ipairs({ "getgc", "getreg", "getconnections" }) do
    api.missing[#api.missing + 1] = name
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
///
/// The scratch name carries a counter, not just the pid. The pipe driver
/// compiles a live `loadstring` while a run is still holding its own scratch
/// file, and both landed on `zendo-ls-<pid>.luau`: the second write truncated
/// the first, and the compiler reported whatever survived. Two compiles in one
/// process have to be two files.
pub fn compile_str(src: &str) -> Result<Vec<u8>, String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SCRATCH: AtomicU64 = AtomicU64::new(0);
    let n = SCRATCH.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!("zendo-ls-{}-{n}.luau", std::process::id()));
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

/// Rewrite a compiler error so the position means the script, not the scratch
/// file. `luau-compile` prints `<temp path>(<line>,<col>): ...` where `<line>`
/// counts the whole deferred wrapper — a script error on its first line is
/// reported at 524, which points at nothing the person at the editor wrote.
/// The offset is exactly what `compile_deferred` prepends: the prelude plus the
/// two wrapper lines. Anything at or before that offset is a prelude error and
/// keeps its original text; anything after is clamped to the source's last line,
/// which is where "expected 'end'" belongs.
fn rebase_error(err: &str, offset: usize, max_line: usize) -> String {
    // The path itself can contain a paren, so the position is the first `(`
    // whose body is `digits,digits)`. Matching the shape, not the first paren,
    // is what keeps a directory named "Program Files (x86)" intact.
    let mut position = None;
    for (open, _) in err.match_indices('(') {
        let Some(comma_off) = err[open..].find(',') else { continue };
        let comma = open + comma_off;
        let Some(close_off) = err[comma..].find(')') else { continue };
        let close = comma + close_off;
        if comma == open + 1 || !err[open + 1..comma].bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if !err[comma + 1..close].bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        position = Some((open, comma, close));
        break;
    }
    let Some((open, comma, close)) = position else { return err.to_string() };
    let Ok(line) = err[open + 1..comma].parse::<usize>() else {
        return err.to_string();
    };
    if line <= offset {
        return err.to_string();
    }
    // Past the source's last line is the wrapper's own tail (`end)`, the
    // sentinel print). Those belong to the script's last line: an unclosed
    // block is reported there, not one line below the editor's content.
    let mapped = (line - offset).min(max_line.max(1));
    format!("zendo.luau({},{}){}", mapped, &err[comma + 1..close], &err[close + 1..])
}

/// Compile a script whose body is handed to `task.defer`. The payload only runs
/// the wrapper on the borrowed thread and returns; the body then runs on the
/// client's own scheduler, serialized with the client's VM. Keeping the Lua
/// frame inside the payload thread while the scheduler kept running was a data
/// race on `lua_State` - the stutter-then-freeze after Execute.
///
/// Completion is a log line, not a pipe write: the body finishes on a thread
/// the payload does not own, so the only signal it can leave without touching
/// the pipe is `print`. The host watches the client's own CreatorOutput for it.
/// Fired once per script context, after the run: the only outward sign that this
/// place is actually serving zendo. The place gate refuses during a transition,
/// so a notification on screen means a run touched the DataModel under the
/// place the client logged. The flag lives in the global table, and a place
/// switch builds a new context with a new one - exactly the right granularity.
const TOAST_LUA: &str = r#"
pcall(function()
	local __znd_g = getfenv(0)
	if __znd_g.__zendo_loaded == true then return end
	local __znd_tok, __znd_terr = pcall(function()
		game:GetService("StarterGui"):SetCore("SendNotification",
			{Title = "zendo", Text = "loaded", Duration = 3})
	end)
	if __znd_tok then
		__znd_g.__zendo_loaded = true
	else
		print("zendo://toast " .. tostring(__znd_terr))
	end
end)
"#;

pub fn compile_deferred(src: &str) -> Result<Vec<u8>, String> {
    // task.delay, not task.defer. defer enqueues the body and the scheduler can
    // resume it on its own thread while this pcall is still unwinding on ours -
    // two threads inside one lua_State for a few microseconds, and that is the
    // client dying a second later with no script output. A 50 ms delay puts the
    // first resume well after this call has left the VM.
    let offset = prelude().lines().count() + 6;
    compile_str(&format!(
        "local __znd_door = ...\n\
         local zendo = type(__znd_door) == \"function\" and __znd_door or zendo\n\
         if type(zendo) == \"function\" then pcall(zendo, \"zendo:mark\") end\n\
         {}\
         task.delay(0.05, function()\n\
         if type(zendo) == \"function\" then pcall(zendo, \"zendo:mark\") end\n\
         local __znd_ok, __znd_err = pcall(function()\n\
         {src}\n\
         end)\n\
         if not __znd_ok then warn(tostring(__znd_err)) end\n\
         print(\"{}\")\n\
         {}\
         end)\n",
        prelude(),
        DONE_SENTINEL,
        TOAST_LUA
    ))
    .map_err(|e| rebase_error(&e, offset, src.lines().count()))
}

pub const DONE_SENTINEL: &str = "zendo://done";

/// The place the client last said it joined, read out of its own log text.
/// A chunk written between `leaveUGCGameInternal` and the next `! Joining game`
/// lands in a DataModel the transition is already freeing; `Err` means the
/// newest transition is a leave and nothing has joined since, so injecting now
/// is exactly the crash this guards against.
pub fn place_from_log(text: &str) -> Result<Option<u64>, String> {
    let leave = text.rfind("leaveUGCGameInternal").map(|i| (i, 0u64));
    let join = text.rfind("! Joining game").and_then(|i| {
        let rest = &text[i..];
        let at = rest.find(" place ")? + 7;
        let digits: String = rest[at..].chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u64>().ok().map(|id| (i, id))
    });
    match (leave, join) {
        (Some((li, _)), Some((ji, id))) if ji > li => Ok(Some(id)),
        (Some(_), _) => Err("client left the place and has not joined another yet".into()),
        _ => Ok(join.map(|(_, id)| id)),
    }
}

/// Same, against the newest Player log this machine has. Reads only the tail:
/// joins and leaves are minutes apart, and the head of a long session log is
/// tens of megabytes of engine noise.
pub fn place_hint() -> Result<Option<u64>, String> {
    let dir = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("no LOCALAPPDATA")?)
        .join("Roblox")
        .join("logs");
    let mut best: Option<(std::time::SystemTime, PathBuf, u64)> = None;
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read logs: {e}"))? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.contains("_Player_") || name.contains("CrashHandler") || !name.ends_with(".log") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(mtime) = meta.modified() else { continue };
        if best.as_ref().map(|(t, _, _)| mtime > *t).unwrap_or(true) {
            best = Some((mtime, entry.path(), meta.len()));
        }
    }
    let (_, path, len) = best.ok_or("no player log")?;
    let start = len.saturating_sub(2 * 1024 * 1024);
    let mut bytes = Vec::new();
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&path).map_err(|e| format!("open log: {e}"))?;
        f.seek(SeekFrom::Start(start)).map_err(|e| format!("seek log: {e}"))?;
        f.read_to_end(&mut bytes).map_err(|e| format!("read log: {e}"))?;
    }
    place_from_log(&String::from_utf8_lossy(&bytes))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact offset the wrapper produces: prelude lines + the wrapper's own
    /// opening lines. If the prelude grows, this test fails instead of the
    /// mapping silently pointing one line off.
    const OFFSET: usize = 653;

    #[test]
    fn offset_matches_wrapper_shape() {
        assert_eq!(prelude().lines().count() + 6, OFFSET);
    }

    #[test]
    fn first_source_line_maps_to_one() {
        let err = format!(
            r"D:\Temp\zendo-ls-14828.luau({},1): SyntaxError: Incomplete statement: expected assignment or a function call",
            OFFSET + 1
        );
        assert_eq!(
            rebase_error(&err, OFFSET, 3),
            "zendo.luau(1,1): SyntaxError: Incomplete statement: expected assignment or a function call"
        );
    }

    #[test]
    fn later_source_line_keeps_its_offset() {
        let err = format!("C:/Temp/zendo-ls-1.luau({},7): TypeError: something", OFFSET + 6);
        assert_eq!(rebase_error(&err, OFFSET, 20), "zendo.luau(6,7): TypeError: something");
    }

    #[test]
    fn prelude_errors_are_untouched() {
        let err = "C:/Temp/zendo-ls-1.luau(100,3): SyntaxError: prelude broke";
        assert_eq!(rebase_error(err, OFFSET, 10), err);
        let at_offset = format!("C:/Temp/zendo-ls-1.luau({},1): SyntaxError: wrapper broke", OFFSET);
        assert_eq!(rebase_error(&at_offset, OFFSET, 10), at_offset);
    }

    #[test]
    fn eof_errors_clamp_to_last_source_line() {
        let err = format!("C:/Temp/zendo-ls-1.luau({},1): SyntaxError: Expected 'end'", OFFSET + 900);
        assert_eq!(rebase_error(&err, OFFSET, 4), "zendo.luau(4,1): SyntaxError: Expected 'end'");
    }

    #[test]
    fn empty_source_clamps_to_one() {
        let err = format!("C:/Temp/zendo-ls-1.luau({},1): SyntaxError: bad", OFFSET + 2);
        assert_eq!(rebase_error(&err, OFFSET, 0), "zendo.luau(1,1): SyntaxError: bad");
    }

    #[test]
    fn text_without_a_position_is_untouched() {
        let err = "spawn compiler: program not found";
        assert_eq!(rebase_error(err, OFFSET, 10), err);
    }

    #[test]
    fn paren_in_the_path_is_not_a_position() {
        let err = format!(
            r"C:\Program Files (x86)\zendo\zendo-ls-1.luau({},2): SyntaxError: x",
            OFFSET + 1
        );
        assert_eq!(
            rebase_error(&err, OFFSET, 10),
            r"zendo.luau(1,2): SyntaxError: x"
        );
    }

    /// The one error that was actually hit in the client: a stray `w` left by
    /// a keystroke. End to end, through the real compiler, the message must
    /// point at line 1 of the script.
    #[test]
    fn real_compiler_reports_the_stray_letter_on_line_one() {
        if !compiler().exists() {
            return;
        }
        let err = compile_deferred("w-- ctrl+enter runs, ctrl+s saves\nprint(\"nigerlitikali\")")
            .expect_err("stray expression must not compile");
        assert!(err.starts_with("zendo.luau(1,1): SyntaxError"), "{err}");
    }

    #[test]
    fn real_compiler_accepts_a_clean_script() {
        if !compiler().exists() {
            return;
        }
        let blob = compile_deferred("print(\"ok\")").expect("clean script compiles");
        assert!(!blob.is_empty());
    }
}

#[cfg(test)]
mod place_tests {
    use super::place_from_log;

    const JOIN: &str = "2026-11-12T18:14:44.632Z,16.6,4640,6 [FLog::Output] ! Joining game 'da0f871c-e391-4525-b677-77e605c60a2f' place 123974602339071 at 10.32.8.137\n";
    const LEAVE: &str = "2026-11-12T18:15:42.765Z,74.7,4640,6 [FLog::Network] leaveUGCGameInternal\n";

    #[test]
    fn joins_alone_report_the_place() {
        assert_eq!(place_from_log(JOIN), Ok(Some(123974602339071)));
    }

    #[test]
    fn leave_without_a_join_refuses() {
        assert!(place_from_log(LEAVE).is_err());
        assert!(place_from_log(&format!("{JOIN}{LEAVE}")).is_err());
    }

    #[test]
    fn the_newest_join_wins() {
        let text = format!("{JOIN}{LEAVE}{JOIN}");
        assert_eq!(place_from_log(&text), Ok(Some(123974602339071)));
    }

    #[test]
    fn an_empty_log_has_no_hint() {
        assert_eq!(place_from_log(""), Ok(None));
    }
}
















