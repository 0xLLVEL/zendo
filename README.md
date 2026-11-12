# zendo

An internal Lua executor for Roblox on Windows: a CRT-free payload mapped into the
live client, a CFG-aware injector, a Rust host with a named-pipe control plane,
and a Luau API layer built on offsets measured from the running process.

> **Target build:** `0.746.0.7461267`, client hash `f0ea5da9412f4e35`.
> Every address, offset and layout in this repository was measured against that
> build. Nothing here is claimed to work on another one.

---

## Contents

- [Design principles](#design-principles)
- [Architecture](#architecture)
- [Components](#components)
- [How it works](#how-it-works)
  - [1. Injection](#1-injection)
  - [2. Control-flow guard](#2-control-flow-guard)
  - [3. Reaching the Lua state](#3-reaching-the-lua-state)
  - [4. Executing a chunk](#4-executing-a-chunk)
  - [5. The native op dispatcher](#5-the-native-op-dispatcher)
  - [6. The pipe protocol](#6-the-pipe-protocol)
  - [7. The Lua API layer](#7-the-lua-api-layer)
- [Build](#build)
- [Usage](#usage)
- [Measured layout](#measured-layout)
- [sUNC status](#sunc-status)
- [Verification rules](#verification-rules)
- [Known issues](#known-issues)
- [Repository layout](#repository-layout)

---

## Design principles

Four rules shape every decision in the codebase.

1. **Do not patch `.text`.** Hyperion checks code integrity, not data. Every hook
   is made by rewriting a pointer in data: a closure's `f` field, a Lua table, a
   namecall entry, a config block.
2. **Every address is resolved at runtime.** RVAs from the dump are a fallback;
   the image base is reported by the payload over the pipe. A new client build
   means regenerating offsets, not rewriting the executor.
3. **Nothing of ours appears in the PEB.** The payload is never passed to
   `LoadLibrary`; there is no entry in `InLoadOrderModuleList`.
4. **Code runs on a client thread.** The payload borrows a thread that is already
   parked in a wait, runs there, and restores the context. Executing from a
   foreign thread was never stable.

---

## Architecture

```
┌──────────────────────────────┐        ┌───────────────────────────────┐
│ zendo-ui (Tauri, Rust)       │        │ zendo-exec (CLI, Rust)        │
│  • process discovery         │        │  • run / build / serve        │
│  • compile + drive the pipe  │        │  • probe / detach             │
└──────────────┬───────────────┘        └──────────────┬────────────────┘
               │  zendo_core (lib)                      │
               │   build() → Luau bytecode chunk        │
               │   pipe::Pipe → \\.\pipe\zendo-dev      │
               │   spawn_inject_stream(["--hijack"])    │
               ▼                                        ▼
        ┌────────────────────────────────────────────────────┐
        │ zendo-inject.exe (Rust, no crates)                 │
        │  • PE parse, relocations, import resolution        │
        │  • SEC_IMAGE mapping (MEM_IMAGE + CFG coverage)    │
        │  • thread hijack: suspend, redirect RIP, restore   │
        └────────────────────────┬───────────────────────────┘
                                 │ WriteProcessMemory / NtMapViewOfSection
                                 ▼
        ┌────────────────────────────────────────────────────┐
        │ zendo.dll (payload, C++20, CRT-free)               │
        │  • PEB-resolved Win32 entry points, empty IAT      │
        │  • pipe client, op dispatcher, Lua reader/writer   │
        │  • CFG bitmap arming for its own code targets      │
        └────────────────────────┬───────────────────────────┘
                                 │  captured C closure → zendo(op, ...)
                                 ▼
        ┌────────────────────────────────────────────────────┐
        │ RobloxPlayerBeta.exe                               │
        │  VisualEngine → DataModel → ScriptContext → lua_State │
        └────────────────────────────────────────────────────┘
```

A run looks like this:

1. Host creates `\\.\pipe\zendo-dev` and waits for a client.
2. If no payload answers, the injector maps `zendo.dll` into the client and
   hijacks a parked thread's RIP into a stub that calls `DllMain`.
3. The payload connects to the pipe as a client and prints `RDY` when idle.
4. The host answers each `RDY` with a command or a chunk.
5. Script output arrives as `P ...` lines; the session ends with `END`, and the
   payload parks itself for the next connection.

---

## Components

| Path | Language | Role |
|---|---|---|
| `payload/` | C++20 | The injected DLL. One translation unit assembled from role files under `src/` (`core/`, `luau/`, `ipc/`, `boot/`, plus the `stages` museum), built `/NODEFAULTLIB /ENTRY:DllMain`, empty import table, Win32 entry points resolved from the PEB by export hash. |
| `injector/` | Rust, no crates | PE loader. Parses the image locally, applies relocations, resolves imports, then maps into the target. Supports both a private manual map and a `SEC_IMAGE` mapping. Provides `--hijack` to run an entry stub on an existing thread. |
| `executor/` | Rust | Host library + CLI. Compiles Luau source with `luau-compile`, parses LBC, hosts the pipe, drives the command/chunk exchange, tails the client log for script output. |
| `ui/` | Rust + Tauri + JS | Desktop front end on the same `zendo_core`: process list, editor, run button, live output. |
| `docs/` | Markdown | `re.md` — reverse-engineering notes, one measured fact at a time. `sunc.md` — the sUNC checklist and current status. *(local only)* |
| `resource/` | — | IDA database, decrypted client image, offset headers, `structs.hpp`, `hyperion.hpp`. *(local only, large)* |
| `tools/` | Python | IDA/disassembly helpers, callers scan, string find, LBC dump. *(local only)* |
| `tests/` | Python | Beacon and injection smoke tests (`pipe_beacon.py`, `remote_inject.py`, `roblox_beacon.py`). *(local only)* |
| `work/` | mixed | Probes, logs, scratch scripts used while measuring. *(local only)* |

Directories marked *local only* are git-ignored: they hold multi-gigabyte dumps,
per-run logs and scratch data that do not belong in history.

---

## How it works

### 1. Injection

The injector has two mapping strategies and they exist for different reasons.

**Private manual map** — the classic route. `VirtualAllocEx`, write headers and
sections, apply relocations, resolve imports, run the entry stub on a remote
thread. The image is `MEM_PRIVATE`: invisible to the loader, but also invisible
to the control-flow guard bitmap, and that is a problem (see next section).

**`SEC_IMAGE` mapping** — `NtCreateSection(SEC_IMAGE)` on the DLL file, then
`NtMapViewOfSection` into the target. The kernel does the relocations and the
pages become `MEM_IMAGE`, which means the CFG bitmap already covers them and an
indirect call from the client's VM into our code is legal without further work.
The payload resolves its own imports, so there is nothing left to fix up.

`CreateRemoteThread` is not usable on this client: it is killed with
`0xC000071C` even when the start address is `kernel32!Sleep`. The injector
therefore borrows a thread:

- enumerate threads, prefer ones parked inside an `ntdll` wait,
- skip threads sitting in waits that never return to user mode (a patched RIP
  there freezes the process),
- suspend, read context, redirect RIP to a stub in the payload, resume,
- the stub runs the entry point and restores the original context.

A named mutex (`zendo-live`) exists, but it is created **unowned** and nothing
ever waits on it. Liveness is the mtime of `work/loop.bin`, which the seek loop
rewrites every second: a fresh stamp means a payload thread is parked in the
client and will reach the next pipe on its own. Ownership was tried and dropped —
a session that ends cleanly leaves its thread alive, so a dead image read as a
live owner and the next injection either waited forever or mapped a second one.

### 2. Control-flow guard

This client runs with Control Flow Guard enabled, and the dispatcher that rejects
our pages is not `ntdll!__guard_dispatch_icall_fptr`. The client's own load
config (RVA `0x6787260`, size `0x138`) points at two slots inside the executable:

| Slot | Address | Holds | Module |
|---|---|---|---|
| check | `base+0x6565d30` | `base+0x710c10` | exe |
| dispatch | `base+0x6565d40` | `entry+0x4c9360` | **RobloxPlayerBeta.dll** |

The slot page cannot be written — `VirtualProtect` returns
`ERROR_ACCESS_DENIED (5)` — and the protector maps it no-change, so patching the
dispatcher body fails the same way.

What did work is the bitmap the dispatcher reads:

```
map base          dll+0xec2998
index page state  MEM_RESERVE, never committed for our range
commit            VirtualAlloc(MEM_COMMIT, PAGE_READWRITE) succeeds, err 0
bit math          byte = addr >> 15, bit = (addr >> 12) & 7
```

Set the bit and the dispatcher's `bt r11, r10; jae reject` falls through to
`jmp rax`. Measured with a C closure whose `f` was swapped to a native loader:
the bit was `0x2`, the VM made the indirect call into our image, and the client
survived.

Two related facts worth recording:

- Fresh executable pages are impossible in this process. `VirtualAlloc` with
  `PAGE_TARGETS_INVALID`, plain `PAGE_EXECUTE_READWRITE`, and
  `PAGE_READWRITE → VirtualProtect(PAGE_EXECUTE_READ)` all fail with `1655`
  (`ERROR_DYNAMIC_CODE_BLOCKED`). There is no shellcode route here; everything
  must live in a mapped image.
- `SetProcessValidCallTargets` is used inside the payload (`arm_cfg`) to mark the
  handful of payload functions a swapped closure points at, so those calls stay
  legal for the whole session.

### 3. Reaching the Lua state

The chain is resolved from the client image, all RVAs relative to the reported
base:

```
VisualEngine static             base + 0x8942E38
  → fake DataModel              + 0xAF0
    → ScriptContext             + 0x440
      → lua_State (encoded)     sc + 0x210
```

The state pointer is stored split-encoded. Decoding a slot (`decode_split`):

```
lo = (u32)slot - (u32)encoded
hi = (u32)slot - (u32)(encoded >> 32)
L  = (hi << 32) | lo
```

Inside `lua_State`, the fields the payload uses:

| Offset | Field |
|---|---|
| `L+0x08` | extras block pointer (`RobloxExtraSpace`); identity lives at `extras+0x70` |
| `L+0x58` | stack base |
| `L+0x60` | stack top |
| `L+0x68` | stack last |
| `L+0x70` | current `CallInfo`; `ci+0x08` is the frame top |

Arguments are read with `lua_arg`: `base + 16 * index`, two 64-bit words. A
`TValue` is `{ value: u64, extra: u64, tag: u32 }` — tag at `+0x0C`.

### 4. Executing a chunk

The client ships no compiler, so compilation happens on the host:

```
luau-compile -O0 -g0 --binary script.luau
```

The resulting LBC blob is wrapped in the container the client's loader expects
(magic `0xE009325B4A107A52`, then the LBC body) and handed to the payload, which
calls the client's own `LuaVMLoad` through a swapped closure. The VM pushes the
closure; returning `1` hands it back to Lua.

Two execution modes exist:

- **wrapped** (default) — the chunk is handed to `task.delay(0.05, …)`, so it
  outlives the pipe and the scheduler thread owns the frame. `task.defer` was
  the first choice and it lost the client: the scheduler can resume the body on
  its own thread while the `pcall` that queued it is still unwinding on ours,
  which is two threads inside one `lua_State`. 50 ms puts the first resume well
  after the queueing call has left the VM;
- **raw** (`ZENDO_RAW=1`) — the chunk runs synchronously inside the pipe step, no
  wrapper. Every probe in `work/` uses this, because it makes frame behaviour
  observable.

Results come back the same way: the payload writes a `TValue` into `L->top` and
advances it. A number is tag `3` with an IEEE double in the value word. The push
is refused if it would cross `stack_last` or `ci->top`, because a push past the
frame is a heap smash that only shows up as a dead client later.

### 5. The native op dispatcher

The Lua layer talks to native code through one captured C closure. `zendo(op,
...)` is dispatched on the op string; each op reads its arguments, does its work,
and returns values by writing into the frame.

Ops implemented today (`payload/src/luau/native.inc`, dispatched by `native_api`; 46 names):

| Group | Ops |
|---|---|
| session | `ping`, `caller`, `mark`, `ident`, `done` |
| memory | `read`, `readn`, `write`, `peek`, `poke`, `wr8`, `scratch`, `base`, `dm` |
| instances | `svc`, `svcs` |
| filesystem | `file`, `filew`, `isfile`, `isfolder`, `mkdir`, `listfiles`, `del` |
| closures | `probe`, `fninfo`, `fnset`, `ref`, `argsum`, `strinfo` |
| proto / constants | `proto`, `protoscan`, `kget`, `kset` |
| upvalues | `ucount`, `uget`, `uset` |
| loading | `load`, `loadf`, `loadstring`, `logv` |

Every read goes through `readable()` (VirtualQuery, `MEM_COMMIT`, no
`PAGE_NOACCESS`/`PAGE_GUARD`, range fits the region). Every write goes through
`api_write()`, which only asks for a protection change when the page really is
read-only, computes the range from the page the address sits in, and keeps
`PAGE_TARGETS_NO_UPDATE` so the CFG bitmap stays intact.

### 6. The pipe protocol

The host is the pipe **server** (`\\.\pipe\zendo-dev`); the payload connects as a
**client**. Framing is line-based for control and length-prefixed for bulk.

Host → payload:

| Frame | Meaning |
|---|---|
| single letter | one command step (`h` print probe, `g` mitigation probe, `k` native loader, `x` guard patch, `y` load-config read, `q` quit) |
| `L` + `u32le len` + bytes | a raw chunk to run |
| `i` + `u8 ident` + `u32le len` + bytes | a chunk run synchronously with a given identity |
| `x` | detach / unwind the parked payload |

Payload → host:

| Frame | Meaning |
|---|---|
| `RDY` | idle, ready for the next frame |
| `P <text>` | script output; the host prints it with a `»` prefix |
| `END` | the deferred chunk finished |
| `C <len>` + source | the script called `loadstring`; compile now and answer on the same stream |
| `Q <6 lens>` + six strings | HTTP request forwarded to the host (url, method, headers, body, body path, header path) |
| `A <0|1>` | filesystem result |
| `F/G/S/L/T/M/D ...` | filesystem request: read, write, is-file, list, is-folder, mkdir, delete |

`loadstring` is answered with `K <len>` + bytecode (or `E <len>` + message). The
filesystem requests are answered with a *chunk* that returns the bytes as a
literal, because the payload cannot construct a Luau string on its own — the VM
turns the literal into a real string on the other side. That chunk carries the
same spoofed 64-byte declared size as the injection chunk; without it the loader's
`size - 8 >= 0x118` gate rejects every reply of 288 bytes or more.

HTTP is a host job. `Q` forwards six strings, WinHTTP performs the round trip, and
the host writes the response body and raw header block into two sandbox files. The
payload answers `R <status> <ok>`; the Lua `request` helper reads both files back
through the file door and builds the sUNC table. No socket is opened inside the
client, and TLS, proxies and redirects are WinHTTP's problem.

The outer host dispatcher must accept every request letter (`F G S L T M D Q`).
Dropping one silently deadlocks the script waiting for an answer.

### 7. The Lua API layer

The prelude is compiled into every chunk ahead of user code. Two rules govern it:

- **`gbind` runs first.** A small binding chunk defines `zendo`, `loadstring`,
  `read`, `write`, `peek`, `poke`, `dm`, `base`, `svc`, `svcs` into the
  environment. The prelude must never overwrite those bindings.
- **The prelude is idempotent.** It stamps `__zendo_api.version` in the shared
  environment and short-circuits when the version already matches, so a second
  run does not rebuild (or double-wrap) anything.

Names are installed with `put(name, value)`, which only sets a global when it is
still `nil`. The `debug` table gets the measured functions wired in with
`rawset`, with a proxy fallback (`__index` → original table) when the client's
`debug` table refuses writes.

The prelude never invents a function it cannot back with a real read. Functions
that would need an allocation, a property descriptor walk, or a signal layout
that has not been measured are simply absent, and the API table records them in
`api.missing`.

---

## Build

Four artifacts, three toolchains, no package manager. Everything is built from
source on the machine that runs it.

### Prerequisites

| Tool | Needed for | Notes |
|---|---|---|
| Windows 11 x64 | everything | the target is a Windows-only process |
| Visual Studio 2022 with **Desktop development with C++** | payload | any edition — BuildTools, Community, Enterprise. `build.bat` finds it with `vswhere`; no PATH setup required |
| Rust stable, edition 2021 (`x86_64-pc-windows-msvc`) | injector, executor, UI | no external crates in the injector; executor and UI pull from crates.io |
| WebView2 runtime | UI | preinstalled on Windows 11, and on `windows-latest` runners |
| `luau-compile.exe` | executor at runtime | default `D:\zend\test\luau\luau-compile.exe`; override with `ZENDO_COMPILER`. Not needed to *build*, only to *run* a script |
| Roblox client matching the target build | running | `0.746.0.7461267` / `f0ea5da9412f4e35` |

Nothing else is vendored: the injector declares its own `kernel32` externs, and
the payload resolves every Win32 entry point from the PEB at runtime, so it has
no import table at all.

### Payload stages

`ZENDO_STAGE` is a compile-time switch (`/DZENDO_STAGE=...`). The whole payload
is one translation unit; the stage selects which entry behaviour and which
probe chunks are compiled in.

| Stage | Entry | Use |
|---|---|---|
| `4` (default) | hello stub | a build sanity check. **Do not inject it into a running client expecting a session** — it does not serve the pipe |
| `11`–`15` | `run_probe`, `run_tree`, `run_load` | instance tree and loader measurements |
| `16`–`19` | `run_ls`, `run_chunk`, `run_bc`, `run_exec` | compile/load/execute path, one step per stage |
| `50`–`62` | `run_verify`, `run_loadtest`, `run_unseal`, `run_src`, `run_bigexec`, `run_optable`, `run_dispatch`, `run_opmap*`, `run_rawexec` | opcode table, dispatch and loader experiments |
| `63` | `run_batch` | one script, then leave |
| `64` | `run_repl` | **the long-lived dispatcher.** This is the build every verified run in `docs/sunc.md` used: connects to the pipe, serves ops until detached |
| `65` | returns `111` after the mutex check | liveness/`dead_wait` instrumentation only |

The lower stages are instruments, not products. If a run behaves like the
payload is dead, check the stage before checking the code.

### Commands

```bat
:: payload — stage 64 is the working build; the default (4) is a hello stub
payload\build.bat 64

:: injector
cargo build --release --manifest-path injector\Cargo.toml

:: executor (CLI) and shared library
cargo build --release --manifest-path executor\Cargo.toml

:: desktop UI (optional, needs Tauri)
cd ui && npm run build
cargo build --release --manifest-path ui\src-tauri\Cargo.toml --features custom-protocol
```

Artifacts:

| Artifact | Path | Size (this build) |
|---|---|---|
| payload DLL | `payload/build/zendo.dll` | ~141 KB |
| injector | `injector/target/release/zendo-inject.exe` | ~207 KB |
| CLI | `executor/target/release/zendo-exec.exe` | ~373 KB |
| UI | `ui/src-tauri/target/release/zendo-ui.exe` | ~8.4 MB (Tauri + WebView2 bindings) |

### What the payload build does

`payload/build.bat` locates `vcvars64.bat` through `vswhere`
(`-latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64`),
falls back to the two paths that exist on most machines, and fails loudly if no
x64 toolset is present. Then one `cl` invocation:

```bat
cl /nologo /LD /O2 /GS- /GR- /EHs-c- /EHa- /DYNAMICBASE /DZENDO_STAGE=64 ^
   /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0A00 ^
   /Fo:build\ /Fe:build\zendo.dll src\dllmain.cpp ^
   /link /FIXED:NO /NODEFAULTLIB /ENTRY:DllMain /SUBSYSTEM:WINDOWS /MACHINE:X64 /INCREMENTAL:NO
```

Why each flag is there:

| Flag | Reason |
|---|---|
| `/LD` | DLL |
| `/O2` | the payload runs inside the client's frame budget |
| `/GS- /GR- /EHs-c- /EHa-` | no stack cookies, no RTTI, no exceptions — no CRT support code is linked |
| `/DYNAMICBASE` + `/FIXED:NO` | relocations are kept, so the image can be mapped anywhere (required for `SEC_IMAGE`) |
| `/NODEFAULTLIB` | nothing from the CRT; the payload is self-contained |
| `/ENTRY:DllMain` | no `_DllMainCRTStartup`, no CRT init |
| `/SUBSYSTEM:WINDOWS` | no console window when the image is mapped |

A successful build prints `BUILT ...\zendo.dll`. The result is a PE32+ image
with an **empty import directory** — every Win32 function is resolved from the
PEB by export hash, which is why it can be mapped without touching the loader.

Clean builds: `target/` and `build/` are ignored. Deleting
`payload\build\zendo.dll` and rebuilding takes a few seconds; the payload has no
generated sources to regenerate.

### Continuous integration

`.github/workflows/ci.yml` runs on `windows-latest` for every push to `main`, on
pull requests, and on demand. It:

1. checks out the repo and installs stable Rust with a cache keyed on
   `executor`, `injector`, `ui`;
2. builds the **payload** with `payload\build.bat 64` — on a runner the toolset
   is the Enterprise install, which is exactly why the script searches instead
   of hardcoding a path;
3. inspects `zendo.dll` as bytes: PE32+ magic (`0x20B`), size over 10 KB, and
   **import directory RVA `0`**. That last check is what protects the "no CRT,
   no imports" invariant from a stray `#include` or an accidental
   `/NODEFAULTLIB` deletion;
4. builds executor, injector and UI in release mode;
5. uploads the four binaries as the `zendo-win64` artifact.

CI does **not** inject into a client, run Luau, or need a Roblox build — those
steps need an elevated live process and are done by hand, one client per run
(see [Verification rules](#verification-rules)).

---

## Usage

```bat
:: compile and run a script in the live client
zendo-exec run myscript.luau

:: compile to a bytecode blob only
zendo-exec build myscript.luau out.bin

:: host the pipe alone (payload connects on its own)
zendo-exec serve chunk.bin

:: is a payload parked in a client right now?
zendo-exec probe

:: ask a parked payload to unwind and leave
zendo-exec detach
```

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `ZENDO_COMPILER` | `D:\zend\test\luau\luau-compile.exe` | Luau compiler path |
| `ZENDO_INJECTOR` | `injector\target\release\zendo-inject.exe` | Injector path |
| `ZENDO_STEPS` | *(empty → `C`, chunk)* | Comma list of steps: `loadcfg`, `chunk`, `ident`, `probe`, `native`, `guard`, `mitig`, or a single letter |
| `ZENDO_RAW` | unset | Run the chunk synchronously instead of through `task.defer` |
| `ZENDO_TAIL` | `8` | Seconds to tail the client's `_last.log` for `print` output |
| `ZENDO_ACCEPT_MS` | `2000` | How long to wait for an existing payload before injecting |
| `ZENDO_DONE_TIMEOUT` | `60` | How long to wait for `END` before detaching |
| `ZENDO_IDENT` | `7` | Identity passed with the `ident` step |

### Elevation

The client runs elevated on this setup. A medium-integrity shell cannot open,
inject into, or kill it. Run the host from an elevated shell, or launch it with
`Start-Process -Verb RunAs`; otherwise `OpenProcess` fails with access denied
before anything else happens.

---

## Measured layout

Everything below came from a live client. Each entry names the probe that
produced it.

### Client

| Name | Value | Source |
|---|---|---|
| `VisualEngine` static | `0x8942E38` | offsets dump + live read |
| VisualEngine → fake DataModel | `+0xAF0` | live read |
| DataModel → ScriptContext | `+0x440` | live read |
| ScriptContext → `lua_State` | `+0x210`, split-encoded | live decode |
| Instance `Name` container | `+0x68` | offsets dump |
| Instance `Parent` | `+0x60` | offsets dump |
| Instance `ChildrenStart` | `+0x70` | offsets dump |
| DataModel `Workspace` | `+0x148` | offsets dump |

### Proto

Measured with `zendo:proto`, two functions defined in the same chunk.

| Offset | Field |
|---|---|
| `+0x60` | `k` — constants array, `TValue[16]` |
| `+0x68` | `code` — instruction pointer |
| `+0xA4` | `linedefined` (`u32`) |
| `+0xA8` | `maxstacksize` (`u32`) — **not** `numparams` |
| `+0xAC` | `sizek` (`u32`) |
| `+0xB4` | code size in words (`u32`) |

### Closure and upvalues

| Offset | Field |
|---|---|
| `+0x04` | `nupvalues` (low byte) |
| `+0x18` | `Proto*` for a Lua closure |
| `+0x28` | `c.f` — entry point of a C closure |
| `+0x30` | `c.upvals[]` — inline `TValue`s of a C closure |
| `+0x20 + 16*i` | capture slot *i* of a Lua closure |

A capture **by value** stores the value inline in its slot. A capture **by
reference** stores an `UpVal*` in the slot's value word with tag **`0x10`**;
`UpVal+0x8` is the `TValue*` cell shared with the stack.

> The tag is `0x10` in hex. Every dump in `docs/` prints tags in hex, so a dump
> line reading `tt=10` means sixteen. Comparing it against ten is what crashed
> the client during Tier 1: the slot was handed to the VM as an inline `TValue`
> with a type the interpreter has no branch for.

### `TValue` and `TString`

| Structure | Layout |
|---|---|
| `TValue` | value `+0x00` (`u64`), extra `+0x08` (`u64`), tag `+0x0C` (`u32`) |
| tags | `0` nil, `1` boolean, `2` light userdata, `3` number, `6` string, `8` function, `0x10` upvalue |
| `TString` | length `+0x14` (`u32`), bytes `+0x18` |

---

## sUNC status

The target list is 79 names (`work/audit/mini.json`). Current state, measured on
one client, one injection per run, client alive at the end:

| # | Name | Proof |
|---|---|---|
| 1 | `readfile` | round-trips `x.txt` |
| 2 | `writefile` | same run |
| 3 | `appendfile` | append then read back |
| 4 | `isfile` | true before delete, false after |
| 5 | `isfolder` | true before `delfolder`, false after |
| 6 | `makefolder` | creates, then listed |
| 7 | `listfiles` | sees `x.txt` |
| 8 | `delfile` | removes the file |
| 9 | `delfolder` | removes the folder |
| 10 | `debug.getconstants` | two constants from a live proto |
| 11 | `debug.getconstant` | indexed read |
| 12 | `debug.setconstant` | `111 → 987`, verified by calling the function |
| 13 | `base64encode` | pure Luau, round-trips |
| 14 | `base64decode` | same |
| 15 | `lz4compress` | literal-only LZ4 block |
| 16 | `lz4decompress` | round-trips |
| 17 | `identifyexecutor` | `zendo`, `4080` |
| 18 | `getgenv` | shared environment |
| 19 | `getrenv` | same table |
| 20 | `getsenv` | returns a function's environment |
| 21 | `setreadonly` | tracked flag |
| 22 | `isreadonly` | reads it back |
| 23 | `getrawmetatable` | returns the metatable |
| 24 | `setrawmetatable` | sets it |
| 25 | `hookmetamethod` | Lua-level swap |
| 26 | `hookfunction` | entry-point swap via `zendo:fnset` |
| 27 | `iscclosure` | entry-page test |
| 28 | `islclosure` | proto presence test |
| 29 | `checkcaller` | identity-8 thread list |
| 30 | `debug.getupvalues` | `{alpha, 99}` |
| 31 | `debug.getupvalue` | `"1", alpha` |
| 32 | `debug.setupvalue` | `5 → 77 → 123`, `bump` sees `124` |
| 33 | `loadfile` | file returning `6*7` → `42` |
| 34 | `loadstring` | `loadstring("return 3+4")()` → `7` |
| 35 | `getthreadidentity` | `8` |
| 36 | `compareinstances` | `true, false, true` |
| 37 | `request` | HTTPS 200 body 577 B, gzip 84 B, redirect, 404 |

**37 / 79.** The checklist with per-item notes lives in `docs/sunc.md`; the
layout measurements behind items 30–36 live in `docs/re.md`.

### Remaining 42, grouped by blocker

| Blocker | Names |
|---|---|
| Instance/registry walk (one shared blocker: `CALL` with a `GETTABLEKS` result kills the client) | `getgc`, `getreg`, `getinstances`, `getnilinstances`, `getscripts`, `getrunningscripts`, `getloadedmodules`, `getcallingscript`, `getscriptfromthread`, `getscriptbytecode`, `getscriptclosure`, `getscripthash`, `filtergc`, `gethui`, `gethiddenproperty`, `sethiddenproperty`, `isscriptable`, `setscriptable`, `getcallbackvalue` |
| Signal layout (`RBXScriptSignal` / connections not measured) | `firesignal`, `getconnections`, `firetouchinterest`, `fireclickdetector`, `fireproximityprompt`, `replicatesignal` |
| Closure allocation | `newcclosure`, `clonefunction`, `restorefunction`, `isexecutorclosure`, `getfunctionhash` |
| Proto children / frame walking | `debug.getprotos`, `debug.getproto`, `debug.getstack`, `debug.setstack` |
| Drawing API (not implemented at all) | `cleardrawcache`, `isrenderobj`, `getrenderproperty`, `setrenderproperty` |
| Host-side work | `getcustomasset` |
| Needs a capability mask, not just a byte | `setthreadidentity` |
| Namecall state | `getnamecallmethod` |

### Deliberately not faked

- **Upvalue names.** Chunks are compiled `-g0`; the proto carries no name table.
  `-g1` was tried and `proto+0x80..0x130` still contains no name strings.
  `debug.getupvalue` returns the index as a string rather than inventing a name.
- **String writes.** `setupvalue` and `setconstant` accept numbers, booleans and
  nil. A string stored into a GC object needs a write barrier (`luaC_barrier*`)
  whose address has not been measured in this build, so the tag is refused and
  the call reports `nil`/`false`.
- **`getgc`, `getreg`, `getconnections`.** Absent rather than stubbed: a fake
  would hand a script a function that lies about what it can see.

---

## Verification rules

These exist because each one was learned the hard way.

1. **One client per run.** Reusing a client across many injections accumulates
   payload images and ends with a crash *after* the script prints `done`. The
   crash is the accumulation, not the script.
2. **Kill the client after every run.** An elevated `taskkill` — a medium shell
   cannot touch it.
3. **Never re-run the linear image scan** (stage `x`). It died mid-walk twice,
   leaving the process gone. The load config names the same target without
   touching a page.
4. **Every probe read uses a ≥48-byte buffer.** The host refuses to write into
   short strings because they are interned; a 16-byte buffer silently fails and
   the probe reports garbage.
5. **A function counts as working only if it touched a real structure.** No
   stubs returning plausible values.
6. **No offset is copied from another executor as fact.** Same client version
   makes a value a hypothesis to verify, nothing more.

---

## Known issues

| Symptom | Cause | Fix |
|---|---|---|
| Client freezes immediately after injection | payload built with the default stage (4, hello stub) | build with `payload\build.bat 64` |
| Script hangs on a file operation | host dispatcher missing a request letter | accept `F G S L T M D` in `pipe.rs` |
| `read()` returns nothing / wrong bytes | buffer ≤ 40 bytes (interned string) | use `string.rep("A", 48)` or larger |
| Crash right after `uget` on a reference capture | REF tag compared against decimal 10 instead of `0x10` | compare against `0x10` |
| `setupvalue` returns `nil` on a writable page | hardcoded `VirtualProtect(start, 0x2000, ...)` | use `api_write`, which sizes the range from the page |
| Client dies minutes after a run | several payloads mapped into one process | relaunch the client per run |
| Load-config probe leaves the client gone | session landed on a thread the protector already saw | relaunch before the next probe |

---

## Repository layout

```
zendo/
├── README.md                  this file
├── .github/workflows/ci.yml   payload + rust builds, import-table check
├── payload/
│   ├── build.bat              cl, /NODEFAULTLIB, /ENTRY:DllMain
│   ├── src/dllmain.cpp        include order + DllMain, nothing else
│   ├── src/core/              api.inc    resolver, Api table, PEB walk
│   │                          mem.inc    read/write, offset gate
│   │                          proto.inc  framing, diag lines
│   │                          trace.inc  trace files, loop heartbeat
│   │                          veh.inc    exception filter
│   ├── src/luau/              out.inc    Out buffer, state dumps, service walk
│   │                          capture.inc, native.inc     print hook, op dispatcher
│   │                          exec.inc, execraw.inc, protected.inc
│   │                          gc.inc, loadstring.inc, caps.inc
│   ├── src/ipc/repl.inc       serve_session, run_repl
│   ├── src/boot/boot.inc      beacon, stage dispatch, threads
│   ├── src/stages.inc         bisect harnesses, behind #if ZENDO_STAGE != 64
│   ├── src/diag.inc           bisect harnesses (gated, same guard)
│   ├── src/probes.inc         loader probes + the blob includes (gated)
│   ├── src/blobs/             generated bytecode: chunk.inc probe.inc raw.inc
│   └── chunks/                52 Luau files, 12 in use, the rest probe debris
├── injector/
│   └── src/main.rs            PE parser, manual map, SEC_IMAGE map, hijack
├── executor/
│   └── src/
│       ├── lib.rs             build pipeline, prelude (Lua API layer), spawn
│       ├── lbc.rs             LBC header/proto parser
│       ├── pipe.rs            named pipe server, protocol, drive loop
│       ├── remap.rs           RVA → runtime address helpers
│       ├── tables.rs          opcode/table dumps
│       └── main.rs            CLI: run / build / serve / probe / detach
├── ui/
│   ├── src-tauri/src/main.rs  Tauri commands, process discovery, run loop
│   ├── src/                   Svelte 5 app: App, Editor, Console, Hub, Settings
│   └── index.html             vite entry, builds to dist/
├── docs/                      re.md, sunc.md                (local only)
├── resource/                  IDA db, client image, offsets  (local only)
├── tools/                     IDA/disasm helpers             (local only)
├── tests/                     beacon + injection smoke tests  (local only)
└── work/                      probes, logs, scratch          (local only)
```

---

Built against one client build, measured field by field, and honest about what
is missing. If a function is not on the verified list, it is because the
structure behind it has not been read yet — not because a stub was good enough.
