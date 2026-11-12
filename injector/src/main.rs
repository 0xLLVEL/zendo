// Zendo injector — manual map, no external crates.
//
// The DLL bytes are mapped into a local Vec first, relocations and imports are
// resolved there, then the finished image is written into the target in one
// WriteProcessMemory. Nothing of ours ever enters the PEB loader list.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
#![windows_subsystem = "console"]

use std::env;
use std::ffi::CString;
use std::fs;
use std::os::raw::c_void;
use std::process::exit;
use std::ptr;

type Handle = *mut c_void;

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

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn VirtualAllocEx(h: Handle, addr: *mut c_void, size: usize, ty: u32, protect: u32) -> *mut c_void;
    fn VirtualProtectEx(h: Handle, addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
    fn WriteProcessMemory(h: Handle, addr: *mut c_void, buf: *const c_void, size: usize, written: *mut usize) -> i32;
    fn ReadProcessMemory(h: Handle, addr: *const c_void, buf: *mut c_void, size: usize, read: *mut usize) -> i32;
    fn CreateRemoteThread(h: Handle, attrs: *mut c_void, stack: usize,
                          start: *mut c_void, param: *mut c_void, flags: u32,
                          tid: *mut u32) -> Handle;
    fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
    fn GetExitCodeThread(h: Handle, code: *mut u32) -> i32;
    fn CloseHandle(h: Handle) -> i32;
    fn LoadLibraryA(name: *const i8) -> Handle;
    fn GetProcAddress(h: Handle, name: *const i8) -> *mut c_void;
    fn GetModuleHandleA(name: *const i8) -> Handle;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Process32FirstW(snap: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snap: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn VirtualFreeEx(h: Handle, addr: *mut c_void, size: usize, ty: u32) -> i32;
    fn SuspendThread(h: Handle) -> u32;
    fn ResumeThread(h: Handle) -> u32;
    fn GetThreadContext(h: Handle, ctx: *mut u8) -> i32;
    fn SetThreadContext(h: Handle, ctx: *const u8) -> i32;
    fn OpenThread(access: u32, inherit: i32, tid: u32) -> Handle;
    fn Thread32First(snap: Handle, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snap: Handle, entry: *mut ThreadEntry32) -> i32;
    fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *mut c_void,
                   disposition: u32, flags: u32, template: Handle) -> Handle;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationThread(thread: Handle, class: u32, info: *mut c_void,
                                len: u32, ret: *mut u32) -> i32;
    fn NtCreateSection(section: *mut Handle, access: u32, attrs: *mut c_void,
                       max_size: *const u64, protect: u32, allocation: u32,
                       file: Handle) -> i32;
    fn NtMapViewOfSection(section: Handle, process: Handle, base: *mut *mut c_void,
                          zero_bits: usize, commit: usize, offset: *const u64,
                          view_size: *mut usize, inherit: u32, allocation: u32,
                          protect: u32) -> i32;
    fn NtUnmapViewOfSection(process: Handle, base: *mut c_void) -> i32;
}

const SEC_IMAGE: u32 = 0x0100_0000;
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const FILE_SHARE_RW: u32 = 0x0000_0003;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL_F: u32 = 0x80;
const GENERIC_READ: u32 = 0x8000_0000;

/// Map the payload as a real image (`SEC_IMAGE`) instead of a private copy.
///
/// The difference that matters: pages become `MEM_IMAGE`, so the CFG bitmap
/// covers them and an indirect call into our code from the client's VM is
/// legal. A manual map is `MEM_PRIVATE`, and every indirect call into it is a
/// guard violation - which is exactly what killed the native `print` hook.
/// The kernel applies relocations for an image section; the payload resolves
/// its own imports from the PEB, so there is nothing left to fix up.
fn sec_image_map(proc: Handle, path: &str) -> Result<(u64, usize), String> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let file = unsafe {
        CreateFileW(wide.as_ptr(), GENERIC_READ, FILE_SHARE_RW, ptr::null_mut(),
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL_F, ptr::null_mut())
    };
    if file as isize == -1 {
        return Err(format!("CreateFileW: {}", std::io::Error::last_os_error()));
    }
    let mut section: Handle = ptr::null_mut();
    let st = unsafe {
        NtCreateSection(&mut section, SECTION_ALL_ACCESS, ptr::null_mut(), ptr::null(),
                        2, SEC_IMAGE, file)
    };
    if st < 0 {
        unsafe { CloseHandle(file) };
        return Err(format!("NtCreateSection {st:#x}"));
    }
    let mut base: *mut c_void = ptr::null_mut();
    let mut view: usize = 0;
    let mut st = unsafe {
        NtMapViewOfSection(section, proc, &mut base, 0, 0, ptr::null(),
                           &mut view, 1, 0, 2)
    };
    if st < 0 {
        // ViewShare is the documented choice for images; ViewUnmap works for
        // some builds where the first call is refused.
        st = unsafe {
            NtMapViewOfSection(section, proc, &mut base, 0, 0, ptr::null(),
                               &mut view, 2, 0, 2)
        };
    }
    unsafe {
        CloseHandle(section);
        CloseHandle(file);
    }
    if st < 0 {
        return Err(format!("NtMapViewOfSection {st:#x}"));
    }
    Ok((base as u64, view))
}

#[repr(C)]
struct ThreadEntry32 {
    dw_size: u32,
    cnt_usage: u32,
    th32_thread_id: u32,
    th32_owner_process_id: u32,
    tp_base_pri: i32,
    tp_delta_pri: i32,
    dw_flags: u32,
}

const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

#[repr(C, align(16))]
struct ThreadContext([u8; 0x4D0]);

#[repr(C)]
struct ModuleInfo {
    base: *mut c_void,
    size: u32,
    entry: *mut c_void,
}

#[link(name = "psapi")]
extern "system" {
    fn EnumProcessModules(h: Handle, modules: *mut Handle, cb: u32, needed: *mut u32) -> i32;
    fn GetModuleFileNameExW(h: Handle, m: Handle, buf: *mut u16, n: u32) -> u32;
    fn GetModuleInformation(h: Handle, m: Handle, info: *mut ModuleInfo, cb: u32) -> i32;
}

fn describe(proc: Handle, addr: u64) {
    if let Some((name, off)) = module_offset(proc, addr) {
        println!("  in {name}{off:+#x}");
    }
}

fn module_offset(proc: Handle, addr: u64) -> Option<(String, u64)> {
    let mut mods = [ptr::null_mut::<c_void>(); 512];
    let mut needed = 0u32;
    let ok = unsafe {
        EnumProcessModules(proc, mods.as_mut_ptr(), (mods.len() * 8) as u32, &mut needed)
    };
    if ok == 0 { return None; }
    let count = (needed as usize / 8).min(mods.len());
    for i in 0..count {
        let mut info: ModuleInfo = unsafe { std::mem::zeroed() };
        if unsafe { GetModuleInformation(proc, mods[i], &mut info, std::mem::size_of::<ModuleInfo>() as u32) } == 0 {
            continue;
        }
        let base = info.base as u64;
        if addr >= base && addr < base + info.size as u64 {
            let mut name = [0u16; 260];
            unsafe { GetModuleFileNameExW(proc, mods[i], name.as_mut_ptr(), 260) };
            let full = wide_to_string(&name);
            let short = full.rsplit('\\').next().unwrap_or("?").to_string();
            return Some((short, addr - base));
        }
    }
    None
}

const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;
const MEM_COMMIT_RESERVE: u32 = 0x0000_3000;
const MEM_RELEASE: u32 = 0x0000_8000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_READONLY: u32 = 0x02;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const INFINITE: u32 = 0xFFFF_FFFF;

fn u16_at(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

fn find_pid_by_name(want: &str) -> Option<u32> {
    let want = want.to_ascii_lowercase();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap as usize == usize::MAX { return None; }
        let mut e: ProcessEntry32W = std::mem::zeroed();
        e.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            if wide_to_string(&e.sz_exe_file).to_ascii_lowercase() == want {
                CloseHandle(snap);
                return Some(e.th32_process_id);
            }
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
    }
    None
}

struct Pe {
    image: Vec<u8>,
    image_base: u64,
    size_of_image: usize,
    entry: usize,
    reloc_dir: (u32, u32),
    import_dir: (u32, u32),
}

/// True when `base` still holds a readable PE image with our header shape.
/// The pid in the marker file can be recycled, so the check is structural:
/// same entry RVA, same SizeOfImage, valid DOS and NT headers.
fn image_at(proc: Handle, base: u64, entry: usize, size: usize) -> bool {
    let mut hdr = [0u8; 0x200];
    let mut got = 0usize;
    let ok = unsafe {
        ReadProcessMemory(proc, base as *const c_void, hdr.as_mut_ptr() as *mut c_void,
                          hdr.len(), &mut got)
    };
    if ok == 0 || got < hdr.len() {
        return false;
    }
    if &hdr[0..2] != b"MZ" {
        return false;
    }
    let nt = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
    if nt + 0x60 > hdr.len() || &hdr[nt..nt + 4] != b"PE\0\0" {
        return false;
    }
    let opt = nt + 0x18;
    let magic = u16::from_le_bytes(hdr[opt..opt + 2].try_into().unwrap());
    if magic != 0x20B {
        return false;
    }
    let aep = u32::from_le_bytes(hdr[opt + 0x10..opt + 0x14].try_into().unwrap()) as usize;
    let soi = u32::from_le_bytes(hdr[opt + 0x38..opt + 0x3C].try_into().unwrap()) as usize;
    aep == entry && soi == size
}

fn read_pe(bytes: &[u8]) -> Result<Pe, String> {
    if bytes.len() < 0x40 || u16_at(bytes, 0) != 0x5A4D {
        return Err("not a PE (bad MZ)".into());
    }
    let nt = u32_at(bytes, 0x3C) as usize;
    if nt + 0x108 > bytes.len() || u32_at(bytes, nt) != 0x0000_4550 {
        return Err("not a PE (bad PE signature)".into());
    }
    let coff = nt + 4;
    let nsec = u16_at(bytes, coff + 2) as usize;
    let opt = coff + 20;
    let magic = u16_at(bytes, opt);
    if magic != 0x20B {
        return Err(format!("not PE32+ (magic {magic:#x})"));
    }
    let entry = u32_at(bytes, opt + 16) as usize;
    let image_base = u64_at(bytes, opt + 24);
    let size_of_image = u32_at(bytes, opt + 56) as usize;
    let dirs = opt + 112;
    let reloc_dir = (u32_at(bytes, dirs + 5 * 8), u32_at(bytes, dirs + 5 * 8 + 4));
    let import_dir = (u32_at(bytes, dirs + 1 * 8), u32_at(bytes, dirs + 1 * 8 + 4));

    let sections = opt + u16_at(bytes, coff + 16) as usize;
    let mut image = vec![0u8; size_of_image];
    let head = u32_at(bytes, opt + 60) as usize;
    let head_len = head.min(bytes.len()).min(size_of_image);
    image[..head_len].copy_from_slice(&bytes[..head_len]);

    let mut mapped = 0usize;
    for i in 0..nsec {
        let sh = sections + i * 40;
        if sh + 40 > bytes.len() { return Err("section table truncated".into()); }
        let vsize = u32_at(bytes, sh + 8) as usize;
        let va = u32_at(bytes, sh + 12) as usize;
        let rsize = u32_at(bytes, sh + 16) as usize;
        let raw = u32_at(bytes, sh + 20) as usize;
        let n = vsize.min(rsize);
        if n == 0 || va + n > size_of_image { continue; }
        let src = raw.min(bytes.len());
        let take = n.min(bytes.len().saturating_sub(src));
        image[va..va + take].copy_from_slice(&bytes[src..src + take]);
        mapped += take;
    }
    eprintln!("  mapped {mapped:#x} bytes across {nsec} sections, image {size_of_image:#x}");

    Ok(Pe { image, image_base, size_of_image, entry, reloc_dir, import_dir })
}

fn apply_relocations(pe: &mut Pe, delta: i64) {
    if delta == 0 || pe.reloc_dir.0 == 0 || pe.reloc_dir.1 == 0 { return; }
    let base = pe.reloc_dir.0 as usize;
    let size = pe.reloc_dir.1 as usize;
    if base + size > pe.image.len() { return; }
    let mut off = base;
    let end = base + size;
    let mut count = 0usize;
    while off + 8 <= end {
        let page = u32_at(&pe.image, off) as usize;
        let block = u32_at(&pe.image, off + 4) as usize;
        if block < 8 { break; }
        let stop = (off + block).min(end);
        let mut p = off + 8;
        while p + 2 <= stop {
            let raw = u16_at(&pe.image, p);
            let ty = (raw >> 12) as u32;
            let at = page + (raw & 0x0FFF) as usize;
            p += 2;
            if at + 8 > pe.image.len() { continue; }
            match ty {
                10 => {
                    let v = u64_at(&pe.image, at).wrapping_add(delta as u64);
                    pe.image[at..at + 8].copy_from_slice(&v.to_le_bytes());
                    count += 1;
                }
                0 => {}
                _ => eprintln!("  reloc type {ty} at {at:#x} unsupported"),
            }
        }
        off += block;
    }
    eprintln!("  applied {count} relocations, delta {delta:+#x}");
}

fn resolve_imports(pe: &mut Pe) -> Result<usize, String> {
    if pe.import_dir.0 == 0 { return Ok(0); }
    let dir = pe.import_dir.0 as usize;
    let mut n = 0usize;
    let mut i = 0usize;
    loop {
        let desc = dir + i * 20;
        if desc + 20 > pe.image.len() { break; }
        let ilt = u32_at(&pe.image, desc) as usize;
        let name_rva = u32_at(&pe.image, desc + 12) as usize;
        let iat = u32_at(&pe.image, desc + 16) as usize;
        if name_rva == 0 || iat == 0 { break; }

        let name_ptr = pe.image[name_rva..].split(|&b| b == 0).next().unwrap_or(&[]);
        let dll = String::from_utf8_lossy(name_ptr).to_string();
        let cname = CString::new(dll.clone()).map_err(|_| "bad dll name".to_string())?;
        let hmod = unsafe { LoadLibraryA(cname.as_ptr()) };
        if hmod.is_null() {
            return Err(format!("LoadLibrary({dll}) failed"));
        }

        let mut slot = 0usize;
        loop {
            let thunk_rva = if ilt != 0 { ilt + slot * 8 } else { iat + slot * 8 };
            if thunk_rva + 8 > pe.image.len() { break; }
            let oracle = u64_at(&pe.image, thunk_rva);
            if oracle == 0 { break; }
            if oracle & (1u64 << 63) != 0 {
                eprintln!("  ordinal import {dll}!{} unsupported", oracle & 0xFFFF);
                slot += 1;
                continue;
            }
            let hint = oracle as usize;
            let sym_off = hint + 2;
            if sym_off >= pe.image.len() { break; }
            let sym = pe.image[sym_off..].split(|&b| b == 0).next().unwrap_or(&[]).to_vec();
            let csym = CString::new(sym.clone()).map_err(|_| "bad symbol".to_string())?;
            let addr = unsafe { GetProcAddress(hmod, csym.as_ptr()) };
            if addr.is_null() {
                return Err(format!("GetProcAddress({dll}!{}) failed", String::from_utf8_lossy(&sym)));
            }
            let at = iat + slot * 8;
            if at + 8 > pe.image.len() { break; }
            pe.image[at..at + 8].copy_from_slice(&(addr as u64).to_le_bytes());
            n += 1;
            slot += 1;
        }
        i += 1;
    }
    Ok(n)
}

fn section_protections(bytes: &[u8]) -> Vec<(usize, usize, u32)> {
    let mut out = Vec::new();
    if bytes.len() < 0x40 { return out; }
    let nt = u32_at(bytes, 0x3C) as usize;
    if nt + 0x108 > bytes.len() { return out; }
    let coff = nt + 4;
    let nsec = u16_at(bytes, coff + 2) as usize;
    let opt = coff + 20;
    let sections = opt + u16_at(bytes, coff + 16) as usize;
    for i in 0..nsec {
        let sh = sections + i * 40;
        if sh + 40 > bytes.len() { break; }
        let vsize = u32_at(bytes, sh + 8) as usize;
        let va = u32_at(bytes, sh + 12) as usize;
        let chars = u32_at(bytes, sh + 36);
        if vsize == 0 { continue; }
        let exec = chars & 0x2000_0000 != 0;
        let write = chars & 0x8000_0000 != 0;
        let prot = match (exec, write) {
            (true, _) => PAGE_EXECUTE_READ,
            (false, true) => PAGE_READWRITE,
            (false, false) => PAGE_READONLY,
        };
        out.push((va, vsize, prot));
    }
    out
}

/// Threads parked inside this ntdll wait never wake on our resume: the wait has
/// no timeout, so the patched RIP is never reached and the client stops
/// responding. Skipping them is the difference between a clean hijack and a
/// frozen process. Kept as a range so nearby instructions in the same helper are
/// covered; other builds simply do not match it, and the fallback keeps the
/// candidate list non-empty.
unsafe fn dead_wait(rip: u64) -> bool {
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
    if ntdll.is_null() {
        return false;
    }
    let base = ntdll as u64;
    rip >= base + 0x16_5900 && rip < base + 0x16_5A80
}

/// A thread's own start address. The primary thread of a process reports the
/// image entry point; every other thread reports the routine handed to
/// `CreateThread`. This is the field that separates the client's scheduler
/// thread from its workers, and therefore the field that decides whether a
/// hijack freezes the game window or runs cleanly beside it.
fn thread_start(tid: u32) -> Option<u64> {
    unsafe {
        let th = OpenThread(0x0040, 0, tid); // THREAD_QUERY_INFORMATION
        if th.is_null() {
            return None;
        }
        let mut start: u64 = 0;
        let mut ret = 0u32;
        let st = NtQueryInformationThread(th, 9, &mut start as *mut u64 as *mut c_void, 8, &mut ret);
        CloseHandle(th);
        if st == 0 { Some(start) } else { None }
    }
}

/// Address the primary thread starts at, read from the loader itself so nobody
/// has to parse the client's PE copy.
fn main_entry(proc: Handle) -> Option<u64> {
    unsafe {
        let mut mods = [ptr::null_mut::<c_void>(); 1];
        let mut needed = 0u32;
        if EnumProcessModules(proc, mods.as_mut_ptr(), 8, &mut needed) == 0 || needed < 8 {
            return None;
        }
        let mut info: ModuleInfo = std::mem::zeroed();
        if GetModuleInformation(proc, mods[0], &mut info,
                                std::mem::size_of::<ModuleInfo>() as u32) == 0 {
            return None;
        }
        Some(info.entry as u64)
    }
}

unsafe extern "system" fn count_window(_w: *mut c_void, l: isize) -> i32 {
    *(l as *mut u32) += 1;
    0 // one is enough to disqualify the thread
}

/// True when this thread owns a top-level window. The client's window thread is
/// its scheduler thread; hijacking it parks the message pump and the deferred
/// body the session waits for can never run.
fn owns_window(tid: u32) -> bool {
    #[link(name = "user32")]
    extern "system" {
        fn EnumThreadWindows(tid: u32,
                             cb: Option<unsafe extern "system" fn(*mut c_void, isize) -> i32>,
                             lparam: isize) -> i32;
    }
    let mut n = 0u32;
    unsafe { EnumThreadWindows(tid, Some(count_window), &mut n as *mut u32 as isize) };
    n > 0
}

/// One appended line per injection in the temp dir: which threads were offered,
/// why the unsafe ones were refused, and which one was borrowed. Written before
/// the hijack, so it survives a frozen client.
fn pick_log(line: &str) {
    use std::io::Write;
    let path = std::env::temp_dir().join("zendo-pick.log");
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{ms} {line}");
    }
}

/// Prefer a thread parked inside an ntdll wait: its stack is shallow and its
/// user-mode state is a syscall return, so an abandoned frame costs nothing.
fn pick_threads(pid: u32) -> Vec<(u32, u8, &'static str)> {
    /// (start, end, priority, name). Lower priority wins: a thread we can always
    /// wake is worth more than one we merely hope will wake.
    unsafe fn wait_ranges() -> Vec<(u64, u64, u8, &'static str)> {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            return Vec::new();
        }
        // Narrow on purpose. Widening this to kernelbase/user32 waits picked up
        // busy worker threads (the SignalR socket thread among them): holding one
        // of those in the REPL loop drops the client's websocket and the process
        // dies seconds later. Only genuine scheduler idlers belong here.
        let names: [(&[u8], u8, &'static str); 5] = [
            // Alertable by definition: NtAlertThread wakes it every time.
            (b"NtWaitForAlertByThreadId\0", 0, "alerted"),
            // A delay always carries a timeout, even if it is a long one.
            (b"NtDelayExecution\0", 0, "delay"),
            // Usually a finite timeout, and it returns to user mode on its own.
            (b"NtWaitForMultipleObjects\0", 1, "multi"),
            // Often an infinite, non-alertable wait: the wedge class.
            (b"NtWaitForSingleObject\0", 2, "single"),
            (b"ZwWaitForSingleObject\0", 2, "single"),
        ];
        let mut out = Vec::new();
        for (n, prio, label) in names {
            let f = GetProcAddress(ntdll, n.as_ptr() as *const i8);
            if !f.is_null() {
                let a = f as u64;
                out.push((a, a + 0x40, prio, label));
            }
        }
        out
    }

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap as usize == usize::MAX {
            return Vec::new();
        }
        let proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        let entry = if proc.is_null() { None } else { main_entry(proc) };
        let mut te: ThreadEntry32 = std::mem::zeroed();
        te.dw_size = std::mem::size_of::<ThreadEntry32>() as u32;
        let mut out: Vec<(u8, u32, &'static str)> = Vec::new();
        let mut spare: Vec<(u8, u32, &'static str)> = Vec::new();
        let mut ok = Thread32First(snap, &mut te);
        while ok != 0 {
            if te.th32_owner_process_id == pid {
                let tid = te.th32_thread_id;
                // Never borrow the thread the client's scheduler runs on. Two
                // measurements say it is that thread and not a worker: it owns
                // the game window, and its start address is the image entry
                // point. A hijacked scheduler parks the only thread that can
                // run the deferred body, so the session waits on a sentinel
                // that can never arrive and the window stops pumping. Runs 1-3
                // hit an alertable worker and finished in under a second; run 4
                // hit the window thread and froze the client.
                let start = thread_start(tid);
                let entry_thread = match (start, entry) {
                    (Some(0), _) => true,
                    (Some(s), Some(e)) => s >= e && s < e + 0x1000,
                    _ => false,
                };
                let window = owns_window(tid);
                if entry_thread || window {
                    pick_log(&format!(
                        "skip tid={tid} start={} entry={} window={window}",
                        start.map(|s| format!("{s:#x}")).unwrap_or_else(|| "?".into()),
                        entry.map(|e| format!("{e:#x}")).unwrap_or_else(|| "?".into())
                    ));
                    ok = Thread32Next(snap, &mut te);
                    continue;
                }
                let ranges = wait_ranges();
                let th = OpenThread(THREAD_ALL_ACCESS, 0, tid);
                if !th.is_null() {
                    let mut ctx = ThreadContext([0u8; 0x4D0]);
                    ctx.0[0x30..0x34].copy_from_slice(&0x0010_000Bu32.to_le_bytes());
                    if GetThreadContext(th, ctx.0.as_mut_ptr()) != 0 {
                        let rip = u64::from_le_bytes(ctx.0[0xF8..0x100].try_into().unwrap());
                        for &(a, b, prio, label) in ranges.iter() {
                            if rip < a || rip >= b {
                                continue;
                            }
                            if dead_wait(rip) {
                                spare.push((9, tid, "dead"));
                            } else {
                                out.push((prio, tid, label));
                            }
                            break;
                        }
                    }
                    CloseHandle(th);
                }
            }
            ok = Thread32Next(snap, &mut te);
        }
        CloseHandle(snap);
        out.sort_by_key(|c| c.0);
        if out.is_empty() {
            out = spare;
        }
        let list: Vec<(u32, u8, &'static str)> =
            out.into_iter().map(|(p, t, l)| (t, p, l)).collect();
        pick_log(&format!(
            "pid={pid} entry={} candidates={:?}",
            entry.map(|e| format!("{e:#x}")).unwrap_or_else(|| "?".into()),
            list.iter().map(|c| (c.0, c.2)).collect::<Vec<_>>()
        ));
        if !proc.is_null() {
            CloseHandle(proc);
        }
        list
    }
}

fn pick_thread(pid: u32) -> Option<u32> {
    pick_threads(pid).into_iter().next().map(|c| c.0)
}

fn pick_first(pid: u32) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap as usize == usize::MAX {
            return None;
        }
        let mut te: ThreadEntry32 = std::mem::zeroed();
        te.dw_size = std::mem::size_of::<ThreadEntry32>() as u32;
        let mut found = None;
        let mut ok = Thread32First(snap, &mut te);
        while ok != 0 {
            if te.th32_owner_process_id == pid {
                found = Some(te.th32_thread_id);
                break;
            }
            ok = Thread32Next(snap, &mut te);
        }
        CloseHandle(snap);
        found
    }
}

enum Attempt {
    Finished(u32),
    Running,
    Retry(String),
    Fatal(String),
}

fn hijack_on(proc: Handle, tid: u32, stub_addr: u64, stub: &[u8], flag_addr: u64) -> Attempt {
    let th = unsafe { OpenThread(THREAD_ALL_ACCESS, 0, tid) };
    if th.is_null() {
        return Attempt::Retry(format!("OpenThread {tid}: {}", std::io::Error::last_os_error()));
    }
    let mut wrote = 0usize;
    let ok = unsafe { WriteProcessMemory(proc, stub_addr as *mut c_void, stub.as_ptr() as *const c_void, stub.len(), &mut wrote) };
    if ok == 0 {
        unsafe { CloseHandle(th); }
        return Attempt::Fatal("stub write failed".into());
    }
    let mut zero = [0u8; 16];
    unsafe { WriteProcessMemory(proc, flag_addr as *mut c_void, zero.as_ptr() as *const c_void, 16, &mut wrote); }

    let prev = unsafe { SuspendThread(th) };
    if prev == u32::MAX {
        let e = std::io::Error::last_os_error();
        unsafe { CloseHandle(th); }
        return Attempt::Retry(format!("SuspendThread {tid}: {e}"));
    }
    // A thread someone else already holds suspended never reaches user mode,
    // so the stub would never run and our resume would only decrement their
    // count. Leave it alone and try another thread.
    if prev > 0 {
        unsafe { ResumeThread(th); CloseHandle(th); }
        println!("  skipping thread {tid}: already suspended ({prev})");
        return Attempt::Retry(format!("thread {tid} already suspended ({prev})"));
    }

    let mut saved = ThreadContext([0u8; 0x4D0]);
    saved.0[0x30..0x34].copy_from_slice(&0x0010_000Bu32.to_le_bytes());
    if unsafe { GetThreadContext(th, saved.0.as_mut_ptr()) } == 0 {
        unsafe { ResumeThread(th); CloseHandle(th); }
        return Attempt::Retry("GetThreadContext failed".into());
    }

    // Park the untouched context where the stub can pick it up after DllMain
    // returns; the stub reloads it with RtlRestoreContext.
    let mut cw = 0usize;
    let ok = unsafe {
        WriteProcessMemory(proc, (stub_addr + 0x200) as *mut c_void,
                           saved.0.as_ptr() as *const c_void, saved.0.len(), &mut cw)
    };
    if ok == 0 || cw != saved.0.len() {
        unsafe { ResumeThread(th); CloseHandle(th); }
        return Attempt::Retry("context stash failed".into());
    }

    let rip = u64::from_le_bytes(saved.0[0xF8..0x100].try_into().unwrap());
    match module_offset(proc, rip) {
        Some((name, off)) => println!("  hijacking thread {tid} at {name}{off:+#x}"),
        None => println!("  hijacking thread {tid} at {rip:#x}"),
    }

    let mut patched = ThreadContext(saved.0);
    patched.0[0xF8..0x100].copy_from_slice(&stub_addr.to_le_bytes());
    patched.0[0x30..0x34].copy_from_slice(&0x0010_000Bu32.to_le_bytes());
    if unsafe { SetThreadContext(th, patched.0.as_ptr()) } == 0 {
        unsafe { ResumeThread(th); CloseHandle(th); }
        return Attempt::Retry("SetThreadContext failed".into());
    }
    unsafe { ResumeThread(th); }

    // A wait with no timeout keeps the thread asleep even with RIP patched, so
    // the stub never runs. NtAlertThread wakes an alertable wait for free and is
    // harmless otherwise, so try it before declaring the thread dead.
    if let Some(alert) = unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        let p = GetProcAddress(ntdll, b"NtAlertThread\0".as_ptr() as *const i8);
        if p.is_null() {
            None
        } else {
            Some(std::mem::transmute::<*mut c_void, unsafe extern "system" fn(*mut c_void) -> i32>(p))
        }
    } {
        std::thread::sleep(std::time::Duration::from_millis(40));
        let mut buf = [0u8; 16];
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(proc, flag_addr as *const c_void, buf.as_mut_ptr() as *mut c_void, 16, &mut got)
        };
        if ok == 0 || u64::from_le_bytes(buf[..8].try_into().unwrap()) == 0 {
            unsafe { alert(th) };
        }
    }

    // Prove whether the patched thread ever reached user mode at all. A thread
    // still sitting at our stub was never scheduled; one that is gone was killed
    // the moment it touched the stub page.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let mut after = ThreadContext([0u8; 0x4D0]);
    after.0[0x30..0x34].copy_from_slice(&0x0010_000Bu32.to_le_bytes());
    if unsafe { GetThreadContext(th, after.0.as_mut_ptr()) } == 0 {
        println!("    thread {tid} gone after patch: {}", std::io::Error::last_os_error());
    } else {
        let rip2 = u64::from_le_bytes(after.0[0xF8..0x100].try_into().unwrap());
        match module_offset(proc, rip2) {
            Some((name, off)) => println!("    thread {tid} now at {name}{off:+#x}"),
            None => println!("    thread {tid} now at {rip2:#x}"),
        }
    }
    let mut got = 0usize;
    let mut state = 0u64;
    let mut ret = 0u64;
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut buf = [0u8; 16];
        let ok = unsafe { ReadProcessMemory(proc, flag_addr as *const c_void, buf.as_mut_ptr() as *mut c_void, 16, &mut got) };
        if ok != 0 {
            state = u64::from_le_bytes(buf[..8].try_into().unwrap());
            ret = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            if state == 1 {
                unsafe { SuspendThread(th); }
                unsafe { SetThreadContext(th, saved.0.as_ptr()) };
                unsafe { ResumeThread(th); CloseHandle(th); }
                return Attempt::Finished(ret as u32);
            }
        }
    }
    // A thread Hyperion has parked under its own suspension never runs the
    // stub at all. The RIP is still patched, so put the saved context back
    // before moving on: otherwise the thread runs the stub whenever it is
    // finally resumed and a second DllMain appears minutes later.
    if state == 0 {
        let s = unsafe { SuspendThread(th) };
        let rc = unsafe { SetThreadContext(th, saved.0.as_ptr()) };
        // Never leave a thread we suspended: an unreleased suspend is a frozen
        // client, and the context we could not write is already parked at
        // stub+0x200 for the next attempt.
        if s != u32::MAX {
            unsafe { ResumeThread(th); }
        }
        unsafe { CloseHandle(th); }
        if rc == 0 {
            return Attempt::Retry(format!(
                "restore {tid} failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        return Attempt::Retry("stub never started".into());
    }
    // DllMain is long-lived (REPL). Do not restore: the stub already overwrote
    // part of this thread's stack.
    unsafe { CloseHandle(th); }
    Attempt::Running
}

fn hijack(proc: Handle, pid: u32, stub_addr: u64, stub: &[u8], flag_addr: u64,
          prefer_main: bool) -> Result<Attempt, String> {
    // Run the stub on a live thread of the target, then put its context back
    // exactly as it was. No thread is created inside the game.
    let candidates: Vec<(u32, u8, &'static str)> = if prefer_main {
        pick_first(pid)
            .map(|t| vec![(t, 0u8, "main")])
            .unwrap_or_default()
    } else {
        pick_threads(pid)
    };
    if candidates.is_empty() {
        pick_log("no safe thread: every parked thread owns a window or is the entry thread");
        return Err("no safe thread: refusing to borrow the client's scheduler".into());
    }
    let mut last = String::from("no idle thread accepted the stub");
    // Four attempts is the whole budget. Every miss leaves a thread parked on
    // our stub page for a while, and a long list of those is itself a wedge.
    for &(tid, prio, label) in candidates.iter().take(4) {
        println!("  candidate {tid} ({label}, prio {prio})");
        // Which thread this actually is, in the log. A client that dies an hour
        // later cannot be attributed to a tid that was reused three times.
        let origin = match thread_start(tid) {
            Some(s) => match module_offset(proc, s) {
                Some((m, o)) => format!("start={s:#x} {m}+{o:#x}"),
                None => format!("start={s:#x}"),
            },
            None => "start=?".to_string(),
        };
        pick_log(&format!("try tid={tid} label={label} prio={prio} {origin}"));
        match hijack_on(proc, tid, stub_addr, stub, flag_addr) {
            Attempt::Finished(code) => {
                pick_log(&format!("finished tid={tid} code={code}"));
                return Ok(Attempt::Finished(code));
            }
            Attempt::Running => {
                pick_log(&format!("running tid={tid}"));
                return Ok(Attempt::Running);
            }
            Attempt::Fatal(e) => {
                pick_log(&format!("fatal tid={tid} {e}"));
                return Err(e);
            }
            Attempt::Retry(e) => {
                pick_log(&format!("retry tid={tid} {e}"));
                last = e;
            }
        }
    }
    Err(last)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: zendo-inject (<pid> | --name process.exe) --dll path [--no-wait]");
        exit(2);
    }
    let mut pid: Option<u32> = None;
    let mut name: Option<String> = None;
    let mut dll_path: Option<String> = None;
    let mut wait = true;
    let mut trace = false;
    let mut probe = false;
    let mut hijack_mode = false;
    let mut main_thread = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => { name = args.get(i + 1).cloned(); i += 2; }
            "--dll" => { dll_path = args.get(i + 1).cloned(); i += 2; }
            "--no-wait" => { wait = false; i += 1; }
            "--trace" => { trace = true; i += 1; }
            "--probe" => { probe = true; i += 1; }
            "--hijack" => { hijack_mode = true; i += 1; }
            "--main" => { main_thread = true; i += 1; }
            other => {
                pid = other.parse::<u32>().ok().or(pid);
                i += 1;
            }
        }
    }
    let dll_path = dll_path.unwrap_or_else(|| {
        eprintln!("missing --dll");
        exit(2);
    });
    let target_pid = match pid {
        Some(p) => p,
        None => {
            let want = name.unwrap_or_else(|| "RobloxPlayerBeta.exe".to_string());
            match find_pid_by_name(&want) {
                Some(p) => p,
                None => { eprintln!("process {want} not running"); exit(3); }
            }
        }
    };

    // ZENDO_THREADS=1 dumps every thread with the module it is parked in and
    // marks the ones the hijack picker would accept. Read-only, changes nothing.
    if std::env::var_os("ZENDO_THREADS").is_some() {
        let proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid) };
        if proc.is_null() {
            eprintln!("OpenProcess failed: {}", std::io::Error::last_os_error());
            exit(5);
        }
        let cands = pick_threads(target_pid);
        println!("candidates: {:?}", cands);
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            let mut te: ThreadEntry32 = std::mem::zeroed();
            te.dw_size = std::mem::size_of::<ThreadEntry32>() as u32;
            let mut ok = Thread32First(snap, &mut te);
            while ok != 0 {
                if te.th32_owner_process_id == target_pid {
                    let th = OpenThread(THREAD_ALL_ACCESS, 0, te.th32_thread_id);
                    if !th.is_null() {
                        let mut ctx = ThreadContext([0u8; 0x4D0]);
                        ctx.0[0x30..0x34].copy_from_slice(&0x0010_000Bu32.to_le_bytes());
                        if GetThreadContext(th, ctx.0.as_mut_ptr()) != 0 {
                            let rip = u64::from_le_bytes(ctx.0[0xF8..0x100].try_into().unwrap());
                            let mark = if cands.iter().any(|c| c.0 == te.th32_thread_id) { "*" } else { " " };
                            match module_offset(proc, rip) {
                                Some((n, o)) => println!("{mark} tid {:>6} {n}{o:+#x}", te.th32_thread_id),
                                None => println!("{mark} tid {:>6} {rip:#x}", te.th32_thread_id),
                            }
                        }
                        CloseHandle(th);
                    }
                }
                ok = Thread32Next(snap, &mut te);
            }
            CloseHandle(snap);
        }
        unsafe { CloseHandle(proc); }
        return;
    }

    let bytes = match fs::read(&dll_path) {
        Ok(b) => b,
        Err(e) => { eprintln!("read {dll_path}: {e}"); exit(3); }
    };
    println!("zendo-inject: pid {target_pid}, payload {} bytes", bytes.len());

    let mut pe = match read_pe(&bytes) {
        Ok(p) => p,
        Err(e) => { eprintln!("parse: {e}"); exit(4); }
    };

    let proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid) };
    if proc.is_null() {
        eprintln!("OpenProcess failed (err {}). run at the same integrity.", std::io::Error::last_os_error());
        exit(5);
    }

    if probe {
        let remote = unsafe { VirtualAllocEx(proc, ptr::null_mut(), pe.size_of_image, MEM_COMMIT_RESERVE, PAGE_READWRITE) };
        let h = unsafe { LoadLibraryA(c"kernel32.dll".as_ptr() as *const i8) };
        let sleep = unsafe { GetProcAddress(h, c"Sleep".as_ptr() as *const i8) };
        let mut ptid = 0u32;
        let t = unsafe {
            CreateRemoteThread(proc, ptr::null_mut(), 0, sleep, 3000 as *mut c_void, 0, &mut ptid)
        };
        if t.is_null() {
            println!("probe: CreateRemoteThread DENIED {}", std::io::Error::last_os_error());
            return;
        }
        let r = unsafe { WaitForSingleObject(t, 10_000) };
        let mut code = 0u32;
        unsafe { GetExitCodeThread(t, &mut code) };
        println!("probe: thread {ptid} wait={r} exit={code:#x} (0 = creation allowed, ran a real module)");
        unsafe { CloseHandle(t); CloseHandle(proc); }
        return;
    }

    // Reuse the image this injector already mapped into this process. The
    // borrowed thread is disposable (the client kills it within seconds), but
    // the mapped image is not: re-entering it keeps one payload copy per
    // process instead of one per script.
    let marker = std::env::temp_dir().join("zendo-image.txt");
    // A rebuilt payload must never be re-entered: the old image is still there
    // but holds the previous code. Size + mtime of the DLL is the stamp.
    let (dll_len, dll_time) = std::fs::metadata(&dll_path)
        .ok()
        .and_then(|m| {
            let t = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            Some((m.len(), t))
        })
        .unwrap_or((0, 0));
    // Re-entry into a previously mapped image is not viable: the second
    // DllMain either hangs before its first mark or the patched thread dies on
    // the stub page. A fresh map per injection is the only route that has ever
    // produced a full MARK run on an already-injected client. Opt back in with
    // ZENDO_REUSE=1 only for experiments.
    let allow_reuse = std::env::var("ZENDO_REUSE").map(|v| v == "1").unwrap_or(false);
    let mut remote_base = 0u64;
    let mut reused = false;
    if allow_reuse {
        if let Ok(s) = std::fs::read_to_string(&marker) {
        let f: Vec<&str> = s.split_whitespace().collect();
        let same = f.len() == 4
            && f[0].parse::<u32>().ok() == Some(target_pid)
            && f[2].parse::<u64>().ok() == Some(dll_len)
            && f[3].parse::<u64>().ok() == Some(dll_time);
        let base = f.get(1).and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok());
        if same {
            if let Some(b) = base {
                if image_at(proc, b, pe.entry, pe.size_of_image) {
                    remote_base = b;
                    reused = true;
                }
            }
        }
        }
    }

    let sec_image = std::env::var("ZENDO_SECIMAGE").map(|v| v == "1").unwrap_or(false);
    if reused {
        println!("  reusing image at {remote_base:#x}");
    } else if sec_image {
        // SEC_IMAGE: the kernel owns the mapping, so relocations, section
        // protections and the import table are its job - the payload resolves
        // API pointers itself from the PEB and never needs the IAT. Both
        // remote_base and pe.entry stay valid for the hijack stub because the
        // preferred base is honoured or the loader rebases the whole image.
        match sec_image_map(proc, &dll_path) {
            Ok((b, view)) => {
                remote_base = b;
                println!("  remote image (SEC_IMAGE) at {remote_base:#x} view={view:#x}");
            }
            Err(e) => { eprintln!("sec_image_map: {e}"); exit(10); }
        }
    } else {
        let remote = unsafe { VirtualAllocEx(proc, ptr::null_mut(), pe.size_of_image, MEM_COMMIT_RESERVE, PAGE_READWRITE) };
        if remote.is_null() {
            eprintln!("VirtualAllocEx failed: {}", std::io::Error::last_os_error());
            exit(6);
        }
        remote_base = remote as u64;
        println!("  remote image at {remote_base:#x}");

        let delta = remote_base.wrapping_sub(pe.image_base) as i64;
        println!("  reloc dir {:#x}+{:#x}  import dir {:#x}+{:#x}",
                 pe.reloc_dir.0, pe.reloc_dir.1, pe.import_dir.0, pe.import_dir.1);
        apply_relocations(&mut pe, delta);
        match resolve_imports(&mut pe) {
            Ok(n) => println!("  resolved {n} imports"),
            Err(e) => { eprintln!("imports: {e}"); exit(7); }
        }

        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(proc, remote, pe.image.as_ptr() as *const c_void, pe.image.len(), &mut written)
        };
        if ok == 0 || written != pe.image.len() {
            eprintln!("WriteProcessMemory {written}/{} err {}", pe.image.len(), std::io::Error::last_os_error());
            exit(8);
        }
        println!("  wrote {written:#x} bytes");

        for (va, size, prot) in section_protections(&bytes) {
            let mut old = 0u32;
            unsafe {
                VirtualProtectEx(proc, remote.add(va), size, prot, &mut old);
            }
        }
        let _ = std::fs::write(&marker, format!("{target_pid} {remote_base:#x} {dll_len} {dll_time}\n"));
    }

    // CreateRemoteThread starts with rcx = parameter and rdx = 0, so calling the
    // entry point directly gives DllMain reason 0. Stage a stub that passes the
    // real arguments.
    // RtlUserThreadStart enters the stub with RSP % 16 == 8, the same state a
    // call leaves. One more push would leave DllMain misaligned, which is what
    // crashed movaps inside kernelbase. Realign around the call.
    let exit_fn = unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr() as *const i8);
        GetProcAddress(ntdll, c"RtlExitUserThread".as_ptr() as *const i8)
    };
    if exit_fn.is_null() {
        eprintln!("RtlExitUserThread not found");
        exit(9);
    }
    let restore_fn = unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr() as *const i8);
        GetProcAddress(ntdll, c"RtlRestoreContext".as_ptr() as *const i8)
    };
    if restore_fn.is_null() {
        eprintln!("RtlRestoreContext not found");
        exit(9);
    }
    let sleep_fn = unsafe {
        let k32 = GetModuleHandleA(c"kernel32.dll".as_ptr() as *const i8);
        GetProcAddress(k32, c"Sleep".as_ptr() as *const i8)
    };
    if sleep_fn.is_null() {
        eprintln!("Sleep not found");
        exit(9);
    }
    let mut stub: Vec<u8> = Vec::new();
    stub.extend_from_slice(&[0x48, 0xB9]);
    stub.extend_from_slice(&remote_base.to_le_bytes());
    stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x45, 0x33, 0xC0]);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x08]);
    stub.extend_from_slice(&[0x48, 0xB8]);
    stub.extend_from_slice(&(remote_base + pe.entry as u64).to_le_bytes());
    stub.extend_from_slice(&[0xFF, 0xD0]);
    // Park forever instead of RtlExitUserThread: leaving via the loader's
    // thread-detach path raises STATUS_BAD_TLS_INDEX in this client.
    stub.extend_from_slice(&[0xB9, 0xFF, 0xFF, 0xFF, 0xFF]);
    stub.extend_from_slice(&[0x48, 0xB8]);
    stub.extend_from_slice(&(sleep_fn as u64).to_le_bytes());
    stub.extend_from_slice(&[0xFF, 0xD0, 0xCC]);

    let stub_mem = unsafe {
        VirtualAllocEx(proc, ptr::null_mut(), 0x1000, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    };
    if stub_mem.is_null() {
        eprintln!("stub alloc failed: {}", std::io::Error::last_os_error());
        exit(9);
    }
    let stub_addr = stub_mem as u64;
    let flag_addr = stub_addr + 0x800;

    if hijack_mode {
        // flags[0]: 0 = untouched, 2 = DllMain started, 1 = returned.
        // flags[8] = DllMain result. The injector restores the saved context
        // once the flag flips. If nobody restores us (the injector timed out),
        // sleep briefly and end this thread instead of spinning a core and
        // freezing the game loop.
        let mut s: Vec<u8> = Vec::new();
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&flag_addr.to_le_bytes());
        s.extend_from_slice(&[0x48, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0xB9]);
        s.extend_from_slice(&remote_base.to_le_bytes());
        s.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
        // Third DllMain argument = the saved CONTEXT. The payload reloads it
        // when the session ends, so the borrowed thread goes back to its wait
        // instead of being left inside the payload image.
        s.extend_from_slice(&[0x49, 0xB8]);
        s.extend_from_slice(&(stub_addr + 0x200).to_le_bytes());
        s.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]);
        s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&(remote_base + pe.entry as u64).to_le_bytes());
        s.extend_from_slice(&[0xFF, 0xD0]);
        // DllMain returned: put the thread back exactly where it was. The
        // saved CONTEXT is written at stub+0x200 for every attempt, and
        // RtlRestoreContext reloads it wholesale, so the borrowed thread
        // resumes its wait instead of staying pinned in our image.
        s.extend_from_slice(&[0x48, 0xB9]);
        s.extend_from_slice(&(stub_addr + 0x200).to_le_bytes());
        s.extend_from_slice(&[0x31, 0xD2]);
        s.extend_from_slice(&[0x48, 0xB8]);
        s.extend_from_slice(&(restore_fn as u64).to_le_bytes());
        s.extend_from_slice(&[0xFF, 0xD0, 0xCC]);
        match hijack(proc, target_pid, stub_addr, &s, flag_addr, main_thread) {
            Ok(Attempt::Finished(code)) => println!("  hijack completed, DllMain returned {code}"),
            Ok(Attempt::Running) => println!("  hijack running (DllMain long-lived)"),
            Ok(Attempt::Retry(_)) | Ok(Attempt::Fatal(_)) => {}
            Err(e) => println!("  hijack failed: {e}"),
        }
        unsafe { CloseHandle(proc); }
        return;
    }

    let mut wrote = 0usize;
    unsafe {
        WriteProcessMemory(proc, stub_mem, stub.as_ptr() as *const c_void, stub.len(), &mut wrote);
    }

    let mut tid = 0u32;
    let thread = unsafe { CreateRemoteThread(proc, ptr::null_mut(), 0, stub_mem, ptr::null_mut(), 0, &mut tid) };
    if thread.is_null() {
        eprintln!("CreateRemoteThread failed: {}", std::io::Error::last_os_error());
        unsafe {
            VirtualFreeEx(proc, stub_mem, 0, MEM_RELEASE);
        }
        exit(9);
    }
    println!("  DllMain thread {tid} via stub at {stub_mem:p}");

    if wait {
        let r = unsafe { WaitForSingleObject(thread, 10_000) };
        if r == 0 {
            let mut code = 0u32;
            unsafe { GetExitCodeThread(thread, &mut code) };
            println!("  DllMain returned {code}");
            unsafe { CloseHandle(thread); CloseHandle(proc); }
            exit(12);
        } else {
            println!("  thread still alive after 10s");
            if trace {
            unsafe {
                SuspendThread(thread);
                let mut ctx = ThreadContext([0u8; 0x4D0]);
                ctx.0[0x30..0x34].copy_from_slice(&0x0010_000Bu32.to_le_bytes()); // CONTEXT_AMD64
                if GetThreadContext(thread, ctx.0.as_mut_ptr()) != 0 {
                    let mut ripb = [0u8; 8];
                    ripb.copy_from_slice(&ctx.0[0xF8..0x100]);
                    let rip = u64::from_le_bytes(ripb);
                    let mut rspb = [0u8; 8];
                    rspb.copy_from_slice(&ctx.0[0x98..0xA0]);
                    let rsp = u64::from_le_bytes(rspb);
                    let reg = |off: usize| -> u64 {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&ctx.0[off..off + 8]);
                        u64::from_le_bytes(b)
                    };
                    println!("  regs rax {:#x} rcx {:#x} rdx {:#x} rbp {:#x} rsi {:#x} rdi {:#x}",
                             reg(0x78), reg(0x80), reg(0x88), reg(0xA0), reg(0xA8), reg(0xB0));
                    println!("  thread RIP {rip:#x} (image+{:#x}) RSP {rsp:#x}",
                             rip.wrapping_sub(remote_base));
                    describe(proc, rip);
                    let mut stack = vec![0u8; 0x300];
                    let mut got = 0usize;
                    if unsafe { ReadProcessMemory(proc, rsp as *const c_void, stack.as_mut_ptr() as *mut c_void, stack.len(), &mut got) } != 0 {
                        for i in 0..got / 8 {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&stack[i * 8..i * 8 + 8]);
                            let v = u64::from_le_bytes(b);
                            if v > 0x7ff0_0000_0000 {
                                let mut line = format!("  [{:#04x}] {v:#x}", i * 8);
                                if let Some((name, off)) = module_offset(proc, v) {
                                    line.push_str(&format!("  {name}+{off:#x}"));
                                }
                                println!("{line}");
                            }
                        }
                    }
                } else {
                    println!("  GetThreadContext failed: {}", std::io::Error::last_os_error());
                }
            }
            }
        }
    }
    unsafe {
        CloseHandle(thread);
        CloseHandle(proc);
    }
    println!("mapped. no PEB entry. base {remote_base:#x}");
}
