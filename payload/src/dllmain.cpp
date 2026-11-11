// Zendo payload — M1 beacon.
// No CRT, no imports beyond what we resolve from the PEB at runtime.
// Build: payload/build.bat (cl, /NODEFAULTLIB, /ENTRY:DllMain)

#include <windows.h>

// Minimal PEB layout (x64). winternl.h leaves these opaque in current SDKs.
struct UString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct PebLdrData {
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct LdrEntry {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UString FullDllName;
    UString BaseDllName;
};

struct Peb {
    BYTE pad0[2];
    BYTE BeingDebugged;
    BYTE pad1;
    DWORD pad2;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PebLdrData* Ldr;
};

namespace zendo {

// The CRT normally provides this marker; a float in the profile needs it or
// the linker refuses _fltused.
extern "C" int _fltused = 1;

constexpr DWORD fnv1a(const char* s, DWORD h = 2166136261u) {
    return *s ? fnv1a(s + 1, (h ^ static_cast<unsigned char>(*s)) * 16777619u) : h;
}

constexpr DWORD fnv1a_w(const wchar_t* s, DWORD h = 2166136261u) {
    if (!*s) return h;
    wchar_t c = *s;
    if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - 32);
    return fnv1a_w(s + 1, (h ^ static_cast<unsigned short>(c)) * 16777619u);
}

struct Module {
    void* base;
    DWORD size;
};

inline Module find_module(DWORD name_hash) {
    auto* peb = reinterpret_cast<Peb*>(__readgsqword(0x60));
    auto* head = &peb->Ldr->InLoadOrderModuleList;
    for (auto* it = head->Flink; it != head; it = it->Flink) {
        auto* entry = CONTAINING_RECORD(it, LdrEntry, InLoadOrderLinks);
        if (!entry->BaseDllName.Buffer || !entry->DllBase) continue;
        if (fnv1a_w(entry->BaseDllName.Buffer) == name_hash) {
            return {entry->DllBase, entry->SizeOfImage};
        }
    }
    return {nullptr, 0};
}

inline LdrEntry* find_module_entry(DWORD name_hash) {
    auto* peb = reinterpret_cast<Peb*>(__readgsqword(0x60));
    auto* head = &peb->Ldr->InLoadOrderModuleList;
    for (auto* it = head->Flink; it != head; it = it->Flink) {
        auto* entry = CONTAINING_RECORD(it, LdrEntry, InLoadOrderLinks);
        if (!entry->BaseDllName.Buffer || !entry->DllBase) continue;
        if (fnv1a_w(entry->BaseDllName.Buffer) == name_hash) return entry;
    }
    return nullptr;
}

// Every address this payload uses is pinned to one client build. On any other
// build the writes land in unrelated code and the client dies with no
// explanation, so the first thing the payload does is prove it is in the build
// it was made for. The build id lives in the module path
// (...\Versions\version-<hash>\RobloxPlayerBeta.dll), which needs no PE parsing
// and no imports.
static const wchar_t k_build_tag[] = L"version-f0ea5da9412f4e35";

inline bool wide_contains(const UString& s, const wchar_t* needle) {
    if (!s.Buffer || s.Length < 2) return false;
    unsigned int n = s.Length / sizeof(wchar_t);
    unsigned int m = 0;
    while (needle[m]) ++m;
    if (m > n) return false;
    for (unsigned int i = 0; i + m <= n; ++i) {
        unsigned int j = 0;
        while (j < m && s.Buffer[i + j] == needle[j]) ++j;
        if (j == m) return true;
    }
    return false;
}

inline bool readable(const void* p, SIZE_T len);

inline void* find_export(void* module_base, DWORD name_hash) {
    auto* base = static_cast<unsigned char*>(module_base);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return nullptr;

    auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* names = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
    auto* ordinals = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);
    auto* functions = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (fnv1a(name) == name_hash) {
            return base + functions[ordinals[i]];
        }
    }
    return nullptr;
}

struct Mbi {
    void* BaseAddress;
    void* AllocationBase;
    DWORD AllocationProtect;
    DWORD pad0;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
    DWORD pad1;
};

struct Api {
    using CreateFileA_t = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using CreateMutexA_t = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
    using WaitForSingleObject_t = DWORD(WINAPI*)(HANDLE, DWORD);
    using ReleaseMutex_t = BOOL(WINAPI*)(HANDLE);
    using WriteFile_t = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using ReadFile_t = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using CloseHandle_t = BOOL(WINAPI*)(HANDLE);
    using Sleep_t = void(WINAPI*)(DWORD);
    using GetLastError_t = DWORD(WINAPI*)();
    using VirtualQuery_t = SIZE_T(WINAPI*)(LPCVOID, Mbi*, SIZE_T);
    using VirtualProtect_t = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD*);
    using FlushICache_t = BOOL(WINAPI*)(HANDLE, LPCVOID, SIZE_T);
    using AddVeh_t = void*(WINAPI*)(ULONG, void*);
    using RtlAddTable_t = unsigned char(WINAPI*)(void*, unsigned long, unsigned long long);
    using SetCfgTargets_t = BOOL(WINAPI*)(HANDLE, void*, SIZE_T, ULONG, void*);
    using VirtualAlloc_t = void*(WINAPI*)(void*, SIZE_T, DWORD, DWORD);
    using VirtualFree_t = BOOL(WINAPI*)(void*, SIZE_T, DWORD);

    CreateFileA_t CreateFileA;
    CreateMutexA_t CreateMutexA;
    WaitForSingleObject_t WaitForSingleObject;
    ReleaseMutex_t ReleaseMutex;
    WriteFile_t WriteFile;
    ReadFile_t ReadFile;
    CloseHandle_t CloseHandle;
    Sleep_t Sleep;
    GetLastError_t GetLastError;
    VirtualQuery_t VirtualQuery;
    VirtualProtect_t VirtualProtect;
    FlushICache_t FlushInstructionCache;
    AddVeh_t AddVectoredExceptionHandler;
    RtlAddTable_t RtlAddFunctionTable;
    SetCfgTargets_t SetProcessValidCallTargets;
    VirtualAlloc_t VirtualAlloc;
    VirtualFree_t VirtualFree;
    using SetMitigation_t = BOOL(WINAPI*)(int, void*, SIZE_T);
    SetMitigation_t SetProcessMitigationPolicy;
};

inline Api& api() {
    static Api a{};
    return a;
}

inline DWORD resolve_api() {
    constexpr DWORD k_kernel32 = fnv1a_w(L"kernel32.dll");
    Module k32 = find_module(k_kernel32);
    if (!k32.base) return 10;
    Api& a = api();
    a.CreateFileA = reinterpret_cast<Api::CreateFileA_t>(find_export(k32.base, fnv1a("CreateFileA")));
    a.CreateMutexA = reinterpret_cast<Api::CreateMutexA_t>(find_export(k32.base, fnv1a("CreateMutexA")));
    a.WaitForSingleObject =
        reinterpret_cast<Api::WaitForSingleObject_t>(find_export(k32.base, fnv1a("WaitForSingleObject")));
    a.ReleaseMutex = reinterpret_cast<Api::ReleaseMutex_t>(find_export(k32.base, fnv1a("ReleaseMutex")));
    a.WriteFile = reinterpret_cast<Api::WriteFile_t>(find_export(k32.base, fnv1a("WriteFile")));
    a.ReadFile = reinterpret_cast<Api::ReadFile_t>(find_export(k32.base, fnv1a("ReadFile")));
    a.CloseHandle = reinterpret_cast<Api::CloseHandle_t>(find_export(k32.base, fnv1a("CloseHandle")));
    a.Sleep = reinterpret_cast<Api::Sleep_t>(find_export(k32.base, fnv1a("Sleep")));
    a.GetLastError = reinterpret_cast<Api::GetLastError_t>(find_export(k32.base, fnv1a("GetLastError")));
    a.VirtualQuery = reinterpret_cast<Api::VirtualQuery_t>(find_export(k32.base, fnv1a("VirtualQuery")));
    a.VirtualProtect = reinterpret_cast<Api::VirtualProtect_t>(find_export(k32.base, fnv1a("VirtualProtect")));
    a.VirtualAlloc = reinterpret_cast<Api::VirtualAlloc_t>(find_export(k32.base, fnv1a("VirtualAlloc")));
    a.VirtualFree = reinterpret_cast<Api::VirtualFree_t>(find_export(k32.base, fnv1a("VirtualFree")));
    a.FlushInstructionCache =
        reinterpret_cast<Api::FlushICache_t>(find_export(k32.base, fnv1a("FlushInstructionCache")));
    a.AddVectoredExceptionHandler =
        reinterpret_cast<Api::AddVeh_t>(find_export(k32.base, fnv1a("AddVectoredExceptionHandler")));
    a.RtlAddFunctionTable =
        reinterpret_cast<Api::RtlAddTable_t>(find_export(k32.base, fnv1a("RtlAddFunctionTable")));
    // Only KernelBase exports this one; Kernel32 does not forward it.
    Module kbase = find_module(fnv1a_w(L"kernelbase.dll"));
    if (kbase.base) {
        a.SetProcessValidCallTargets = reinterpret_cast<Api::SetCfgTargets_t>(
            find_export(kbase.base, fnv1a("SetProcessValidCallTargets")));
        a.SetProcessMitigationPolicy = reinterpret_cast<Api::SetMitigation_t>(
            find_export(kbase.base, fnv1a("SetProcessMitigationPolicy")));
    }
    if (!a.CreateFileA) return 11;
    if (!a.WriteFile) return 12;
    if (!a.ReadFile) return 13;
    if (!a.CloseHandle) return 14;
    if (!a.Sleep) return 15;
    if (!a.VirtualQuery) return 16;
    return 0;
}

constexpr wchar_t k_pipe_dev[] = L"\\\\.\\pipe\\zendo-dev";

// A manual map has no PE header in the loader list, so RtlLookupFunctionEntry
// finds nothing for our frames and the x64 unwinder treats them as leaves.
// Any C++ throw or SEH exception that crosses a payload frame then fails to
// unwind and takes the process down. RtlAddFunctionTable hands the runtime our
// own .pdata, which is the whole fix.
inline unsigned long long self_image_base() {
    Mbi mbi;
    unsigned long long probe = reinterpret_cast<unsigned long long>(&self_image_base);
    if (!api().VirtualQuery(reinterpret_cast<const void*>(probe), &mbi, sizeof(mbi))) return 0;
    return reinterpret_cast<unsigned long long>(mbi.AllocationBase);
}

inline unsigned long long self_image_size(unsigned long long base) {
    if (!base) return 0;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

inline unsigned long long register_unwind_table() {
    unsigned long long base = self_image_base();
    if (!base || !api().RtlAddFunctionTable) return 0;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || dir.Size < 12) return 0;
    unsigned long count = dir.Size / 12;
    if (!api().RtlAddFunctionTable(reinterpret_cast<void*>(base + dir.VirtualAddress), count, base)) {
        return 0;
    }
    return count;
}

// Beacon: announce ourselves on the dev pipe and exit. Returns a status code
// the injector surfaces through the thread exit code while we bring M2 up.
// Bring-up bisect switch: build.bat <stage> selects how far DllMain goes.
// The injector surfaces the returned code as the thread exit status.
#ifndef ZENDO_STAGE
#define ZENDO_STAGE 4
#endif

inline char* append_hex(char* p, unsigned long long v) {
    *p++ = '0';
    *p++ = 'x';
    char tmp[16];
    int n = 0;
    if (!v) tmp[n++] = '0';
    while (v) {
        int d = static_cast<int>(v & 0xF);
        tmp[n++] = static_cast<char>(d < 10 ? '0' + d : 'a' + d - 10);
        v >>= 4;
    }
    while (n) *p++ = tmp[--n];
    return p;
}

// ---------------------------------------------------------------------------
// Runtime probe: find the real lua_State from live process memory.
//
// The capability helper at RVA 0x4274D10 reads an encoded pointer from
// <object>+0x210 and <object>+0x520. The encoding is split into two halves,
// each relative to the low 32 bits of the slot's own address:
//     lo = (u32)slot - (u32)enc
//     hi = (u32)slot - (u32)(enc >> 32)
// A plain 64-bit subtraction is reported too, so the wrong hypothesis is
// visible instead of assumed.
// ---------------------------------------------------------------------------

constexpr unsigned long long k_fake_dm_static = 0x8EB6960;
constexpr unsigned long long k_ve_static = 0x8942E38;
constexpr unsigned long long k_fake_dm_to_dm = 0x1F8;
constexpr unsigned long long k_dm_to_script_context = 0x440;
constexpr unsigned long long k_ve_to_fake_dm = 0xAF0;
constexpr unsigned long long k_slot_a = 0x210;
constexpr unsigned long long k_slot_b = 0x520;

// Primary vtable of ScriptContext, extracted from the image's RTTI:
// type descriptor ".?AVScriptContext@RBX@@" -> COL 0x78bc9e8 (offset 0)
// -> vtable[-1] at 0x71b0fe0, so the object's [0] is base + 0x71b0fe8.
constexpr unsigned long long k_script_context_vtable = 0x71B0FE8;
constexpr unsigned long long k_lua_vm_load = 0x426A570;

inline bool readable(const void* p, SIZE_T len) {
    if (reinterpret_cast<unsigned long long>(p) < 0x10000) return false;
    Mbi mbi;
    if (!api().VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return false;
    unsigned long long begin = reinterpret_cast<unsigned long long>(mbi.BaseAddress);
    unsigned long long at = reinterpret_cast<unsigned long long>(p);
    return at + len <= begin + mbi.RegionSize;
}

// A pinned address cannot be validated by asking whether its page is mapped:
// the protector commits and releases code pages on demand, so a healthy client
// reports FREE at an address that works the moment it is executed. What is
// stable is the image itself - a valid PE header at the base we resolved and a
// plausible size. Which build it is, the path tag already says precisely.
static int g_off_fail = -1;

inline bool offsets_ok(unsigned long long base, const Module& m) {
    (void)m;
    g_off_fail = 0;
    if (base < 0x10000) return false;
    if (!readable(reinterpret_cast<const void*>(base), 0x40)) return false;
    auto* dos = reinterpret_cast<const unsigned char*>(base);
    if (dos[0] != 'M' || dos[1] != 'Z') return false;
    unsigned int lfanew = *reinterpret_cast<const volatile unsigned int*>(base + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x1000) return false;
    if (!readable(reinterpret_cast<const void*>(base + lfanew), 0x58)) return false;
    auto* nt = reinterpret_cast<const unsigned char*>(base + lfanew);
    if (nt[0] != 'P' || nt[1] != 'E') return false;
    unsigned short machine = *reinterpret_cast<const volatile unsigned short*>(nt + 4);
    if (machine != 0x8664) return false;
    unsigned int size_of_image = *reinterpret_cast<const volatile unsigned int*>(nt + 0x50);
    if (size_of_image < 0x100000 || size_of_image > 0x40000000) return false;
    g_off_fail = -1;
    return true;
}

inline bool read_u64(unsigned long long addr, unsigned long long* out) {
    if (!addr || !readable(reinterpret_cast<const void*>(addr), 8)) return false;
    *out = *reinterpret_cast<volatile unsigned long long*>(addr);
    return true;
}

inline bool read_u32(unsigned long long addr, unsigned int* out) {
    if (!addr || !readable(reinterpret_cast<const void*>(addr), 4)) return false;
    *out = *reinterpret_cast<volatile unsigned int*>(addr);
    return true;
}

inline unsigned long long decode_split(unsigned long long slot) {
    unsigned long long enc = 0;
    if (!read_u64(slot, &enc)) return 0;
    unsigned int slot_lo = static_cast<unsigned int>(slot);
    unsigned long long lo = static_cast<unsigned int>(slot_lo - static_cast<unsigned int>(enc));
    unsigned long long hi = static_cast<unsigned int>(slot_lo - static_cast<unsigned int>(enc >> 32));
    return (hi << 32) | lo;
}

inline void wr64(unsigned long long addr, unsigned long long v) {
    *reinterpret_cast<volatile unsigned long long*>(addr) = v;
}

// Every offset the payload writes to belongs to an object the game's own GC
// owns. Between two sessions that object can be collected and the page handed
// to something else, so a blind store is a write into whatever lives there now
// - a crash the client reports as nothing at all. This variant refuses unless
// the page is committed and writable, and says whether it wrote.
inline bool wr64_live(unsigned long long addr, unsigned long long v) {
    if (addr < 0x10000) return false;
    Mbi mbi;
    if (!api().VirtualQuery || !api().VirtualQuery(reinterpret_cast<void*>(addr), &mbi,
                                                   sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    DWORD prot = mbi.Protect & 0xff;
    if (prot != PAGE_READWRITE && prot != PAGE_WRITECOPY &&
        prot != PAGE_EXECUTE_READWRITE && prot != PAGE_EXECUTE_WRITECOPY)
        return false;
    *reinterpret_cast<volatile unsigned long long*>(addr) = v;
    return true;
}

inline void wr32(unsigned long long addr, unsigned int v) {
    *reinterpret_cast<volatile unsigned int*>(addr) = v;
}

struct Out {
    char buf[16384];
    DWORD n;

    void reset() { n = 0; }
    void ch(char c) {
        if (n + 1 < sizeof(buf)) buf[n++] = c;
    }
    void str(const char* s) {
        while (*s) ch(*s++);
    }
    void hex(unsigned long long v) {
        char* p = append_hex(buf + n, v);
        n = static_cast<DWORD>(p - buf);
        if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    }
    void dec(unsigned int v) {
        char tmp[10];
        int k = 0;
        if (!v) tmp[k++] = '0';
        while (v) {
            tmp[k++] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
        while (k) ch(tmp[--k]);
    }
    void nl() { ch('\n'); }
};

inline void dump_state(Out& o, unsigned long long L) {
    o.str("      L=");
    o.hex(L);
    unsigned long long gs = 0, gt = 0, stk = 0, top = 0, ci = 0, extra = 0, identity = 0, mt = 0;
    unsigned int cap = 0;
    bool ok = read_u64(L + 0x50, &gs) && read_u64(L + 0x10, &gt) && read_u64(L + 0x48, &stk) &&
              read_u64(L + 0x60, &top) && read_u64(L + 0x70, &ci) && read_u64(L + 0x8, &extra);
    o.str(" gs=");
    o.hex(gs);
    if (gs) {
        read_u32(gs + 0x640, &cap);
        read_u64(gs + 0x78, &mt);
    }
    if (extra) read_u64(extra + 0x70, &identity);
    o.str(" cap=");
    o.hex(cap);
    o.str(" id=");
    o.hex(identity);
    o.str(" mt=");
    o.hex(mt);
    o.str(" gt=");
    o.hex(gt);
    o.str(" stk=");
    o.hex(stk);
    o.str(" top=");
    o.hex(top);
    o.str(" ci=");
    o.hex(ci);
    if (!ok) o.str(" partial");
    o.nl();
}

inline void probe_object(Out& o, char tag, unsigned long long obj) {
    o.str("  ");
    o.ch(tag);
    o.str(" obj=");
    o.hex(obj);
    if (!obj) {
        o.nl();
        return;
    }
    unsigned int state = 0;
    unsigned long long vt = 0, cls = 0;
    read_u64(obj, &vt);
    read_u64(obj + 0x18, &cls);
    read_u32(obj + 0x1628, &state);
    o.str(" vt=");
    o.hex(vt);
    o.str(" cls=");
    o.hex(cls);
    o.str(" st=");
    o.hex(state);
    o.nl();

    const unsigned long long slots[2] = {k_slot_a, k_slot_b};
    const char* names[2] = {"s210", "s520"};
    for (int i = 0; i < 2; ++i) {
        unsigned long long slot = obj + slots[i];
        unsigned long long enc = 0;
        if (!read_u64(slot, &enc)) {
            o.str("    ");
            o.str(names[i]);
            o.str(" unreadable");
            o.nl();
            continue;
        }
        unsigned long long d32 = decode_split(slot);
        unsigned long long d64 = slot - enc;
        o.str("    ");
        o.str(names[i]);
        o.str(" enc=");
        o.hex(enc);
        o.str(" d32=");
        o.hex(d32);
        o.str(" d64=");
        o.hex(d64);
        o.nl();
        dump_state(o, d32);
        if (d64 != d32) dump_state(o, d64);
    }
}

inline int find_by_vtable(unsigned long long target, unsigned long long* hits, int cap) {
    int n = 0;
    unsigned long long addr = 0x10000;
    for (;;) {
        Mbi mbi;
        if (!api().VirtualQuery(reinterpret_cast<const void*>(addr), &mbi, sizeof(mbi))) break;
        unsigned long long begin = reinterpret_cast<unsigned long long>(mbi.BaseAddress);
        unsigned long long next = begin + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
        if (mbi.State != MEM_COMMIT) continue;
        DWORD prot = mbi.Protect & 0xFF;
        if (prot != PAGE_READWRITE && prot != PAGE_EXECUTE_READWRITE &&
            prot != PAGE_WRITECOPY && prot != PAGE_EXECUTE_WRITECOPY) continue;
        unsigned long long p = (begin + 7) & ~7ull;
        unsigned long long end = begin + mbi.RegionSize;
        for (; p + 8 <= end; p += 8) {
            if (*reinterpret_cast<volatile unsigned long long*>(p) == target) {
                hits[n++] = p;
                if (n >= cap) return n;
            }
        }
    }
    return n;
}

inline int scan_for_vtable(unsigned long long begin, unsigned long long limit,
                           unsigned long long target, unsigned long long* fields,
                           unsigned long long* objs, int cap) {
    int n = 0;
    for (unsigned long long off = 0; off + 8 <= limit; off += 8) {
        unsigned long long v = 0, vt = 0;
        if (!read_u64(begin + off, &v)) break;
        if (v < 0x10000 || v > 0x7fffffffffffull) continue;
        if (!read_u64(v, &vt)) continue;
        if (vt == target) {
            fields[n] = begin + off;
            objs[n] = v;
            if (++n >= cap) return n;
        }
    }
    return n;
}

// The service map is an MSVC std::map<uint64 classId, shared_ptr<Instance>>:
// head node at [provider + 0xB0], root at [head + 8], node = {left, parent,
// right, colour, pad, key @+0x20, shared_ptr value @+0x28}.
inline void tree_report(Out& o, unsigned long long dm) {
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("  dm=");
    o.hex(dm);
    unsigned long long head = 0, root = 0, cls = 0;
    read_u64(dm + 0xB0, &head);
    read_u64(head + 8, &root);
    read_u64(base + 0x8D7EAE0, &cls);
    o.str(" head=");
    o.hex(head);
    o.str(" root=");
    o.hex(root);
    o.str(" classIdStatic=");
    o.hex(cls);
    o.nl();
    if (!head || !root) return;

    unsigned long long stack[128];
    int sp = 0;
    stack[sp++] = root;
    int seen = 0, hits = 0, sc_key = -1;
    while (sp > 0 && seen < 160) {
        unsigned long long n = stack[--sp];
        if (!n || n == head) continue;
        unsigned long long key = 0, val = 0, left = 0, right = 0;
        if (!read_u64(n + 0x20, &key)) continue;
        read_u64(n + 0x28, &val);
        read_u64(n, &left);
        read_u64(n + 0x10, &right);
        if (left && left != head && sp < 128) stack[sp++] = left;
        if (right && right != head && sp < 128) stack[sp++] = right;
        ++seen;
        unsigned long long vt = 0;
        if (val) read_u64(val, &vt);
        unsigned long long vt_rva = (vt > base && vt < base + 0x20000000) ? vt - base : 0;
        o.str("    n=");
        o.hex(n);
        o.str(" key=");
        o.hex(key);
        o.str(" val=");
        o.hex(val);
        o.str(" vt+");
        o.hex(vt_rva);
        if (vt_rva == k_script_context_vtable) {
            o.str("  <== ScriptContext");
            sc_key = hits;
        }
        o.nl();
        if (vt_rva == k_script_context_vtable) {
            ++hits;
            if (hits == 1) {
                probe_object(o, 'S', val);
                unsigned long long l0 = decode_split(val + k_slot_a);
                unsigned long long l1 = decode_split(val + k_slot_b);
                o.str("    L210=");
                o.hex(l0);
                o.str(" L520=");
                o.hex(l1);
                o.nl();
                if (l0) dump_state(o, l0);
                if (l1 && l1 != l0) dump_state(o, l1);
            }
        }
    }
    o.str("  nodes=");
    o.dec(static_cast<unsigned int>(seen));
    o.str(" sc=");
    o.dec(static_cast<unsigned int>(hits));
    o.str(" sc_key=");
    o.dec(static_cast<unsigned int>(sc_key));
    o.nl();
}

inline void probe_report(Out& o, bool scan, bool local) {
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 probe base=");
    o.hex(base);
    o.nl();

    unsigned long long fake_static = 0, ve = 0;
    read_u64(base + k_fake_dm_static, &fake_static);
    read_u64(base + k_ve_static, &ve);
    o.str("  fake_static=");
    o.hex(fake_static);
    o.str(" ve=");
    o.hex(ve);
    o.nl();

    unsigned long long fake_from_ve = 0, dm_a = 0, dm_c = 0, dm_b = fake_static, dm_d = 0;
    if (ve) read_u64(ve + k_ve_to_fake_dm, &fake_from_ve);
    if (fake_from_ve) read_u64(fake_from_ve + k_fake_dm_to_dm, &dm_c);
    if (fake_static) read_u64(fake_static + k_fake_dm_to_dm, &dm_a);
    dm_d = fake_from_ve;

    o.str("  dmA=");
    o.hex(dm_a);
    o.str(" dmB=");
    o.hex(dm_b);
    o.str(" dmC=");
    o.hex(dm_c);
    o.str(" dmD=");
    o.hex(dm_d);
    o.nl();

    probe_object(o, 'A', dm_a);
    probe_object(o, 'B', dm_b);
    probe_object(o, 'C', dm_c);
    probe_object(o, 'D', dm_d);

    unsigned long long sc_a = 0, sc_b = 0, sc_c = 0, sc_d = 0;
    if (dm_a) read_u64(dm_a + k_dm_to_script_context, &sc_a);
    if (dm_b) read_u64(dm_b + k_dm_to_script_context, &sc_b);
    if (dm_c) read_u64(dm_c + k_dm_to_script_context, &sc_c);
    if (dm_d) read_u64(dm_d + k_dm_to_script_context, &sc_d);
    o.str("  scA=");
    o.hex(sc_a);
    o.str(" scB=");
    o.hex(sc_b);
    o.str(" scC=");
    o.hex(sc_c);
    o.str(" scD=");
    o.hex(sc_d);
    o.nl();

    probe_object(o, 'a', sc_a);
    probe_object(o, 'b', sc_b);
    probe_object(o, 'c', sc_c);
    probe_object(o, 'd', sc_d);

    unsigned long long hits[3] = {0, 0, 0};
    if (scan) {
        int nh = find_by_vtable(base + k_script_context_vtable, hits, 3);
        o.str("  scan vt=");
        o.hex(base + k_script_context_vtable);
        o.str(" hits=");
        o.dec(static_cast<unsigned int>(nh));
        o.nl();
        for (int i = 0; i < nh; ++i) probe_object(o, 'S', hits[i]);
    }
    if (local) {
        const unsigned long long roots[2] = {dm_a, dm_b};
        const char* names[2] = {"dmA", "dmB"};
        for (int r = 0; r < 2; ++r) {
            unsigned long long root = roots[r];
            if (!root) continue;
            unsigned long long limit = 0x8000;
            Mbi mbi;
            if (api().VirtualQuery(reinterpret_cast<const void*>(root), &mbi, sizeof(mbi))) {
                unsigned long long region_end =
                    reinterpret_cast<unsigned long long>(mbi.BaseAddress) + mbi.RegionSize;
                if (region_end > root && region_end - root < limit) limit = region_end - root;
            }
            unsigned long long fields[4] = {0, 0, 0, 0};
            unsigned long long objs[4] = {0, 0, 0, 0};
            int nh = scan_for_vtable(root, limit, base + k_script_context_vtable, fields, objs, 4);
            o.str("  local ");
            o.str(names[r]);
            o.str("=");
            o.hex(root);
            o.str(" limit=");
            o.hex(limit);
            o.str(" hits=");
            o.dec(static_cast<unsigned int>(nh));
            o.nl();
            for (int i = 0; i < nh; ++i) {
                o.str("    field=+");
                o.hex(fields[i] - root);
                o.nl();
                probe_object(o, 'L', objs[i]);
            }
        }
    }
    o.str("END\n");
}

// Walks the DataModel service map (std::map keyed by class id at +0xB0) and
// returns the first instance whose vtable matches.
inline unsigned long long find_service(unsigned long long base, unsigned long long target,
                                       unsigned long long dm) {
    unsigned long long head = 0, root = 0;
    if (!dm || !read_u64(dm + 0xB0, &head) || !head) return 0;
    if (!read_u64(head + 8, &root) || !root) return 0;
    unsigned long long stack[128];
    int sp = 0, seen = 0;
    stack[sp++] = root;
    while (sp > 0 && seen < 256) {
        unsigned long long n = stack[--sp];
        if (!n || n == head) continue;
        unsigned long long val = 0, left = 0, right = 0;
        read_u64(n + 0x28, &val);
        read_u64(n, &left);
        read_u64(n + 0x10, &right);
        if (left && left != head && sp < 128) stack[sp++] = left;
        if (right && right != head && sp < 128) stack[sp++] = right;
        ++seen;
        if (!val) continue;
        unsigned long long vt = 0;
        if (!read_u64(val, &vt)) continue;
        if (vt == target) return val;
    }
    (void)base;
    return 0;
}

inline DWORD run_load() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 load base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    o.str("  sc=");
    o.hex(sc);
    if (!sc) {
        o.str("  no ScriptContext\n");
    } else {
        unsigned long long L = decode_split(sc + k_slot_a);
        unsigned int guard = 0;
        read_u32(sc + 0x1628, &guard);
        unsigned long long top0 = 0, stack = 0;
        read_u64(L + 0x60, &top0);
        read_u64(L + 0x48, &stack);
        o.str("  L=");
        o.hex(L);
        o.str(" guard=");
        o.hex(guard);
        o.str(" top=");
        o.hex(top0);
        o.str(" stack=");
        o.hex(stack);
        o.nl();

        unsigned long long cache[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        typedef int (*LoadFn)(void*, void*, const char*, unsigned int, int);
        LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
        const char* tests[5] = {
            "",
            "x",
            "local x = 1",
            "return 1 + 1",
            "local x = 1 + 1 return x",
        };
        for (int ti = 0; ti < 5; ++ti) {
            const char* src = tests[ti];
            unsigned int len = 0;
            while (src[len]) ++len;
            unsigned long long t0 = 0;
            read_u64(L + 0x60, &t0);
            int ret = load(reinterpret_cast<void*>(L), cache, src, len, 0);
            unsigned long long t1 = 0;
            read_u64(L + 0x60, &t1);
            o.str("  t");
            o.dec(static_cast<unsigned int>(ti));
            o.str(" len=");
            o.dec(len);
            o.str(" ret=");
            o.dec(static_cast<unsigned int>(ret));
            o.str(" d=");
            o.hex(t1 - t0);
            o.str(" src='");
            o.str(src);
            o.str("'");
            o.nl();
            if (t1 > t0 && t1 - t0 >= 16) {
                unsigned long long v = 0, hi = 0;
                read_u64(t0, &v);
                read_u64(t0 + 8, &hi);
                o.str("    v=");
                o.hex(v);
                o.str(" w=");
                o.hex(hi);
                o.str(" tt=");
                o.dec(static_cast<unsigned int>((hi >> 32) & 0xffff));
                o.nl();
                if (v && readable(reinterpret_cast<const void*>(v + 0x18), 4)) {
                    unsigned int slen = 0;
                    read_u32(v + 0x14, &slen);
                    o.str("    s len=");
                    o.dec(slen);
                    o.str(" '");
                    if (slen < 120) {
                        for (unsigned int k = 0; k < slen; ++k)
                            o.ch(*reinterpret_cast<char*>(v + 0x18 + k));
                    }
                    o.str("'");
                    o.nl();
                }
            }
        }
    }
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline void dump_tv(Out& o, unsigned long long slot, const char* tag);

inline void dump_tv(Out& o, unsigned long long slot, const char* tag) {
    unsigned long long v = 0, w = 0;
    if (!read_u64(slot, &v) || !read_u64(slot + 8, &w)) {
        o.str(tag);
        o.str(" unreadable");
        o.nl();
        return;
    }
    o.str(tag);
    o.str(" v=");
    o.hex(v);
    o.str(" w=");
    o.hex(w);
    o.str(" tt=");
    o.dec(static_cast<unsigned int>((w >> 32) & 0xff));
    if (v && readable(reinterpret_cast<const void*>(v + 0x18), 4)) {
        unsigned int slen = 0;
        read_u32(v + 0x14, &slen);
        if (slen < 90) {
            o.str(" '");
            for (unsigned int k = 0; k < slen; ++k) o.ch(*reinterpret_cast<char*>(v + 0x18 + k));
            o.str("'");
        }
    }
    o.nl();
}

// MSVC std::string: inline buffer / heap pointer at +0, size at +0x10,
// capacity at +0x18. LuaVMLoad checks size>8 and capacity>=16, then reads
// the data pointer from +0.
struct ChunkName {
    const char* data;
    unsigned long long pad;
    unsigned long long size;
    unsigned long long cap;
};

// Loads plain Luau source with a well formed chunkname and reports exactly
// what the loader pushed. No task machinery, no unproven calls.
inline DWORD run_chunk() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 chunk base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("  sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    unsigned int flag = 0;
    read_u32(base + 0x81967B0, &flag);
    o.str("  byte_81967B0=");
    o.hex(flag & 0xff);
    o.nl();
    if (!L) {
        o.str("  no state\n");
    } else {
        unsigned long long top0 = 0;
        read_u64(L + 0x60, &top0);

        static char name_buf[32];
        const char* nm = "=zendo.chunk";
        int k = 0;
        while (nm[k]) { name_buf[k] = nm[k]; ++k; }
        name_buf[k] = 0;

        ChunkName cn;
        cn.data = name_buf;
        cn.pad = 0;
        cn.size = static_cast<unsigned long long>(k);
        cn.cap = 31;

        const char* src = "return 1 + 1";
        unsigned int len = 0;
        while (src[len]) ++len;
        o.str("  cn len=");
        o.dec(k);
        o.str(" src len=");
        o.dec(len);
        o.nl();

        typedef int (*LoadFn)(void*, void*, const char*, int);
        LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
        int ret = load(reinterpret_cast<void*>(L), &cn, src, 0);
        unsigned long long t1 = 0;
        read_u64(L + 0x60, &t1);
        o.str("  ret=");
        o.dec(static_cast<unsigned int>(ret));
        o.str(" top=");
        o.hex(t1);
        o.str(" d=");
        o.hex(t1 - top0);
        o.nl();
        if (t1 > top0) dump_tv(o, top0, "  val:");
        if (t1 > top0 && t1 - top0 >= 16) {
            unsigned long long v = 0, w = 0;
            read_u64(top0, &v);
            read_u64(top0 + 8, &w);
            if (v && readable(reinterpret_cast<const void*>(v), 0x40)) {
                o.str("  raw:");
                for (int i = 0; i < 0x40; i += 8) {
                    unsigned long long q = 0;
                    read_u64(v + static_cast<unsigned long long>(i), &q);
                    o.str(" ");
                    o.hex(q);
                }
                o.nl();
            }
        }
    }
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 18: real bytecode. LuaVMLoad's raw path compares the first qword of
// the std::string against 0xE009325B4A107A52 (rodata 0x6AF9FF0) and, on match,
// hands data+8 / size-8 to the protected undump. Body compiled offline by
// luau-compile; header is the build's 8 byte magic.
#include "chunk.inc"
#include "probe.inc"
#include "raw.inc"
#include "../chunks/live_a.inc"
#include "../chunks/live_b.inc"
#include "../chunks/live_c.inc"
#include "../chunks/live_d.inc"
#include "../chunks/c1.inc"
#include "../chunks/c2.inc"
#include "../chunks/c3.inc"
#include "../chunks/c4.inc"
#include "../chunks/c6.inc"
#include "../chunks/c7.inc"
#include "../chunks/live1.inc"
#include "../chunks/c8.inc"
#include "../chunks/c9.inc"
#include "../chunks/c10.inc"
#include "../chunks/c11.inc"
#include "../chunks/c12.inc"
#include "../chunks/c13.inc"
#include "../chunks/c14.inc"
#include "../chunks/c15.inc"
#include "../chunks/c16.inc"
#include "../chunks/c17.inc"
#include "../chunks/c18.inc"
#include "../chunks/c19.inc"
#include "../chunks/c20.inc"
#include "../chunks/c21.inc"
#include "../chunks/c22.inc"
#include "../chunks/c23.inc"
#include "../chunks/c24.inc"
#include "../chunks/c25.inc"
#include "../chunks/c26.inc"
#include "../chunks/c27.inc"
#include "../chunks/c28.inc"
#include "../chunks/c29.inc"
#include "../chunks/c31.inc"
#include "../chunks/c32.inc"
#include "../chunks/c33.inc"
#include "../chunks/c34.inc"
#include "../chunks/gbind.inc"
#include "../chunks/c35.inc"
#include "../chunks/c36.inc"
#include "../chunks/c37.inc"
#include "../chunks/c39.inc"
#include "../chunks/c40.inc"
#include "../chunks/c41.inc"
#include "../chunks/c42.inc"
#include "../chunks/kcapture.inc"
#include "../chunks/knative.inc"
#include "../chunks/z42.inc"
#include "../chunks/zapi.inc"
#include "../chunks/zbind.inc"
#include "../chunks/zcall.inc"

inline DWORD run_bc() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 bc base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("  sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    if (!L) {
        o.str("  no state\n");
    } else {
        static unsigned char container[8 + kChunkLen];
        const unsigned long long magic = 0xE009325B4A107A52ull;
        for (int i = 0; i < 8; ++i) container[i] = static_cast<unsigned char>(magic >> (8 * i));
        for (unsigned int i = 0; i < kChunkLen; ++i) container[8 + i] = kChunkBody[i];

        ChunkName src;
        src.data = reinterpret_cast<const char*>(container);
        src.pad = 0;
        src.size = 8ull + kChunkLen;
        src.cap = 8ull + kChunkLen;

        unsigned long long top0 = 0;
        read_u64(L + 0x60, &top0);

        o.str("  body=");
        o.dec(kChunkLen);
        o.str(" bytes, hdr=");
        o.hex(container[0]);
        o.hex(container[1]);
        o.hex(container[2]);
        o.hex(container[3]);
        o.nl();

        typedef int (*LoadFn)(void*, void*, const char*, int);
        LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
        int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
        unsigned long long t1 = 0;
        read_u64(L + 0x60, &t1);
        o.str("  ret=");
        o.dec(static_cast<unsigned int>(ret));
        o.str(" top=");
        o.hex(t1);
        o.str(" d=");
        o.hex(t1 - top0);
        o.nl();
        if (t1 > top0) dump_tv(o, top0, "  val:");
    }
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Writes whatever the report buffer holds and empties it. Stage diagnostics
// flush after every section so a crash still leaves a trail on the pipe.
inline void flush_out(Api& a, HANDLE pipe, Out& o) {
    if (o.n == 0) return;
    DWORD written = 0;
    a.WriteFile(pipe, o.buf, o.n, &written, nullptr);
    o.reset();
}

// Pipe reads are message-mode: each WriteFile on the far side is one message.
// Drain until the caller's byte count is satisfied or the pipe dies.
inline bool read_all(Api& a, HANDLE pipe, void* dst, unsigned int len) {
    unsigned char* p = static_cast<unsigned char*>(dst);
    unsigned int got = 0;
    while (got < len) {
        DWORD rd = 0;
        if (!a.ReadFile(pipe, p + got, len - got, &rd, nullptr) || rd == 0)
            return false;
        got += rd;
    }
    return true;
}

inline void diag_line(Out& o, const char* tag, unsigned long long v) {
    o.str("  ");
    o.str(tag);
    o.str("=");
    o.hex(v);
    o.nl();
}

inline void diag_ci(Out& o, unsigned long long ci_addr) {
    unsigned long long base = 0, top = 0, func = 0, p = 0, pc = 0;
    unsigned int nresults = 0, flags = 0;
    bool ok = read_u64(ci_addr, &base) && read_u64(ci_addr + 8, &top) &&
              read_u64(ci_addr + 0x10, &func) && read_u64(ci_addr + 0x18, &p) &&
              read_u64(ci_addr + 0x20, &pc);
    read_u32(ci_addr + 0x28, &nresults);
    read_u32(ci_addr + 0x2C, &flags);
    o.str("    ci ");
    o.hex(ci_addr);
    if (!ok) {
        o.str(" unreadable");
        o.nl();
        return;
    }
    o.str(" base=");
    o.hex(base);
    o.str(" top=");
    o.hex(top);
    o.str(" func=");
    o.hex(func);
    o.str(" p=");
    o.hex(p);
    o.str(" pc=");
    o.hex(pc);
    o.str(" nr=");
    o.dec(nresults);
    o.str(" fl=");
    o.hex(flags);
    o.nl();
}

inline void diag_proto(Out& o, unsigned long long p) {
    if (!p || !readable(reinterpret_cast<const void*>(p), 0xE8)) {
        o.str("  proto unreadable");
        o.nl();
        return;
    }
    unsigned int u = 0;
    unsigned long long q = 0;
    o.str("  proto=");
    o.hex(p);
    read_u32(p + 3, &u);
    o.str(" vararg=");
    o.dec(u & 0xff);
    read_u32(p + 4, &u);
    o.str(" maxstack=");
    o.dec(u & 0xff);
    read_u32(p + 5, &u);
    o.str(" nups=");
    o.dec(u & 0xff);
    read_u32(p + 6, &u);
    o.str(" flags=");
    o.dec(u & 0xff);
    read_u32(p + 7, &u);
    o.str(" nparams=");
    o.dec(u & 0xff);
    o.nl();

    o.str("    execdata=");
    read_u64(p + 0x08, &q);
    o.hex(q);
    o.str(" exectarget=");
    read_u64(p + 0x10, &q);
    o.hex(q);
    read_u32(p + 0x18, &u);
    o.str(" execflags=");
    o.hex(u & 0xff);
    read_u32(p + 0x28, &u);
    o.str(" execcount=");
    o.dec(u);
    o.nl();

    o.str("    code=");
    read_u64(p + 0x68, &q);
    o.hex(q);
    o.str(" codeentry=");
    read_u64(p + 0x90, &q);
    o.hex(q);
    read_u32(p + 0x98, &u);
    o.str(" sizeupvalues=");
    o.dec(u);
    read_u32(p + 0xA0, &u);
    o.str(" sizep=");
    o.dec(u);
    read_u32(p + 0xA4, &u);
    o.str(" linedefined=");
    o.dec(u);
    o.nl();

    read_u32(p + 0xA8, &u);
    o.str("    sizecode=");
    o.dec(u);
    unsigned int sizecode = u;
    read_u32(p + 0xAC, &u);
    o.str(" sizek=");
    o.dec(u);
    read_u32(p + 0xB0, &u);
    o.str(" size_lineinfo=");
    o.dec(u);
    read_u32(p + 0xB4, &u);
    o.str(" bytecodeid=");
    o.dec(u);
    read_u32(p + 0xB8, &u);
    o.str(" sizetypeinfo=");
    o.dec(u);
    o.nl();

    read_u32(p + 0xC8, &u);
    o.str("    feedbackvecsize=");
    o.dec(u);
    read_u32(p + 0xCC, &u);
    o.str(" funid=");
    o.dec(u);
    o.str(" optimized=");
    read_u64(p + 0xD0, &q);
    o.hex(q);
    o.str(" deoptimized=");
    read_u64(p + 0xD8, &q);
    o.hex(q);
    o.nl();

    unsigned long long code = 0;
    read_u64(p + 0x68, &code);
    if (code && sizecode && sizecode < 512 &&
        readable(reinterpret_cast<const void*>(code), 4ull * sizecode)) {
        unsigned int n = sizecode < 10 ? sizecode : 10;
        o.str("    insn:");
        for (unsigned int i = 0; i < n; ++i) {
            unsigned int ins = 0;
            read_u32(code + 4ull * i, &ins);
            o.str(" ");
            o.hex(ins);
        }
        o.nl();
    }
}

// The VM can fault (or throw) inside client code with our manual-mapped frame
// on the stack, where no .pdata exists and nothing can unwind. A vectored
// handler still runs first, so it writes the fault address and the VM's own
// frame state to the pipe before the process dies.
static HANDLE g_veh_pipe = nullptr;
static unsigned long long g_veh_base = 0;
static unsigned long long g_veh_L = 0;
static unsigned long long g_veh_payload = 0;
static unsigned long long g_veh_payload_size = 0;
static const char* g_veh_phase = "boot";
static volatile long g_veh_depth = 0;
// The thread that runs DllMain. Anything faulting elsewhere is the client's
// own business and must not be turned into a report or a pipe write.
static unsigned long long g_veh_tid = 0;

inline void stage_mark(Api& a, const char* s);
inline void loop_mark(Api& a, unsigned int n);

inline bool str_eq(const char* a, const char* b) {
    if (!a || !b) return false;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

inline LONG CALLBACK veh_log(EXCEPTION_POINTERS* ep) {
    if (g_veh_depth) return EXCEPTION_CONTINUE_SEARCH;
    g_veh_depth = 1;

    const unsigned long long exc_code = ep->ExceptionRecord->ExceptionCode;
    const unsigned long long exc_rip =
        static_cast<unsigned long long>(ep->ContextRecord->Rip);
    const bool in_payload =
        g_veh_payload && exc_rip >= g_veh_payload &&
        exc_rip < g_veh_payload + g_veh_payload_size;
    const bool ours = in_payload || (g_veh_tid && __readgsqword(0x48) == g_veh_tid);

    // Luau raises a C++ exception (0xE06D7363) on every pcall failure. It is
    // the normal error path, not a fault: logging it would report every script
    // error as a crash and, worse, fill a pipe the session is still using.
    if (exc_code == 0xE06D7363ull) {
        g_veh_depth = 0;
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Fatal codes deserve a line even from a client thread: if the client dies
    // during our session, the reason has to survive longer than the process.
    const bool fatal = exc_code == 0xC0000005ull ||  // access violation
                       exc_code == 0xC000001Dull ||  // illegal instruction
                       exc_code == 0xC0000094ull ||  // integer divide by zero
                       exc_code == 0xC00000FDull ||  // stack overflow
                       exc_code == 0xC0000409ull ||  // fast fail
                       exc_code == 0xC0000006ull ||  // in-page I/O error
                       exc_code == 0xC0000017ull;    // out of memory
    if (!ours && (!fatal || str_eq(g_veh_phase, "boot"))) {
        g_veh_depth = 0;
        return EXCEPTION_CONTINUE_SEARCH;
    }

    static Out h;
    h.reset();
    h.str("!! FAULT kind=");
    h.str(exc_code == 0xC0000005ull ? "av" : (fatal ? "fatal" : "exc"));
    h.str(" code=");
    h.hex(exc_code);
    h.str(" rip=");
    h.hex(exc_rip);
    h.str(" rva=");
    h.hex(exc_rip > g_veh_base ? exc_rip - g_veh_base : 0);
    if (in_payload) {
        h.str(" INPAY p_rva=");
        h.hex(exc_rip - g_veh_payload);
    }
    if (g_veh_phase && readable(g_veh_phase, 4)) {
        h.str(" ph=");
        h.str(g_veh_phase);
    }
    h.str(" rsp=");
    h.hex(static_cast<unsigned long long>(ep->ContextRecord->Rsp));
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005u) {
        h.str(" av=");
        h.hex(ep->ExceptionRecord->ExceptionInformation[0]);
        h.str("/");
        h.hex(ep->ExceptionRecord->ExceptionInformation[1]);
    }
    if (ep->ExceptionRecord->ExceptionCode >= 0xE0000000u) {
        h.str(" nparams=");
        h.dec(ep->ExceptionRecord->NumberParameters);
    }
    h.nl();

    unsigned long long L = g_veh_L;
    unsigned long long ci = 0, p = 0, pc = 0, top = 0, code = 0;
    unsigned int len = 0;
    if (L && read_u64(L + 0x70, &ci) && ci && read_u64(ci + 0x18, &p) && p) {
        read_u64(ci + 0x20, &pc);
        read_u64(p + 0x68, &code);
        h.str("   ci=");
        h.hex(ci);
        h.str(" p=");
        h.hex(p);
        h.str(" savedpc=");
        h.hex(pc);
        if (code && pc > code && pc - code < 4096) {
            h.str(" insn#=");
            h.dec(static_cast<unsigned int>((pc - code) / 4));
            unsigned int ins = 0;
            read_u32(pc - 4, &ins);
            h.str(" last=");
            h.hex(ins);
        }
        read_u32(p + 0xA8, &len);
        h.str(" sizecode=");
        h.dec(static_cast<unsigned int>(len));
    }
    if (L) {
        read_u64(L + 0x60, &top);
        h.str(" top=");
        h.hex(top);
        unsigned int st = 0;
        read_u32(L + 3, &st);
        h.str(" st=");
        h.hex(st & 0xff);
    }
    h.nl();

    DWORD w = 0;
    if (g_veh_pipe) api().WriteFile(g_veh_pipe, h.buf, h.n, &w, nullptr);
    if (in_payload && fatal) stage_mark(api(), "FAULT-INPAY");
    g_veh_depth = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

// Stage 20/21: diagnostics around the proven load path. do_call=false stops
// before any VM entry; do_call=true attempts exactly one luaD_call and nothing
// else, so a hang is attributable to that single call.
inline DWORD run_diag(bool do_call) {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 diag base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("  fake=");
    o.hex(fake);
    o.str(" dm=");
    o.hex(dm);
    o.str(" sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    unsigned int globals = 0;
    read_u32(base + 0x81E60C0, &globals);
    o.str("  g60c0=");
    o.hex(globals & 0xff);
    read_u32(base + 0x81E60A0, &globals);
    o.str(" g60a0=");
    o.hex(globals & 0xff);
    read_u32(base + 0x81E5F60, &globals);
    o.str(" g5f60=");
    o.hex(globals & 0xff);
    o.nl();
    flush_out(a, pipe, o);

    if (!L) {
        o.str("  no state");
        o.nl();
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    unsigned long long v = 0;
    read_u64(L + 0x00, &v);
    diag_line(o, "hdr", v);
    read_u64(L + 0x08, &v);
    diag_line(o, "ud", v);
    read_u64(L + 0x10, &v);
    diag_line(o, "gt", v);
    read_u64(L + 0x18, &v);
    diag_line(o, "namecall", v);
    read_u64(L + 0x20, &v);
    diag_line(o, "end_ci", v);
    read_u64(L + 0x28, &v);
    diag_line(o, "base_ci", v);
    read_u64(L + 0x30, &v);
    diag_line(o, "openupval", v);
    read_u64(L + 0x40, &v);
    diag_line(o, "gclist", v);
    read_u64(L + 0x48, &v);
    diag_line(o, "stack", v);
    read_u64(L + 0x50, &v);
    diag_line(o, "gs", v);
    read_u64(L + 0x58, &v);
    diag_line(o, "lbase", v);
    read_u64(L + 0x60, &v);
    diag_line(o, "ltop", v);
    read_u64(L + 0x68, &v);
    diag_line(o, "stack_last", v);
    read_u64(L + 0x70, &v);
    diag_line(o, "ci", v);
    read_u64(L + 0x80, &v);
    diag_line(o, "finalizers", v);
    unsigned int u = 0;
    read_u32(L + 0x00, &u);
    o.str("  hdr_tt=");
    o.dec(u & 0xff);
    read_u32(L + 3, &u);
    o.str(" status=");
    o.hex(u & 0xff);
    read_u32(L + 4, &u);
    o.str(" single=");
    o.hex(u & 0xff);
    read_u32(L + 5, &u);
    o.str(" active=");
    o.hex(u & 0xff);
    o.nl();
    read_u32(L + 0x38, &u);
    o.str("  nCcalls=");
    o.dec(u & 0xffff);
    read_u32(L + 0x3A, &u);
    o.str("/");
    o.dec(u & 0xffff);
    read_u32(L + 0x3C, &u);
    o.str(" cachedslot=");
    o.dec(u);
    read_u32(L + 0x78, &u);
    o.str(" stacksize=");
    o.hex(u);
    read_u32(L + 0x7C, &u);
    o.str(" size_ci=");
    o.dec(u);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long ud = 0;
    read_u64(L + 0x08, &ud);
    if (ud && readable(reinterpret_cast<const void*>(ud), 0xB8)) {
        read_u64(ud + 0x70, &v);
        o.str("  identity=");
        o.hex(v);
        read_u64(ud + 0xA0, &v);
        o.str(" capabilities=");
        o.hex(v);
        o.nl();
    }
    unsigned long long base_ci = 0, ci = 0, end_ci = 0;
    read_u64(L + 0x28, &base_ci);
    read_u64(L + 0x70, &ci);
    read_u64(L + 0x20, &end_ci);
    o.str("  ci frames base=");
    o.hex(base_ci);
    o.str(" cur=");
    o.hex(ci);
    o.str(" end=");
    o.hex(end_ci);
    unsigned long long frames = 0;
    if (base_ci && ci >= base_ci) frames = (ci - base_ci) / 48;
    o.str(" count=");
    o.dec(static_cast<unsigned int>(frames));
    o.nl();
    if (base_ci && ci >= base_ci && (ci - base_ci) % 48 == 0 && frames < 64) {
        for (unsigned long long f = 0; f <= frames; ++f) diag_ci(o, base_ci + 48 * f);
    }
    flush_out(a, pipe, o);

    unsigned long long top0 = 0;
    read_u64(L + 0x60, &top0);
    unsigned long long stack0 = 0;
    read_u64(L + 0x48, &stack0);
    o.str("  top0=");
    o.hex(top0);
    o.str(" index=");
    o.hex(stack0 ? top0 - stack0 : 0);
    o.nl();

    static unsigned char container[8 + kChunkLen];
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i) container[i] = static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < kChunkLen; ++i) container[8 + i] = kChunkBody[i];

    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = 8ull + kChunkLen;
    src.cap = 8ull + kChunkLen;

    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str("  load ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    unsigned int stat = 0;
    read_u32(L + 3, &stat);
    o.str(" st=");
    o.hex(stat & 0xff);
    o.nl();
    flush_out(a, pipe, o);

    if (t1 > top0) {
        unsigned long long cv = 0, cw = 0;
        read_u64(top0, &cv);
        read_u64(top0 + 8, &cw);
        o.str("  closure=");
        o.hex(cv);
        o.str(" tt=");
        o.dec(static_cast<unsigned int>((cw >> 32) & 0xff));
        o.nl();
        if (cv && readable(reinterpret_cast<const void*>(cv), 0x40)) {
            unsigned int cb = 0;
            read_u32(cv + 4, &cb);
            o.str("    preload/ntotal=");
            o.hex(cb & 0xffff);
            read_u32(cv + 5, &cb);
            o.str(" isC=");
            o.dec(cb & 0xff);
            read_u32(cv + 6, &cb);
            o.str(" stacksize=");
            o.dec(cb & 0xff);
            unsigned long long g = 0;
            read_u64(cv + 8, &g);
            o.str(" gclist=");
            o.hex(g);
            read_u64(cv + 0x10, &g);
            o.str(" env=");
            o.hex(g);
            o.nl();
            unsigned long long p = 0;
            read_u64(cv + 0x18, &p);
            diag_proto(o, p);
        }
    }
    flush_out(a, pipe, o);

    if (!do_call) {
        o.str("  VM not entered (diag only)\n");
        flush_out(a, pipe, o);
    } else if (t1 > top0) {
        unsigned long long ci0 = 0;
        unsigned int cc0 = 0;
        read_u64(L + 0x70, &ci0);
        read_u32(L + 0x38, &cc0);
        unsigned int act0 = 0;
        read_u32(L + 5, &act0);
        o.str("  PRECALL top0=");
        o.hex(top0);
        o.str(" ci0=");
        o.hex(ci0);
        o.str(" ncc=");
        o.dec(cc0 & 0xffff);
        o.str(" act=");
        o.hex(act0 & 0xff);
        o.str(" path=g60c0 ");
        read_u32(base + 0x81E60C0, &globals);
        o.hex(globals & 0xff);
        o.nl();

        g_veh_pipe = pipe;
        g_veh_base = base;
        g_veh_L = L;
        unsigned long long vh = 0;
        if (a.AddVectoredExceptionHandler) {
            vh = reinterpret_cast<unsigned long long>(
                a.AddVectoredExceptionHandler(1, reinterpret_cast<void*>(&veh_log)));
        }
        o.str("  veh=");
        o.hex(vh);
        o.nl();
        flush_out(a, pipe, o);

        typedef int (*CallFn)(void*, void*, int, void*);
        CallFn call = reinterpret_cast<CallFn>(base + 0x26361C0);
        int rc = call(reinterpret_cast<void*>(L), reinterpret_cast<void*>(top0), 0, nullptr);

        o.str("  POSTCALL rc=");
        o.dec(static_cast<unsigned int>(rc));
        unsigned long long t2 = 0, ci1 = 0;
        read_u64(L + 0x60, &t2);
        read_u64(L + 0x70, &ci1);
        o.str(" d=");
        o.hex(t2 - top0);
        o.str(" ci1=");
        o.hex(ci1);
        o.str(" same=");
        o.dec(static_cast<unsigned int>(ci1 == ci0));
        read_u32(L + 3, &u);
        o.str(" st=");
        o.hex(u & 0xff);
        o.nl();
        flush_out(a, pipe, o);

        if (t2 > top0) dump_tv(o, top0, "  res:");
        flush_out(a, pipe, o);
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline DWORD run_diag_only() {
    return run_diag(false);
}

inline DWORD run_diag_call() {
    return run_diag(true);
}

// Stage 24: register our own exception table, then walk the whole path with a
// marker flushed after every statement, and guard the frame push plus the
// single-step loop with SEH. If anything raises, the handler logs the code and
// the VM state instead of letting the process die mid-unwind.
static DWORD g_seh_code = 0;

inline void dump_mode11_results(Api& a, HANDLE pipe, Out& o, unsigned long long base_ci) {
    unsigned long long fn = 0;
    read_u64(base_ci + 48 + 0x10, &fn);
    o.str("Q3 fn=");
    o.hex(fn);
    o.nl();
    for (int k = 0; k < 3; ++k) {
        unsigned long long rvk = 0, rwk = 0;
        read_u64(fn + 16ull * k, &rvk);
        read_u64(fn + 16ull * k + 8, &rwk);
        unsigned int ttv = static_cast<unsigned int>((rwk >> 32) & 0xff);
        o.str("Q2 r");
        o.dec(static_cast<unsigned int>(k));
        o.str(" v=");
        o.hex(rvk);
        o.str(" w=");
        o.hex(rwk);
        o.str(" tt=");
        o.dec(ttv);
        if (ttv == 6) {
            unsigned int slen = 0;
            unsigned long long s0 = 0, s1 = 0;
            read_u32(rvk + 0x14, &slen);
            read_u64(rvk + 0x18, &s0);
            read_u64(rvk + 0x20, &s1);
            o.str(" len=");
            o.dec(slen);
            o.str(" b0=");
            o.hex(s0);
            o.str(" b1=");
            o.hex(s1);
        } else if (ttv == 8 && rvk) {
            for (int q = 0; q < 8; ++q) {
                unsigned long long cv = 0;
                read_u64(rvk + 8ull * q, &cv);
                o.str(" c");
                o.dec(static_cast<unsigned int>(q));
                o.str("=");
                o.hex(cv);
            }
        }
        o.nl();
    }
    flush_out(a, pipe, o);
}

inline void dump_val(Out& o, const char* tag, unsigned long long slot) {
    unsigned long long v = 0, w = 0;
    if (!read_u64(slot, &v) || !read_u64(slot + 8, &w)) {
        o.str(tag);
        o.str(" unreadable\n");
        return;
    }
    unsigned int tt = static_cast<unsigned int>((w >> 32) & 0xff);
    o.str(tag);
    o.str(" tt=");
    o.dec(tt);
    o.str(" v=");
    o.hex(v);
    o.str(" w=");
    o.hex(w);
    if (tt == 6 && v && readable(reinterpret_cast<const void*>(v + 0x18), 4)) {
        unsigned int len = 0;
        read_u32(v + 0x14, &len);
        o.str(" len=");
        o.dec(len);
        if (len < 200) {
            o.str(" '");
            for (unsigned int k = 0; k < len; ++k)
                o.ch(*reinterpret_cast<char*>(v + 0x18 + k));
            o.str("'");
        }
    }
    if (tt >= 4 && tt <= 8 && v && readable(reinterpret_cast<const void*>(v), 0x30)) {
        unsigned char isC = *reinterpret_cast<unsigned char*>(v + 5);
        unsigned long long boxed = 0;
        read_u64(v + (isC ? 0x28 : 0x18), &boxed);
        o.str(" isC=");
        o.dec(isC);
        o.str(isC ? " f=" : " proto=");
        o.hex(boxed);
    }
    o.nl();
}

// Stage 40: the client's own pcall is the protected boundary.
// Calling a game method straight from our fabricated frame raises a
// lua_exception, and 0x26360e0 hands that to _CxxThrowException. Nothing above
// our frame catches it, the unwinder cannot walk a manual-mapped frame that has
// no .pdata, and the process dies. Wrapping the call in the sandbox's pcall
// closure puts the client's own catcher between the throw and our frame.
static unsigned long long g_exec_fn = 0;
static unsigned long long g_full_mask = 0xFFFFFFFFFFFFFFFFull;
static bool g_patch_proto = false;
static bool g_sentinel = false;

inline bool slot_is_str(unsigned long long slot, const char* lit) {
    unsigned long long v = 0, w = 0;
    if (!read_u64(slot, &v) || !read_u64(slot + 8, &w)) return false;
    if (((w >> 32) & 0xff) != 6 || !v) return false;
    unsigned int len = 0;
    read_u32(v + 0x14, &len);
    unsigned int need = 0;
    while (lit[need]) ++need;
    if (len != need || !readable(reinterpret_cast<const void*>(v + 0x18), len)) return false;
    for (unsigned int i = 0; i < len; ++i)
        if (*reinterpret_cast<char*>(v + 0x18 + i) != lit[i]) return false;
    return true;
}

// Declared std::string size handed to LuaVMLoad. Non-zero lies about the blob
// length so sub_43178A0's `size-8 >= 0x118` watermark gate never fires; the
// undump parser does not bounds-check, so the real buffer is parsed whole.
static unsigned long long g_declared_size = 0;

inline int exec_chunk(Api& a, HANDLE pipe, Out& o, unsigned long long L,
                      unsigned long long base, const unsigned char* body,
                      unsigned int len, const char* tag) {
    static unsigned char container[4096];
    if (len + 8u > sizeof(container)) {
        o.str(tag);
        o.str(" too big\n");
        flush_out(a, pipe, o);
        return 0;
    }
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + i) =
            static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < len; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + 8 + i) = body[i];

    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = g_declared_size ? g_declared_size : (8ull + len);
    src.cap = 8ull + len;

    unsigned long long top0 = 0, base_ci = 0;
    read_u64(L + 0x60, &top0);
    read_u64(L + 0x28, &base_ci);

    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);

    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str(tag);
    o.str(" load ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    o.str(" top0=");
    o.hex(top0);
    o.str(" bci=");
    o.hex(base_ci);
    o.nl();
    flush_out(a, pipe, o);

    if (ret != 0 || t1 != top0 + 16) {
        o.str(tag);
        o.str(" load failed\n");
        dump_val(o, "LERR", top0);
        flush_out(a, pipe, o);
        return 0;
    }

    unsigned long long clo = 0, proto = 0, code = 0;
    unsigned int ss = 0;
    read_u64(top0, &clo);
    read_u64(clo + 0x18, &proto);
    read_u64(proto + 0x68, &code);
    read_u32(clo + 6, &ss);
    ss &= 0xff;
    unsigned int w0 = 0, w1 = 0;
    read_u32(code, &w0);
    read_u32(code + 4, &w1);
    o.str(tag);
    o.str(" clo=");
    o.hex(clo);
    o.str(" proto=");
    o.hex(proto);
    o.str(" code=");
    o.hex(code);
    o.str(" ss=");
    o.dec(ss);
    o.str(" w0=");
    o.hex(w0);
    o.str(" w1=");
    o.hex(w1);
    o.nl();
    // Raw instruction stream as the loader left it. Comparing this against the
    // blob we submitted tells us whether undump rewrites opcodes in place.
    static const char hxd[] = "0123456789abcdef";
    for (int row = 0; row < 16; ++row) {
        o.str(tag);
        o.str(" C");
        o.dec(static_cast<unsigned int>(row));
        o.str(" ");
        for (int j = 0; j < 16; ++j) {
            unsigned int b = 0;
            read_u32(code + 16 * row + j, &b);
            b &= 0xFF;
            char s3[3];
            s3[0] = hxd[(b >> 4) & 0xf];
            s3[1] = hxd[b & 0xf];
            s3[2] = 0;
            o.str(s3);
        }
        o.nl();
    }
    flush_out(a, pipe, o);

    // sub_4266AA0 ANDs the thread mask with the script capability qword reached
    // through an encoded pointer at proto+0x80:
    //   ptr = [proto+0x80]; ptr = (ptr == &ptr) ? default : (ptr ^ &ptr);
    //   mask &= *ptr;
    // A freshly loaded chunk has 0 there, so the decoded address is &ptr itself
    // and the AND produces zero. Point it at our own full mask instead.
    if (g_patch_proto) {
        unsigned long long enc = 0, chk = 0;
        unsigned long long self = proto + 0x80;
        unsigned long long qw = reinterpret_cast<unsigned long long>(&g_full_mask);
        read_u64(self, &enc);
        wr64(self, self ^ qw);
        read_u64(self, &chk);
        unsigned long long defmask = 0;
        read_u64(base + 0x8D87878, &defmask);
        o.str(tag);
        o.str(" PROTO80 old=");
        o.hex(enc);
        o.str(" new=");
        o.hex(chk);
        o.str(" dec=");
        o.hex(chk ^ self);
        o.str(" qw=");
        o.hex(qw);
        o.str(" def=");
        o.hex(defmask);
        o.nl();
        flush_out(a, pipe, o);
    }

    unsigned long long ci = base_ci + 48;
    unsigned long long fbase = top0 + 16;
    unsigned int bci_flags = 0;
    read_u32(base_ci + 0x2c, &bci_flags);

    wr64(ci + 0x00, fbase);
    wr64(ci + 0x08, fbase + 16ull * ss);
    wr64(ci + 0x10, top0);
    wr64(ci + 0x18, proto);
    wr64(ci + 0x20, code + 4);
    wr32(ci + 0x28, 0xFFFFFFFFu);
    wr32(ci + 0x2C, 1);
    wr64(L + 0x70, ci);
    wr64(L + 0x58, fbase);
    wr32(base_ci + 0x2c, bci_flags | 4u);

    unsigned char old_single = *reinterpret_cast<volatile unsigned char*>(L + 4);
    unsigned char old_active = *reinterpret_cast<volatile unsigned char*>(L + 5);
    *reinterpret_cast<volatile unsigned char*>(L + 4) = 0;
    *reinterpret_cast<volatile unsigned char*>(L + 5) = 1;

    unsigned int ncc = 0;
    read_u32(L + 0x38, &ncc);
    wr32(L + 0x38, (ncc & 0xffff0000u) | (((ncc & 0xffffu) + 1u) & 0xffffu));

    unsigned long long pre_stack = 0, pre_base = 0;
    read_u64(L + 0x48, &pre_stack);
    read_u64(L + 0x58, &pre_base);

    o.str(tag);
    o.str(" EXEC ci=");
    o.hex(ci);
    o.str(" base=");
    o.hex(fbase);
    o.str(" pc=");
    o.hex(code + 4);
    o.str(" stk=");
    o.hex(pre_stack);
    o.nl();
    flush_out(a, pipe, o);

    g_veh_pipe = pipe;
    g_veh_base = base;
    g_veh_L = L;
    g_veh_phase = tag;

    if (g_sentinel) {
        // Marker doubles in the register window we just handed the VM. After
        // the run, scanning L->stack for them says whether the interpreter
        // really used base = L->base or built its own frame somewhere else.
        const unsigned long long marks[4] = {0x3FF8000000000000ull, 0x4004000000000000ull,
                                             0x400C000000000000ull, 0x4012000000000000ull};
        for (int i = 0; i < 4; ++i)
            wr64(fbase + 16ull * i, marks[i]);
    }

    typedef void (*ExecFn)(void*);
    ExecFn exec = reinterpret_cast<ExecFn>(base + 0x26862E0);
    exec(reinterpret_cast<void*>(L));

    wr32(L + 0x38, ncc);
    *reinterpret_cast<volatile unsigned char*>(L + 4) = old_single;
    *reinterpret_cast<volatile unsigned char*>(L + 5) = old_active;
    wr32(base_ci + 0x2c, bci_flags);

    unsigned long long t2 = 0, ci2 = 0, fn = 0;
    unsigned long long post_stack = 0, post_base = 0, post_bci = 0;
    unsigned int post_size_ci = 0;
    unsigned int st2 = 0;
    read_u64(L + 0x60, &t2);
    read_u64(L + 0x70, &ci2);
    read_u64(L + 0x48, &post_stack);
    read_u64(L + 0x58, &post_base);
    read_u64(L + 0x28, &post_bci);
    read_u32(L + 0x7C, &post_size_ci);
    // A stack reallocation during the run leaves top0 pointing into freed
    // memory. Rebuild the same stack offset inside whatever buffer now holds
    // the stack, then use that everywhere below.
    unsigned long long t0live = pre_stack ? post_stack + (top0 - pre_stack) : top0;
    fn = t0live;
    read_u32(L + 3, &st2);
    g_exec_fn = fn;
    o.str(tag);
    o.str(" done top=");
    o.hex(t2);
    o.str(" d=");
    o.hex(t2 - t0live);
    o.str(" t0=");
    o.hex(t0live);
    o.str(" st=");
    o.hex(st2 & 0xff);
    o.nl();
    // Did the run move the stack or the CallInfo array under us? If stack() or
    // base_ci() changed, every pointer we cached from before exec is stale and
    // the base we handed the VM points into freed memory.
    o.str(tag);
    o.str(" post stack=");
    o.hex(post_stack);
    o.str(" base=");
    o.hex(post_base);
    o.str(" bci=");
    o.hex(post_bci);
    o.str(" size_ci=");
    o.dec(post_size_ci);
    o.str(" idx=");
    o.hex(ci2 >= post_bci ? (ci2 - post_bci) / 48 : 0xFFFF);
    o.nl();
    if (post_bci && ci2 >= post_bci && ci2 < post_bci + 48ull * post_size_ci) {
        unsigned long long cbase = 0, ctop = 0, cfunc = 0;
        read_u64(ci2 + 0x00, &cbase);
        read_u64(ci2 + 0x08, &ctop);
        read_u64(ci2 + 0x10, &cfunc);
        o.str(tag);
        o.str(" cifld base=");
        o.hex(cbase);
        o.str(" top=");
        o.hex(ctop);
        o.str(" func=");
        o.hex(cfunc);
        o.str(" fbase=");
        o.hex(fbase);
        o.nl();
    }
    flush_out(a, pipe, o);

    if (fn && readable(reinterpret_cast<const void*>(fn), 48)) {
        for (int k = 0; k < 3; ++k) {
            char tag2[8] = {tag[0], tag[1], ' ', 'r', static_cast<char>('0' + k), 0, 0, 0};
            dump_val(o, tag2, fn + 16ull * k);
        }
        flush_out(a, pipe, o);
    }
    // Window dump: slot -1 is the chunk closure slot, slot 0 is register 0.
    // A chunk that returns nothing leaves its locals untouched, so this is the
    // only view of the register file after a nested call ran.
    for (int k = -1; k < 8; ++k) {
        char tag3[8] = {tag[0], tag[1], ' ', 'w', 0, 0, 0, 0};
        if (k < 0) {
            tag3[3] = 'm';
            tag3[4] = '1';
        } else {
            tag3[4] = static_cast<char>('0' + k);
        }
        dump_val(o, tag3, t0live + 16ull * static_cast<unsigned int>(k));
    }
    flush_out(a, pipe, o);

    if (g_sentinel) {
        unsigned long long stk = 0;
        read_u64(L + 0x48, &stk);
        o.str(tag);
        o.str(" scan stk=");
        o.hex(stk);
        o.str(" fbase=");
        o.hex(fbase);
        o.nl();
        for (unsigned int i = 0; i < 0x2000; i += 8) {
            unsigned long long q = 0;
            read_u64(stk + i, &q);
            if (q == 0x3FF8000000000000ull || q == 0x4004000000000000ull ||
                q == 0x400C000000000000ull || q == 0x4012000000000000ull) {
                o.str(tag);
                o.str(" mark ");
                o.hex(stk + i);
                o.str(" rel=");
                o.str((stk + i) >= fbase ? "+" : "-");
                o.hex((stk + i) >= fbase ? (stk + i) - fbase : fbase - (stk + i));
                o.str(" q=");
                o.hex(q);
                o.nl();
            }
        }
        flush_out(a, pipe, o);
    }
    // Results have been captured. Drop L->top back to where the chunk started
    // so consecutive chunks reuse the same stack window instead of creeping
    // upward until a reallocation moves the whole stack.
    wr64(L + 0x60, t0live);
    return 1;
}

// Stage 65: protected execution through the client's own pcall builtin.
// The fabricated-CallInfo path works until a nested call moves the
// interpreter's register window. Handing the chunk to builtinPcall through
// luaD_call lets the client build the frame and catch every Lua error itself,
// so nothing ever unwinds through this manual-mapped image.
inline void beacon(Api& a, const char* s) {
    unsigned int n = 0;
    while (s[n]) ++n;
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\beacon.bin", GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    a.WriteFile(f, s, n, &w, nullptr);
    a.CloseHandle(f);
}

// Same as beacon, different file: the last stage reached survives a client
// death, so a frozen REPL can be located without a debugger.
inline void stage_mark(Api& a, const char* s) {
    unsigned int n = 0;
    while (s[n]) ++n;
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\repl_stage.bin", GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    a.WriteFile(f, s, n, &w, nullptr);
    a.CloseHandle(f);
}

// Every function we point a captured closure at has to pass the same CFG check
// the dispatcher performs, so its map bit is armed here instead of relying on a
// previous stage having done it. The page is brought in only when the map has
// not committed it: reading a reserved page is what killed the client once.
inline bool arm_cfg(Api& a, Out& o, unsigned long long target, const char* tag) {
    Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
    if (!dll.base) {
        o.str(tag);
        o.str(" no dll\n");
        return false;
    }
    unsigned long long db = reinterpret_cast<unsigned long long>(dll.base);
    unsigned long long bitmap = 0;
    read_u64(db + 0x4c9376ull + 0x9f9622ull, &bitmap);
    if (!bitmap) {
        o.str(tag);
        o.str(" no map\n");
        return false;
    }
    unsigned long long slotp = bitmap + (target >> 15);
    unsigned long long page = slotp & ~0xfffull;
    unsigned int bit = static_cast<unsigned int>((target >> 12) & 7);
    Mbi q{};
    a.VirtualQuery(reinterpret_cast<const void*>(page), &q, sizeof(q));
    if (q.State != MEM_COMMIT) {
        void* got = a.VirtualAlloc ? a.VirtualAlloc(reinterpret_cast<void*>(page), 0x1000,
                                                    MEM_COMMIT, PAGE_READWRITE)
                                   : nullptr;
        if (!got) {
            o.str(tag);
            o.str(" commit err=");
            o.dec(static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            return false;
        }
        a.VirtualQuery(reinterpret_cast<const void*>(page), &q, sizeof(q));
    }
    if (q.State != MEM_COMMIT || (q.Protect & 0xff) != PAGE_READWRITE) {
        o.str(tag);
        o.str(" page bad state=");
        o.hex(q.State);
        o.str(" prot=");
        o.hex(q.Protect);
        o.nl();
        return false;
    }
    unsigned char b0 = *reinterpret_cast<unsigned char*>(slotp);
    *reinterpret_cast<volatile unsigned char*>(slotp) =
        static_cast<unsigned char>(b0 | (1u << bit));
    o.str(tag);
    o.str(" bit ");
    o.hex(b0);
    o.str(" -> ");
    o.hex(*reinterpret_cast<unsigned char*>(slotp));
    o.str(" want=");
    o.hex(1u << bit);
    o.nl();
    return true;
}

// bind_clo: when nonzero, the closure is pushed as a second argument and the
// wrapper forwards it to the chunk (`local f, a = ... pcall(f, a)`). That is the
// only way to reach a specific C closure from Lua without naming it: the object
// we swapped travels as a value, not through a global that may resolve to a
// different function of the same name.
inline int exec_protected(Api& a, HANDLE pipe, Out& o, unsigned long long L,
                          unsigned long long base, const unsigned char* body,
                          unsigned int len, const char* tag,
                          unsigned long long bind_clo = 0) {
    static unsigned char container[4096];
    if (len + 8u > sizeof(container)) {
        o.str(tag);
        o.str(" too big\n");
        flush_out(a, pipe, o);
        return 0;
    }
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + i) =
            static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < len; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + 8 + i) = body[i];

    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = g_declared_size ? g_declared_size : (8ull + len);
    src.cap = 8ull + len;

    unsigned long long top0 = 0;
    read_u64(L + 0x60, &top0);

    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);

    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str(tag);
    o.str(" load ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" top0=");
    o.hex(top0);
    o.str(" t1=");
    o.hex(t1);
    o.nl();
    flush_out(a, pipe, o);
    if (ret != 0 || t1 != top0 + 16) {
        o.str(tag);
        o.str(" load failed\n");
        flush_out(a, pipe, o);
        return 0;
    }

    unsigned long long clo = 0, proto = 0;
    read_u64(top0, &clo);
    read_u64(clo + 0x18, &proto);

    if (g_patch_proto) {
        unsigned long long self = proto + 0x80;
        unsigned long long qw = reinterpret_cast<unsigned long long>(&g_full_mask);
        unsigned long long enc = 0;
        read_u64(self, &enc);
        wr64(self, self ^ qw);
        o.str(tag);
        o.str(" PROTO80 old=");
        o.hex(enc);
        o.str(" new=");
        o.hex(self ^ qw);
        o.nl();
        flush_out(a, pipe, o);
    }

    // The call frame is [wrapper][userChunk]. The user chunk already sits at
    // top0, so push it one slot up and load the wrapper underneath:
    //   local f = ... return pcall(f)
    {
        unsigned long long lo = 0, hi = 0;
        read_u64(top0, &lo);
        read_u64(top0 + 8, &hi);
        wr64(top0 + 16, lo);
        wr64(top0 + 24, hi);
    }

    static unsigned char wcontainer[256];
    const unsigned char* wbody = bind_clo ? kZBindBody : kChunkC34Body;
    const unsigned int wlen = bind_clo ? kZBindLen : kChunkC34Len;
    for (int i = 0; i < 8; ++i)
        *reinterpret_cast<volatile unsigned char*>(wcontainer + i) =
            static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < wlen; ++i)
        *reinterpret_cast<volatile unsigned char*>(wcontainer + 8 + i) = wbody[i];

    ChunkName wsrc;
    wsrc.data = reinterpret_cast<const char*>(wcontainer);
    wsrc.pad = 0;
    wsrc.size = g_declared_size ? g_declared_size : (8ull + wlen);
    wsrc.cap = 8ull + wlen;

    wr64(L + 0x60, top0);
    int ret2 = load(reinterpret_cast<void*>(L), &wsrc, "=zendo", 0);
    unsigned long long t2w = 0;
    read_u64(L + 0x60, &t2w);
    o.str(tag);
    o.str(" wrapper ret=");
    o.dec(static_cast<unsigned int>(ret2));
    o.str(" top=");
    o.hex(t2w);
    o.nl();
    flush_out(a, pipe, o);
    if (ret2 != 0 || t2w != top0 + 16) {
        o.str(tag);
        o.str(" wrapper load failed\n");
        flush_out(a, pipe, o);
        return 0;
    }

    // The wrapper runs as a real script too: its proto carries the same
    // obfuscated capability word, and an error raised while a wrapper frame is
    // live walks that field. Patch it the same way as the user chunk.
    {
        unsigned long long wclo = 0, wproto = 0, wenc = 0;
        read_u64(top0, &wclo);
        if (!read_u64(wclo + 0x18, &wproto) || !wproto) {
            o.str(tag);
            o.str(" wrapper proto unreadable\n");
            flush_out(a, pipe, o);
        } else {
            unsigned long long self = wproto + 0x80;
            unsigned long long qw = reinterpret_cast<unsigned long long>(&g_full_mask);
            read_u64(self, &wenc);
            wr64(self, self ^ qw);
            o.str(tag);
            o.str(" WPROTO80 old=");
            o.hex(wenc);
            o.str(" new=");
            o.hex(self ^ qw);
            o.nl();
            flush_out(a, pipe, o);
        }
    }

    if (bind_clo) {
        // [wrapper][chunk][closure] - the wrapper takes both varargs and hands
        // the closure to the chunk. Written after the wrapper load so no other
        // load can overwrite the slot before the call.
        wr64(top0 + 32, bind_clo);
        wr64(top0 + 40, 0x8ull << 32);
        wr64(L + 0x60, top0 + 48);
    } else {
        wr64(L + 0x60, top0 + 32);
    }

    // The protected-error callback is the debugger hook Roblox installs. If it
    // is armed, luaD_pcall runs it on any caught error, and its own stack walk
    // sees our loaded chunk. Null it for the duration of the call.
    unsigned long long gs = 0, cbErrAddr = 0, cbErr = 0, ccounts = 0;
    read_u64(L + 0x50, &gs);
    read_u64(L + 0x38, &ccounts);
    if (gs) {
        cbErrAddr = gs + 0x670 + 0x18;
        read_u64(cbErrAddr, &cbErr);
    }
    o.str(tag);
    o.str(" cb.err=");
    o.hex(cbErr);
    o.str(" ccounts=");
    o.hex(ccounts);
    o.nl();
    flush_out(a, pipe, o);
    if (cbErr) wr64(cbErrAddr, 0);

    o.str(tag);
    o.str(" EXEC pcall L=");
    o.hex(L);
    o.str(" func=");
    o.hex(top0);
    o.str(" arg=");
    o.hex(top0 + 16);
    o.nl();
    flush_out(a, pipe, o);

    beacon(a, "PRE");

    g_veh_pipe = pipe;
    g_veh_base = base;
    g_veh_L = L;
    g_veh_phase = tag;

    typedef void (*CallFn)(void*, unsigned long long, int, unsigned long long);
    CallFn call = reinterpret_cast<CallFn>(base + 0x26361C0);
    call(reinterpret_cast<void*>(L), top0, -1, 0);

    beacon(a, "POST");
    if (cbErr) wr64(cbErrAddr, cbErr);

    unsigned long long t2 = 0;
    read_u64(L + 0x60, &t2);
    // The stack can be reallocated by the call itself (a deeper frame grew it),
    // and then top0 points into the old block: n computed from it is garbage.
    // Treat anything outside the reservation as "moved" instead of trusting it.
    unsigned long long n = 0;
    if (t2 > top0 && (t2 - top0) < 0x1000)
        n = (t2 - top0) / 16;
    else
        o.str(" STACKMOVED");
    o.str(tag);
    o.str(" done top=");
    o.hex(t2);
    o.str(" n=");
    o.dec(static_cast<unsigned int>(n));
    o.nl();
    flush_out(a, pipe, o);

    if (n > 8) n = 8;
    for (unsigned long long k = 0; k < n; ++k) {
        char tag2[8] = {tag[0], tag[1], ' ', 'p', 0, 0, 0, 0};
        tag2[4] = static_cast<char>('0' + static_cast<int>(k));
        dump_val(o, tag2, top0 + 16ull * k);
    }
    flush_out(a, pipe, o);

    // `return pcall` lands here: the result slot holds the builtin closure, so
    // its c.f is luaB_pcally inside the client image � the entry point for
    // locating lua_pcallyieldable and luaD_pcall without guessing.
    if (body == kChunkC40Body && n >= 2) {
        unsigned long long fnv = 0, cname = 0, cont = 0, cf = 0, hdr = 0;
        read_u64(top0 + 16, &fnv);
        if (fnv) {
            read_u64(fnv, &hdr);
            read_u64(fnv + 0x18, &cname);
            read_u64(fnv + 0x20, &cont);
            read_u64(fnv + 0x28, &cf);
        }
        o.str("F clo=");
        o.hex(fnv);
        o.str(" hdr=");
        o.hex(hdr);
        o.str(" isC=");
        o.hex((hdr >> 40) & 0xff);
        o.str(" f=");
        o.hex(cf);
        o.str(" off=");
        o.hex(cf - base);
        o.str(" cont=");
        o.hex(cont);
        o.str(" name=");
        o.hex(cname);
        o.nl();
        flush_out(a, pipe, o);
    }
    return 1;
}

// luaF_close + luaC_upvalclosed, lifted instruction-for-instruction from the
// inlined copy inside lua_pcallyieldable (0x26320C3..0x263216D). Open upvalues
// whose stack slot is at or above `level` are unlinked from both lists, their
// value is copied into the UpVal, and the GC colour is brought in sync.
inline void close_upvals(unsigned long long L, unsigned long long level,
                         unsigned long long base) {
    unsigned long long g = 0;
    read_u64(L + 0x50, &g);
    if (!g) return;
    for (;;) {
        unsigned long long uv = 0;
        read_u64(L + 0x30, &uv);
        if (!uv) break;
        unsigned long long v = 0;
        read_u64(uv + 8, &v);
        if (v < level) break;

        unsigned long long threadnext = 0;
        read_u64(uv + 0x20, &threadnext);
        wr64(L + 0x30, threadnext);

        unsigned long long nx = 0, pv = 0;
        read_u64(uv + 0x10, &nx);
        read_u64(uv + 0x18, &pv);
        wr64(pv + 0x10, nx);
        wr64(nx + 0x18, pv);

        unsigned long long a = 0, b = 0;
        read_u64(v, &a);
        read_u64(v + 8, &b);
        wr64(uv + 0x10, a);
        wr64(uv + 0x18, b);
        wr64(uv + 8, uv + 0x10);

        unsigned char marked = *reinterpret_cast<volatile unsigned char*>(uv);
        if ((marked & 7) == 0) {
            unsigned char gcstate =
                *reinterpret_cast<volatile unsigned char*>(g + 2);
            if (static_cast<unsigned char>(gcstate - 1) <= 2) {
                *reinterpret_cast<volatile unsigned char*>(uv) = marked | 4;
                int tag = *reinterpret_cast<volatile int*>(uv + 0x1c);
                if (tag >= 6) {
                    unsigned long long obj = a;
                    unsigned char oc =
                        *reinterpret_cast<volatile unsigned char*>(obj);
                    if ((oc & 3) != 0) {
                        typedef void (*BarFn)(void*, void*);
                        BarFn bar = reinterpret_cast<BarFn>(base + 0x2659BA0);
                        bar(reinterpret_cast<void*>(g),
                            reinterpret_cast<void*>(obj));
                    }
                }
            } else {
                unsigned char cw = *reinterpret_cast<volatile unsigned char*>(g);
                *reinterpret_cast<volatile unsigned char*>(uv) =
                    static_cast<unsigned char>((marked & 0xf8) | (cw & 3));
            }
        }
    }
}

// A protected call that never installs a Lua-level wrapper: Roblox's own
// luaD_rawrunprotected (0x26360B0) catches the C++ throw, and its callback is
// Roblox's CallContext::run (0x2632230), so control-flow guard accepts the
// target. The chunk frame sits directly under the try block.
// --- print capture ---------------------------------------------------------
// The sandbox's `print` is a C closure inside the client image. We keep that
// closure and swap its function pointer around every chunk, so whatever the
// script prints also reaches the pipe as a `P` line.
static const unsigned char kChunkPrint[] = {
    0x0e, 0x03, 0x01, 0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x00, 0x01, 0x21,
    0x01, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x04, 0xa3, 0x00, 0x00, 0x00, 0x35,
    0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x82, 0x00, 0x02, 0x00, 0x01,
    0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
};
static const unsigned int kChunkPrintLen = sizeof(kChunkPrint);

// print("probe", 1, true, nil, 2.5) � used by the capture probes below.
static const unsigned char kChunkProbe[] = {
    0x0e, 0x03, 0x02, 0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x05, 0x70, 0x72,
    0x6f, 0x62, 0x65, 0x00, 0x01, 0x4d, 0x06, 0x00, 0x00, 0x01, 0x0a, 0x00,
    0x0a, 0xa3, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00,
    0x00, 0x6f, 0x01, 0x01, 0x00, 0x6f, 0x02, 0x02, 0x00, 0xa9, 0x03, 0x01,
    0x00, 0xc6, 0x04, 0x00, 0x00, 0x6f, 0x05, 0x03, 0x00, 0x9f, 0x00, 0x06,
    0x01, 0x82, 0x00, 0x01, 0x00, 0x04, 0x03, 0x01, 0x03, 0x02, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
};
static const unsigned int kChunkProbeLen = sizeof(kChunkProbe);

// Print capture, Lua side. The C hook is dead: the client's CFG bitmap has no
// valid bit for a manual-mapped page, so the VM's indirect call into our own
// `print` hook is a guard violation that kills the process before the hook's
// first instruction runs. Wrapping `print` in Lua instead costs nothing and
// never leaves the VM.
//
// capi:   print = function(...) buffer the joined arguments end ; buffer global
// flush:  join the buffer, clear it, return the text
static const unsigned char kChunkCapi[] = {
    0x0e, 0x03, 0x0d, 0x06, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x01, 0x23,
    0x08, 0x74, 0x6f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x05, 0x74, 0x61,
    0x62, 0x6c, 0x65, 0x06, 0x63, 0x6f, 0x6e, 0x63, 0x61, 0x74, 0x01, 0x09,
    0x01, 0x20, 0x05, 0x77, 0x61, 0x72, 0x6e, 0x3a, 0x08, 0x5f, 0x5f, 0x7a,
    0x6e, 0x64, 0x5f, 0x6f, 0x70, 0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x04,
    0x77, 0x61, 0x72, 0x6e, 0x08, 0x5f, 0x5f, 0x7a, 0x6e, 0x64, 0x5f, 0x6f,
    0x77, 0x05, 0x5f, 0x5f, 0x7a, 0x6e, 0x64, 0x00, 0x04, 0xe1, 0x01, 0x0b,
    0x02, 0x01, 0x01, 0x00, 0x00, 0x2e, 0xa3, 0x02, 0x00, 0x00, 0x35, 0x02,
    0x00, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x03, 0x01, 0x00, 0xdd, 0x04,
    0x00, 0x00, 0x9f, 0x02, 0x00, 0x02, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x6f, 0x06, 0x02, 0x00, 0x52, 0x04, 0x02, 0x00, 0x8c, 0x05,
    0x01, 0x00, 0xa8, 0x04, 0x0b, 0x00, 0x35, 0x07, 0x00, 0x05, 0x03, 0x00,
    0x00, 0x00, 0x35, 0x08, 0x00, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x52, 0x09,
    0x06, 0x00, 0xdd, 0x0a, 0x00, 0x00, 0x9f, 0x08, 0x00, 0x02, 0x25, 0x07,
    0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x07, 0x03, 0x06, 0x8b, 0x04,
    0xf5, 0xff, 0x35, 0x04, 0x00, 0x4b, 0x04, 0x00, 0x00, 0x00, 0x4d, 0x04,
    0x04, 0x1a, 0x05, 0x00, 0x00, 0x00, 0x52, 0x05, 0x03, 0x00, 0x6f, 0x06,
    0x06, 0x00, 0x25, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x01,
    0x04, 0x00, 0x52, 0x05, 0x01, 0x00, 0x6f, 0x06, 0x07, 0x00, 0x52, 0x07,
    0x04, 0x00, 0x73, 0x04, 0x05, 0x07, 0xfb, 0x05, 0x00, 0x00, 0xfb, 0x08,
    0x00, 0x00, 0x1c, 0x07, 0x08, 0x00, 0x6f, 0x08, 0x02, 0x00, 0x43, 0x06,
    0x07, 0x08, 0x6a, 0x04, 0x05, 0x06, 0x52, 0x05, 0x00, 0x00, 0xdd, 0x06,
    0x00, 0x00, 0x9f, 0x05, 0x00, 0x00, 0x82, 0x05, 0x00, 0x00, 0x08, 0x03,
    0x01, 0x03, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f,
    0x03, 0x03, 0x03, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x07, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x13, 0x00, 0x1d, 0x2a, 0x04, 0x00, 0x02,
    0x01, 0x00, 0x00, 0x07, 0xa3, 0x00, 0x00, 0x00, 0xfb, 0x00, 0x00, 0x00,
    0xfb, 0x01, 0x01, 0x00, 0xc6, 0x02, 0x00, 0x00, 0xdd, 0x03, 0x00, 0x00,
    0x9f, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00,
    0x00, 0x00, 0x00, 0x2c, 0x04, 0x00, 0x02, 0x01, 0x00, 0x00, 0x07, 0xa3,
    0x00, 0x00, 0x00, 0xfb, 0x00, 0x00, 0x00, 0xfb, 0x01, 0x01, 0x00, 0x6f,
    0x02, 0x00, 0x00, 0xdd, 0x03, 0x00, 0x00, 0x9f, 0x00, 0x00, 0x00, 0x82,
    0x00, 0x00, 0x00, 0x01, 0x03, 0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00,
    0xb5, 0x01, 0x05, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x24, 0xa3, 0x00, 0x00,
    0x00, 0x35, 0x00, 0x00, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x08,
    0x00, 0x35, 0x00, 0x00, 0x46, 0x01, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,
    0xe7, 0x00, 0x00, 0x00, 0x00, 0x35, 0x01, 0x00, 0x83, 0x02, 0x00, 0x00,
    0x00, 0x18, 0x01, 0x00, 0x8d, 0x03, 0x00, 0x00, 0x00, 0x35, 0x01, 0x00,
    0x8d, 0x03, 0x00, 0x00, 0x00, 0x2b, 0x01, 0x02, 0x00, 0x35, 0x01, 0x00,
    0x83, 0x02, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xd9, 0x03, 0x00, 0x00, 0x12, 0x00, 0x02, 0x00, 0xd9, 0x04, 0x01,
    0x00, 0x12, 0x00, 0x03, 0x00, 0x12, 0x01, 0x00, 0x00, 0x18, 0x04, 0x00,
    0x46, 0x01, 0x00, 0x00, 0x00, 0xd9, 0x04, 0x02, 0x00, 0x12, 0x00, 0x03,
    0x00, 0x12, 0x00, 0x01, 0x00, 0x18, 0x04, 0x00, 0x83, 0x02, 0x00, 0x00,
    0x00, 0x18, 0x02, 0x00, 0xcb, 0x04, 0x00, 0x00, 0x00, 0x6f, 0x04, 0x05,
    0x00, 0xc1, 0x00, 0x00, 0x00, 0x82, 0x04, 0x02, 0x00, 0x06, 0x03, 0x09,
    0x03, 0x0a, 0x03, 0x0b, 0x03, 0x0c, 0x03, 0x0d, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xf0, 0x3f, 0x03, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x35, 0x03,
};
static const unsigned int kChunkCapiLen = sizeof(kChunkCapi);

static const unsigned char kChunkFlush[] = {
    0x0e, 0x03, 0x06, 0x05, 0x5f, 0x5f, 0x7a, 0x6e, 0x64, 0x04, 0x74, 0x79,
    0x70, 0x65, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x00, 0x06, 0x63, 0x6f,
    0x6e, 0x63, 0x61, 0x74, 0x01, 0x0a, 0x00, 0x01, 0x94, 0x01, 0x06, 0x00,
    0x00, 0x01, 0x08, 0x00, 0x1c, 0xa3, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00,
    0xcb, 0x00, 0x00, 0x00, 0x00, 0x35, 0x01, 0x00, 0x71, 0x01, 0x00, 0x00,
    0x00, 0x52, 0x02, 0x00, 0x00, 0x9f, 0x01, 0x02, 0x02, 0x6f, 0x02, 0x02,
    0x00, 0xf1, 0x01, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x6f, 0x01, 0x03,
    0x00, 0x82, 0x01, 0x02, 0x00, 0x35, 0x01, 0x00, 0x4b, 0x02, 0x00, 0x00,
    0x00, 0x4d, 0x01, 0x01, 0x1a, 0x04, 0x00, 0x00, 0x00, 0x52, 0x02, 0x00,
    0x00, 0x6f, 0x03, 0x05, 0x00, 0x9f, 0x01, 0x03, 0x02, 0x1c, 0x04, 0x00,
    0x00, 0x6f, 0x02, 0x06, 0x00, 0x6f, 0x05, 0x06, 0x00, 0x39, 0x03, 0x05,
    0x00, 0xa8, 0x02, 0x03, 0x00, 0xc6, 0x05, 0x00, 0x00, 0x6a, 0x05, 0x00,
    0x04, 0x8b, 0x02, 0xfd, 0xff, 0x82, 0x01, 0x02, 0x00, 0x07, 0x03, 0x01,
    0x03, 0x02, 0x03, 0x03, 0x03, 0x04, 0x03, 0x05, 0x03, 0x06, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x16, 0x00,
};
static const unsigned int kChunkFlushLen = sizeof(kChunkFlush);

static unsigned long long g_cap_closure = 0;
static unsigned long long g_cap_f = 0;
// Threads we have actually run code on. `zendo:mark` records the calling
// lua_State, `zendo:caller` answers whether the current one is in the list.
// checkcaller built on this says "this thread is ours", not "this VM happens to
// be elevated" - a game callback shares the identity but not the list.
static unsigned long long g_ours[16] = {};
static int g_ours_n = 0;
static HANDLE g_cap_pipe = INVALID_HANDLE_VALUE;
// Set by the `x` command. It means "detach for good": unwind out of the REPL
// so DllMain can restore the borrowed thread. A payload that stays parked keeps
// the process in a state the anti-cheat refuses to terminate - the window dies
// but the pid survives, and only a reboot clears it.
static int g_leave = 0;
// Counts completed sessions. Written to work/loop.bin after each one, which is
// how "the seek loop is alive" is proven instead of assumed.
static unsigned int g_loop_n = 0;
static int g_cap_mode = 0;   // 0 = untouched, 1 = swap only, 2 = +read args, 3 = +pipe
static int g_api_live = 0;   // the closure slot carries native_api for this session
static unsigned int g_cap_calls = 0;

inline void cap_put(const char* s, unsigned int n) {
    if (g_cap_pipe == INVALID_HANDLE_VALUE) return;
    static char line[4224];
    unsigned int k = 0;
    line[k++] = 'P';
    for (unsigned int i = 0; i < n && k < sizeof(line) - 2; ++i) {
        char c = s[i];
        line[k++] = (c == '\n' || c == '\r') ? ' ' : c;
    }
    line[k++] = '\n';
    DWORD w = 0;
    api().WriteFile(g_cap_pipe, line, k, &w, nullptr);
}

inline void cap_double(char* d, unsigned int& n, double x) {
    if (x != x) { d[n++] = 'n'; d[n++] = 'a'; d[n++] = 'n'; return; }
    bool neg = x < 0.0;
    if (neg) x = -x;
    if (x > 1.0e15) { d[n++] = 'i'; d[n++] = 'n'; d[n++] = 'f'; return; }
    unsigned long long ip = static_cast<unsigned long long>(x);
    double frac = x - static_cast<double>(ip);
    char tmp[24];
    int td = 0;
    if (!ip) tmp[td++] = '0';
    while (ip) { tmp[td++] = static_cast<char>('0' + ip % 10ull); ip /= 10ull; }
    if (neg) d[n++] = '-';
    while (td) d[n++] = tmp[--td];
    if (frac > 0.0) {
        d[n++] = '.';
        for (int k = 0; k < 6; ++k) {
            frac *= 10.0;
            int digit = static_cast<int>(frac);
            if (digit < 0) digit = 0;
            if (digit > 9) digit = 9;
            d[n++] = static_cast<char>('0' + digit);
            frac -= static_cast<double>(digit);
            if (frac <= 0.0) break;
        }
    }
}

inline void cap_value(char* d, unsigned int& n, unsigned long long slot) {
    if (n > 1900) return;
    unsigned long long v = 0, w = 0;
    if (!read_u64(slot, &v) || !read_u64(slot + 8, &w)) return;
    unsigned int tt = static_cast<unsigned int>((w >> 32) & 0xff);
    if (tt == 6 && v && readable(reinterpret_cast<const void*>(v + 0x18), 4)) {
        unsigned int len = 0;
        read_u32(v + 0x14, &len);
        if (len > 1000) len = 1000;
        for (unsigned int i = 0; i < len && n < 2040; ++i)
            d[n++] = *reinterpret_cast<char*>(v + 0x18 + i);
        return;
    }
    if (tt == 3) {
        union { unsigned long long u; double f; } cv;
        cv.u = v;
        cap_double(d, n, cv.f);
        return;
    }
    if (tt == 0) { d[n++] = 'n'; d[n++] = 'i'; d[n++] = 'l'; return; }
    if (tt == 1) {
        const char* b = (v & 0xffull) ? "true" : "false";
        while (*b) d[n++] = *b++;
        return;
    }
    if (tt == 8) {
        const char* b = "function";
        while (*b) d[n++] = *b++;
        return;
    }
    d[n++] = '<';
    d[n++] = static_cast<char>('0' + tt % 10);
    d[n++] = '>';
}

static unsigned long long g_base = 0;
// 0: run the load. 1: prove entry only - the guard question and the load
// question are different questions, and they cost a client relaunch each.
static int g_native_mode = 0;
static unsigned long long g_native_hits = 0;
static unsigned long long g_api_hits = 0;

// stage_mark is overwritten by the runner when a session ends, so a function
// that was entered and then killed leaves no trace there. This file is never
// touched by the host: if it exists, the VM called in.
inline void hit_mark() {
    Api& a = api();
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\hit.bin", GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    char b[32];
    unsigned int n = 0;
    b[n++] = static_cast<char>('0' + (g_native_mode % 10));
    b[n++] = ' ';
    char d[20];
    unsigned int k = 0;
    unsigned long long v = g_native_hits;
    do {
        d[k++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    } while (v && k < sizeof(d));
    while (k) b[n++] = d[--k];
    DWORD w = 0;
    a.WriteFile(f, b, n, &w, nullptr);
    a.CloseHandle(f);
}

// cap_print is defined further down; the dispatcher falls back into it for
// anything that is not a zendo op so print capture survives the swap.
inline int cap_print(void* L);

// A C closure is the only way Lua can reach native code, and the target of
// every call it makes is an indirect call - which is exactly what CFG checks.
// The guard bit for this function is set by stage U, so the call arrives.
// Results are written straight into the frame: Luau's TValue is 16 bytes, the
// number tag sits in the high dword of the second qword, and L->top is at 0x60
// (the same field exec_protected uses). 42.0 is the wire test value.
inline int native_loadstring(void* L) {
    unsigned long long l = reinterpret_cast<unsigned long long>(L);
    ++g_native_hits;
    hit_mark();
    stage_mark(api(), g_native_mode ? "ENTER-1" : "ENTER-42");
    if (g_native_mode == 1) return 1;
    // The client has no Luau compiler, so the only honest loadstring is one
    // that was compiled somewhere else. This body is `return 42`, built by the
    // same pipeline that makes every other chunk, with the guard magic in
    // front. LuaVMLoad pushes the resulting function and we hand it back: the
    // caller gets something it can call, which is what loadstring means.
    static unsigned char buf[8 + sizeof(kZ42Body)];
    static bool built = false;
    if (!built) {
        const unsigned long long magic = 0xE009325B4A107A52ull;
        for (int i = 0; i < 8; ++i)
            buf[i] = static_cast<unsigned char>(magic >> (8 * i));
        for (unsigned int i = 0; i < sizeof(kZ42Body); ++i) buf[8 + i] = kZ42Body[i];
        built = true;
    }
    if (!g_base) return 0;
    ChunkName src;
    src.data = reinterpret_cast<const char*>(buf);
    src.pad = 0;
    src.size = 8 + sizeof(kZ42Body);
    src.cap = src.size;
    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(g_base + 0x426A570);
    int ret = load(L, &src, "=z42", 0);
    stage_mark(api(), ret == 0 ? "LOAD-OK" : "LOAD-ERR");
    if (ret != 0) return 0;
    return 1;
}

// The dispatcher behind a captured closure. `print` has to keep working for
// the game, so the sentinel string decides: first argument equal to the ping
// op is ours, anything else is passed straight to the original print. This is
// the shape the rest of the API takes - one door, a name in front, native work
// behind it.
// Argument and result marshalling for the dispatcher. Everything below was
// measured against a live frame: arguments start at L->base (+0x58), 16 bytes
// each; a string is a TString* with its byte length at +0x14 and data at +0x18;
// a number is a raw double in the value qword with tag 3 in the high dword of
// the second qword. The Lua layer never sees any of this - it only calls a
// function with ordinary values, exactly as it would call print.
struct LuaArg {
    unsigned long long v;
    unsigned long long w;
};

inline bool lua_arg(unsigned long long L, int i, LuaArg* out) {
    unsigned long long base = 0;
    if (!read_u64(L + 0x58, &base) || !base) return false;
    unsigned long long slot = base + 16ull * static_cast<unsigned int>(i);
    return read_u64(slot, &out->v) && read_u64(slot + 8, &out->w);
}

inline bool lua_arg_num(unsigned long long L, int i, double* out) {
    LuaArg a{};
    if (!lua_arg(L, i, &a) || ((a.w >> 32) & 0xff) != 3) return false;
    *out = *reinterpret_cast<const double*>(&a.v);
    return true;
}

// Returns the byte pointer, not a copy: a script argument is a live TString and
// its buffer is used in place. Length is a 32-bit field, so the cap is a sanity
// bound, not a policy.
inline char* lua_arg_str(unsigned long long L, int i, unsigned int* len) {
    LuaArg a{};
    if (!lua_arg(L, i, &a) || ((a.w >> 32) & 0xff) != 6 || !a.v) return nullptr;
    unsigned int n = 0;
    if (!read_u32(a.v + 0x14, &n) || n > (1u << 24)) return nullptr;
    *len = n;
    return reinterpret_cast<char*>(a.v + 0x18);
}

inline unsigned long long lua_arg_tstr(unsigned long long L, int i, unsigned int* len) {
    LuaArg a{};
    if (!lua_arg(L, i, &a) || ((a.w >> 32) & 0xff) != 6 || !a.v) return 0;
    unsigned int n = 0;
    if (!read_u32(a.v + 0x14, &n) || n > (1u << 24)) return 0;
    *len = n;
    return a.v;
}

// Stack-frame headroom, written to work/api_stk.bin: top, stack_last, ci->top.
// A C call frame gets no reserved result slots, so a push past stack_last writes
// outside the stack block and the next GC walk dies on the smashed heap. This
// report says how much room a handler actually has.
// Appends one tagged line of addresses to work/api_stk.bin. Because entries from
// consecutive script calls land in the same file, a single run shows whether a
// frame is still sane *after* the previous native call returned - which is the
// only way to tell "the op broke the frame" from "the return path broke it".
inline void api_line(char tag, unsigned long long a, unsigned long long b,
                     unsigned long long c, unsigned long long d) {
    HANDLE f = api().CreateFileA("D:\\zendo\\work\\api_stk.bin", FILE_APPEND_DATA,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    const char* hex = "0123456789abcdef";
    unsigned long long v[4] = {a, b, c, d};
    char line[128];
    unsigned int n = 0;
    line[n++] = tag;
    line[n++] = ' ';
    for (int q = 0; q < 4; ++q) {
        for (int bb = 15; bb >= 0; --bb) line[n++] = hex[(v[q] >> (4 * bb)) & 0xf];
        line[n++] = q == 3 ? '\n' : ' ';
    }
    DWORD w = 0;
    api().WriteFile(f, line, n, &w, nullptr);
    api().CloseHandle(f);
}

// Off by default. Every result push used to open, write and close a log file,
// which turned a script that makes a few hundred native calls into a few
// hundred file opens - measurable at exactly the moment a memory walk is being
// bisected, and a variable nobody needs while the surface is stable.
static int g_api_trace = 0;

inline void api_stk(unsigned long long L, unsigned long long top, unsigned long long last,
                    unsigned long long citop, int pushed) {
    if (!g_api_trace) return;
    unsigned long long base = 0;
    read_u64(L + 0x58, &base);
    api_line(static_cast<char>('0' + (pushed & 0xf)), L, top, citop, base);
}

// Results are read back from L->top - n, so every push must land inside the
// frame the call actually reserved. Refuse the push instead of writing past it:
// a missing value becomes nil, which a script can see, while a heap smash only
// shows up as a dead client minutes later.
inline int lua_ret_num(unsigned long long L, double x) {
    unsigned long long top = 0;
    if (!read_u64(L + 0x60, &top) || !top) return 0;
    unsigned long long last = 0, ci = 0, citop = 0;
    read_u64(L + 0x68, &last);
    if (read_u64(L + 0x70, &ci) && ci) read_u64(ci + 0x8, &citop);
    unsigned long long limit = last;
    if (citop && citop < limit) limit = citop;
    if (limit && top + 16 > limit) {
        api_stk(L, top, last, citop, 0);
        return 0;
    }
    *reinterpret_cast<double*>(top) = x;
    *reinterpret_cast<unsigned long long*>(top + 8) = 0x3ull << 32;
    wr64(L + 0x60, top + 16);
    api_stk(L, top, last, citop, 1);
    return 1;
}

inline bool op_is(const char* s, unsigned int len, const char* want) {
    unsigned int i = 0;
    while (want[i]) ++i;
    if (len != i) return false;
    for (unsigned int k = 0; k < i; ++k)
        if (s[k] != want[k]) return false;
    return true;
}

// Writes through WinAPI so a script can patch read-only data as well as code.
// PAGE_TARGETS_NO_UPDATE keeps the CFG bitmap for these pages intact: changing
// protection on a page that holds valid call targets would otherwise reset
// them, and the next indirect call into that page would be rejected.
inline bool api_write(unsigned long long addr, const char* src, unsigned int len) {
    if (!addr || !len || !src) return false;
    // A page that is already writable needs no protection change. Asking for one
    // on a plain data page with PAGE_TARGETS_NO_UPDATE is rejected outright by
    // the kernel - that flag is only meaningful when the page is executable.
    Mbi mbi;
    unsigned long long start = addr & ~0xfffull;
    unsigned long long end = (addr + len + 0xfffull) & ~0xfffull;
    DWORD prot = 0;
    if (api().VirtualQuery(reinterpret_cast<const void*>(start), &mbi, sizeof(mbi)) &&
        mbi.State == MEM_COMMIT)
        prot = mbi.Protect & 0xFF;
    bool already = prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE;
    if (!already) {
        DWORD oldp = 0;
        DWORD want = (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                         ? (PAGE_EXECUTE_READWRITE | 0x40000000u)
                         : PAGE_READWRITE;
        if (!api().VirtualProtect(reinterpret_cast<void*>(start), static_cast<SIZE_T>(end - start),
                                  want, &oldp))
            return false;
    }
    for (unsigned int i = 0; i < len; ++i)
        *reinterpret_cast<volatile char*>(addr + i) = src[i];
    if (!already) {
        DWORD tmp = 0;
        DWORD back = (prot == PAGE_EXECUTE) ? PAGE_EXECUTE
                    : (prot & PAGE_EXECUTE) ? PAGE_EXECUTE_READ
                                            : prot;
        api().VirtualProtect(reinterpret_cast<void*>(start), static_cast<SIZE_T>(end - start),
                             back, &tmp);
    }
    return true;
}

// Survives a dead process, like the other markers: the last op reached is the
// last thing in the file, so a fault can be pinned to an operation without a
// debugger attached.
inline void api_step(char phase, int op) {
    HANDLE f = api().CreateFileA("D:\\zendo\\work\\api_step.bin", GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    char b[3] = {phase, static_cast<char>('0' + op), '\n'};
    DWORD w = 0;
    api().WriteFile(f, b, 3, &w, nullptr);
    api().CloseHandle(f);
}

// Layout report for a script string: writes the header qwords and the first 32
// data bytes to work/strinfo.bin. Used to settle whether long strings carry
// their bytes inline at +0x18 or point somewhere else, which decides whether a
// script string can be used as an output buffer at all.
inline void api_strinfo(unsigned long long tstr, unsigned int len) {
    HANDLE f = api().CreateFileA("D:\\zendo\\work\\strinfo.bin", GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    char line[256];
    unsigned int n = 0;
    const char* hex = "0123456789abcdef";
    line[n++] = 'l';
    line[n++] = 'e';
    line[n++] = 'n';
    line[n++] = ' ';
    char d[12];
    unsigned int k = 0, v = len;
    do { d[k++] = static_cast<char>('0' + v % 10); v /= 10; } while (v);
    while (k) line[n++] = d[--k];
    line[n++] = '\n';
    for (int q = 0; q < 6; ++q) {
        unsigned long long x = 0;
        read_u64(tstr + 8ull * q, &x);
        line[n++] = 'p';
        line[n++] = static_cast<char>('0' + q);
        line[n++] = ' ';
        for (int b = 15; b >= 0; --b) line[n++] = hex[(x >> (4 * b)) & 0xf];
        line[n++] = '\n';
    }
    DWORD w = 0;
    api().WriteFile(f, line, n, &w, nullptr);
    api().CloseHandle(f);
}

// One captured closure is the whole native surface. The first argument picks
// the operation; anything unrecognised is handed to the original f, so the
// game's own print keeps working while we live inside its object.
//
//   zendo:ping                 -> 4080
//   zendo:scratch              -> address of a writable byte buffer in payload
//   zendo:read   (addr, buf)   -> bytes copied into the caller's string buffer
//   zendo:write  (addr, src)   -> bytes copied out of a script string, 1 or 0
//
// read/write take a Lua string as the buffer. Writing into a long string
// (length > 40) is safe: Luau only interns short strings, so no hash table is
// touched. The chunk test uses 64-byte buffers for that reason.
// --- loadstring -------------------------------------------------------------
// The client ships without a Luau compiler, so source cannot be compiled in
// process. What it can do is load bytecode, and that is all loadstring really
// needs: the executor compiles offline, the bytes travel, the VM turns them into
// a callable closure. This is the door those bytes come through.

// Staging area for the magic prefix plus the caller's bytecode. One page block,
// allocated once per payload instance, never freed: the loader keeps pointers
// into the proto it builds and the process dies with us anyway.
inline unsigned long long load_stage(unsigned int need) {
    static unsigned long long stage = 0;
    if (!stage) {
        void* p = api().VirtualAlloc ? api().VirtualAlloc(nullptr, 1u << 20,
                                                          MEM_COMMIT | MEM_RESERVE,
                                                          PAGE_READWRITE)
                                     : nullptr;
        if (p) stage = reinterpret_cast<unsigned long long>(p);
    }
    if (!stage || need > (1u << 20)) return 0;
    return stage;
}

// Prepends the guard magic to whatever already sits at buf+8 and hands the blob
// to LuaVMLoad. The loader pushes the resulting closure onto L's stack, so a
// caller that returns 1 gives it straight to the script.
inline int lua_load_stage(unsigned long long l, unsigned long long buf, unsigned int blen) {
    if (!buf || !blen || !g_base) return 0;
    const unsigned long long magic = 0xE009325B4A107A52ull;
    char* p = reinterpret_cast<char*>(buf);
    for (int i = 0; i < 8; ++i) p[i] = static_cast<char>(magic >> (8 * i));
    ChunkName src;
    src.data = p;
    src.pad = 0;
    src.size = blen + 8;
    src.cap = blen + 8;
    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(g_base + 0x426A570);
    int ret = load(reinterpret_cast<void*>(l), &src, "=zendo", 0);
    return ret == 0 ? 1 : 0;
}

inline int lua_load_bytes(unsigned long long l, const char* body, unsigned int blen) {
    if (!body || !blen || blen > (1u << 20) - 8) return 0;
    unsigned long long buf = load_stage(blen + 8);
    if (!buf) return 0;
    char* p = reinterpret_cast<char*>(buf);
    for (unsigned int i = 0; i < blen; ++i)
        *reinterpret_cast<volatile char*>(p + 8 + i) = body[i];
    return lua_load_stage(l, buf, blen);
}

// Reads a compiled chunk from disk into the staging buffer and loads it.
inline int lua_load_file(unsigned long long l, const char* path) {
    HANDLE f = api().CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return 0;
    unsigned long long buf = load_stage((1u << 20));
    if (!buf) {
        api().CloseHandle(f);
        return 0;
    }
    DWORD got = 0;
    char* p = reinterpret_cast<char*>(buf);
    if (!api().ReadFile(f, p + 8, (1u << 20) - 8, &got, nullptr) || !got) {
        api().CloseHandle(f);
        return 0;
    }
    api().CloseHandle(f);
    return lua_load_stage(l, buf, got);
}

// Reads one newline terminated field from the session pipe.
inline unsigned int pipe_line(Api& a, HANDLE pipe, char* dst, unsigned int cap) {
    unsigned int n = 0;
    for (;;) {
        char c = 0;
        DWORD rd = 0;
        if (!a.ReadFile(pipe, &c, 1, &rd, nullptr) || rd == 0) return 0;
        if (c == '\n') break;
        if (n + 1 < cap) dst[n++] = c;
    }
    dst[n] = 0;
    return n;
}

inline unsigned int parse_dec(const char* s) {
    unsigned int v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + static_cast<unsigned int>(*s++ - '0');
    return v;
}

// Reply-path diagnostic: a failed loadstring has to say where it stopped.
inline void ls_log(const char* tag, unsigned long long v) {
    Api& a = api();
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\ls.bin", FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    char b[96];
    char* p = b;
    while (*tag) *p++ = *tag++;
    *p++ = ' ';
    p = append_hex(p, v);
    *p++ = '\n';
    DWORD w = 0;
    a.WriteFile(f, b, static_cast<DWORD>(p - b), &w, nullptr);
    a.CloseHandle(f);
}

// Live loadstring. The client has no compiler, so the source goes out on the
// session pipe exactly as Lua handed it over; the executor compiles and remaps
// it offline and answers with the blob. The reply lands in the staging buffer
// and LuaVMLoad turns it into the closure the script asked for.
//
// Wire, payload -> endpoint:  "C <len>\n" + source bytes
//       endpoint -> payload:  "K <len>\n" + bytecode  |  "E <len>\n" + message
inline int lua_compile_remote(unsigned long long l, const char* src, unsigned int slen) {
    HANDLE pipe = g_cap_pipe;
    Api& a = api();
    if (pipe == INVALID_HANDLE_VALUE || !src || !slen || slen > 262144) return 0;
    char head[24];
    unsigned int n = 0;
    head[n++] = 'C';
    head[n++] = ' ';
    char d[12];
    unsigned int k = 0, v = slen;
    do { d[k++] = static_cast<char>('0' + (v % 10)); v /= 10; } while (v);
    while (k) head[n++] = d[--k];
    head[n++] = '\n';
    DWORD w = 0;
    if (!a.WriteFile(pipe, head, n, &w, nullptr)) return 0;
    if (!a.WriteFile(pipe, src, slen, &w, nullptr)) return 0;

    char line[64];
    if (!pipe_line(a, pipe, line, sizeof(line))) {
        ls_log("no-reply", 0);
        return 0;
    }
    unsigned int rlen = parse_dec(line + 2);
    ls_log("line", static_cast<unsigned long long>(static_cast<unsigned char>(line[0])));
    ls_log("rlen", rlen);
    if (rlen > (1u << 20) - 8) rlen = 0;
    if (line[0] == 'K' && rlen) {
        unsigned long long buf = load_stage(rlen + 8);
        if (!buf) return 0;
        if (!read_all(a, pipe, reinterpret_cast<void*>(buf + 8), rlen)) {
            ls_log("short-body", rlen);
            return 0;
        }
        int r = lua_load_stage(l, buf, rlen);
        ls_log("load", static_cast<unsigned long long>(r));
        if (r == 0) {
            HANDLE f = a.CreateFileA("D:\\zendo\\work\\ls_blob.bin", GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (f != INVALID_HANDLE_VALUE) {
                DWORD w2 = 0;
                a.WriteFile(f, reinterpret_cast<void*>(buf + 8), rlen, &w2, nullptr);
                a.CloseHandle(f);
            }
        }
        return r;
    }
    if (line[0] == 'E' && rlen) {
        static char err[256];
        unsigned int keep = rlen < sizeof(err) - 1 ? rlen : sizeof(err) - 1;
        read_all(a, pipe, err, rlen);
        err[keep] = 0;
        char out[300];
        const char* pre = "Ploadstring: ";
        unsigned int q = 0;
        while (*pre) out[q++] = *pre++;
        for (unsigned int i = 0; i < keep && q < sizeof(out) - 2; ++i) out[q++] = err[i];
        out[q++] = '\n';
        a.WriteFile(pipe, out, q, &w, nullptr);
    }
    return 0;
}

// Defined after exec_raw, next to the call machinery it borrows.
int zendo_file_op(unsigned long long l, const char* op, unsigned int oplen);

inline int native_api(void* L) {
    unsigned long long l = reinterpret_cast<unsigned long long>(L);
    // A dedicated page, not a static in the image: the write op changes page
    // protection, and touching the page our own code lives on is a variable
    // this test does not need.
    static unsigned long long scratch = 0;
    if (!scratch) {
        void* p = api().VirtualAlloc ? api().VirtualAlloc(nullptr, 0x1000,
                                                          MEM_COMMIT | MEM_RESERVE,
                                                          PAGE_READWRITE)
                                     : nullptr;
        if (p) {
            scratch = reinterpret_cast<unsigned long long>(p);
            const char init[] = "ZENDO-API-OK";
            for (unsigned int i = 0; i < sizeof(init); ++i)
                *reinterpret_cast<char*>(scratch + i) = init[i];
        }
    }
    // Every entry is recorded, matched or not: the fallback prints, so the log
    // cannot tell "dispatcher ran and fell through" from "never called".
    {
        HANDLE f = api().CreateFileA("D:\\zendo\\work\\api.bin", GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            char b[4] = {'A', ' ', static_cast<char>('0' + (g_api_hits % 10)), '\n'};
            DWORD w = 0;
            ++g_api_hits;
            api().WriteFile(f, b, 4, &w, nullptr);
            api().CloseHandle(f);
        }
    }

    unsigned int oplen = 0;
    char* op = lua_arg_str(l, 0, &oplen);
    if (op) {
        if (op_is(op, oplen, "zendo:ping")) {
            api_step('S', 1);
            int r = lua_ret_num(l, 4080.0);
            api_step('E', 1);
            return r;
        }
        if (op_is(op, oplen, "zendo:scratch")) {
            api_step('S', 2);
            int r = lua_ret_num(l, static_cast<double>(scratch));
            api_step('E', 2);
            return r;
        }

        // The identity lives on the state's extras block, the same +0x70 the
        // session gate writes 8 into. Reading it from the caller's own state is
        // what checkcaller needs: a thread we lifted answers 8, a plain game
        // callback answers its own level.
        if (op_is(op, oplen, "zendo:caller")) {
            api_step('S', 23);
            for (int i = 0; i < g_ours_n; ++i) {
                if (g_ours[i] == l) {
                    api_step('E', 23);
                    return lua_ret_num(l, 1.0);
                }
            }
            unsigned long long ex = 0, ident = 0;
            if (read_u64(l + 8, &ex) && ex) read_u64(ex + 0x70, &ident);
            api_step('E', 23);
            return lua_ret_num(l, ident >= 8.0 ? 2.0 : 0.0);
        }

        // Same op the other way round: the chunk announces the state it runs on.
        if (op_is(op, oplen, "zendo:mark")) {
            api_step('S', 24);
            bool known = false;
            for (int i = 0; i < g_ours_n; ++i) {
                if (g_ours[i] == l) { known = true; break; }
            }
            if (!known) {
                if (g_ours_n == 16) {
                    for (int i = 1; i < 16; ++i) g_ours[i - 1] = g_ours[i];
                    g_ours[15] = l;
                } else {
                    g_ours[g_ours_n++] = l;
                }
            }
            api_step('E', 24);
            return lua_ret_num(l, static_cast<double>(g_ours_n));
        }

        if (op_is(op, oplen, "zendo:file") || op_is(op, oplen, "zendo:filew") ||
            op_is(op, oplen, "zendo:isfile") || op_is(op, oplen, "zendo:listfiles") ||
            op_is(op, oplen, "zendo:isfolder") || op_is(op, oplen, "zendo:mkdir") ||
            op_is(op, oplen, "zendo:del")) {
            api_step('S', 25);
            int r = zendo_file_op(l, op, oplen);
            api_step('E', 25);
            return r;
        }

        // A raw window into a closure's Proto. Nothing here interprets the
        // fields - it hands back the first words so a script can show which
        // offset is which, and the reading is decided from that, not guessed.
        if (op_is(op, oplen, "zendo:proto")) {
            api_step('S', 26);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) return 0;
            unsigned long long proto = 0;
            if (!read_u64(a.v + 0x18, &proto) || !proto) return 0;
            double startf = 0;
            unsigned int start = 0;
            if (lua_arg_num(l, 2, &startf) && startf > 0 && startf < 0x200) {
                start = static_cast<unsigned int>(startf) & ~3u;
            }
            int pushed = 0;
            for (unsigned int i = 0; i < 24; ++i) {
                unsigned int w = 0;
                if (!read_u32(proto + start + 4ull * i, &w)) break;
                pushed += lua_ret_num(l, static_cast<double>(w));
            }
            api_step('E', 26);
            return pushed;
        }

        // Copy a TValue out of the proto's constants array. The value already
        // lives in the VM heap, so moving its 16 bytes onto the result stack
        // gives the script a real string or number without constructing one.
        if (op_is(op, oplen, "zendo:kget")) {
            api_step('S', 28);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) return 0;
            double idxf = 0;
            if (!lua_arg_num(l, 2, &idxf) || idxf < 0 || idxf > 4096) return 0;
            unsigned long long proto = 0, k = 0;
            if (!read_u64(a.v + 0x18, &proto) || !proto) return 0;
            if (!read_u64(proto + 0x60, &k) || !k) return 0;
            unsigned int sizek = 0;
            read_u32(proto + 0xac, &sizek);
            unsigned int i = static_cast<unsigned int>(idxf);
            if (i >= sizek) return 0;
            unsigned long long src = k + 16ull * i;
            unsigned long long v = 0, w = 0;
            if (!read_u64(src, &v) || !read_u64(src + 8, &w)) return 0;

            unsigned long long top = 0;
            if (!read_u64(l + 0x60, &top) || !top) return 0;
            unsigned long long last = 0, ci = 0, citop = 0;
            read_u64(l + 0x68, &last);
            if (read_u64(l + 0x70, &ci) && ci) read_u64(ci + 0x8, &citop);
            unsigned long long limit = last;
            if (citop && citop < limit) limit = citop;
            if (limit && top + 16 > limit) return 0;
            wr64(top, v);
            wr64(top + 8, w);
            wr64(l + 0x60, top + 16);
            api_step('E', 28);
            return 1;
        }
        // the tag found at each pointer, so the constants array can be found by
        // looking for tag 6 at the address a word holds - not by assuming an
        // offset from a layout doc.
        if (op_is(op, oplen, "zendo:protoscan")) {
            api_step('S', 27);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) return 0;
            unsigned long long proto = 0;
            if (!read_u64(a.v + 0x18, &proto) || !proto) return 0;
            int pushed = 0;
            for (unsigned int i = 0; i < 24; ++i) {
                unsigned long long word = 0;
                if (!read_u64(proto + 8ull * i, &word)) break;
                unsigned int code = 0;
                if (word && readable(reinterpret_cast<const void*>(word), 16)) {
                    unsigned long long w2 = 0;
                    read_u64(word + 8, &w2);
                    unsigned int tt = static_cast<unsigned int>((w2 >> 32) & 0xff);
                    code = 1u | (tt << 1);
                }
                pushed += lua_ret_num(l, static_cast<double>(code));
            }
            api_step('E', 27);
            return pushed;
        }

        if (op_is(op, oplen, "zendo:strinfo")) {
            api_step('S', 3);
            unsigned int slen = 0;
            unsigned long long t = lua_arg_tstr(l, 1, &slen);
            if (t) api_strinfo(t, slen);
            int r = lua_ret_num(l, static_cast<double>(slen));
            api_step('E', 3);
            return r;
        }

        // Raw identity of any Lua value: the pointer inside the TValue and its
        // type tag. Every introspection path starts here - a closure, a table
        // and a userdata all answer with the address of the object the value
        // points at, which is what the GC walk and the proto readers need. The
        // pointer fits a double exactly below 2^48, so it round-trips through
        // the Lua number without losing bits.
        if (op_is(op, oplen, "zendo:ref")) {
            api_step('S', 21);
            LuaArg a{};
            if (!lua_arg(l, 1, &a)) {
                api_step('E', 21);
                return 0;
            }
            int pushed = lua_ret_num(l, static_cast<double>(a.v));
            pushed += lua_ret_num(l, static_cast<double>((a.w >> 32) & 0xff));
            api_step('P', 21);
            return pushed;
        }

        // Closure shape, for the layout probe. A C closure and a Luau closure
        // are different objects behind the same type tag, and the only honest
        // way to tell them apart is to look: the entry candidate at +0x28 and
        // the proto candidate at +0x18 are checked against the page protection
        // they point into. Executable means C; a mapped, non-executable heap
        // page means a proto. The three header bytes go back untouched so the
        // script can print them next to a known C closure and a known Luau one
        // and read the real layout off the two rows.
        if (op_is(op, oplen, "zendo:probe")) {
            api_step('S', 22);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) {
                api_step('E', 22);
                return 0;
            }
            unsigned long long entry = 0, proto = 0;
            read_u64(a.v + 0x28, &entry);
            read_u64(a.v + 0x18, &proto);
            int entry_exec = 0;
            if (entry) {
                Mbi mbi{};
                if (api().VirtualQuery(reinterpret_cast<void*>(entry), &mbi,
                                       sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT) {
                    DWORD prot = mbi.Protect & 0xff;
                    if (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
                        prot == PAGE_EXECUTE_READWRITE ||
                        prot == PAGE_EXECUTE_WRITECOPY)
                        entry_exec = 1;
                }
            }
            unsigned int head = 0;
            read_u32(a.v + 4, &head);
            int pushed = lua_ret_num(l, static_cast<double>(a.v));
            pushed += lua_ret_num(l, static_cast<double>(entry));
            pushed += lua_ret_num(l, static_cast<double>(entry_exec));
            pushed += lua_ret_num(l, static_cast<double>(proto));
            pushed += lua_ret_num(l, static_cast<double>(head & 0xff));
            pushed += lua_ret_num(l, static_cast<double>((head >> 8) & 0xff));
            pushed += lua_ret_num(l, static_cast<double>((head >> 16) & 0xff));
            api_step('P', 22);
            return pushed;
        }

        // Function identity for the Lua layer. A function TValue carries a
        // pointer to a GC closure object; the isC byte sits at +5 and, for a C
        // closure, the entry point at +0x28. Both offsets were measured on this
        // build: the dispatcher swap already writes +0x28 to take over print.
        // Handing them to the script is what lets hookfunction patch and
        // restore a real entry point instead of shadowing a global name.
        if (op_is(op, oplen, "zendo:fninfo")) {
            api_step('S', 19);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) {
                api_step('E', 19);
                return 0;
            }
            unsigned long long head = 0;
            if (!read_u64(a.v + 4, &head)) {
                api_step('E', 19);
                return 0;
            }
            unsigned int isC = static_cast<unsigned int>((head >> 8) & 0xff);
            unsigned long long entry = 0;
            if (isC && !read_u64(a.v + 0x28, &entry)) {
                api_step('E', 19);
                return 0;
            }
            int pushed = lua_ret_num(l, static_cast<double>(a.v));
            pushed += lua_ret_num(l, static_cast<double>(entry));
            pushed += lua_ret_num(l, static_cast<double>(isC));
            api_step('P', 19);
            return pushed;
        }

        // Patch the entry point of a C closure in place. One 8 byte store, so a
        // second thread either sees the old pointer or the new one, never half
        // of each. The page a closure lives on belongs to the GC heap and is
        // writable, but the protect call keeps this honest if that ever changes.
        if (op_is(op, oplen, "zendo:fnset")) {
            api_step('S', 20);
            LuaArg a{};
            double entry = 0;
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v ||
                !lua_arg_num(l, 2, &entry) || entry == 0) {
                api_step('E', 20);
                return 0;
            }
            unsigned long long head = 0;
            if (!read_u64(a.v + 4, &head)) {
                api_step('E', 20);
                return 0;
            }
            if (((head >> 8) & 0xff) != 1) {
                api_step('E', 20);
                return 0;
            }
            unsigned long long slot = a.v + 0x28;
            unsigned long long start = slot & ~0xfffull;
            DWORD oldp = 0;
            if (!api().VirtualProtect(reinterpret_cast<void*>(start), 0x2000,
                                      PAGE_READWRITE, &oldp)) {
                api_step('E', 20);
                return 0;
            }
            *reinterpret_cast<volatile unsigned long long*>(slot) =
                static_cast<unsigned long long>(entry);
            DWORD back = 0;
            api().VirtualProtect(reinterpret_cast<void*>(start), 0x2000, oldp,
                                 &back);
            int r = lua_ret_num(l, 1.0);
            api_step('P', 20);
            return r;
        }

        // loadstring: the loader pushes the closure, so returning 1 hands it
        // back to the script as the result of the call.
        if (op_is(op, oplen, "zendo:load")) {
            api_step('S', 11);
            unsigned int blen = 0;
            char* body = lua_arg_str(l, 1, &blen);
            int n = body ? lua_load_bytes(l, body, blen) : 0;
            api_step(n ? 'P' : 'E', 11);
            return n;
        }

        // Live compile: source in, callable closure out. The executor answers on
        // the same pipe it is already streaming this chunk over.
        if (op_is(op, oplen, "zendo:loadstring")) {
            api_step('S', 13);
            unsigned int slen = 0;
            char* src = lua_arg_str(l, 1, &slen);
            int n = 0;
            if (src && slen) n = lua_compile_remote(l, src, slen);
            api_step(n ? 'P' : 'E', 13);
            return n;
        }

        if (op_is(op, oplen, "zendo:loadf")) {
            api_step('S', 12);
            unsigned int plen = 0;
            char* path = lua_arg_str(l, 1, &plen);
            int n = 0;
            if (path && plen && plen < 240) {
                char tmp[256];
                for (unsigned int i = 0; i < plen; ++i)
                    *reinterpret_cast<volatile char*>(tmp + i) = path[i];
                tmp[plen] = 0;
                n = lua_load_file(l, tmp);
            }
            api_step(n ? 'P' : 'E', 12);
            return n;
        }

        // Chunk-side reporting. The script hands the values it wants recorded to
        // this op, so the numbers are read from a live call frame instead of from
        // the pcall result area, which can sit in a stack block that was
        // reallocated by the call.
        if (op_is(op, oplen, "zendo:logv")) {
            unsigned long long raw[4] = {0, 0, 0, 0};
            for (int i = 1; i <= 4; ++i) {
                LuaArg a{};
                if (!lua_arg(l, i, &a)) continue;
                raw[i - 1] = a.v;
            }
            api_line('V', raw[0], raw[1], raw[2], raw[3]);
            return lua_ret_num(l, 1.0);
        }

        // Frame probe: records L, base, top, ci->top as the script sees the call
        // arrive. Runs before and after other ops in a chunk, so a frame that
        // goes bad can be pinned to the call that broke it.
        if (op_is(op, oplen, "zendo:mark")) {
            unsigned long long top = 0, base = 0, ci = 0, citop = 0;
            read_u64(l + 0x60, &top);
            read_u64(l + 0x58, &base);
            if (read_u64(l + 0x70, &ci) && ci) read_u64(ci + 0x8, &citop);
            api_line('M', l, base, top, citop);
            return 0;
        }

        // Reads five numeric arguments and returns their sum. No memory access
        // at all: this isolates argument marshalling from the store itself.
        if (op_is(op, oplen, "zendo:argsum")) {
            api_step('S', 9);
            double sum = 0, v = 0;
            int got = 0;
            for (int i = 1; i <= 5; ++i) {
                if (!lua_arg_num(l, i, &v)) break;
                sum += v;
                ++got;
            }
            int r = lua_ret_num(l, sum);
            api_step('P', 9);
            return r;
        }

        // Plain write, no protection change: this is the same store the poke op
        // does, with VirtualProtect taken out of the picture, so a crash can be
        // blamed on one of the two.
        if (op_is(op, oplen, "zendo:wr8")) {
            api_step('S', 8);
            double addr = 0;
            if (!lua_arg_num(l, 1, &addr)) {
                api_step('E', 8);
                return 0;
            }
            unsigned long long a = static_cast<unsigned long long>(addr);
            if (!readable(reinterpret_cast<const void*>(a), 4)) {
                api_step('E', 8);
                return 0;
            }
            int written = 0;
            for (int i = 2; i <= 9; ++i) {
                double v = 0;
                if (!lua_arg_num(l, i, &v)) break;
                *reinterpret_cast<volatile unsigned char*>(a + written) =
                    static_cast<unsigned char>(static_cast<unsigned long long>(v) & 0xff);
                ++written;
            }
            int r = lua_ret_num(l, static_cast<double>(written));
            api_step('P', 8);
            return r;
        }

        // The output path that matters: copy memory into a caller-supplied
        // script string. A long string stores its bytes inline at +0x18, so this
        // is a straight memcpy into the GC heap - no allocation, no interning,
        // no return marshalling for strings.
        if (op_is(op, oplen, "zendo:readn")) {
            api_step('S', 10);
            double addr = 0;
            unsigned int blen = 0;
            unsigned long long t = lua_arg_tstr(l, 2, &blen);
            if (!lua_arg_num(l, 1, &addr) || !t || !blen || blen <= 40) {
                api_step('E', 10);
                return lua_ret_num(l, 0);
            }
            unsigned long long src = static_cast<unsigned long long>(addr);
            if (!readable(reinterpret_cast<const void*>(src), blen) ||
                !readable(reinterpret_cast<const void*>(t + 0x18), blen)) {
                api_step('E', 10);
                return lua_ret_num(l, 0);
            }
            char* dst = reinterpret_cast<char*>(t + 0x18);
            for (unsigned int i = 0; i < blen; ++i)
                dst[i] = *reinterpret_cast<const char*>(src + i);
            int r = lua_ret_num(l, static_cast<double>(blen));
            api_step('P', 10);
            return r;
        }

        if (op_is(op, oplen, "zendo:peek")) {
            api_step('S', 6);
            double addr = 0, cnt = 0;
            if (!lua_arg_num(l, 1, &addr) || !lua_arg_num(l, 2, &cnt)) {
                api_step('E', 6);
                return 0;
            }
            unsigned long long a = static_cast<unsigned long long>(addr);
            int n = static_cast<int>(cnt);
            if (n < 0) n = 0;
            if (n > 8) n = 8;
            if (!readable(reinterpret_cast<const void*>(a), static_cast<SIZE_T>(n))) {
                api_step('E', 6);
                return 0;
            }
            int pushed = 0;
            for (int i = 0; i < n; ++i)
                pushed += lua_ret_num(l, static_cast<double>(
                                             *reinterpret_cast<const unsigned char*>(a + i)));
            api_step('P', 6);
            return pushed;
        }

        if (op_is(op, oplen, "zendo:poke")) {
            api_step('S', 7);
            double addr = 0;
            if (!lua_arg_num(l, 1, &addr)) {
                api_step('E', 7);
                return 0;
            }
            unsigned long long a = static_cast<unsigned long long>(addr);
            if (!readable(reinterpret_cast<const void*>(a), 4)) {
                api_step('E', 7);
                return 0;
            }
            unsigned long long start = a & ~0xfffull;
            unsigned long long end = (a + 4 + 0xfffull) & ~0xfffull;
            DWORD oldp = 0;
            if (!api().VirtualProtect(reinterpret_cast<void*>(start),
                                      static_cast<SIZE_T>(end - start),
                                      PAGE_READWRITE | 0x40000000u, &oldp)) {
                api_step('E', 7);
                return lua_ret_num(l, 0);
            }
            int written = 0;
            for (int i = 2; i <= 5; ++i) {
                double v = 0;
                if (!lua_arg_num(l, i, &v)) break;
                *reinterpret_cast<volatile unsigned char*>(a + written) =
                    static_cast<unsigned char>(static_cast<unsigned long long>(v) & 0xff);
                ++written;
            }
            DWORD tmp = 0;
            api().VirtualProtect(reinterpret_cast<void*>(start),
                                 static_cast<SIZE_T>(end - start), oldp, &tmp);
            api_step('P', 7);
            return lua_ret_num(l, static_cast<double>(written));
        }

        if (op_is(op, oplen, "zendo:read")) {
            api_step('S', 4);
            double addr = 0;
            unsigned int blen = 0;
            char* buf = lua_arg_str(l, 2, &blen);
            // Only a long string owns its bytes. A short one is interned and
            // shared with every other literal of the same text, so writing into
            // it would edit the whole string table instead of one buffer.
            if (!lua_arg_num(l, 1, &addr) || !buf || blen <= 40) {
                api_step('E', 4);
                return lua_ret_num(l, 0);
            }
            unsigned long long src = static_cast<unsigned long long>(addr);
            if (!readable(reinterpret_cast<const void*>(src), blen) ||
                !readable(reinterpret_cast<const void*>(buf), blen)) {
                api_step('E', 4);
                return lua_ret_num(l, 0);
            }
            for (unsigned int i = 0; i < blen; ++i) buf[i] = *reinterpret_cast<const char*>(src + i);
            int r = lua_ret_num(l, static_cast<double>(blen));
            api_step('P', 4);
            return r;
        }

        if (op_is(op, oplen, "zendo:write")) {
            api_step('S', 5);
            double addr = 0;
            unsigned int slen = 0;
            char* src = lua_arg_str(l, 2, &slen);
            if (!lua_arg_num(l, 1, &addr) || !src || !slen) {
                api_step('E', 5);
                return lua_ret_num(l, 0);
            }
            bool ok = api_write(static_cast<unsigned long long>(addr), src, slen);
            api_step('E', 5);
            return lua_ret_num(l, ok ? 1.0 : 0.0);
        }

        // Image base. Every other address a script derives starts here, so the
        // RVAs from the disassembly become usable without hardcoding a mapping.
        if (op_is(op, oplen, "zendo:base")) {
            api_step('S', 14);
            int r = lua_ret_num(l, static_cast<double>(g_base));
            api_step('P', 14);
            return r;
        }

        // DataModel. Two hops off a static: the static holds a pointer to a
        // holder, the holder's +0x1F8 is the DataModel itself. Both offsets are
        // the ones the loader already proved against this build.
        if (op_is(op, oplen, "zendo:dm")) {
            api_step('S', 15);
            unsigned long long fake = 0, dm = 0;
            if (g_base) read_u64(g_base + k_fake_dm_static, &fake);
            if (fake && !read_u64(fake + k_fake_dm_to_dm, &dm)) dm = 0;
            if (dm && !readable(reinterpret_cast<const void*>(dm), 0x10)) dm = 0;
            int r = lua_ret_num(l, static_cast<double>(dm));
            api_step(dm ? 'P' : 'E', 15);
            return r;
        }

        // Service by vtable: walk the DataModel's class-id map and return the
        // first instance whose [0] equals the vtable the script passed in.
        // The script supplies the target because the map is keyed by class id,
        // not by name, and a name lookup would need a per-class layout we have
        // not measured.
        if (op_is(op, oplen, "zendo:svc")) {
            api_step('S', 16);
            double vt = 0;
            unsigned long long dm = 0, fake = 0;
            if (lua_arg_num(l, 1, &vt) && g_base) {
                read_u64(g_base + k_fake_dm_static, &fake);
                read_u64(fake + k_fake_dm_to_dm, &dm);
            }
            unsigned long long hit = 0;
            if (dm && vt) hit = find_service(g_base, static_cast<unsigned long long>(vt), dm);
            int r = lua_ret_num(l, static_cast<double>(hit));
            api_step(hit ? 'P' : 'E', 16);
            return r;
        }

        // Map walk: pushes (instance, vtable) pairs in tree order. This is the
        // discovery half of `svc` - a script lists what the DataModel holds,
        // then matches the vtables it cares about.
        if (op_is(op, oplen, "zendo:svcs")) {
            api_step('S', 17);
            double want = 0;
            unsigned long long dm = 0, fake = 0;
            if (g_base) {
                read_u64(g_base + k_fake_dm_static, &fake);
                read_u64(fake + k_fake_dm_to_dm, &dm);
            }
            int cap = lua_arg_num(l, 1, &want) ? static_cast<int>(want) : 8;
            if (cap < 1) cap = 1;
            if (cap > 16) cap = 16;
            int pushed = 0;
            unsigned long long head = 0, root = 0;
            if (dm && read_u64(dm + 0xB0, &head) && head && read_u64(head + 8, &root) && root) {
                unsigned long long stack[64];
                int sp = 0, seen = 0;
                stack[sp++] = root;
                while (sp > 0 && pushed < cap * 2 && seen < 128) {
                    unsigned long long n = stack[--sp];
                    if (!n || n == head) continue;
                    unsigned long long val = 0, left = 0, right = 0;
                    read_u64(n + 0x28, &val);
                    read_u64(n, &left);
                    read_u64(n + 0x10, &right);
                    if (left && left != head && sp < 64) stack[sp++] = left;
                    if (right && right != head && sp < 64) stack[sp++] = right;
                    ++seen;
                    if (!val) continue;
                    unsigned long long vt = 0;
                    if (!read_u64(val, &vt) || !vt) continue;
                    pushed += lua_ret_num(l, static_cast<double>(val));
                    if (pushed >= cap * 2) break;
                    pushed += lua_ret_num(l, static_cast<double>(vt));
                }
            }
            api_step(pushed ? 'P' : 'E', 17);
            return pushed;
        }

        // End of a deferred script. The wrapper signals this after its pcall
        // returns, which is the only moment the executor can tell a scheduler
        // thread is done using the pipe. Writing END does not end the session
        // by itself: the host answers with 'q', and the read loop breaks there.
        if (op_is(op, oplen, "zendo:done")) {
            api_step('S', 18);
            HANDLE pipe = g_cap_pipe;
            if (pipe != INVALID_HANDLE_VALUE) {
                DWORD w = 0;
                api().WriteFile(pipe, "END\n", 4, &w, nullptr);
            }
            api_step('P', 18);
            return 0;
        }
    }

    if (g_cap_mode) return cap_print(L);
    if (g_cap_f) return reinterpret_cast<int (*)(void*)>(g_cap_f)(L);
    return 0;
}

// The bytecode door, kept behind its own switch because the client carries no
// Luau compiler: anything that is not already a container has to be rejected
// before it reaches the undump, or the undump reads lengths out of prose.
inline int native_loadbytecode(void* L) {
    unsigned long long l = reinterpret_cast<unsigned long long>(L);
    stage_mark(api(), "ENTER-BC");
    unsigned long long base = 0;
    read_u64(l + 0x58, &base);
    unsigned long long v = 0, w = 0;
    if (!base || !read_u64(base, &v) || !read_u64(base + 8, &w)) return 0;
    unsigned int tt = static_cast<unsigned int>((w >> 32) & 0xff);
    if (tt != 6 || !v) return 0;
    unsigned int len = 0;
    read_u32(v + 0x14, &len);
    if (len < 8 || len > 1u << 20) return 0;
    unsigned long long magic = 0;
    read_u64(v + 0x18, &magic);
    if (magic != 0xE009325B4A107A52ull) {
        stage_mark(api(), "BC-REJECT");
        return 0;
    }
    if (!g_base) return 0;
    using Load_t = int (*)(void*, const char*, const char*, unsigned long long, int);
    Load_t load = reinterpret_cast<Load_t>(g_base + 0x426A570);
    int rc = load(L, "=zendo", reinterpret_cast<const char*>(v + 0x18), len, 0);
    stage_mark(api(), rc == 0 ? "BC-OK" : "BC-ERR");
    return 1;
}


// cap_print is the closure body the client calls for print, so it is also the
// one place every script call passes through. A `zendo:` first argument is
// handed to the native dispatcher; everything else is captured and printed.
inline int native_api(void* L);

inline int cap_print(void* L) {
    stage_mark(api(), "H1");
    ++g_cap_calls;
    // Every script call that reaches our page passes through here, so this is
    // also where `zendo:op` is recognised: the first argument names the op,
    // anything else is ordinary print traffic and falls through to capture.
    {
        unsigned long long b = 0, t = 0;
        read_u64(reinterpret_cast<unsigned long long>(L) + 0x58, &b);
        read_u64(reinterpret_cast<unsigned long long>(L) + 0x60, &t);
        if (t > b) {
            unsigned long long v = 0, w = 0;
            if (read_u64(b, &v) && read_u64(b + 8, &w) &&
                static_cast<unsigned int>((w >> 32) & 0xff) == 6 && v) {
                unsigned int len = 0;
                read_u32(v + 0x14, &len);
                if (len >= 6 && readable(reinterpret_cast<const void*>(v + 0x18), 6)) {
                    const char* s = reinterpret_cast<const char*>(v + 0x18);
                    if (s[0] == 'z' && s[1] == 'e' && s[2] == 'n' && s[3] == 'd' &&
                        s[4] == 'o' && s[5] == ':')
                        return native_api(L);
                }
            }
        }
    }
    if (g_cap_mode >= 2) {
        unsigned long long base = 0, top = 0;
        read_u64(reinterpret_cast<unsigned long long>(L) + 0x58, &base);
        read_u64(reinterpret_cast<unsigned long long>(L) + 0x60, &top);
        static char d[2048];
        unsigned int n = 0;
        unsigned long long count = top > base ? (top - base) / 16ull : 0;
        if (count > 24) count = 24;
        for (unsigned long long i = 0; i < count && n < 1900; ++i) {
            if (i) d[n++] = '\t';
            cap_value(d, n, base + 16ull * i);
        }
        if (g_cap_mode >= 3) cap_put(d, n);
    }
    if (g_cap_f) {
        stage_mark(api(), "H2");
        int rc = reinterpret_cast<int (*)(void*)>(g_cap_f)(L);
        stage_mark(api(), "H3");
        return rc;
    }
    stage_mark(api(), "H4");
    return 0;
}

struct CfgCallTargetInfo {
    unsigned long long Offset;
    unsigned long long Flags;
};
static int g_cfg_status = -99;

// A manual map is invisible to the loader, so the CFG bitmap has no valid bit
// for our pages. The first indirect call the client makes into the payload --
// the VM invoking the swapped print pointer -- is then a control flow guard
// violation, which terminates the process without a trace. Register the hook's
// page as a legal call target.
inline int cfg_register(void* target) {
    Api& a = api();
    if (!a.SetProcessValidCallTargets) return -1;
    unsigned long long t = reinterpret_cast<unsigned long long>(target);
    unsigned long long page = t & ~0xfffull;
    static CfgCallTargetInfo info[256];
    for (unsigned int i = 0; i < 256; ++i) {
        info[i].Offset = 16ull * i;
        info[i].Flags = 1;  // CFG_CALL_TARGET_VALID
    }
    HANDLE self = reinterpret_cast<HANDLE>(static_cast<long long>(-1));
    if (a.SetProcessValidCallTargets(self, reinterpret_cast<void*>(page), 0x1000, 256, info)) return 0;
    int err = static_cast<int>(a.GetLastError());
    // Some builds insist the address be the allocation base; retry that way.
    unsigned long long base = self_image_base();
    unsigned long long size = self_image_size(base);
    if (base && page >= base) {
        unsigned long long off = page - base;
        for (unsigned int i = 0; i < 256; ++i) info[i].Offset = off + 16ull * i;
        if (a.SetProcessValidCallTargets(self, reinterpret_cast<void*>(base),
                                         static_cast<SIZE_T>(size), 256, info))
            return 0;
        err = static_cast<int>(a.GetLastError());
    }
    return err;
}

inline void cap_install() {
    // A live dispatcher owns the closure slot for the whole session: swapping
    // print in for the duration of every call would hide the native surface.
    if (!g_api_live && g_cap_mode >= 1 && g_cap_closure && g_cap_f) {
        g_cfg_status = cfg_register(reinterpret_cast<void*>(&cap_print));
        wr64(g_cap_closure + 0x28, reinterpret_cast<unsigned long long>(&cap_print));
    }
}

inline void cap_restore() {
    if (g_api_live) return;
    if (g_cap_closure && g_cap_f) wr64(g_cap_closure + 0x28, g_cap_f);
}

static bool g_flush_next = false;

// The `P` protocol: one line per captured print, written straight to the dev
// pipe. The UI turns each into a `� ` line.
inline void emit_capture(unsigned long long slot) {
    unsigned long long v = 0, w = 0;
    if (!read_u64(slot, &v) || !read_u64(slot + 8, &w)) return;
    if (static_cast<unsigned int>((w >> 32) & 0xff) != 6 || !v) return;
    unsigned int len = 0;
    read_u32(v + 0x14, &len);
    if (len > 65536) len = 65536;
    static char line[4096];
    unsigned int k = 0;
    for (unsigned int i = 0; i < len; ++i) {
        char c = *reinterpret_cast<char*>(v + 0x18 + i);
        if (c == '\n') {
            if (k) cap_put(line, k);
            k = 0;
            continue;
        }
        if (c == '\r') continue;
        if (k + 1 >= sizeof(line)) {
            cap_put(line, k);
            k = 0;
        }
        line[k++] = c;
    }
    if (k) cap_put(line, k);
}

inline int exec_raw(Api& a, HANDLE pipe, Out& o, unsigned long long L,
                    unsigned long long base, const unsigned char* body,
                    unsigned int len, const char* tag) {
    static unsigned char rcontainer[8 + 262144];
    if (len + 8u > sizeof(rcontainer)) {
        o.str(tag);
        o.str(" too big\n");
        flush_out(a, pipe, o);
        return 0;
    }
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i)
        *reinterpret_cast<volatile unsigned char*>(rcontainer + i) =
            static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < len; ++i)
        *reinterpret_cast<volatile unsigned char*>(rcontainer + 8 + i) = body[i];

    ChunkName src;
    src.data = reinterpret_cast<const char*>(rcontainer);
    src.pad = 0;
    src.size = g_declared_size ? g_declared_size : (8ull + len);
    src.cap = 8ull + len;

    unsigned long long top0 = 0;
    read_u64(L + 0x60, &top0);

    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    static char chunkname[24];
    static unsigned int chunkseq = 0;
    ++chunkseq;
    {
        const char* pre = "=zendo";
        int n = 0;
        while (pre[n]) { chunkname[n] = pre[n]; ++n; }
        char digits[8];
        int d = 0;
        unsigned int v = chunkseq;
        do { digits[d++] = static_cast<char>('0' + v % 10u); v /= 10u; } while (v);
        while (d) chunkname[n++] = digits[--d];
        chunkname[n] = 0;
    }
    int ret = load(reinterpret_cast<void*>(L), &src, chunkname, 0);

    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str(tag);
    o.str(" load ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" top0=");
    o.hex(top0);
    o.str(" t1=");
    o.hex(t1);
    o.nl();
    flush_out(a, pipe, o);
    if (ret != 0 || t1 != top0 + 16) return 0;

    if (g_patch_proto) {
        unsigned long long clo = 0, proto = 0, enc = 0;
        read_u64(top0, &clo);
        read_u64(clo + 0x18, &proto);
        unsigned long long self = proto + 0x80;
        unsigned long long qw = reinterpret_cast<unsigned long long>(&g_full_mask);
        read_u64(self, &enc);
        wr64(self, self ^ qw);
        o.str(tag);
        o.str(" PROTO80 old=");
        o.hex(enc);
        o.str(" new=");
        o.hex(self ^ qw);
        o.nl();
        flush_out(a, pipe, o);
    }

    // Hand the native surface to the chunk as its single vararg. Same closure
    // the session installed the dispatcher on, so `local z = ...` is all a
    // script needs to reach it.
    {
        unsigned long long last = 0;
        read_u64(L + 0x68, &last);
        if (g_cap_closure && top0 + 32 <= last) {
            wr64(top0 + 16, g_cap_closure);
            wr64(top0 + 24, 0x8ull << 32);
            wr64(L + 0x60, top0 + 32);
        }
    }

    struct CallCtx {
        unsigned long long func;
        int nresults;
        int pad;
    } ctx;
    ctx.func = top0;
    ctx.nresults = -1;
    ctx.pad = 0;

    unsigned long long ci = 0, baseci = 0, cc = 0, hdr = 0, stk = 0;
    read_u64(L + 0x70, &ci);
    read_u64(L + 0x28, &baseci);
    read_u64(L + 0x38, &cc);
    read_u64(L + 0x48, &stk);
    read_u64(L, &hdr);
    const unsigned long long ci_off = ci - baseci;
    const unsigned long long func_off = top0 - stk;
    const unsigned short ncc_old = static_cast<unsigned short>(cc & 0xffffull);
    const unsigned short bcc_old =
        static_cast<unsigned short>((cc >> 16) & 0xffffull);
    const unsigned char oldactive = static_cast<unsigned char>((hdr >> 40) & 0xff);

    o.str(tag);
    o.str(" raw ci=");
    o.hex(ci);
    o.str(" off=");
    o.hex(ci_off);
    o.str(" ncc=");
    o.dec(ncc_old);
    o.str(" bcc=");
    o.dec(bcc_old);
    o.nl();
    flush_out(a, pipe, o);

    // lua_pcallyieldable hands luaD_callint `lua_isyieldable(L) != 0`. With
    // nCcalls <= baseCcalls that only *schedules* a reentry (status 0x7f) and
    // luau_execute never runs. A C call made from inside the VM always holds
    // nCcalls > baseCcalls, so restore that invariant and call.
    wr64(L + 0x38, (cc & ~0xffffull) | (unsigned long long)(bcc_old + 1));
    *reinterpret_cast<volatile unsigned char*>(L + 3) = 0;

    typedef int (*ProtFn)(void*, void*, void*);
    ProtFn prot = reinterpret_cast<ProtFn>(base + 0x26360B0);

    beacon(a, "PRE");
    if (pipe != INVALID_HANDLE_VALUE) g_cap_pipe = pipe;
    cap_install();
    int st = prot(reinterpret_cast<void*>(L),
                  reinterpret_cast<void*>(base + 0x2632230), &ctx);
    cap_restore();
    beacon(a, "POST");

    wr64(L + 0x38, cc);

    o.str(tag);
    o.str(" raw st=");
    o.dec(static_cast<unsigned int>(st));
    o.nl();
    flush_out(a, pipe, o);

    if (st != 0) {
        unsigned long long stk2 = 0, nbase = 0, curtop = 0;
        read_u64(L + 0x48, &stk2);
        unsigned long long oldtop = stk2 + func_off;
        read_u64(L + 0x60, &curtop);

        close_upvals(L, oldtop, base);

        typedef void (*SetErrFn)(void*, int, void*);
        SetErrFn seterr = reinterpret_cast<SetErrFn>(base + 0x2637250);
        seterr(reinterpret_cast<void*>(L), st, reinterpret_cast<void*>(oldtop));

        unsigned long long nci = baseci + ci_off;
        wr64(L + 0x70, nci);
        read_u64(nci, &nbase);
        wr64(L + 0x58, nbase);
        if (!oldactive) *reinterpret_cast<volatile unsigned char*>(L + 5) = 0;

        unsigned long long after = 0;
        read_u64(L + 0x60, &after);
        o.str(tag);
        o.str(" err top=");
        o.hex(curtop);
        o.str(" msg=");
        o.hex(oldtop);
        o.str(" -> ");
        o.hex(after);
        o.nl();
        dump_val(o, "err", oldtop);
        emit_capture(oldtop);
        wr64(L + 0x60, oldtop);
        flush_out(a, pipe, o);
        return 2;
    }

    unsigned long long stk2 = 0, t2 = 0;
    read_u64(L + 0x48, &stk2);
    read_u64(L + 0x60, &t2);
    top0 = stk2 + func_off;
    o.str(tag);
    o.str(" raw done top=");
    o.hex(t2);
    o.str(" n=");
    o.dec(static_cast<unsigned int>((t2 - top0) / 16));
    o.nl();

    unsigned long long n = (t2 - top0) / 16;
    if (n > 8) n = 8;
    for (unsigned long long k = 0; k < n; ++k) {
        if (!g_cap_closure) {
            unsigned long long cv = 0, cw = 0;
            read_u64(top0 + 16ull * k, &cv);
            read_u64(top0 + 16ull * k + 8, &cw);
            unsigned int ctt = static_cast<unsigned int>((cw >> 32) & 0xff);
            if (ctt == 8 && cv && readable(reinterpret_cast<const void*>(cv), 0x30) &&
                *reinterpret_cast<unsigned char*>(cv + 5)) {
                unsigned long long cf = 0;
                read_u64(cv + 0x28, &cf);
                if (cf) {
                    g_cap_closure = cv;
                    g_cap_f = cf;
                    o.str(tag);
                    o.str(" captured print clo=");
                    o.hex(cv);
                    o.str(" f=");
                    o.hex(cf);
                    o.nl();
                }
            }
        }
        char tag2[8] = {tag[0], tag[1], ' ', 'r', 0, 0, 0, 0};
        tag2[4] = static_cast<char>('0' + static_cast<int>(k));
        dump_val(o, tag2, top0 + 16ull * k);
    }
    if (g_flush_next && n > 0) emit_capture(top0);
    wr64(L + 0x60, top0);
    flush_out(a, pipe, o);
    return 1;
}

// A filesystem answer crosses the pipe as a compiled chunk, never as raw
// bytes: the payload still has no way to build a Luau string, but the VM builds
// one from a literal. This op sends the request, loads the reply, calls it, and
// leaves the result where the caller expects one.
int zendo_file_op(unsigned long long l, const char* op, unsigned int oplen) {
    HANDLE pipe = g_cap_pipe;
    Api& a = api();
    if (pipe == INVALID_HANDLE_VALUE || !g_base) return 0;
    unsigned int plen = 0;
    char* path = lua_arg_str(l, 1, &plen);
    if (!path || !plen || plen > 4096) return 0;

    char cmd = 'F';
    if (op_is(op, oplen, "zendo:isfile")) cmd = 'S';
    else if (op_is(op, oplen, "zendo:isfolder")) cmd = 'T';
    else if (op_is(op, oplen, "zendo:mkdir")) cmd = 'M';
    else if (op_is(op, oplen, "zendo:del")) cmd = 'D';
    else if (op_is(op, oplen, "zendo:listfiles")) cmd = 'L';
    else if (op_is(op, oplen, "zendo:filew")) cmd = 'G';

    unsigned int dlen = 0;
    char* data = nullptr;
    if (cmd == 'G') {
        data = lua_arg_str(l, 2, &dlen);
        if (!data) dlen = 0;
    }

    char head[48];
    unsigned int n = 0, q = 0;
    char digits[12];
    unsigned int v = 0;
    head[n++] = cmd;
    head[n++] = ' ';
    v = plen;
    do { digits[q++] = static_cast<char>('0' + (v % 10)); v /= 10; } while (v);
    while (q) head[n++] = digits[--q];
    if (cmd == 'G') {
        head[n++] = ' ';
        v = dlen;
        do { digits[q++] = static_cast<char>('0' + (v % 10)); v /= 10; } while (v);
        while (q) head[n++] = digits[--q];
    }
    head[n++] = '\n';

    DWORD w = 0;
    if (!a.WriteFile(pipe, head, n, &w, nullptr)) return 0;
    if (!a.WriteFile(pipe, path, plen, &w, nullptr)) return 0;
    if (cmd == 'G' && dlen && !a.WriteFile(pipe, data, dlen, &w, nullptr)) return 0;

    char line[64];
    if (!pipe_line(a, pipe, line, sizeof(line))) return 0;
    if (line[0] == 'A') return lua_ret_num(l, parse_dec(line + 2) ? 1.0 : 0.0);
    if (line[0] != 'K') return 0;
    unsigned int rlen = parse_dec(line + 2);
    if (!rlen || rlen > (1u << 20) - 8) return 0;
    unsigned long long buf = load_stage(rlen + 8);
    if (!buf) return 0;
    if (!read_all(a, pipe, reinterpret_cast<void*>(buf + 8), rlen)) return 0;

    unsigned long long top0 = 0;
    read_u64(l + 0x60, &top0);
    if (!lua_load_stage(l, buf, rlen)) return 0;

    struct CallCtx {
        unsigned long long func;
        int nresults;
        int pad;
    } ctx;
    ctx.func = top0;
    ctx.nresults = -1;
    ctx.pad = 0;

    unsigned long long ci = 0, bci = 0, cc = 0, hdr = 0, stk = 0;
    read_u64(l + 0x70, &ci);
    read_u64(l + 0x28, &bci);
    read_u64(l + 0x38, &cc);
    read_u64(l, &hdr);
    read_u64(l + 0x48, &stk);
    const unsigned long long ci_off = ci - bci;
    const unsigned long long func_off = top0 - stk;
    const unsigned short bcc = static_cast<unsigned short>((cc >> 16) & 0xffffull);
    const unsigned char oldactive = static_cast<unsigned char>((hdr >> 40) & 0xff);

    wr64(l + 0x38, (cc & ~0xffffull) | static_cast<unsigned long long>(bcc + 1));
    *reinterpret_cast<volatile unsigned char*>(l + 3) = 0;

    typedef int (*ProtFn)(void*, void*, void*);
    ProtFn prot = reinterpret_cast<ProtFn>(g_base + 0x26360B0);
    int st = prot(reinterpret_cast<void*>(l), reinterpret_cast<void*>(g_base + 0x2632230), &ctx);
    wr64(l + 0x38, cc);

    if (st != 0) {
        unsigned long long stk2 = 0, nbase = 0, curtop = 0;
        read_u64(l + 0x48, &stk2);
        unsigned long long oldtop = stk2 + func_off;
        read_u64(l + 0x60, &curtop);
        close_upvals(l, oldtop, g_base);
        typedef void (*SetErrFn)(void*, int, void*);
        SetErrFn seterr = reinterpret_cast<SetErrFn>(g_base + 0x2637250);
        seterr(reinterpret_cast<void*>(l), st, reinterpret_cast<void*>(oldtop));
        unsigned long long nci = bci + ci_off;
        wr64(l + 0x70, nci);
        read_u64(nci, &nbase);
        wr64(l + 0x58, nbase);
        if (!oldactive) *reinterpret_cast<volatile unsigned char*>(l + 5) = 0;
        wr64(l + 0x60, oldtop);
        return 0;
    }

    unsigned long long stk2 = 0, t2 = 0;
    read_u64(l + 0x48, &stk2);
    read_u64(l + 0x60, &t2);
    unsigned long long base_top = stk2 + func_off;
    unsigned long long got = (t2 - base_top) / 16;
    if (got > 4) got = 4;
    return static_cast<int>(got);
}

// Runs the flush chunk with the report pipe muted: the payload's chatter would
// otherwise flood the UI on every script. Only `P` lines survive.
inline void flush_capture(Api& a, Out& o, unsigned long long L, unsigned long long base) {
    if (g_cap_pipe == INVALID_HANDLE_VALUE) return;
    static Out quiet;
    quiet.reset();
    g_flush_next = true;
    exec_raw(a, INVALID_HANDLE_VALUE, quiet, L, base, kChunkFlush, kChunkFlushLen, "flush");
    g_flush_next = false;
}

inline DWORD run_pcall() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 pcall base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("M1 fake=");
    o.hex(fake);
    o.str(" dm=");
    o.hex(dm);
    o.str(" sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);

    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;

    unsigned long long extra = 0, xtra_next = 0, xtra_prev = 0, xtra_id = 0, xtra_caps = 0;
    read_u64(L + 8, &extra);
    if (extra) {
        read_u64(extra, &xtra_next);
        read_u64(extra + 0x10, &xtra_prev);
        read_u64(extra + 0x70, &xtra_id);
        read_u64(extra + 0xA0, &xtra_caps);
    }
    o.str("X extra=");
    o.hex(extra);
    o.str(" next=");
    o.hex(xtra_next);
    o.str(" prev=");
    o.hex(xtra_prev);
    o.str(" id=");
    o.dec(static_cast<unsigned int>(xtra_id));
    o.str(" caps=");
    o.hex(xtra_caps);
    o.nl();
    flush_out(a, pipe, o);

    // Identity goes on before the gate so every chunk below runs with the
    // privileges an executor normally has. Readback proves the write landed on
    // the same struct the VM reads, not on a stale copy.
    if (extra) {
        wr64(extra + 0x70, 8);
        wr64(extra + 0xA0, 0xFFFFFFFFFFFFFFFFull);
        unsigned long long chk_id = 0, chk_caps = 0;
        read_u64(extra + 0x70, &chk_id);
        read_u64(extra + 0xA0, &chk_caps);
        o.str("XI set id=");
        o.dec(static_cast<unsigned int>(chk_id));
        o.str(" caps=");
        o.hex(chk_caps);
        o.nl();
        flush_out(a, pipe, o);
    } else {
        o.str("XI no extra space, identity untouched\n");
        flush_out(a, pipe, o);
    }

    g_veh_phase = "A";
    o.str("MA chunkA gate type(pcall), type(game)\n");
    flush_out(a, pipe, o);
    g_exec_fn = 0;
    exec_chunk(a, pipe, o, L, base, kChunkBody, kChunkLen, "A");

    unsigned long long fn = g_exec_fn;
    bool pcall_fn = fn && slot_is_str(fn, "function");
    bool game_ud = fn && slot_is_str(fn + 16, "userdata");
    o.str("GATE pcall=");
    o.dec(static_cast<unsigned int>(pcall_fn ? 1 : 0));
    o.str(" game=");
    o.dec(static_cast<unsigned int>(game_ud ? 1 : 0));
    o.nl();
    flush_out(a, pipe, o);

    if (!pcall_fn || !game_ud) {
        o.str("  gate closed, U probes skipped\n");
    } else {
        // U probes: everything below stays on the property path, which already
        // returns real Instance userdata. U1/U5 ask whether a service object
        // can hand back a method and be called with it; U2 reads two scalar
        // properties off the same instance; U3/U4 check that services reachable
        // only by property are alive and not nil.
        g_veh_phase = "S5";
        o.str("MS5 property game.Players; type(p)\n");
        flush_out(a, pipe, o);
        exec_chunk(a, pipe, o, L, base, kChunkS5Body, kChunkS5Len, "S5");

        g_veh_phase = "U1";
        o.str("MU1 pcall(p.GetPlayers, p)\n");
        flush_out(a, pipe, o);
        exec_chunk(a, pipe, o, L, base, kChunkU1Body, kChunkU1Len, "U1");

        g_veh_phase = "U2";
        o.str("MU2 p.ClassName, p.Name\n");
        flush_out(a, pipe, o);
        exec_chunk(a, pipe, o, L, base, kChunkU2Body, kChunkU2Len, "U2");

        g_veh_phase = "U3";
        o.str("MU3 type(game.RunService)\n");
        flush_out(a, pipe, o);
        exec_chunk(a, pipe, o, L, base, kChunkU3Body, kChunkU3Len, "U3");

        g_veh_phase = "U4";
        o.str("MU4 type(game.TweenService)\n");
        flush_out(a, pipe, o);
        exec_chunk(a, pipe, o, L, base, kChunkU4Body, kChunkU4Len, "U4");

        g_veh_phase = "U5";
        o.str("MU5 pcall -> ok, type(players)\n");
        flush_out(a, pipe, o);
        exec_chunk(a, pipe, o, L, base, kChunkU5Body, kChunkU5Len, "U5");
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline DWORD run_caps() {
    DWORD st = resolve_api();
    if (st) return 70 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 caps base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;

    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0, val0 = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);
    if (obj) read_u64(obj + 0x30, &val0);
    o.str("T obj=");
    o.hex(obj);
    o.str(" cur=");
    o.hex(val0);
    o.nl();
    flush_out(a, pipe, o);

    if (!obj) {
        o.str("  no tls object\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    // Mask 1: only the Players bit. Mask 2: everything. The pending getter at
    // +0x38 is cleared so a lazy refresh cannot put the old value back.
    unsigned long long masks[2] = {0x400000000ull, 0xFFFFFFFFFFFFFFFFull};
    for (int m = 0; m < 2; ++m) {
        wr64(obj + 0x38, 0);
        wr64(obj + 0x30, masks[m]);
        unsigned long long chk = 0;
        read_u64(obj + 0x30, &chk);
        o.str("W mask=");
        o.hex(masks[m]);
        o.str(" got=");
        o.hex(chk);
        o.nl();
        flush_out(a, pipe, o);

        g_veh_phase = "U1";
        o.str("MU1 pcall(p.GetPlayers, p)\n");
        flush_out(a, pipe, o);
        g_exec_fn = 0;
        exec_chunk(a, pipe, o, L, base, kChunkU1Body, kChunkU1Len, "U1");
        if (g_exec_fn) {
            for (int k = 0; k < 3; ++k) {
                char tag[8] = {'U', '1', ' ', 'r', static_cast<char>('0' + k), 0, 0, 0};
                dump_val(o, tag, g_exec_fn + 16ull * k);
            }
            flush_out(a, pipe, o);
        }
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline DWORD run_tls() {
    DWORD st = resolve_api();
    if (st) return 60 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 tls base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    // sub_1270 resolves the module TLS block the same way the client does:
    //   index = *(u32*)(base + 0x8616010);  block = gs:[0x58][index];
    //   object = *(u64*)(block + 0x20)
    // The capability mask the checks read is at object + 0x30.
    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);

    o.str("T idx=");
    o.hex(tls_index);
    o.str(" array=");
    o.hex(tls_array);
    o.str(" block=");
    o.hex(block);
    o.str(" obj=");
    o.hex(obj);
    o.nl();
    flush_out(a, pipe, o);

    if (obj && readable(reinterpret_cast<const void*>(obj), 0x80)) {
        for (int i = 0; i < 16; i += 2) {
            unsigned long long v0 = 0, v1 = 0;
            read_u64(obj + 8ull * i, &v0);
            read_u64(obj + 8ull * (i + 1), &v1);
            o.str("O +");
            o.hex(8ull * i);
            o.str(" ");
            o.hex(v0);
            o.str(" ");
            o.hex(v1);
            o.nl();
        }
        flush_out(a, pipe, o);
    } else {
        o.str("O unreadable\n");
        flush_out(a, pipe, o);
    }

    if (block && readable(reinterpret_cast<const void*>(block), 0x40)) {
        unsigned long long b0 = 0, b1 = 0, b2 = 0, b3 = 0;
        read_u64(block, &b0);
        read_u64(block + 8, &b1);
        read_u64(block + 0x10, &b2);
        read_u64(block + 0x18, &b3);
        o.str("B ");
        o.hex(b0);
        o.str(" ");
        o.hex(b1);
        o.str(" ");
        o.hex(b2);
        o.str(" ");
        o.hex(b3);
        o.nl();
        flush_out(a, pipe, o);
    }

    unsigned long long dm = 0;
    read_u64(base + k_fake_dm_static, &dm);
    unsigned long long fake2 = dm, dm2 = 0;
    read_u64(fake2 + k_fake_dm_to_dm, &dm2);

    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm2);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    unsigned long long extra2 = 0;
    if (L) read_u64(L + 8, &extra2);
    o.str("E L=");
    o.hex(L);
    o.str(" extra=");
    o.hex(extra2);
    o.nl();
    flush_out(a, pipe, o);

    if (extra2 && readable(reinterpret_cast<const void*>(extra2), 0xC0)) {
        for (int i = 0; i < 24; i += 2) {
            unsigned long long v0 = 0, v1 = 0;
            read_u64(extra2 + 8ull * i, &v0);
            read_u64(extra2 + 8ull * (i + 1), &v1);
            o.str("E +");
            o.hex(8ull * i);
            o.str(" ");
            o.hex(v0);
            o.str(" ");
            o.hex(v1);
            o.nl();
        }
        flush_out(a, pipe, o);

        // shared_ptr<Shared> at +0x18, container pointer at +0x8: one of these
        // is the environment both identity and capabilities are read from.
        unsigned long long shared = 0, container = 0;
        read_u64(extra2 + 0x18, &shared);
        read_u64(extra2 + 0x08, &container);
        o.str("S shared=");
        o.hex(shared);
        o.str(" container=");
        o.hex(container);
        o.nl();
        flush_out(a, pipe, o);

        if (shared && readable(reinterpret_cast<const void*>(shared), 0x80)) {
            for (int i = 0; i < 16; i += 2) {
                unsigned long long v0 = 0, v1 = 0;
                read_u64(shared + 8ull * i, &v0);
                read_u64(shared + 8ull * (i + 1), &v1);
                o.str("S +");
                o.hex(8ull * i);
                o.str(" ");
                o.hex(v0);
                o.str(" ");
                o.hex(v1);
                o.nl();
            }
            flush_out(a, pipe, o);
        }
    } else {
        o.str("E unreadable\n");
        flush_out(a, pipe, o);
    }

    typedef unsigned long long (*CapsFn)(const unsigned int*);
    CapsFn caps_of = reinterpret_cast<CapsFn>(base + 0x1CEA140);
    unsigned int id8 = 8, id0 = 0, id2 = 2;
    o.str("C caps(8)=");
    o.hex(caps_of(&id8));
    o.str(" caps(0)=");
    o.hex(caps_of(&id0));
    o.str(" caps(2)=");
    o.hex(caps_of(&id2));
    o.nl();
    flush_out(a, pipe, o);

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline void copy_tv(unsigned long long dst, unsigned long long src) {
    unsigned long long lo = 0, hi = 0;
    read_u64(src, &lo);
    read_u64(src + 8, &hi);
    wr64(dst, lo);
    wr64(dst + 8, hi);
}

// Stage 41: run arbitrary bytecode under the client's own pcall without
// closures. Two chunks go on the stack: the user chunk first, then a fixed
// wrapper `return pcall("P")`. The wrapper's first constant is overwritten
// with the user closure's TValue, so LOADK hands pcall the user chunk instead
// of the placeholder string. Every error inside the user chunk unwinds into
// pcall's own catch, never into our manual-mapped frame.
inline DWORD run_protected() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 prot base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("M1 sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);

    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;
    g_veh_phase = "prot";

    const unsigned long long magic = 0xE009325B4A107A52ull;
    static unsigned char userbuf[8 + kChunkKLen];
    static unsigned char wrapbuf[8 + kChunkJLen];
    for (int i = 0; i < 8; ++i) {
        userbuf[i] = static_cast<unsigned char>(magic >> (8 * i));
        wrapbuf[i] = static_cast<unsigned char>(magic >> (8 * i));
    }
    for (unsigned int i = 0; i < kChunkKLen; ++i) userbuf[8 + i] = kChunkKBody[i];
    for (unsigned int i = 0; i < kChunkJLen; ++i) wrapbuf[8 + i] = kChunkJBody[i];

    unsigned long long t0 = 0, base_ci = 0;
    read_u64(L + 0x60, &t0);
    read_u64(L + 0x28, &base_ci);

    ChunkName us;
    us.data = reinterpret_cast<const char*>(userbuf);
    us.pad = 0;
    us.size = 8ull + kChunkKLen;
    us.cap = 8ull + kChunkKLen;

    ChunkName ws;
    ws.data = reinterpret_cast<const char*>(wrapbuf);
    ws.pad = 0;
    ws.size = 8ull + kChunkJLen;
    ws.cap = 8ull + kChunkJLen;

    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);

    int r1 = load(reinterpret_cast<void*>(L), &us, "=zendo", 0);
    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    int r2 = load(reinterpret_cast<void*>(L), &ws, "=zendo", 0);
    unsigned long long t2 = 0;
    read_u64(L + 0x60, &t2);

    o.str("M2 user ret=");
    o.dec(static_cast<unsigned int>(r1));
    o.str(" t1-t0=");
    o.hex(t1 - t0);
    o.str(" wrap ret=");
    o.dec(static_cast<unsigned int>(r2));
    o.str(" t2-t0=");
    o.hex(t2 - t0);
    o.str(" t0=");
    o.hex(t0);
    o.nl();
    flush_out(a, pipe, o);

    if (r1 != 0 || r2 != 0 || t2 != t0 + 32) {
        o.str("  load failed\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    unsigned long long uclo = 0, wclo = 0, wproto = 0, wcode = 0, wk = 0;
    read_u64(t0, &uclo);
    read_u64(t0 + 16, &wclo);
    read_u64(wclo + 0x18, &wproto);
    read_u64(wproto + 0x68, &wcode);
    read_u64(wproto + 0x60, &wk);
    unsigned int ss = 0;
    read_u32(wclo + 6, &ss);
    ss &= 0xff;

    unsigned long long uvt = 0, wvt = 0, ulo = 0, uhi = 0;
    read_u64(uclo, &uvt);
    read_u64(wclo, &wvt);
    read_u64(t0, &ulo);
    read_u64(t0 + 8, &uhi);
    o.str("M3 uclo=");
    o.hex(uclo);
    o.str(" wclo=");
    o.hex(wclo);
    o.str(" wproto=");
    o.hex(wproto);
    o.str(" wcode=");
    o.hex(wcode);
    o.str(" wk=");
    o.hex(wk);
    o.str(" ss=");
    o.dec(ss);
    o.nl();
    o.str("M4 k0 before: ");
    dump_val(o, "slot", wk);
    flush_out(a, pipe, o);

    copy_tv(wk, t0);
    o.str("M5 k0 after: ");
    dump_val(o, "slot", wk);
    flush_out(a, pipe, o);

    unsigned long long ci = base_ci + 48;
    unsigned long long fbase = t0 + 32;
    unsigned int bci_flags = 0;
    read_u32(base_ci + 0x2c, &bci_flags);

    wr64(ci + 0x00, fbase);
    wr64(ci + 0x08, fbase + 16ull * ss);
    wr64(ci + 0x10, t0 + 16);
    wr64(ci + 0x18, wproto);
    wr64(ci + 0x20, wcode + 4);
    wr32(ci + 0x28, 0xFFFFFFFFu);
    wr32(ci + 0x2C, 1);
    wr64(L + 0x70, ci);
    wr64(L + 0x58, fbase);
    wr32(base_ci + 0x2c, bci_flags | 4u);

    unsigned char old_single = *reinterpret_cast<volatile unsigned char*>(L + 4);
    unsigned char old_active = *reinterpret_cast<volatile unsigned char*>(L + 5);
    *reinterpret_cast<volatile unsigned char*>(L + 4) = 0;
    *reinterpret_cast<volatile unsigned char*>(L + 5) = 1;

    unsigned int ncc = 0;
    read_u32(L + 0x38, &ncc);
    wr32(L + 0x38, (ncc & 0xffff0000u) | (((ncc & 0xffffu) + 1u) & 0xffffu));

    o.str("M6 EXEC ci=");
    o.hex(ci);
    o.str(" base=");
    o.hex(fbase);
    o.nl();
    flush_out(a, pipe, o);

    g_veh_pipe = pipe;
    g_veh_base = base;
    g_veh_phase = "protexec";

    typedef void (*ExecFn)(void*);
    ExecFn exec = reinterpret_cast<ExecFn>(base + 0x26862E0);
    exec(reinterpret_cast<void*>(L));

    wr32(L + 0x38, ncc);
    *reinterpret_cast<volatile unsigned char*>(L + 4) = old_single;
    *reinterpret_cast<volatile unsigned char*>(L + 5) = old_active;
    wr32(base_ci + 0x2c, bci_flags);

    unsigned long long t3 = 0, ci3 = 0, fn = 0;
    unsigned int st3 = 0;
    read_u64(L + 0x60, &t3);
    read_u64(L + 0x70, &ci3);
    read_u64(ci + 0x10, &fn);
    read_u32(L + 3, &st3);
    o.str("M7 done top=");
    o.hex(t3);
    o.str(" d=");
    o.hex(t3 - t0);
    o.str(" ci=");
    o.hex(ci3);
    o.str(" fn=");
    o.hex(fn);
    o.str(" st=");
    o.hex(st3 & 0xff);
    o.nl();
    flush_out(a, pipe, o);

    if (fn && readable(reinterpret_cast<const void*>(fn), 48)) {
        for (int k = 0; k < 3; ++k) {
            char tag[8] = {'P', ' ', 'r', static_cast<char>('0' + k), 0, 0, 0, 0};
            dump_val(o, tag, fn + 16ull * k);
        }
        flush_out(a, pipe, o);
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline DWORD run_seh(int guard, int mode) {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    o.str("ZPIPE ok\n");
    flush_out(a, pipe, o);
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);

    // Install the handler before the first read, so a fault in our own payload
    // is logged too, not only one inside the VM.
    o.str("ZSTART base=");
    o.hex(base);
    o.str(" guard=");
    o.dec(static_cast<unsigned int>(guard));
    o.nl();
    flush_out(a, pipe, o);

    if (guard) {
        unsigned long long pbase = self_image_base();
        unsigned long long psize = self_image_size(pbase);
        o.str("ZIMG p=");
        o.hex(pbase);
        o.str(" sz=");
        o.hex(psize);
        o.nl();
        flush_out(a, pipe, o);

        g_veh_pipe = pipe;
        g_veh_base = base;
        g_veh_payload = pbase;
        g_veh_payload_size = psize;
        g_veh_phase = "unwind";
        if (guard == 1) {
            o.str("ZVEHB try\n");
            flush_out(a, pipe, o);
            if (a.AddVectoredExceptionHandler) {
                unsigned long long vh = reinterpret_cast<unsigned long long>(
                    a.AddVectoredExceptionHandler(1, reinterpret_cast<void*>(&veh_log)));
                o.str("ZVEHA vh=");
                o.hex(vh);
                o.nl();
                flush_out(a, pipe, o);
            }
        }

        o.str("ZUTB try\n");
        flush_out(a, pipe, o);
        unsigned long long ntab = register_unwind_table();
        o.str("ZUTA n=");
        o.dec(static_cast<unsigned int>(ntab));
        o.nl();
        flush_out(a, pipe, o);
    }

    o.str("ZEND1 seh base=");
    o.hex(base);
    o.str(" ok=");
    o.dec(static_cast<unsigned int>(guard));
    o.nl();
    flush_out(a, pipe, o);

    if (mode == 3) {
        // Read-only dump of the opcode dispatch tables as they exist in the
        // running process. The file copies are the ones already decoded; if
        // these differ, Hyperion permutes them at init and the bytecode opcodes
        // only make sense against the live copy.
        static const unsigned long long ranges[4][2] = {
            {0x26933f4ull, 256ull},
            {0x2693278ull, 1024ull},
            {0x26860f8ull, 256ull},
            {0x2685f7cull, 1024ull},
        };
        static const char hx[] = "0123456789abcdef";
        for (int r = 0; r < 4; ++r) {
            unsigned long long addr = base + ranges[r][0];
            unsigned long long n = ranges[r][1];
            o.str("T");
            o.dec(static_cast<unsigned int>(r));
            o.str(" rva=");
            o.hex(ranges[r][0]);
            o.nl();
            flush_out(a, pipe, o);
            for (unsigned long long off = 0; off < n; off += 16) {
                o.str("  ");
                o.hex(off);
                o.str(" ");
                for (unsigned long long j = 0; j < 16 && off + j < n; ++j) {
                    unsigned int b = 0;
                    read_u32(addr + off + j, &b);
                    char t[3];
                    t[0] = hx[b & 0xf];
                    t[1] = hx[(b >> 4) & 0xf];
                    t[2] = 0;
                    o.str(t);
                }
                o.nl();
                flush_out(a, pipe, o);
            }
        }
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack3[8];
        DWORD rd3 = 0;
        a.ReadFile(pipe, ack3, sizeof(ack3), &rd3, nullptr);
        a.CloseHandle(pipe);
        return 121;
    }

    unsigned long long fake = 0, dm = 0;
    g_veh_phase = "dm";
    bool ok = read_u64(base + k_fake_dm_static, &fake);
    ok = read_u64(fake + k_fake_dm_to_dm, &dm) && ok;
    o.str("M1 fake=");
    o.hex(fake);
    o.str(" dm=");
    o.hex(dm);
    o.nl();
    flush_out(a, pipe, o);

    g_veh_phase = "svc";
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("M2 sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);

    if (!L) {
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    g_veh_L = L;

    unsigned long long top0 = 0, stack = 0, base_ci = 0, lbase = 0;
    read_u64(L + 0x60, &top0);
    read_u64(L + 0x48, &stack);
    read_u64(L + 0x28, &base_ci);
    read_u64(L + 0x58, &lbase);
    o.str("M3 top0=");
    o.hex(top0);
    o.str(" stack=");
    o.hex(stack);
    o.str(" base_ci=");
    o.hex(base_ci);
    o.str(" lbase=");
    o.hex(lbase);
    o.nl();
    flush_out(a, pipe, o);

    static unsigned char container[8 + kChunkLen];
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i) container[i] = static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < kChunkLen; ++i) container[8 + i] = kChunkBody[i];

    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = 8ull + kChunkLen;
    src.cap = 8ull + kChunkLen;
    o.str("M4 len=");
    o.dec(8u + kChunkLen);
    o.nl();
    flush_out(a, pipe, o);

    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    g_veh_phase = "load";
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str("M5 load ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    o.nl();
    flush_out(a, pipe, o);

    if (ret != 0 || t1 != top0 + 16) {
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    unsigned long long clo = 0, proto = 0, code = 0;
    read_u64(top0, &clo);
    read_u64(clo + 0x18, &proto);
    read_u64(proto + 0x68, &code);
    unsigned int ss = 0, sizecode = 0;
    read_u32(clo + 6, &ss);
    read_u32(proto + 0xA8, &sizecode);
    ss &= 0xff;
    o.str("M6 clo=");
    o.hex(clo);
    o.str(" proto=");
    o.hex(proto);
    o.str(" code=");
    o.hex(code);
    o.str(" ss=");
    o.dec(ss);
    o.str(" nins=");
    o.dec(sizecode);
    o.nl();
    flush_out(a, pipe, o);

    if (mode == 2) {
        // Read-only. Nothing here touches the VM, the frame, or the stack, so
        // this run cannot trip the fastfail path. It only answers one question:
        // are the bytes we handed the loader the same bytes now sitting in
        // proto->code, or did the loader rewrite the opcode stream?
        unsigned int dn = sizecode * 4u;
        if (dn > 256u) dn = 256u;
        for (unsigned int off = 0; off < dn; off += 4) {
            unsigned int w = 0;
            read_u32(code + off, &w);
            o.str("D1 ");
            o.dec(off);
            o.str(" w=");
            o.hex(w);
            o.nl();
            flush_out(a, pipe, o);
        }
        for (unsigned int off = 0; off < kChunkLen; off += 8) {
            unsigned long long w = 0;
            for (unsigned int j = 0; j < 8 && off + j < kChunkLen; ++j)
                w |= static_cast<unsigned long long>(kChunkBody[off + j]) << (8 * j);
            o.str("D3 ");
            o.dec(off);
            o.str(" w=");
            o.hex(w);
            o.nl();
            flush_out(a, pipe, o);
        }
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack2[8];
        DWORD rd2 = 0;
        a.ReadFile(pipe, ack2, sizeof(ack2), &rd2, nullptr);
        a.CloseHandle(pipe);
        return 120;
    }

    if (mode == 4) {
        // Empirical map of whatever transform the loader applies to the opcode
        // byte. Instruction 0 lives at body offset 13; every other byte of the
        // chunk stays fixed, so each iteration feeds one candidate and reads
        // back what actually landed in proto->code[0]. Read-only: nothing here
        // executes bytecode.
        typedef int (*LoadFn2)(void*, void*, const char*, int);
        LoadFn2 lf2 = reinterpret_cast<LoadFn2>(base + k_lua_vm_load);
        static const char hx2[] = "0123456789abcdef";
        for (unsigned int b = 0; b < 256; ++b) {
            container[8 + 13] = static_cast<unsigned char>(b);
            wr64(L + 0x60, top0);
            int r2 = lf2(reinterpret_cast<void*>(L), &src, "=zendo", 0);
            unsigned long long tp = 0, c2 = 0, pr2 = 0, cd2 = 0;
            unsigned int w = 0;
            read_u64(L + 0x60, &tp);
            if (r2 == 0 && tp == top0 + 16) {
                read_u64(top0, &c2);
                read_u64(c2 + 0x18, &pr2);
                read_u64(pr2 + 0x68, &cd2);
                read_u32(cd2, &w);
            }
            o.str("P ");
            char bb[3];
            bb[0] = hx2[b >> 4];
            bb[1] = hx2[b & 15];
            bb[2] = 0;
            o.str(bb);
            o.str(" r=");
            o.dec(static_cast<unsigned int>(r2));
            o.str(" w=");
            o.hex(w);
            o.nl();
            flush_out(a, pipe, o);
        }
        wr64(L + 0x60, top0);
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack4[8];
        DWORD rd4 = 0;
        a.ReadFile(pipe, ack4, sizeof(ack4), &rd4, nullptr);
        a.CloseHandle(pipe);
        return 122;
    }

    if (mode == 5) {
        // Read-only walk of the globals table looking for Lua closures. A real
        // proto carries the client's own opcode numbering, so the final
        // instruction of each chunk names RETURN without any guessing.
        unsigned long long gt = 0;
        read_u64(L + 0x10, &gt);
        unsigned int lsv = 0;
        read_u32(gt + 4, &lsv);
        unsigned int ls = (lsv >> 24) & 0xff;
        if (ls > 12) ls = 12;
        unsigned int count = 1u << ls;
        unsigned long long node = 0;
        read_u64(gt + 0x20, &node);
        o.str("G gt=");
        o.hex(gt);
        o.str(" ls=");
        o.dec(ls);
        o.str(" node=");
        o.hex(node);
        o.nl();
        flush_out(a, pipe, o);

        // The live call stack is the cheapest source of real protos: every
        // CallInfo points at the proto currently executing on that frame.
        unsigned long long ciw = 0, bci = 0;
        read_u64(L + 0x70, &ciw);
        read_u64(L + 0x28, &bci);
        for (int k = 0; k < 32 && ciw && ciw >= bci; ++k) {
            unsigned long long pp = 0;
            unsigned int nn = 0;
            read_u64(ciw + 0x18, &pp);
            if (pp) read_u32(pp + 0xa8, &nn);
            o.str("C k=");
            o.dec(static_cast<unsigned int>(k));
            o.str(" ci=");
            o.hex(ciw);
            o.str(" p=");
            o.hex(pp);
            o.str(" n=");
            o.dec(nn);
            o.nl();
            flush_out(a, pipe, o);
            if (pp && nn && nn < 4000) {
                unsigned long long cd2 = 0;
                read_u64(pp + 0x68, &cd2);
                for (unsigned int j = 0; j < nn; ++j) {
                    if (j >= 3 && j + 2 < nn) continue;
                    unsigned int w = 0;
                    read_u32(cd2 + static_cast<unsigned long long>(j) * 4ull, &w);
                    o.str("  w");
                    o.dec(j);
                    o.str("=");
                    o.hex(w);
                    o.nl();
                }
                flush_out(a, pipe, o);
            }
            if (ciw == bci) break;
            ciw -= 48;
        }

        int found = 0;
        for (unsigned int i = 0; i < count; ++i) {
            unsigned long long nb = node + static_cast<unsigned long long>(i) * 32ull;
            unsigned int tt = 0;
            read_u32(nb + 0x0c, &tt);
            if (tt < 4 || tt > 12) continue;
            unsigned long long v = 0;
            if (!read_u64(nb, &v) || !v) continue;
            unsigned long long pr = 0;
            if (!read_u64(v + 0x18, &pr) || !pr) continue;
            unsigned int isc = 0;
            read_u32(v + 4, &isc);
            if ((isc >> 8) & 0xff) continue;
            unsigned long long cd = 0;
            unsigned int nins = 0, npar = 0, mstack = 0;
            read_u64(pr + 0x68, &cd);
            read_u32(pr + 0xa8, &nins);
            if (!cd || nins == 0 || nins > 4000) continue;
            read_u32(pr + 4, &mstack);
            read_u32(pr + 7, &npar);
            o.str("G i=");
            o.dec(i);
            o.str(" tt=");
            o.dec(tt);
            o.str(" clo=");
            o.hex(v);
            o.str(" pr=");
            o.hex(pr);
            o.str(" n=");
            o.dec(nins);
            o.str(" np=");
            o.dec(npar & 0xff);
            o.str(" ms=");
            o.dec(mstack & 0xff);
            o.nl();
            flush_out(a, pipe, o);
            for (unsigned int j = 0; j < nins; ++j) {
                if (j >= 6 && j + 3 < nins) continue;
                unsigned int w = 0;
                read_u32(cd + static_cast<unsigned long long>(j) * 4ull, &w);
                o.str("  w");
                o.dec(j);
                o.str("=");
                o.hex(w);
                o.nl();
            }
            flush_out(a, pipe, o);
            ++found;
            if (found >= 6) break;
        }
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack5[8];
        DWORD rd5 = 0;
        a.ReadFile(pipe, ack5, sizeof(ack5), &rd5, nullptr);
        a.CloseHandle(pipe);
        return 123;
    }

    if (mode == 6) {
        // Walk the GC page list and fingerprint every object that looks like a
        // Proto: valid code pointer, sane instruction count, and both the first
        // and last opcode accepted by the live dispatch table. The dominant
        // last opcode across real protos is RETURN; the dominant first opcode
        // is the chunk prologue.
        static unsigned short lastcnt[256];
        static unsigned short firstcnt[256];
        for (int i = 0; i < 256; ++i) {
            lastcnt[i] = 0;
            firstcnt[i] = 0;
        }
        unsigned long long gsb = 0, page = 0;
        read_u64(L + 0x50, &gsb);
        read_u64(gsb + 0xa8, &page);
        unsigned int pages = 0, objs = 0, protos = 0;
        unsigned long long samp[4] = {0, 0, 0, 0};
        unsigned int sampn[4] = {0, 0, 0, 0};
        int nsamp = 0;
        while (page && pages < 96 && objs < 60000) {
            unsigned int psize = 0, bsize = 0;
            read_u32(page + 0x20, &psize);
            read_u32(page + 0x24, &bsize);
            if (bsize < 32 || bsize > 4096 || psize < 0x40 || psize > 0x200000) break;
            unsigned int nblocks = (psize - 0x40) / bsize;
            if (nblocks > 2048) nblocks = 2048;
            ++pages;
            for (unsigned int i = 0; i < nblocks; ++i) {
                ++objs;
                unsigned long long obj = page + 0x40 + static_cast<unsigned long long>(i) * bsize;
                unsigned long long code = 0;
                unsigned int nins = 0;
                if (!read_u64(obj + 0x68, &code) || !code) continue;
                if (!read_u32(obj + 0xa8, &nins) || nins == 0 || nins > 3000) continue;
                unsigned int w0 = 0, wl = 0;
                if (!read_u32(code, &w0)) continue;
                if (!read_u32(code + static_cast<unsigned long long>(nins - 1) * 4ull, &wl)) continue;
                unsigned int op0 = w0 & 0xff, opl = wl & 0xff;
                if (op0 == 0 || opl == 0) continue;
                unsigned int g0 = 0, gl = 0;
                read_u32(base + 0x26933f4 + op0 - 1, &g0);
                read_u32(base + 0x26933f4 + opl - 1, &gl);
                if ((g0 & 0xff) == 0x5e || (gl & 0xff) == 0x5e) continue;
                ++lastcnt[opl];
                ++firstcnt[op0];
                ++protos;
                if (nsamp < 4) {
                    samp[nsamp] = code;
                    sampn[nsamp] = nins;
                    ++nsamp;
                }
            }
            unsigned long long nxt = 0;
            if (!read_u64(page + 0x8, &nxt) || nxt == page) break;
            page = nxt;
        }
        o.str("H pages=");
        o.dec(pages);
        o.str(" objs=");
        o.dec(objs);
        o.str(" protos=");
        o.dec(protos);
        o.nl();
        flush_out(a, pipe, o);
        for (int i = 1; i < 256; ++i) {
            if (!lastcnt[i] && !firstcnt[i]) continue;
            o.str("H op=");
            o.hex(static_cast<unsigned long long>(i));
            o.str(" first=");
            o.dec(firstcnt[i]);
            o.str(" last=");
            o.dec(lastcnt[i]);
            o.nl();
            flush_out(a, pipe, o);
        }
        for (int s = 0; s < nsamp; ++s) {
            o.str("H samp n=");
            o.dec(sampn[s]);
            o.nl();
            for (unsigned int j = 0; j < sampn[s]; ++j) {
                unsigned int w = 0;
                read_u32(samp[s] + static_cast<unsigned long long>(j) * 4ull, &w);
                o.str("   ");
                o.hex(w);
                o.nl();
            }
            flush_out(a, pipe, o);
        }
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack6[8];
        DWORD rd6 = 0;
        a.ReadFile(pipe, ack6, sizeof(ack6), &rd6, nullptr);
        a.CloseHandle(pipe);
        return 124;
    }

    if (mode == 7) {
        // Learn the object type byte straight from a proto we know (the one the
        // loader just produced), then walk the GC pages filtering on that tag.
        unsigned long long own_proto = proto;
        unsigned int ptt = 0;
        read_u32(own_proto, &ptt);
        ptt = (ptt >> 8) & 0xff;
        unsigned int ctt = 0;
        read_u32(top0 + 0x0c, &ctt);
        o.str("K ptt=");
        o.dec(ptt);
        o.str(" ctt=");
        o.hex(ctt);
        o.nl();
        flush_out(a, pipe, o);

        unsigned long long gsb2 = 0, pg = 0;
        read_u64(L + 0x50, &gsb2);
        read_u64(gsb2 + 0xa8, &pg);
        int pages = 0;
        while (pg && pages < 64) {
            unsigned int psz = 0, bsz = 0;
            read_u32(pg + 0x20, &psz);
            read_u32(pg + 0x24, &bsz);
            o.str("K page=");
            o.hex(pg);
            o.str(" psz=");
            o.dec(psz);
            o.str(" bsz=");
            o.dec(bsz);
            o.nl();
            flush_out(a, pipe, o);
            if (bsz >= 32 && bsz <= 8192 && psz > 0x40 && psz < 0x400000) {
                unsigned int nb = (psz - 0x40) / bsz;
                if (nb > 512) nb = 512;
                unsigned int hit = 0;
                for (unsigned int i = 0; i < nb; ++i) {
                    unsigned long long obj = pg + 0x40 + static_cast<unsigned long long>(i) * bsz;
                    unsigned int hdr = 0;
                    read_u32(obj, &hdr);
                    if (((hdr >> 8) & 0xff) != ptt) continue;
                    ++hit;
                    if (hit <= 2) {
                        unsigned long long cd3 = 0;
                        unsigned int nx = 0;
                        read_u64(obj + 0x68, &cd3);
                        read_u32(obj + 0xa8, &nx);
                        unsigned int w0 = 0, wl = 0;
                        read_u32(cd3, &w0);
                        if (nx) read_u32(cd3 + static_cast<unsigned long long>(nx - 1) * 4ull, &wl);
                        o.str("  obj=");
                        o.hex(obj);
                        o.str(" code=");
                        o.hex(cd3);
                        o.str(" n=");
                        o.dec(nx);
                        o.str(" w0=");
                        o.hex(w0);
                        o.str(" wl=");
                        o.hex(wl);
                        o.nl();
                        flush_out(a, pipe, o);
                    }
                }
                o.str("  hits=");
                o.dec(hit);
                o.nl();
                flush_out(a, pipe, o);
            }
            unsigned long long nxt = 0;
            if (!read_u64(pg + 0x8, &nxt) || nxt == pg) break;
            pg = nxt;
            ++pages;
        }
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack7[8];
        DWORD rd7 = 0;
        a.ReadFile(pipe, ack7, sizeof(ack7), &rd7, nullptr);
        a.CloseHandle(pipe);
        return 125;
    }

    unsigned int exec_mode = (mode >= 8 && mode <= 13) ? 1u : static_cast<unsigned int>(mode);
    unsigned int saved_bci_flags = 0;
    if (mode == 8) {
        // Static read of the build's own dispatch tables pinned the numbers:
        // LOADN = 0x2a (handler 0x2686b93), RETURN = 0x5a (handler 0x2689718).
        // Overwrite the first two words of the code buffer the loader handed
        // us so the VM runs our hand-assembled pair directly, bypassing the
        // bytecode permuter that mangled the compiler's numbering.
        unsigned int w0 = 0, w1 = 0;
        read_u32(code, &w0);
        read_u32(code + 4, &w1);
        o.str("Q0 w0=");
        o.hex(w0);
        o.str(" w1=");
        o.hex(w1);
        o.nl();
        flush_out(a, pipe, o);

        wr32(code, 0x2au | (15u << 16));      // LOADN R0, 15
        wr32(code + 4, 0x5au | (2u << 16));   // RETURN R0, 2

        unsigned int n0 = 0, n1 = 0;
        read_u32(code, &n0);
        read_u32(code + 4, &n1);
        read_u32(base_ci + 0x2c, &saved_bci_flags);
        o.str("Q1 w0=");
        o.hex(n0);
        o.str(" w1=");
        o.hex(n1);
        o.str(" bci_flags=");
        o.hex(saved_bci_flags);
        o.nl();
        flush_out(a, pipe, o);

        // CIST_FRESH on the caller frame is what sends RETURN down 0x2692aa6
        // (hook + epilogue) instead of resuming Roblox's own bytecode.
        wr32(base_ci + 0x2c, saved_bci_flags | 4u);
    }

    if (mode >= 9 && mode <= 13) {
        // Loader-path probe: the chunk body already carries this build's LBC
        // opcode numbering, so the permuter turns it into the internal enum
        // on its own. Print what landed in code[] and run it untouched.
        unsigned int c0 = 0, c1 = 0, c2 = 0;
        read_u32(code, &c0);
        read_u32(code + 4, &c1);
        read_u32(code + 8, &c2);
        read_u32(base_ci + 0x2c, &saved_bci_flags);
        o.str("Q0 c0=");
        o.hex(c0);
        o.str(" c1=");
        o.hex(c1);
        o.str(" c2=");
        o.hex(c2);
        o.str(" bci_flags=");
        o.hex(saved_bci_flags);
        o.nl();
        flush_out(a, pipe, o);
        wr32(base_ci + 0x2c, saved_bci_flags | 4u);
    }

    unsigned long long ci = base_ci + 48;
    unsigned long long fbase = top0 + 16;
    g_veh_phase = "frame";
    o.str("M7 push ci=");
    o.hex(ci);
    o.str(" fbase=");
    o.hex(fbase);
    o.str(" ctop=");
    o.hex(fbase + 16ull * ss);
    o.nl();
    flush_out(a, pipe, o);

    wr64(ci + 0x00, fbase);
    wr64(ci + 0x08, fbase + 16ull * ss);
    wr64(ci + 0x10, top0);
    wr64(ci + 0x18, proto);
    wr64(ci + 0x20, (mode >= 9 && mode <= 13) ? code + 4 : code);
    wr32(ci + 0x28, (mode >= 9 && mode <= 13) ? 0xFFFFFFFFu : 0u);
    wr32(ci + 0x2C, 1);
    wr64(L + 0x70, ci);
    wr64(L + 0x58, fbase);
    unsigned char old_single = *reinterpret_cast<volatile unsigned char*>(L + 4);
    unsigned char old_active = *reinterpret_cast<volatile unsigned char*>(L + 5);
    *reinterpret_cast<volatile unsigned char*>(L + 4) = (exec_mode == 1) ? 0 : 1;
    *reinterpret_cast<volatile unsigned char*>(L + 5) = 1;
    o.str("M8 stored\n");
    flush_out(a, pipe, o);

    typedef void (*StepFn)(void*, unsigned long long, unsigned long long, unsigned long long);
    StepFn step = reinterpret_cast<StepFn>(base + 0x26791E0);

    g_seh_code = 0;
    g_veh_phase = "exec";

    if (exec_mode == 1) {
        // The real call path: luaD_call picks 0x26862E0 whenever singlestep is
        // clear, so drive that interpreter directly and skip luaD_call's own
        // bookkeeping (0x2639B40 with zero depth is what killed stage 21).
        unsigned int ncc = 0;
        read_u32(L + 0x38, &ncc);
        unsigned int ncs = ((ncc & 0xffffu) + 1u) & 0xffffu;
        wr32(L + 0x38, (ncc & 0xffff0000u) | ncs);
        o.str("R0 call L=");
        o.hex(L);
        o.str(" nc=");
        o.dec(ncs);
        o.nl();
        flush_out(a, pipe, o);

        typedef void (*ExecFn)(void*);
        ExecFn exec = reinterpret_cast<ExecFn>(base + 0x26862E0);
        exec(reinterpret_cast<void*>(L));

        o.str("R1 ret\n");
        flush_out(a, pipe, o);
        wr32(L + 0x38, ncc);

        if (mode >= 8 && mode <= 13) {
            wr32(base_ci + 0x2c, saved_bci_flags);
            if (mode >= 11 && mode <= 13) {
                dump_mode11_results(a, pipe, o, base_ci);
            } else if (mode == 10) {
                for (int k = 0; k < 3; ++k) {
                    unsigned long long rvk = 0, rwk = 0;
                    read_u64(top0 + 16ull * k, &rvk);
                    read_u64(top0 + 16ull * k + 8, &rwk);
                    o.str("Q2 r");
                    o.dec(static_cast<unsigned int>(k));
                    o.str(" v=");
                    o.hex(rvk);
                    o.str(" w=");
                    o.hex(rwk);
                    o.str(" tt=");
                    o.dec(static_cast<unsigned int>((rwk >> 32) & 0xff));
                    o.nl();
                }
                flush_out(a, pipe, o);
            } else {
            unsigned long long rv0 = 0, rw0 = 0;
            read_u64(fbase, &rv0);
            read_u64(fbase + 8, &rw0);
            o.str("Q2 R0 v=");
            o.hex(rv0);
            o.str(" w=");
            o.hex(rw0);
            o.str(" tt=");
            o.dec(static_cast<unsigned int>((rw0 >> 32) & 0xff));
            o.nl();
            flush_out(a, pipe, o);
            }
        }
    } else
    for (int i = 0; i < 80; ++i) {
        unsigned long long cur_ci = 0, p = 0, pc = 0, c = 0;
        unsigned int status = 0, ins = 0;
        read_u64(L + 0x70, &cur_ci);
        read_u32(L + 3, &status);
        o.str("S ");
        o.dec(static_cast<unsigned int>(i));
        o.str(" ci=");
        o.hex(cur_ci);
        o.str(" st=");
        o.hex(status & 0xff);
        if (cur_ci && cur_ci <= base_ci + 48 * 8) {
            read_u64(cur_ci + 0x18, &p);
            read_u64(cur_ci + 0x20, &pc);
            if (p) read_u64(p + 0x68, &c);
            o.str(" pc=");
            o.hex(pc);
            if (c && pc >= c) {
                o.str(" #");
                o.dec(static_cast<unsigned int>((pc - c) >> 2));
            }
            if (pc) {
                read_u32(pc, &ins);
                o.str(" ins=");
                o.hex(ins);
                o.str(" op=");
                o.hex(ins & 0xff);
                o.str(" A=");
                o.dec((ins >> 8) & 0xff);
                o.str(" B=");
                o.dec((ins >> 16) & 0xff);
                o.str(" C=");
                o.dec((ins >> 24) & 0xff);
            }
        }
        o.nl();
        flush_out(a, pipe, o);

        if (!cur_ci || cur_ci <= base_ci) break;
        if ((status & 0xff) != 0) break;
        step(reinterpret_cast<void*>(L), 0, 0, 0);
    }

    *reinterpret_cast<volatile unsigned char*>(L + 4) = old_single;
    *reinterpret_cast<volatile unsigned char*>(L + 5) = old_active;

    unsigned long long fin_ci = 0, fin_top = 0;
    read_u64(L + 0x70, &fin_ci);
    read_u64(L + 0x60, &fin_top);
    unsigned int fin_st = 0;
    read_u32(L + 3, &fin_st);
    o.str("M9 done ci=");
    o.hex(fin_ci);
    o.str(" top=");
    o.hex(fin_top);
    o.str(" d=");
    o.hex(fin_top - top0);
    o.str(" st=");
    o.hex(fin_st & 0xff);
    o.nl();
    flush_out(a, pipe, o);

    if (fin_top > top0 && readable(reinterpret_cast<const void*>(top0), 16)) {
        unsigned long long rv = 0, rw = 0;
        read_u64(top0, &rv);
        read_u64(top0 + 8, &rw);
        o.str("  res v=");
        o.hex(rv);
        o.str(" w=");
        o.hex(rw);
        o.str(" tt=");
        o.dec(static_cast<unsigned int>((rw >> 32) & 0xff));
        o.nl();
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline DWORD run_step() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 step base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("  sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    if (!L) {
        o.str("  no state\n");
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    g_veh_pipe = pipe;
    g_veh_base = base;
    g_veh_L = L;
    if (a.AddVectoredExceptionHandler) {
        a.AddVectoredExceptionHandler(1, reinterpret_cast<void*>(&veh_log));
    }

    unsigned long long top0 = 0, stack = 0, base_ci = 0, lbase = 0;
    read_u64(L + 0x60, &top0);
    read_u64(L + 0x48, &stack);
    read_u64(L + 0x28, &base_ci);
    read_u64(L + 0x58, &lbase);
    unsigned int hdr4 = 0;
    read_u32(L + 4, &hdr4);

    static unsigned char container[8 + kChunkLen];
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i) container[i] = static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < kChunkLen; ++i) container[8 + i] = kChunkBody[i];

    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = 8ull + kChunkLen;
    src.cap = 8ull + kChunkLen;

    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str("  load ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    o.str(" top0=");
    o.hex(top0);
    o.str(" stack=");
    o.hex(stack);
    o.str(" base_ci=");
    o.hex(base_ci);
    o.str(" lbase=");
    o.hex(lbase);
    o.str(" single=");
    o.hex(hdr4 & 0xff);
    o.nl();
    flush_out(a, pipe, o);

    if (ret != 0 || t1 != top0 + 16) {
        o.str("  load failed, no step\n");
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    unsigned long long clo = 0, proto = 0, code = 0;
    read_u64(top0, &clo);
    read_u64(clo + 0x18, &proto);
    read_u64(proto + 0x68, &code);
    unsigned int ss = 0, sizecode = 0;
    read_u32(clo + 6, &ss);
    read_u32(proto + 0xA8, &sizecode);
    ss &= 0xff;
    o.str("  clo=");
    o.hex(clo);
    o.str(" proto=");
    o.hex(proto);
    o.str(" code=");
    o.hex(code);
    o.str(" stacksize=");
    o.dec(ss);
    o.str(" sizecode=");
    o.dec(sizecode);
    o.nl();

    unsigned long long ci = base_ci + 48;
    unsigned long long fbase = top0 + 16;
    o.str("  push ci=");
    o.hex(ci);
    o.str(" func=");
    o.hex(top0);
    o.str(" base=");
    o.hex(fbase);
    o.str(" top=");
    o.hex(top0 + 16ull * ss);
    o.nl();
    flush_out(a, pipe, o);

    wr64(ci + 0x00, fbase);
    wr64(ci + 0x08, top0 + 16ull * ss);
    wr64(ci + 0x10, top0);
    wr64(ci + 0x18, proto);
    wr64(ci + 0x20, code);
    wr32(ci + 0x28, 0);
    wr32(ci + 0x2C, 1);
    wr64(L + 0x70, ci);
    wr64(L + 0x58, fbase);
    unsigned char old_single = *reinterpret_cast<volatile unsigned char*>(L + 4);
    unsigned char old_active = *reinterpret_cast<volatile unsigned char*>(L + 5);
    *reinterpret_cast<volatile unsigned char*>(L + 4) = 1;
    *reinterpret_cast<volatile unsigned char*>(L + 5) = 1;

    typedef void (*StepFn)(void*, unsigned long long, unsigned long long, unsigned long long);
    StepFn step = reinterpret_cast<StepFn>(base + 0x26791E0);

    for (int i = 0; i < 80; ++i) {
        unsigned long long cur_ci = 0, p = 0, pc = 0, c = 0;
        unsigned int status = 0, ins = 0;
        read_u64(L + 0x70, &cur_ci);
        read_u32(L + 3, &status);
        o.str("  step ");
        o.dec(static_cast<unsigned int>(i));
        o.str(" ci=");
        o.hex(cur_ci);
        o.str(" st=");
        o.hex(status & 0xff);
        if (cur_ci && cur_ci <= base_ci + 48 * 8) {
            read_u64(cur_ci + 0x18, &p);
            read_u64(cur_ci + 0x20, &pc);
            if (p) read_u64(p + 0x68, &c);
            o.str(" p=");
            o.hex(p);
            o.str(" pc=");
            o.hex(pc);
            if (c && pc >= c) {
                o.str(" #");
                o.dec(static_cast<unsigned int>((pc - c) >> 2));
            }
            if (pc) {
                read_u32(pc, &ins);
                o.str(" ins=");
                o.hex(ins);
                o.str(" op=");
                o.hex(ins & 0xff);
                o.str(" A=");
                o.dec((ins >> 8) & 0xff);
                o.str(" B=");
                o.dec((ins >> 16) & 0xff);
                o.str(" C=");
                o.dec((ins >> 24) & 0xff);
            }
        }
        o.nl();
        flush_out(a, pipe, o);

        if (!cur_ci || cur_ci <= base_ci) {
            o.str("  frame balanced, stop\n");
            break;
        }
        if ((status & 0xff) != 0) {
            o.str("  status nonzero, stop\n");
            break;
        }
        step(reinterpret_cast<void*>(L), 0, 0, 0);
    }

    unsigned long long fin_ci = 0, fin_top = 0;
    read_u64(L + 0x70, &fin_ci);
    read_u64(L + 0x60, &fin_top);
    unsigned int fin_st = 0;
    read_u32(L + 3, &fin_st);
    o.str("  done ci=");
    o.hex(fin_ci);
    o.str(" top=");
    o.hex(fin_top);
    o.str(" d=");
    o.hex(fin_top - top0);
    o.str(" st=");
    o.hex(fin_st & 0xff);
    o.nl();
    flush_out(a, pipe, o);

    *reinterpret_cast<volatile unsigned char*>(L + 4) = old_single;
    *reinterpret_cast<volatile unsigned char*>(L + 5) = old_active;
    if (fin_top > top0 && readable(reinterpret_cast<const void*>(top0), 16)) {
        unsigned long long rv = 0, rw = 0;
        read_u64(top0, &rv);
        read_u64(top0 + 8, &rw);
        o.str("  res v=");
        o.hex(rv);
        o.str(" w=");
        o.hex(rw);
        o.str(" tt=");
        o.dec(static_cast<unsigned int>((rw >> 32) & 0xff));
        o.nl();
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 19: load a chunk, then run the pushed closure.
// Call convention taken from the interpreter's own OP_CALL handler (0x268344B):
//   rcx = L, rdx = func slot, r8b = nresults (0 = MULTRET), r9 = 0
// 0x26361C0 enters the frame (returns 0 for Lua closures, nonzero for C).
// 0x2639B40 is the execute loop; it runs while ci > base_ci and returns
// immediately when the frame stack is already balanced.
inline DWORD run_exec() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 exec base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("  sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    if (!L) {
        o.str("  no state\n");
    } else {
        static unsigned char container[8 + kChunkLen];
        const unsigned long long magic = 0xE009325B4A107A52ull;
        for (int i = 0; i < 8; ++i) container[i] = static_cast<unsigned char>(magic >> (8 * i));
        for (unsigned int i = 0; i < kChunkLen; ++i) container[8 + i] = kChunkBody[i];

        ChunkName src;
        src.data = reinterpret_cast<const char*>(container);
        src.pad = 0;
        src.size = 8ull + kChunkLen;
        src.cap = 8ull + kChunkLen;

        unsigned long long top0 = 0;
        read_u64(L + 0x60, &top0);

        typedef int (*LoadFn)(void*, void*, const char*, int);
        LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
        int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
        unsigned long long t1 = 0;
        read_u64(L + 0x60, &t1);
        o.str("  load ret=");
        o.dec(static_cast<unsigned int>(ret));
        o.str(" d=");
        o.hex(t1 - top0);
        o.nl();

        unsigned int stat = 0, mode = 0, single = 0;
        read_u32(L + 3, &stat);
        read_u32(L + 4, &mode);
        read_u32(base + 0x81E60C0, &single);
        o.str("  st=");
        o.hex(stat & 0xff);
        o.str(" L4=");
        o.hex(mode & 0xff);
        o.str(" ss=");
        o.hex(single & 0xff);
        o.nl();

        if (ret == 0 && t1 == top0 + 16 && (stat & 0xff) == 0) {
            dump_tv(o, top0, "  fn:");

            unsigned long long ci0 = 0;
            read_u64(L + 0x70, &ci0);

            typedef int (*CallFn)(void*, void*, int, void*);
            CallFn call = reinterpret_cast<CallFn>(base + 0x26361C0);
            int rc = call(reinterpret_cast<void*>(L), reinterpret_cast<void*>(top0), 0, nullptr);

            unsigned long long t2 = 0, ci1 = 0;
            read_u64(L + 0x60, &t2);
            read_u64(L + 0x70, &ci1);
            o.str("  call rc=");
            o.dec(static_cast<unsigned int>(rc));
            o.str(" d=");
            o.hex(t2 - top0);
            o.str(" ci=");
            o.hex(ci1);
            o.nl();

            if (rc == 0 && ci1 != ci0) {
                typedef unsigned long long (*LoopFn)(void*, unsigned long long);
                LoopFn loop = reinterpret_cast<LoopFn>(base + 0x2639B40);
                unsigned long long lr = loop(reinterpret_cast<void*>(L), 0);
                unsigned long long t3 = 0, ci2 = 0;
                read_u64(L + 0x60, &t3);
                read_u64(L + 0x70, &ci2);
                o.str("  loop lr=");
                o.hex(lr);
                o.str(" d=");
                o.hex(t3 - top0);
                o.str(" ci=");
                o.hex(ci2);
                o.nl();
            }

            unsigned long long t4 = 0;
            read_u64(L + 0x60, &t4);
            if (t4 > top0) dump_tv(o, top0, "  res:");
            read_u32(L + 3, &stat);
            o.str("  st2=");
            o.hex(stat & 0xff);
            o.nl();
        }
    }
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// sub_4321B00 builds a task from the lua_State, walks thread->ScriptContext,
// then calls LuaVMLoad with the correctly shaped chunkname object.
inline DWORD run_ls() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 ls base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("  sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();

    unsigned long long top0 = 0, extra = 0, th = 0, sc2 = 0;
    if (L) {
        read_u64(L + 0x60, &top0);
        read_u64(L + 0x8, &extra);
        if (extra) read_u64(extra + 0x18, &th);
        if (th) read_u64(th + 0x18, &sc2);
    }
    o.str("  top=");
    o.hex(top0);
    o.str(" extra=");
    o.hex(extra);
    o.str(" th=");
    o.hex(th);
    o.str(" sc2=");
    o.hex(sc2);
    o.nl();
    if (!L || !th) {
        o.str("  thread chain broken, skipping\n");
    } else {
        const char* src = "return 1 + 1";
        typedef int (*PushFn)(void*, const char*);
        PushFn push = reinterpret_cast<PushFn>(base + 0x4269620);
        int pr = push(reinterpret_cast<void*>(L), src);
        unsigned long long t1 = 0;
        read_u64(L + 0x60, &t1);
        o.str("  push ret=");
        o.dec(static_cast<unsigned int>(pr));
        o.str(" d=");
        o.hex(t1 - top0);
        o.nl();
        if (t1 > top0) dump_tv(o, top0, "  arg:");

        typedef int (*RunFn)(void*);
        RunFn run = reinterpret_cast<RunFn>(base + 0x4321B00);
        int r = run(reinterpret_cast<void*>(L));
        unsigned long long t2 = 0;
        read_u64(L + 0x60, &t2);
        o.str("  run ret=");
        o.dec(static_cast<unsigned int>(r));
        o.str(" top=");
        o.hex(t2);
        o.str(" d=");
        o.hex(t2 - top0);
        o.nl();
        for (unsigned long long s = top0, i = 0; s + 16 <= t2 && i < 4; s += 16, ++i) {
            dump_tv(o, s, "  res:");
        }
    }
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline DWORD run_tree() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 tree base=");
    o.hex(base);
    o.nl();
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    tree_report(o, fake);
    if (dm && dm != fake) tree_report(o, dm);
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline DWORD run_probe(bool scan, bool local) {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    probe_report(o, scan, local);
    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 48: write candidate capability fields on the TLS security context itself
// and re-run the same GetPlayers probe after each one.
inline DWORD run_ctxfields() {
    DWORD st = resolve_api();
    if (st) return 97 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 cf base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;

    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0, q1 = 0, q2 = 0, ctx = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);
    if (obj) {
        read_u64(obj + 0x18, &q1);
        if (q1) read_u64(q1 + 0x68, &q2);
        if (q2) read_u64(q2 + 0x58, &ctx);
    }
    if (!ctx) {
        o.str("  no ctx\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    for (int i = 0x20; i < 0x60; i += 2) {
        unsigned long long v0 = 0, v1 = 0;
        read_u64(ctx + 8ull * i, &v0);
        read_u64(ctx + 8ull * (i + 1), &v1);
        o.str("C +");
        o.hex(8ull * i);
        o.str(" ");
        o.hex(v0);
        o.str(" ");
        o.hex(v1);
        o.nl();
    }
    flush_out(a, pipe, o);

    const unsigned long long fields[4] = {0x30, 0x38, 0x190, 0xA0};
    for (int m = 0; m < 4; ++m) {
        wr64(ctx + fields[m], 0xFFFFFFFFFFFFFFFFull);
        g_veh_phase = "U1";
        o.str("MC +");
        o.hex(fields[m]);
        o.nl();
        flush_out(a, pipe, o);

        g_exec_fn = 0;
        exec_chunk(a, pipe, o, L, base, kChunkU1Body, kChunkU1Len, "U1");
        if (g_exec_fn) {
            for (int k = 0; k < 3; ++k) {
                char tag[8] = {'U', '1', ' ', 'r', static_cast<char>('0' + k), 0, 0, 0};
                dump_val(o, tag, g_exec_fn + 16ull * k);
            }
            flush_out(a, pipe, o);
        }
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 47: IdentityPtr points at the identity descriptor table, 0x20 bytes per
// identity. Entry[identity] holds { idx, off } at +0x10; the capability mask for
// that identity is a qword at ctx + off + 0x30.
inline DWORD run_id() {
    DWORD st = resolve_api();
    if (st) return 95 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 id base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;

    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0, q1 = 0, q2 = 0, ctx = 0, E = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);
    if (obj) {
        read_u64(obj + 0x18, &q1);
        if (q1) read_u64(q1 + 0x68, &q2);
        if (q2) read_u64(q2 + 0x58, &ctx);
    }
    read_u64(L + 8, &E);

    unsigned long long idesc = 0;
    read_u64(base + 0x855CF68, &idesc);
    unsigned long long curid = 0;
    if (E) read_u64(E + 0x70, &curid);

    o.str("I ctx=");
    o.hex(ctx);
    o.str(" idesc=");
    o.hex(idesc);
    o.str(" id=");
    o.hex(curid);
    o.nl();
    flush_out(a, pipe, o);

    if (!idesc || !ctx) {
        o.str("  no identity\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    unsigned int metas[16] = {0};
    for (int i = 0; i < 16; ++i) {
        read_u32(idesc + 0x20ull * i + 0x10, &metas[i]);
        o.str("T ");
        o.dec((unsigned int)i);
        o.str(" meta=");
        o.hex(metas[i]);
        o.nl();
    }
    flush_out(a, pipe, o);

    unsigned int id = static_cast<unsigned int>(curid & 0xFF);
    if (id > 15) id = 15;
    unsigned long long off = metas[id] >> 16;
    unsigned long long slot = ctx + off;
    unsigned long long mask = 0, pend = 0;
    read_u64(slot + 0x30, &mask);
    read_u64(slot + 0x38, &pend);
    o.str("S id=");
    o.dec(id);
    o.str(" off=");
    o.hex(off);
    o.str(" slot=");
    o.hex(slot);
    o.str(" mask=");
    o.hex(mask);
    o.str(" pend=");
    o.hex(pend);
    o.nl();
    flush_out(a, pipe, o);

    wr64(slot + 0x38, 0);
    wr64(slot + 0x30, 0xFFFFFFFFFFFFFFFFull);

    g_veh_phase = "U1";
    g_exec_fn = 0;
    exec_chunk(a, pipe, o, L, base, kChunkU1Body, kChunkU1Len, "U1");
    if (g_exec_fn) {
        for (int k = 0; k < 3; ++k) {
            char tag[8] = {'U', '1', ' ', 'r', static_cast<char>('0' + k), 0, 0, 0};
            dump_val(o, tag, g_exec_fn + 16ull * k);
        }
        flush_out(a, pipe, o);
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 46: the identity descriptor lives behind IdentityPtr (0x855CF68).
// sub_C700(identity) returns context + desc[0x12]; that slot's +0x30 is the
// capability mask sub_7B3C40 tests against each method's required bits.
inline DWORD run_slot() {
    DWORD st = resolve_api();
    if (st) return 90 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 slot base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;

    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0, q1 = 0, q2 = 0, ctx = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);
    if (obj) {
        read_u64(obj + 0x18, &q1);
        if (q1) read_u64(q1 + 0x68, &q2);
        if (q2) read_u64(q2 + 0x58, &ctx);
    }

    unsigned long long idesc = 0;
    read_u64(base + 0x855CF68, &idesc);
    unsigned int req = 0, idx = 0;
    if (idesc) {
        read_u32(idesc, &req);
        read_u32(idesc + 0x10, &idx);
    }
    o.str("I ctx=");
    o.hex(ctx);
    o.str(" idesc=");
    o.hex(idesc);
    o.str(" req=");
    o.hex(req);
    o.str(" idx=");
    o.hex(idx & 0xFFFF);
    o.str(" off=");
    o.hex((idx >> 16) & 0xFFFF);
    o.nl();
    flush_out(a, pipe, o);

    if (!idesc || !ctx) {
        o.str("  no identity\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    if (readable(reinterpret_cast<const void*>(idesc), 0x40)) {
        for (int i = 0; i < 8; i += 2) {
            unsigned long long v0 = 0, v1 = 0;
            read_u64(idesc + 8ull * i, &v0);
            read_u64(idesc + 8ull * (i + 1), &v1);
            o.str("D +");
            o.hex(8ull * i);
            o.str(" ");
            o.hex(v0);
            o.str(" ");
            o.hex(v1);
            o.nl();
        }
        flush_out(a, pipe, o);
    }

    unsigned long long slot = ctx + ((idx >> 16) & 0xFFFF);
    unsigned long long mask = 0, pend = 0;
    read_u64(slot + 0x30, &mask);
    read_u64(slot + 0x38, &pend);
    o.str("S slot=");
    o.hex(slot);
    o.str(" mask=");
    o.hex(mask);
    o.str(" pend=");
    o.hex(pend);
    o.nl();
    flush_out(a, pipe, o);

    wr64(slot + 0x38, 0);
    wr64(slot + 0x30, 0xFFFFFFFFFFFFFFFFull);
    read_u64(slot + 0x30, &mask);
    o.str("SW mask=");
    o.hex(mask);
    o.nl();
    flush_out(a, pipe, o);

    g_veh_phase = "U1";
    g_exec_fn = 0;
    exec_chunk(a, pipe, o, L, base, kChunkU1Body, kChunkU1Len, "U1");
    if (g_exec_fn) {
        for (int k = 0; k < 3; ++k) {
            char tag[8] = {'U', '1', ' ', 'r', static_cast<char>('0' + k), 0, 0, 0};
            dump_val(o, tag, g_exec_fn + 16ull * k);
        }
        flush_out(a, pipe, o);
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 45: the checker keeps a "verified capability" bitset at context+0xBF0.
// Setting bit 34 skips the Players capability checker entirely.
inline DWORD run_bits() {
    DWORD st = resolve_api();
    if (st) return 80 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 bits base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;

    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0, q1 = 0, q2 = 0, ctx = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);
    if (obj) {
        read_u64(obj + 0x18, &q1);
        if (q1) read_u64(q1 + 0x68, &q2);
        if (q2) read_u64(q2 + 0x58, &ctx);
    }

    unsigned long long bits0 = 0, bits1 = 0;
    if (ctx) {
        read_u64(ctx + 0xBF0, &bits0);
        read_u64(ctx + 0xBF8, &bits1);
    }
    o.str("C ctx=");
    o.hex(ctx);
    o.str(" bits=");
    o.hex(bits0);
    o.str(" ");
    o.hex(bits1);
    o.nl();
    flush_out(a, pipe, o);

    if (!ctx) {
        o.str("  no context\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    for (int m = 0; m < 2; ++m) {
        unsigned long long mask = m == 0 ? 0x400000000ull : 0xFFFFFFFFFFFFFFFFull;
        wr64(ctx + 0xBF0, bits0 | mask);
        g_veh_phase = "U1";
        o.str("MB pc=");
        o.hex(mask);
        o.str(" now=");
        unsigned long long chk = 0;
        read_u64(ctx + 0xBF0, &chk);
        o.hex(chk);
        o.nl();
        flush_out(a, pipe, o);

        g_exec_fn = 0;
        exec_chunk(a, pipe, o, L, base, kChunkU1Body, kChunkU1Len, "U1");
        if (g_exec_fn) {
            for (int k = 0; k < 3; ++k) {
                char tag[8] = {'U', '1', ' ', 'r', static_cast<char>('0' + k), 0, 0, 0};
                dump_val(o, tag, g_exec_fn + 16ull * k);
            }
            flush_out(a, pipe, o);
        }
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 44: follow the capability-check context chain the checker itself uses.
// sub_8420: v9 = *(*(tls_obj+0x18) + 0x68); verified bits live at v9 + 0xBF0.
inline DWORD run_ctx() {
    DWORD st = resolve_api();
    if (st) return 60 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 ctx base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);

    o.str("X obj=");
    o.hex(obj);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long p1 = 0, v9 = 0, tail = 0;
    if (obj) {
        read_u64(obj + 0x18, &p1);
        if (p1) read_u64(p1 + 0x68, &v9);
        read_u64(obj + 0x18 + 0x88, &tail);
    }
    o.str("X p1=");
    o.hex(p1);
    o.str(" v9=");
    o.hex(v9);
    o.str(" tailA0=");
    o.hex(tail);
    o.nl();
    flush_out(a, pipe, o);

    if (obj && readable(reinterpret_cast<const void*>(obj), 0xC0)) {
        for (int i = 0x80; i < 0xC0; i += 2) {
            unsigned long long v0 = 0, v1 = 0;
            read_u64(obj + 8ull * i, &v0);
            read_u64(obj + 8ull * (i + 1), &v1);
            o.str("X +");
            o.hex(8ull * i);
            o.str(" ");
            o.hex(v0);
            o.str(" ");
            o.hex(v1);
            o.nl();
        }
        flush_out(a, pipe, o);
    }

    if (v9 && readable(reinterpret_cast<const void*>(v9), 0x80)) {
        for (int i = 0; i < 16; i += 2) {
            unsigned long long v0 = 0, v1 = 0;
            read_u64(v9 + 8ull * i, &v0);
            read_u64(v9 + 8ull * (i + 1), &v1);
            o.str("V +");
            o.hex(8ull * i);
            o.str(" ");
            o.hex(v0);
            o.str(" ");
            o.hex(v1);
            o.nl();
        }
        flush_out(a, pipe, o);
    } else {
        o.str("V unreadable or null\n");
        flush_out(a, pipe, o);
    }

    if (v9 && readable(reinterpret_cast<const void*>(v9 + 0xBC0), 0x180)) {
        for (int i = 0; i < 0x180; i += 16) {
            unsigned long long v0 = 0, v1 = 0;
            read_u64(v9 + 0xBC0 + i, &v0);
            read_u64(v9 + 0xBC0 + i + 8, &v1);
            o.str("B +");
            o.hex(0xBC0ull + i);
            o.str(" ");
            o.hex(v0);
            o.str(" ");
            o.hex(v1);
            o.nl();
        }
        flush_out(a, pipe, o);
    } else {
        o.str("B unreadable\n");
        flush_out(a, pipe, o);
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 49: sub_7B3D30 is the thread-identity gate. It resolves the identity
// descriptor through [0x855CF68], takes the a3=1 context branch (ctx = *(p1+0x58))
// and tests bit 3 of the slot mask at ctx+0x158+0x30. Missing bit 3 throws through
// sub_1CE9FA0 with a1=8, which is exactly the "lacking capability" wording we see.
// Stages 42-48 all wrote the a3=0 context (ctx = *(*(p1+0x68)+0x58)) -- wrong object.
inline DWORD run_ident() {
    DWORD st = resolve_api();
    if (st) return 98 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 id base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;

    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0, p1 = 0, q2 = 0;
    unsigned long long ctx_id = 0, ctx_caps = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);
    if (obj) {
        read_u64(obj + 0x18, &p1);
        if (p1) {
            read_u64(p1 + 0x58, &ctx_id);
            read_u64(p1 + 0x68, &q2);
            if (q2) read_u64(q2 + 0x58, &ctx_caps);
        }
    }

    unsigned long long desc = 0, meta = 0;
    read_u64(base + 0x855CF68, &desc);
    if (desc && readable(reinterpret_cast<const void*>(desc), 0x20))
        read_u64(desc + 0x10, &meta);

    unsigned long long slot = ctx_id ? ctx_id + 0x158 : 0;
    o.str("I obj=");
    o.hex(obj);
    o.str(" p1=");
    o.hex(p1);
    o.nl();
    o.str("I ctx_id=");
    o.hex(ctx_id);
    o.str(" ctx_caps=");
    o.hex(ctx_caps);
    o.nl();
    o.str("I desc=");
    o.hex(desc);
    o.str(" meta=");
    o.hex(meta);
    o.str(" slot=");
    o.hex(slot);
    o.nl();
    flush_out(a, pipe, o);

    if (!slot || !readable(reinterpret_cast<const void*>(slot), 0x40)) {
        o.str("  slot unreadable\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    unsigned long long sm0 = 0, sr0 = 0, sl0 = 0;
    read_u64(slot + 0x30, &sm0);
    read_u64(slot + 0x38, &sr0);
    read_u64(slot + 0x20, &sl0);
    o.str("I slot.L=");
    o.hex(sl0);
    o.str(" mask=");
    o.hex(sm0);
    o.str(" res=");
    o.hex(sr0);
    o.nl();
    flush_out(a, pipe, o);

    wr64(slot + 0x30, 0xFFFFFFFFFFFFFFFFull);
    wr64(slot + 0x38, 0);
    unsigned long long sm1 = 0;
    read_u64(slot + 0x30, &sm1);

    // The resolver is oldMask & scriptMask, and scriptMask starts at
    // *(lua_State+8)+0xA0 with the thread identity at +0x70. If that is zero the
    // resolver writes zero straight back over the mask. Fill both.
    unsigned long long E = 0, capsE = 0, identE = 0;
    read_u64(L + 8, &E);
    if (E) {
        read_u64(E + 0xA0, &capsE);
        read_u64(E + 0x70, &identE);
        wr64(E + 0xA0, 0xFFFFFFFFFFFFFFFFull);
        wr64(E + 0x70, 8);
    }
    unsigned long long capsE2 = 0, identE2 = 0;
    if (E) {
        read_u64(E + 0xA0, &capsE2);
        read_u64(E + 0x70, &identE2);
    }
    o.str("I E=");
    o.hex(E);
    o.str(" capsE ");
    o.hex(capsE);
    o.str("->");
    o.hex(capsE2);
    o.str(" ident ");
    o.hex(identE);
    o.str("->");
    o.hex(identE2);
    o.nl();
    o.str("I wrote mask=");
    o.hex(sm1);
    o.nl();
    flush_out(a, pipe, o);

    g_veh_phase = "U1";
    o.str("MU1 pcall(p.GetPlayers, p)\n");
    flush_out(a, pipe, o);
    g_exec_fn = 0;
    g_patch_proto = true;
    exec_chunk(a, pipe, o, L, base, kChunkU1Body, kChunkU1Len, "U1");
    g_patch_proto = false;
    if (g_exec_fn) {
        for (int k = 0; k < 3; ++k) {
            char tag[8] = {'U', '1', ' ', 'r', static_cast<char>('0' + k), 0, 0, 0};
            dump_val(o, tag, g_exec_fn + 16ull * k);
        }
        flush_out(a, pipe, o);
    }

    unsigned long long sm2 = 0, sr2 = 0;
    read_u64(slot + 0x30, &sm2);
    read_u64(slot + 0x38, &sr2);
    o.str("I after mask=");
    o.hex(sm2);
    o.str(" res=");
    o.hex(sr2);
    o.nl();

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 50: same fix as 49, then a broader capability sweep in one chunk:
// Players:GetPlayers, game:GetService, Instance.new, workspace:FindFirstChild.
inline DWORD run_verify() {
    DWORD st = resolve_api();
    if (st) return 99 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 verify base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("  no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;

    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0, p1 = 0, ctx = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);
    if (obj) {
        read_u64(obj + 0x18, &p1);
        if (p1) read_u64(p1 + 0x58, &ctx);
    }
    unsigned long long slot = ctx ? ctx + 0x158 : 0;
    unsigned long long E = 0;
    read_u64(L + 8, &E);
    if (E) {
        wr64(E + 0xA0, 0xFFFFFFFFFFFFFFFFull);
        wr64(E + 0x70, 8);
    }
    if (slot && readable(reinterpret_cast<const void*>(slot), 0x40)) {
        wr64(slot + 0x30, 0xFFFFFFFFFFFFFFFFull);
        wr64(slot + 0x38, 0);
    }
    o.str("V slot=");
    o.hex(slot);
    o.str(" E=");
    o.hex(E);
    o.nl();
    flush_out(a, pipe, o);

    g_veh_phase = "V1";
    g_exec_fn = 0;
    g_patch_proto = true;
    exec_chunk(a, pipe, o, L, base, kChunkV1Body, kChunkV1Len, "V1");
    g_patch_proto = false;

    if (g_exec_fn) {
        for (int k = 0; k < 9; ++k) {
            char tag[8] = {'V', '1', ' ', 'r', static_cast<char>('0' + k), 0, 0, 0};
            dump_val(o, tag, g_exec_fn + 16ull * k);
        }
        flush_out(a, pipe, o);
    }

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 51: load-only bisect. Compiles four variants and reports the loader's
// verdict without executing anything; stack is restored after each attempt.
inline void load_only(Api& a, HANDLE pipe, Out& o, unsigned long long L,
                      unsigned long long base, const unsigned char* body,
                      unsigned int len, const char* tag) {
    static unsigned char container[4096];
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + i) =
            static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < len; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + 8 + i) = body[i];
    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = 8ull + len;
    src.cap = 8ull + len;
    unsigned long long top0 = 0;
    read_u64(L + 0x60, &top0);
    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str(tag);
    o.str(" ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    o.nl();
    if (ret != 0) dump_val(o, "  err", top0);
    flush_out(a, pipe, o);
    wr64(L + 0x60, top0);
}

inline DWORD run_loadtest() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;
    o.str("ZEND1 loadtest L=");
    o.hex(L);
    o.nl();
    load_only(a, pipe, o, L, base, kChunkP264Body, kChunkP264Len, "P264");
    load_only(a, pipe, o, L, base, kChunkP268Body, kChunkP268Len, "P268");
    load_only(a, pipe, o, L, base, kChunkP270Body, kChunkP270Len, "P270");
    load_only(a, pipe, o, L, base, kChunkP272Body, kChunkP272Len, "P272");
    load_only(a, pipe, o, L, base, kChunkP274Body, kChunkP274Len, "P274");
    load_only(a, pipe, o, L, base, kChunkP276Body, kChunkP276Len, "P276");
    load_only(a, pipe, o, L, base, kChunkP278Body, kChunkP278Len, "P278");
    load_only(a, pipe, o, L, base, kChunkP279Body, kChunkP279Len, "P279");
    load_only(a, pipe, o, L, base, kChunkP280Body, kChunkP280Len, "P280");
    load_only(a, pipe, o, L, base, kChunkB279Body, kChunkB279Len, "B279-code");
    load_only(a, pipe, o, L, base, kChunkB280Body, kChunkB280Len, "B280-code");
    load_only(a, pipe, o, L, base, kChunkB300Body, kChunkB300Len, "B300-code");
    load_only(a, pipe, o, L, base, kChunkV8Body, kChunkV8Len, "V8-280");
    load_only(a, pipe, o, L, base, kChunkV3Body, kChunkV3Len, "V3-216");
    load_only(a, pipe, o, L, base, kChunkV9Body, kChunkV9Len, "V9-271");
    load_only(a, pipe, o, L, base, kChunkU1Body, kChunkU1Len, "U1");
    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 54: the size gate reads the std::string's *size* field, not the real
// buffer length. sub_43178A0 skips the watermark when size-8 < 0x118. Nothing
// downstream bounds-checks (sub_265E4D0 -- the varint reader -- never even
// looks at the size argument), so a small declared size parses the whole blob.
inline void load_fake(Api& a, HANDLE pipe, Out& o, unsigned long long L,
                      unsigned long long base, const unsigned char* body,
                      unsigned int len, const char* tag, unsigned long long declared) {
    static unsigned char container[8192];
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + i) =
            static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < len; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + 8 + i) = body[i];
    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = declared;
    src.cap = 8ull + len;
    unsigned long long top0 = 0;
    read_u64(L + 0x60, &top0);
    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str(tag);
    o.str(" blobbytes=");
    o.dec(8u + len);
    o.str(" declared=");
    o.dec(static_cast<unsigned int>(declared));
    o.str(" ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    o.nl();
    if (ret != 0) dump_val(o, "  err", top0);
    flush_out(a, pipe, o);
    wr64(L + 0x60, top0);
}

// Full capability unlock: thread identity slot + RobloxExtraSpace script mask.
// Proven in stage 49; every chunk needs it before touching service methods.
inline void caps_open(unsigned long long base, unsigned long long L, Out& o,
                      HANDLE pipe, Api& a, const char* tag) {
    unsigned int tls_index = 0;
    read_u32(base + 0x84F4A10, &tls_index);
    unsigned long long tls_array = __readgsqword(0x58);
    unsigned long long block = 0, obj = 0, p1 = 0, ctx_id = 0;
    if (tls_array && tls_index < 0x1000)
        read_u64(tls_array + 8ull * tls_index, &block);
    if (block) read_u64(block + 0x20, &obj);
    if (obj) {
        read_u64(obj + 0x18, &p1);
        if (p1) read_u64(p1 + 0x58, &ctx_id);
    }
    unsigned long long slot = ctx_id ? ctx_id + 0x158 : 0;
    if (slot && readable(reinterpret_cast<const void*>(slot), 0x40)) {
        wr64(slot + 0x30, 0xFFFFFFFFFFFFFFFFull);
        // Both words are capability-shaped. The second one was zeroed when only
        // the synchronous path mattered; a deferred thread asks that slot first
        // and reports "lacking capability Players", so widen it too.
        wr64(slot + 0x38, 0xFFFFFFFFFFFFFFFFull);
    }
    unsigned long long E = 0;
    read_u64(L + 8, &E);
    if (E) {
        wr64(E + 0xA0, 0xFFFFFFFFFFFFFFFFull);
        // Identity 8 is the RobloxScript context. Identity 7 was tried here to
        // lift the loadstring refusal; the chunk still reported RobloxScript
        // and the client died ~40 s after the thread was restored, so the write
        // buys nothing and costs stability. Back to the proven value.
        wr64(E + 0x70, 8);
    }
    // A proto decodes its capability qword at proto+0x80; an unpatched proto
    // decodes to this global default, and the sandbox ANDs the thread mask with
    // it. The deferred chunk runs inside a proto built after this session
    // started, so the default is the one word that reaches it.
    unsigned long long defaddr = base + 0x8D87878;
    unsigned long long defold = 0, defnew = 0;
    bool defw = false;
    {
        Mbi mbi;
        if (a.VirtualQuery(reinterpret_cast<void*>(defaddr), &mbi, sizeof(mbi))) {
            DWORD prot = mbi.Protect & 0xFF;
            defw = mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
                   (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
                    prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
        }
    }
    if (defw) {
        read_u64(defaddr, &defold);
        wr64(defaddr, 0xFFFFFFFFFFFFFFFFull);
        read_u64(defaddr, &defnew);
    }
    unsigned long long sm = 0, capsE = 0;
    if (slot) read_u64(slot + 0x30, &sm);
    if (E) read_u64(E + 0xA0, &capsE);
    o.str(tag);
    o.str(" caps slot=");
    o.hex(slot);
    o.str(" mask=");
    o.hex(sm);
    o.str(" E=");
    o.hex(E);
    o.str(" capsE=");
    o.hex(capsE);
    o.str(" def=");
    o.hex(defaddr);
    o.str("/");
    o.hex(defold);
    o.str("/");
    o.hex(defnew);
    o.str(defw ? "/w" : "/no");
    o.nl();
    flush_out(a, pipe, o);
}

// Stage 55: full execution of a >280 byte chunk through the declared-size lie.
inline DWORD run_bigexec() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    o.str("ZEND1 bigexec L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);

    caps_open(base, L, o, pipe, a, "BIG1");

    g_declared_size = 0;
    g_patch_proto = 1;
    exec_chunk(a, pipe, o, L, base, kChunkP279Body, kChunkP279Len, "P279-real");

    g_declared_size = 64;
    exec_chunk(a, pipe, o, L, base, kChunkP280Body, kChunkP280Len, "P280-fake");

    g_declared_size = 64;
    exec_chunk(a, pipe, o, L, base, kChunkB300Body, kChunkB300Len, "B300-fake");

    g_declared_size = 0;

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline DWORD run_fakesize() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    o.str("ZEND1 fakesize L=");
    o.hex(L);
    o.nl();
    load_fake(a, pipe, o, L, base, kChunkB300Body, kChunkB300Len, "B300-real", 8ull + kChunkB300Len);
    load_fake(a, pipe, o, L, base, kChunkB300Body, kChunkB300Len, "B300-fake64", 64);
    load_fake(a, pipe, o, L, base, kChunkP280Body, kChunkP280Len, "P280-real", 8ull + kChunkP280Len);
    load_fake(a, pipe, o, L, base, kChunkP280Body, kChunkP280Len, "P280-fake64", 64);
    load_fake(a, pipe, o, L, base, kChunkP279Body, kChunkP279Len, "P279-ctrl", 8ull + kChunkP279Len);
    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Any precompiled chunk of 280 bytes or more is rejected: LuaVMLoad hands the
// blob to sub_4316CF0, which runs a watermark check against a trailer that
// Roblox's own compiler appends (sub_43178A0, `cmp rcx, 0x118` on the size).
// Everything below 280 skips the check outright -- that is exactly the
// boundary the bisect found. Lift the immediate and the gate disappears.
constexpr unsigned long long k_watermark_gate = 0x43178DFull;

inline DWORD run_unseal() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long imm = base + k_watermark_gate;
    unsigned int before = 0, after = 0;
    read_u32(imm, &before);
    unsigned long long page = imm & ~0xFFFull;
    DWORD oldp = 0, oldp2 = 0;
    BOOL prot = a.VirtualProtect(reinterpret_cast<void*>(page), 0x1000,
                                 PAGE_EXECUTE_READWRITE, &oldp);
    wr32(imm, 0x7FFFFFFFu);
    a.FlushInstructionCache(reinterpret_cast<HANDLE>(static_cast<long long>(-1)),
                            reinterpret_cast<void*>(imm), 4);
    if (prot)
        a.VirtualProtect(reinterpret_cast<void*>(page), 0x1000, oldp, &oldp2);
    read_u32(imm, &after);

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;

    o.str("ZEND1 unseal base=");
    o.hex(base);
    o.str(" prot=");
    o.dec(static_cast<unsigned int>(prot));
    o.str(" before=");
    o.hex(before);
    o.str(" after=");
    o.hex(after);
    o.str(" L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);
    if (!L) {
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;
    load_only(a, pipe, o, L, base, kChunkB300Body, kChunkB300Len, "B300");
    load_only(a, pipe, o, L, base, kChunkZ3Body, kChunkZ3Len, "Z3");
    load_only(a, pipe, o, L, base, kChunkV1Body, kChunkV1Len, "V1");
    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 53: the same call with no magic prefix. LuaVMLoad's bytecode branch is
// gated on the 8-byte magic; without it the blob goes down the source-text
// path and the client compiles it itself -- which is where the 280-byte
// watermark gate (and the whole stock->client opcode remap) disappears.
inline void load_src(Api& a, HANDLE pipe, Out& o, unsigned long long L,
                     unsigned long long base, const char* text, unsigned int len,
                     const char* tag) {
    static unsigned char container[4096];
    for (unsigned int i = 0; i < len; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + i) =
            static_cast<unsigned char>(text[i]);
    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = len;
    src.cap = len;
    unsigned long long top0 = 0;
    read_u64(L + 0x60, &top0);
    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str(tag);
    o.str(" ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    o.nl();
    if (ret != 0) dump_val(o, "  err", top0);
    else if (t1 > top0) dump_val(o, "  fn", top0);
    flush_out(a, pipe, o);
    wr64(L + 0x60, top0);
}

inline DWORD run_src() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("ZEND1 src L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);
    if (!L) {
        o.str("END\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    g_veh_L = L;
    const char src1[] = "return 1+1";
    load_src(a, pipe, o, L, base, src1, sizeof(src1) - 1, "SRC-small");
    const char src2[] = "return 2+2 -- ";
    static char big[512];
    unsigned int n = 0;
    for (unsigned int i = 0; i < sizeof(src2) - 1; ++i) big[n++] = src2[i];
    for (int i = 0; i < 300; ++i) big[n++] = 'x';
    big[n++] = '\n';
    load_src(a, pipe, o, L, base, big, n, "SRC-300");
    const char src3[] =
        "local p = game.Players\n"
        "local ok, a = pcall(p.GetPlayers, p)\n"
        "return ok, a\n";
    load_src(a, pipe, o, L, base, src3, sizeof(src3) - 1, "SRC-game");
    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 56: dump the live opcode permutation table. Hyperion decodes
// 0x735B280 at init, so the file copy is ciphertext and useless for remapping.
inline DWORD run_optable() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    static const char hx[] = "0123456789abcdef";
    static const unsigned long long addrs[2] = {0x735B280ull, 0x735B380ull};
    for (int t = 0; t < 2; ++t) {
        unsigned long long addr = base + addrs[t];
        o.str("OPT ");
        o.hex(addrs[t]);
        o.nl();
        flush_out(a, pipe, o);
        for (unsigned long long off = 0; off < 256; off += 16) {
            o.str("  ");
            o.hex(off);
            o.str(" ");
            for (unsigned long long j = 0; j < 16; ++j) {
                unsigned int b = 0;
                read_u32(addr + off + j, &b);
                char s2[3];
                s2[0] = hx[b & 0xf];
                s2[1] = hx[(b >> 4) & 0xf];
                s2[2] = 0;
                o.str(s2);
            }
            o.nl();
        }
        flush_out(a, pipe, o);
    }
    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[8];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 57: decode the VM dispatch from the live tables.
// 0x2686430 is the dispatch head:
//   movzx eax, byte [r15]        ; r15 = pc
//   dec rax                      ; opcode-1
//   movzx eax, byte [r9+rax+0x26933F4]   ; 256-entry byte index
//   mov ecx, dword [r9+rax*4+0x2693278]  ; 256-entry relative offset
//   add rcx, r9 ; jmp rcx
// Both tables are ciphertext on disk, so read them from the running process.
inline DWORD run_dispatch() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    static const char hx[] = "0123456789abcdef";

    unsigned char idx_tab[256];
    unsigned int off_tab[256];
    for (int i = 0; i < 256; ++i) {
        unsigned int b = 0;
        read_u32(base + 0x26933F4ull + i, &b);
        idx_tab[i] = static_cast<unsigned char>(b);
    }
    for (int i = 0; i < 256; ++i) {
        unsigned int v = 0;
        read_u32(base + 0x2693278ull + 4ull * i, &v);
        off_tab[i] = v;
    }
    for (int i = 0; i < 256; i += 16) {
        o.str("IDX ");
        for (int j = 0; j < 16; ++j) {
            char s2[3];
            s2[0] = hx[idx_tab[i + j] & 0xf];
            s2[1] = hx[(idx_tab[i + j] >> 4) & 0xf];
            s2[2] = 0;
            o.str(s2);
        }
        o.nl();
    }
    for (int i = 0; i < 256; i += 8) {
        o.str("OFF ");
        for (int j = 0; j < 8; ++j) {
            char buf[9];
            unsigned int v = off_tab[i + j];
            for (int k = 0; k < 8; ++k) buf[k] = hx[(v >> (4 * (7 - k))) & 0xf];
            buf[8] = 0;
            o.str(buf);
            o.str(" ");
        }
        o.nl();
    }
    // Known pairs from live probes: stock -> client.
    static const unsigned char known[12] = {0x82, 0xa3, 0x6f, 0x52, 0x8c, 0x9f,
                                            0x4d, 0x35, 0x43, 0xa8, 0x8b, 0x64};
    for (int i = 0; i < 12; ++i) {
        unsigned char op = known[i];
        unsigned int idx = idx_tab[op - 1];
        unsigned int h = off_tab[idx];
        o.str("H op=");
        o.hex(op);
        o.str(" idx=");
        o.hex(idx);
        o.str(" rva=");
        o.hex(h);
        o.str(" va=");
        o.hex(base + h);
        o.nl();
    }
    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[8];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 59: hand the loader a chunk whose code array carries every file opcode
// once, then read Proto.code back. Whatever the loader writes there is the
// authoritative file-opcode -> runtime-opcode map. Nothing is executed.
inline DWORD run_opmap() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    o.str("ZEND1 opmap L=");
    o.hex(L);
    o.str(" words=");
    o.dec(kProbeWords);
    o.nl();
    flush_out(a, pipe, o);

    static unsigned char container[8192];
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + i) =
            static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < kProbeLen; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + 8 + i) = kProbeBody[i];

    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = 64;
    src.cap = 8ull + kProbeLen;

    unsigned long long top0 = 0;
    read_u64(L + 0x60, &top0);
    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str("load ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    o.nl();
    if (ret != 0) {
        dump_val(o, "  err", top0);
        o.str("END\n");
        flush_out(a, pipe, o);
        wr64(L + 0x60, top0);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }

    unsigned long long clo = 0, proto = 0, code = 0;
    read_u64(top0, &clo);
    read_u64(clo + 0x18, &proto);
    read_u64(proto + 0x68, &code);
    o.str("clo=");
    o.hex(clo);
    o.str(" proto=");
    o.hex(proto);
    o.str(" code=");
    o.hex(code);
    o.nl();
    for (unsigned int i = 0; i < kProbeWords; i += 8) {
        o.str("W ");
        o.dec(i);
        o.str(" ");
        for (unsigned int j = 0; j < 8 && i + j < kProbeWords; ++j) {
            unsigned int w = 0;
            read_u32(code + 4ull * (i + j), &w);
            o.hex(w);
            o.str(" ");
        }
        o.nl();
    }
    wr64(L + 0x60, top0);
    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Load one probe blob and dump the code array the loader produced. Returns false
// if the load failed. Every step flushes, because a bad instruction stream can
// fastfail the client and take the buffer with it.
inline bool probe_load(Api& a, Out& o, HANDLE pipe, unsigned long long L,
                       unsigned long long base, const unsigned char* body,
                       unsigned int len, unsigned int words, const char* tag) {
    static unsigned char container[8192];
    if (8u + len > sizeof(container)) {
        o.str(tag);
        o.str(" too big\n");
        flush_out(a, pipe, o);
        return false;
    }
    const unsigned long long magic = 0xE009325B4A107A52ull;
    for (int i = 0; i < 8; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + i) =
            static_cast<unsigned char>(magic >> (8 * i));
    for (unsigned int i = 0; i < len; ++i)
        *reinterpret_cast<volatile unsigned char*>(container + 8 + i) = body[i];

    ChunkName src;
    src.data = reinterpret_cast<const char*>(container);
    src.pad = 0;
    src.size = 64;
    src.cap = 8ull + len;

    unsigned long long top0 = 0;
    read_u64(L + 0x60, &top0);
    o.str(tag);
    o.str(" pre-load top0=");
    o.hex(top0);
    o.nl();
    flush_out(a, pipe, o);

    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
    int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);

    unsigned long long t1 = 0;
    read_u64(L + 0x60, &t1);
    o.str(tag);
    o.str(" ret=");
    o.dec(static_cast<unsigned int>(ret));
    o.str(" d=");
    o.hex(t1 - top0);
    o.nl();
    flush_out(a, pipe, o);
    if (ret != 0) {
        dump_val(o, "  err", top0);
        flush_out(a, pipe, o);
        wr64(L + 0x60, top0);
        return false;
    }

    unsigned long long clo = 0, proto = 0, code = 0;
    read_u64(top0, &clo);
    read_u64(clo + 0x18, &proto);
    read_u64(proto + 0x68, &code);
    o.str(tag);
    o.str(" clo=");
    o.hex(clo);
    o.str(" proto=");
    o.hex(proto);
    o.str(" code=");
    o.hex(code);
    o.nl();
    flush_out(a, pipe, o);

    for (unsigned int i = 0; i < words; i += 8) {
        o.str(tag);
        o.str(" W");
        o.dec(i);
        o.str(" ");
        for (unsigned int j = 0; j < 8 && i + j < words; ++j) {
            unsigned int w = 0;
            read_u32(code + 4ull * (i + j), &w);
            o.hex(w);
            o.str(" ");
        }
        o.nl();
        if ((i & 63u) == 0) flush_out(a, pipe, o);
    }
    flush_out(a, pipe, o);
    wr64(L + 0x60, top0);
    read_u64(L + 0x60, &t1);
    o.str(tag);
    o.str(" post top=");
    o.hex(t1);
    o.nl();
    flush_out(a, pipe, o);
    return true;
}

// Stage 60: safe chunk first (only opcodes already proven to load), then the
// full sweep. If the sweep fastfails we still keep the safe result.
inline DWORD run_opmap2() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    o.str("ZEND1 opmap2 L=");
    o.hex(L);
    o.str(" words=");
    o.dec(kProbeWords);
    o.nl();
    flush_out(a, pipe, o);

    probe_load(a, o, pipe, L, base, kProbeSafeBody, kProbeSafeLen, kProbeSafeWords, "SAFE");
    probe_load(a, o, pipe, L, base, kProbeBody, kProbeLen, kProbeWords, "SWEEP");

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 61: the control that decides everything. Feed luau-compile output
// straight in, no opcode pre-mapping. The loader rewrites every word through
// the table at 0x735B280 on its own, so a stock stream should already be valid.
inline DWORD run_rawexec() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    o.str("ZEND1 rawexec L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);

    caps_open(base, L, o, pipe, a, "RAW");

    g_declared_size = 64;
    g_patch_proto = 1;
    exec_chunk(a, pipe, o, L, base, kChunkRawBody, kChunkRawLen, "STOCK280");

    g_declared_size = 0;
    g_patch_proto = 0;

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 62: the live opcode map, read correctly this time. Every earlier dump
// ran through a nibble-reversed printer, which made the table look scrambled.
// The loader's rewrite at 0x2661587 indexes this table with the file byte, and
// stage 60 proved 0x4d comes back as 0x4d -- a fixed point the on-disk copy does
// not have, so Hyperion patches the table at init.
inline DWORD run_opmap_live() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    static const char hx[] = "0123456789abcdef";
    o.str("ZEND1 optab base=");
    o.hex(base);
    o.nl();
    flush_out(a, pipe, o);

    unsigned long long addr = base + 0x735B280ull;
    for (int row = 0; row < 16; ++row) {
        o.str("T ");
        o.dec(static_cast<unsigned int>(row * 16));
        o.str(" ");
        for (int j = 0; j < 16; ++j) {
            unsigned int b = 0;
            read_u32(addr + row * 16 + j, &b);
            b &= 0xFF;
            char s[3];
            s[0] = hx[(b >> 4) & 0xf];
            s[1] = hx[b & 0xf];
            s[2] = 0;
            o.str(s);
        }
        o.nl();
        flush_out(a, pipe, o);
    }
    for (int row = 0; row < 8; ++row) {
        o.str("I ");
        o.dec(static_cast<unsigned int>(row * 16));
        o.str(" ");
        for (int j = 0; j < 16; ++j) {
            unsigned int b = 0;
            read_u32(base + 0x26933F4ull + row * 16 + j, &b);
            b &= 0xFF;
            char s[3];
            s[0] = hx[(b >> 4) & 0xf];
            s[1] = hx[b & 0xf];
            s[2] = 0;
            o.str(s);
        }
        o.nl();
        flush_out(a, pipe, o);
    }
    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[8];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 63: sequential opcode-remap bisect. Each chunk is remapped offline
// (stock -> runtime -> file) by work/remap.py; the loader rewrites file ->
// runtime and the dump in exec_chunk must reproduce the expected stream.
// Order: A scalar math, B the proven pad_280 (caps + pcall + properties),
// C a Lua closure with no upvalue, D a closure that captures a local.
inline DWORD run_batch() {
    DWORD st = resolve_api();
    if (st) return 100 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;
    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        o.str("no state\nEND\n");
        flush_out(a, pipe, o);
        char ack[8];
        DWORD rd = 0;
        a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
        a.CloseHandle(pipe);
        return 111;
    }
    o.str("ZEND1 batch L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);

    caps_open(base, L, o, pipe, a, "BATCH");
    g_declared_size = 64;
    g_patch_proto = 1;

    exec_chunk(a, pipe, o, L, base, kChunkALBody, kChunkALLen, "A-math");
    exec_chunk(a, pipe, o, L, base, kChunkBLBody, kChunkBLLen, "B-pad280");
    exec_chunk(a, pipe, o, L, base, kChunkCLBody, kChunkCLLen, "C-closure");
    exec_chunk(a, pipe, o, L, base, kChunkDLBody, kChunkDLLen, "D-capture");

    g_declared_size = 0;
    g_patch_proto = 0;

    o.str("END\n");
    flush_out(a, pipe, o);
    char ack[16];
    DWORD rd = 0;
    a.ReadFile(pipe, ack, sizeof(ack), &rd, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 64: command-driven bisect. One injection, many chunks. The harness
// sends a one-character command per chunk; the payload answers RDY and streams
// the report. A crashing combination costs one client relaunch instead of one
// per guess.
struct ReplEntry {
    char cmd;
    const char* name;
    const unsigned char* body;
    unsigned int len;
};

static const ReplEntry kReplTable[] = {
    {'a', "A-math", kChunkALBody, kChunkALLen},
    {'c', "C-closure", kChunkCLBody, kChunkCLLen},
    {'d', "D-capture", kChunkDLBody, kChunkDLLen},
    {'1', "C+D", kChunkC1Body, kChunkC1Len},
    {'2', "D+pcall(error)", kChunkC2Body, kChunkC2Len},
    {'6', "D+pcall(lua)", kChunkC6Body, kChunkC6Len},
    {'3', "D+pcall(prop)", kChunkC3Body, kChunkC3Len},
    {'7', "pcall(prop)+D", kChunkC7Body, kChunkC7Len},
    {'4', "pcall(prop)", kChunkC4Body, kChunkC4Len},
    {'8', "closure+pcall(prop), no call", kChunkC8Body, kChunkC8Len},
    {'9', "pcall(prop) then closure", kChunkC9Body, kChunkC9Len},
    {'0', "plain closure+pcall(prop)", kChunkC10Body, kChunkC10Len},
    {'b', "pcall(prop)+C call", kChunkC11Body, kChunkC11Len},
    {'e', "lua call then pcall(prop)", kChunkC12Body, kChunkC12Len},
    {'f', "pcall(prop)+lua noarg call", kChunkC13Body, kChunkC13Len},
    {'g', "pcall(prop)+table", kChunkC14Body, kChunkC14Len},
    {'h', "pcall(prop) ignored+lua call", kChunkC15Body, kChunkC15Len},
    {'j', "pcall(prop)+pcall(error)", kChunkC17Body, kChunkC17Len},
    {'i', "pcall(prop)+pcall(f,3)", kChunkC16Body, kChunkC16Len},
    {'k', "pcall(prop)+table{f()}", kChunkC18Body, kChunkC18Len},
    {'o', "type(f) after pcall(prop)", kChunkC20Body, kChunkC20Len},
    {'m', "err text upvalue", kChunkC19Body, kChunkC19Len},
    {'n', "err text no upvalue", kChunkC21Body, kChunkC21Len},
    {'p', "regs after pcall(prop)", kChunkC22Body, kChunkC22Len},
    {'r', "regs after pcall(type,1)", kChunkC23Body, kChunkC23Len},
    {'s', "regs after pcall(error)", kChunkC24Body, kChunkC24Len},
    {'t', "regs after pcall(lua fn)", kChunkC25Body, kChunkC25Len},
    {'u', "const ret after pcall(prop)", kChunkC26Body, kChunkC26Len},
    {'v', "const ret control", kChunkC27Body, kChunkC27Len},
    {'w', "window after pcall(prop)", kChunkC28Body, kChunkC28Len},
    {'y', "window control", kChunkC29Body, kChunkC29Len},
    {'z', "sentinel plain", kChunkC31Body, kChunkC31Len},
    {'Z', "sentinel pcall prop", kChunkC28Body, kChunkC28Len},
    {'5', "live1", kChunkL1Body, kChunkL1Len},
};

inline DWORD serve_session(Api& a, HANDLE pipe, unsigned long long base,
                           unsigned long long L) {
    static Out o;
    o.reset();
    o.str("ZEND1 repl L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);

    caps_open(base, L, o, pipe, a, "REPL");
    g_base = base;
    g_declared_size = 64;
    g_patch_proto = 1;
    g_veh_pipe = pipe;
    g_veh_base = base;
    g_veh_L = L;

    // Lua-side print capture. Every later chunk's `print` output lands in a
    // buffer this same thread drains after the chunk returns. Re-running the
    // chunk on each session is safe: the wrapper is idempotent and the buffer
    // starts empty.
    g_cap_pipe = pipe;
    exec_raw(a, pipe, o, L, base, kChunkCapi, kChunkCapiLen, "capi");
    flush_capture(a, o, L, base);
    // The closure every script call travels through. Captured once; its C
    // function pointer is what the dispatcher replaces.
    if (!g_cap_closure)
        exec_raw(a, pipe, o, L, base, kChunkKCaptureBody, kChunkKCaptureLen, "zcapture");

    // Install the dispatcher for the session. The captured print closure keeps
    // its identity; only its C function pointer is swapped, so an armed call
    // target is all CFG needs. Capture stays on (mode 3): the dispatcher falls
    // back into cap_print for anything that is not a zendo op.
    if (g_cap_closure && g_cap_f) {
        g_cap_mode = 3;
        if (arm_cfg(a, o, reinterpret_cast<unsigned long long>(&native_api), "api cfg")) {
            wr64(g_cap_closure + 0x28, reinterpret_cast<unsigned long long>(&native_api));
            g_api_live = 1;
            o.str("api live clo=");
            o.hex(g_cap_closure);
            o.nl();
        } else {
            o.str("api cfg failed, surface off\n");
        }
        flush_out(a, pipe, o);
    }

    // Global bindings. Runs while the dispatcher already owns the closure, so
    // the setup chunk can hand plain Luau scripts the same door under their own
    // names: `loadstring(src)`, `read`, `write`, `dm`, `base`, `svc`, `svcs`.
    // The chunk gets the closure as its vararg, exactly like a pipe chunk.
    if (g_api_live)
        exec_raw(a, pipe, o, L, base, kZGlobalBody, kZGlobalLen, "gbind");

    for (;;) {
        stage_mark(a, "RDY");
        o.str("RDY\n");
        flush_out(a, pipe, o);
        char cmd[16];
        DWORD rd = 0;
        if (!a.ReadFile(pipe, cmd, 1, &rd, nullptr) || rd == 0) {
            beacon(a, "EOF");
            break;
        }
        cmd[1] = 0;
        stage_mark(a, cmd);
        // Detach: leave the client with no payload thread parked inside it.
        if (cmd[0] == 'x') {
            g_leave = 1;
            break;
        }
        // Session over. Unwind back to the seek loop so this payload thread can
        // serve the next run instead of forcing a second image into the same
        // client. Only the idle timeout leaves DllMain for good, and that path
        // restores the borrowed thread's saved context on the way out.
        if (cmd[0] == 'q') break;
        if (cmd[0] == 'L' || cmd[0] == 'i') {
            unsigned int want_id = 7;
            if (cmd[0] == 'i') {
                char idb[1];
                DWORD idr = 0;
                if (!a.ReadFile(pipe, idb, 1, &idr, nullptr) || idr == 0) continue;
                want_id = static_cast<unsigned char>(idb[0]);
                if (want_id > 15 && want_id != 0xFF) want_id = 7;
            }
            unsigned int blen = 0;
            if (!read_all(a, pipe, &blen, 4) || blen == 0 || blen > 262144) {
                o.str("dyn bad len\n");
                flush_out(a, pipe, o);
                continue;
            }
            static unsigned char lbuf[262144];
            if (!read_all(a, pipe, lbuf, blen)) {
                o.str("dyn read short\n");
                flush_out(a, pipe, o);
                continue;
            }
            stage_mark(a, "BODY");
            o.str("RUN raw dyn len=");
            o.dec(blen);
            o.nl();
            flush_out(a, pipe, o);
            // Identity swap for the synchronous test path: run this chunk on the
            // borrowed thread as identity 7 and put the old value back before
            // returning, so a failed experiment cannot leave a game thread
            // carrying an identity the scheduler did not give it.
            unsigned long long E2 = 0, oldid = 0;
            bool swapped = false;
            if (cmd[0] == 'i') {
                read_u64(L + 8, &E2);
                if (E2 && read_u64(E2 + 0x70, &oldid)) {
                    swapped = true;
                    o.str("ident was=");
                    o.dec(static_cast<unsigned int>(oldid));
                    o.nl();
                    flush_out(a, pipe, o);
                }
            }
            if (swapped && want_id == 0xFF) {
                // One session, every identity: the loadstring refusal changes
                // wording with identity, so the whole table is worth having.
                for (unsigned int id = 0; id <= 9; ++id) {
                    wr64(E2 + 0x70, id);
                    unsigned long long rb = 0;
                    read_u64(E2 + 0x70, &rb);
                    o.str("sweep id=");
                    o.dec(id);
                    o.str(" readback=");
                    o.dec(static_cast<unsigned int>(rb));
                    o.nl();
                    flush_out(a, pipe, o);
                    exec_raw(a, pipe, o, L, base, lbuf, blen, "sweep");
                    flush_capture(a, o, L, base);
                }
                wr64(E2 + 0x70, oldid);
                o.str("ident restored=");
                o.dec(static_cast<unsigned int>(oldid));
                o.nl();
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            if (swapped) {
                wr64(E2 + 0x70, want_id);
            }
            stage_mark(a, "EXEC");
            exec_raw(a, pipe, o, L, base, lbuf, blen, cmd[0] == 'i' ? "ident" : "raw dyn");
            if (swapped) {
                wr64(E2 + 0x70, oldid);
                o.str("ident restored=");
                o.dec(static_cast<unsigned int>(oldid));
                o.nl();
                flush_out(a, pipe, o);
            }
            flush_capture(a, o, L, base);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'N') {
            // Run 1 of the guard work: read only. The CFG dispatch stub is a
            // fixed byte pattern in ntdll, not something to guess. Take the
            // address from the image's own load config, then confirm it against
            // every `jmp rax` in .text so the patch target in stage 'x' is
            // picked from bytes instead of a histogram of call sites. Nothing
            // is written here - no VirtualProtect, no store.
            Module ntdll = find_module(fnv1a_w(L"ntdll.dll"));
            if (!ntdll.base) {
                o.str("ntdll missing\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned long long nb = reinterpret_cast<unsigned long long>(ntdll.base);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll.base);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(nb + dos->e_lfanew);
            o.str("ntdll base=");
            o.hex(nb);
            o.str(" image=");
            o.hex(nt->OptionalHeader.SizeOfImage);
            o.str(" sections=");
            o.dec(nt->FileHeader.NumberOfSections);
            o.nl();

            unsigned long long check = 0, dispatch = 0, table = 0, count = 0;
            unsigned int gflags = 0, lsz = 0;
            auto& lc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (!lc.VirtualAddress) {
                o.str("ldcfg none\n");
            } else {
                auto* lp = reinterpret_cast<unsigned char*>(nb + lc.VirtualAddress);
                lsz = *reinterpret_cast<unsigned int*>(lp);
                if (lsz > lc.Size) lsz = lc.Size;
                o.str("ldcfg rva=");
                o.hex(lc.VirtualAddress);
                o.str(" size=");
                o.dec(lsz);
                o.nl();
                if (lsz >= 0x80) {
                    check = *reinterpret_cast<unsigned long long*>(lp + 0x70);
                    dispatch = *reinterpret_cast<unsigned long long*>(lp + 0x78);
                }
                if (lsz >= 0x88) table = *reinterpret_cast<unsigned long long*>(lp + 0x80);
                if (lsz >= 0x90) count = *reinterpret_cast<unsigned long long*>(lp + 0x88);
                if (lsz >= 0x94) gflags = *reinterpret_cast<unsigned int*>(lp + 0x90);
            }

            const unsigned long long ptrs[2] = {check, dispatch};
            const char* names[2] = {"cf_check   ", "cf_dispatch"};
            for (int i = 0; i < 2; ++i) {
                o.str("guard ");
                o.str(names[i]);
                o.str("=");
                o.hex(ptrs[i]);
                if (ptrs[i] >= nb && ptrs[i] < nb + ntdll.size) {
                    o.str(" rva=");
                    o.hex(ptrs[i] - nb);
                }
                o.str(" head=");
                for (int k = 0; k < 24; ++k) {
                    unsigned char b = 0;
                    if (readable(reinterpret_cast<const void*>(ptrs[i] + k), 1))
                        b = *reinterpret_cast<unsigned char*>(ptrs[i] + k);
                    o.hex(b);
                    o.ch(' ');
                }
                o.nl();
            }
            o.str("guard flags=");
            o.hex(gflags);
            o.str(" table=");
            o.hex(table);
            o.str(" count=");
            o.dec(static_cast<unsigned int>(count));
            o.nl();
            flush_out(a, pipe, o);

            auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                reinterpret_cast<unsigned char*>(&nt->OptionalHeader) +
                nt->FileHeader.SizeOfOptionalHeader);
            unsigned char* text = nullptr;
            unsigned int text_rva = 0, text_sz = 0;
            for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
                const char* nm = reinterpret_cast<const char*>(sec->Name);
                if (nm[0] == '.' && nm[1] == 't' && nm[2] == 'e' && nm[3] == 'x' && nm[4] == 't') {
                    text = reinterpret_cast<unsigned char*>(nb + sec->VirtualAddress);
                    text_rva = sec->VirtualAddress;
                    text_sz = sec->Misc.VirtualSize;
                    break;
                }
            }
            if (!text || !text_sz) {
                o.str("text missing\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            o.str("text rva=");
            o.hex(text_rva);
            o.str(" size=");
            o.hex(text_sz);
            o.nl();
            flush_out(a, pipe, o);

            unsigned int hits = 0, rex = 0, shown = 0, first = 0;
            for (unsigned int i = 0; i + 1 < text_sz; ++i) {
                if (text[i] != 0xff || text[i + 1] != 0xe0) continue;
                if (!hits) first = text_rva + i;
                ++hits;
                bool has_rex = i > 0 && text[i - 1] == 0x48;
                if (has_rex) ++rex;
                if (shown >= 40) continue;
                ++shown;
                o.str("  hit rva=");
                o.hex(text_rva + i);
                o.str(" va=");
                o.hex(nb + text_rva + i);
                o.str(" rex=");
                o.dec(has_rex ? 1 : 0);
                o.str(" pre=");
                for (int k = 16; k >= 1; --k) {
                    if (i < static_cast<unsigned int>(k)) continue;
                    o.hex(text[i - k]);
                    o.ch(' ');
                }
                o.nl();
            }
            o.str("scan_ff_e0 total=");
            o.dec(hits);
            o.str(" rex=");
            o.dec(rex);
            o.str(" first=");
            o.hex(first);
            o.nl();
            // Which of these hits is the load config's own dispatch pointer?
            // The one whose VA matches is the stub the compiler's guarded
            // indirect calls go through; anything else is an ordinary thunk.
            if (dispatch) {
                bool found = false;
                for (unsigned int i = 0; i + 1 < text_sz; ++i) {
                    if (text[i] != 0xff || text[i + 1] != 0xe0) continue;
                    if (nb + text_rva + i != dispatch) continue;
                    found = true;
                    break;
                }
                o.str("dispatch_is_jmp_rax=");
                o.dec(found ? 1 : 0);
                o.str(" dispatch_rva=");
                o.hex(dispatch >= nb ? dispatch - nb : 0);
                o.nl();
            }
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'y') {
            // The CFG dispatch stub is named in the PE load config, not in the
            // import table. GuardCFDispatchFunctionPointer (+0x78) is exactly
            // the address every instrumented indirect call routes through, so
            // one qword replaces the whole image scan. Report only - patching
            // waits for a second look at the prologue.
            unsigned int lfanew = 0;
            // The client's own PE directories are stripped by the protector, so
            // read the load config from a system module instead: every guarded
            // module in this process points at the same ntdll stub.
            Module sys = find_module(fnv1a_w(L"kernel32.dll"));
            unsigned long long pb0 = reinterpret_cast<unsigned long long>(sys.base);
            if (!pb0 || !read_u32(pb0 + 0x3C, &lfanew)) { stage_mark(a, "DONE"); continue; }
            unsigned long long opt = pb0 + lfanew + 0x18;
            unsigned long long ddir = opt + 0x70 + 10 * 8;
            unsigned int lc_rva = 0, lc_size = 0;
            read_u32(ddir, &lc_rva);
            read_u32(ddir + 4, &lc_size);
            o.str("lc rva=");
            o.hex(lc_rva);
            o.str(" size=");
            o.hex(lc_size);
            o.nl();
            flush_out(a, pipe, o);
            if (!lc_rva) { stage_mark(a, "DONE"); continue; }
            unsigned long long lc = pb0 + lc_rva;
            unsigned long long chk = 0, disp = 0;
            read_u64(lc + 0x70, &chk);
            read_u64(lc + 0x78, &disp);
            o.str("cf check=");
            o.hex(chk);
            o.str(" dispatch=");
            o.hex(disp);
            o.nl();
            unsigned char pb[16] = {0};
            bool jmpr = false;
            if (disp) {
                for (int k = 0; k < 16; ++k) pb[k] = *reinterpret_cast<unsigned char*>(disp + k);
                for (int k = 0; k + 1 < 16; ++k)
                    if (pb[k] == 0xff && pb[k + 1] == 0xe0) jmpr = true;
            }
            o.str("dispatch prologue=");
            for (int k = 0; k < 16; ++k) { o.hex(pb[k]); o.str(" "); }
            o.str(jmpr ? "has_jmp_rax" : "no_jmp_rax");
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'Q') {
            // Read-only follow-up to M. M proved the client's dispatch slot is
            // not writable (VirtualProtect err 5) and that its value points
            // somewhere that is not our image. Name that module before deciding
            // anything else: a protector stub and a CFG dispatcher need
            // different answers, and guessing between them killed the client
            // once already.
            auto mod_of = [](unsigned long long addr, char* out, unsigned int cap) {
                out[0] = 0;
                auto* peb = reinterpret_cast<Peb*>(__readgsqword(0x60));
                auto* head = &peb->Ldr->InLoadOrderModuleList;
                for (auto* it = head->Flink; it != head; it = it->Flink) {
                    auto* e = CONTAINING_RECORD(it, LdrEntry, InLoadOrderLinks);
                    unsigned long long b = reinterpret_cast<unsigned long long>(e->DllBase);
                    if (!b || addr < b || addr >= b + e->SizeOfImage) continue;
                    unsigned int n = e->BaseDllName.Length / sizeof(wchar_t);
                    if (n >= cap) n = cap - 1;
                    for (unsigned int i = 0; i < n; ++i) {
                        wchar_t c = e->BaseDllName.Buffer[i];
                        out[i] = (c >= 32 && c < 127) ? static_cast<char>(c) : '?';
                    }
                    out[n] = 0;
                    return b;
                }
                return 0ull;
            };
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                o.str("guard Q bad image\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            auto& lc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            unsigned int lsz = 0, flags = 0;
            unsigned long long slot_c = 0, slot_d = 0, val_c = 0, val_d = 0;
            if (lc.VirtualAddress) {
                read_u32(base + lc.VirtualAddress, &lsz);
                if (lsz > lc.Size) lsz = lc.Size;
                if (lsz >= 0x80) {
                    read_u64(base + lc.VirtualAddress + 0x70, &slot_c);
                    read_u64(base + lc.VirtualAddress + 0x78, &slot_d);
                }
                if (lsz >= 0x94) read_u32(base + lc.VirtualAddress + 0x90, &flags);
            }
            if (slot_c) read_u64(slot_c, &val_c);
            if (slot_d) read_u64(slot_d, &val_d);
            char name[64];
            o.str("guard Q client=");
            o.hex(base);
            o.str(" lc_rva=");
            o.hex(lc.VirtualAddress);
            o.str(" lc_size=");
            o.dec(lsz);
            o.str(" dir_size=");
            o.hex(lc.Size);
            o.str(" flags=");
            o.hex(flags);
            o.nl();
            const unsigned long long addrs[4] = {slot_c, val_c, slot_d, val_d};
            const char* tags[4] = {"slot_c", "val_c ", "slot_d", "val_d "};
            for (int i = 0; i < 4; ++i) {
                if (!addrs[i]) continue;
                unsigned long long mb = mod_of(addrs[i], name, sizeof(name));
                o.str("guard Q ");
                o.str(tags[i]);
                o.str("=");
                o.hex(addrs[i]);
                o.str(" mod=");
                o.str(name);
                o.str("+");
                o.hex(mb ? addrs[i] - mb : 0);
                o.nl();
            }
            o.str("guard Q val_d_head=");
            for (int k = 0; k < 16; ++k) {
                unsigned char b = 0;
                if (readable(reinterpret_cast<const void*>(val_d + k), 1))
                    b = *reinterpret_cast<unsigned char*>(val_d + k);
                o.hex(b);
                o.ch(' ');
            }
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'z') {
            // Capture print's closure, leave its f pointing at the dispatcher,
            // then hand the same object to a chunk as an argument. The chunk
            // calls it with the sentinel; if 4080 comes back, the loop is
            // closed: Lua -> value -> closure -> CFG dispatcher -> our page.
            g_base = base;
            g_cap_closure = 0;
            exec_raw(a, pipe, o, L, base, kChunkKCaptureBody, kChunkKCaptureLen, "zcapture");
            if (!g_cap_closure) {
                o.str("api no closure\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            wr64(g_cap_closure + 0x28, reinterpret_cast<unsigned long long>(&native_api));
            o.str("api swapped clo=");
            o.hex(g_cap_closure);
            o.str(" f=");
            o.hex(g_cap_f);
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "API");
            if (!arm_cfg(a, o, reinterpret_cast<unsigned long long>(&native_api), "api cfg"))
                o.str("api cfg unarmed, calling anyway\n");
            flush_out(a, pipe, o);
            exec_protected(a, pipe, o, L, base, kZCallBody, kZCallLen, "zapi", g_cap_closure);
            o.str("api left in place\n");
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'v' || cmd[0] == 'u') {
            // Same bitmap write as U, different native body. 'v' returns the
            // moment it is entered, so a crash on 'v' can only mean the call
            // never arrived. 'u' runs the real load. One build, both answers.
            g_native_mode = (cmd[0] == 'v') ? 1 : 0;
            o.str("guard mode=");
            o.dec(static_cast<unsigned int>(g_native_mode));
            o.nl();
            flush_out(a, pipe, o);
            cmd[0] = 'U';
        }
        if (cmd[0] == 'T') {
            // The dispatcher at RobloxPlayerBeta.dll+0x4c9360 is stock CFG and
            // reads one bit out of a bitmap that measures PAGE_READWRITE in
            // this process. Dynamic code is blocked (1655) and private pages
            // cannot be opted in, so setting that bit by hand is the remaining
            // route: byte = addr >> 15, bit = (addr >> 12) & 7, exactly the
            // way the dispatcher reads it. Then the same native test as 'k'.
            Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
            unsigned long long target =
                reinterpret_cast<unsigned long long>(&native_loadstring);
            o.str("guard T target=");
            o.hex(target);
            o.nl();
            flush_out(a, pipe, o);
            if (!dll.base) {
                o.str("guard T no dll\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned long long db = reinterpret_cast<unsigned long long>(dll.base);
            unsigned long long bitmap = 0;
            read_u64(db + 0x4c9376ull + 0x9f9622ull, &bitmap);
            unsigned long long slotp = bitmap + (target >> 15);
            unsigned int bit = static_cast<unsigned int>((target >> 12) & 7);
            o.str("guard T bitmap=");
            o.hex(bitmap);
            o.str(" slot=");
            o.hex(slotp);
            o.str(" bit=");
            o.dec(bit);
            o.nl();
            flush_out(a, pipe, o);
            Mbi mbi{};
            if (!bitmap ||
                !a.VirtualQuery(reinterpret_cast<const void*>(slotp), &mbi, sizeof(mbi))) {
                o.str("guard T unreadable\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned char b0 = 0;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xff) == PAGE_READWRITE) {
                b0 = *reinterpret_cast<unsigned char*>(slotp);
            }
            o.str("guard T prot=");
            o.hex(mbi.Protect);
            o.str(" state=");
            o.hex(mbi.State);
            o.str(" region=");
            o.hex(mbi.RegionSize);
            o.str(" before=");
            o.hex(b0);
            o.nl();
            flush_out(a, pipe, o);
            if (mbi.State != MEM_COMMIT || (mbi.Protect & 0xff) != PAGE_READWRITE) {
                // The map is a 4 GB reservation covering the whole user space;
                // pages only exist where loaded images put targets. Indexing one
                // that was never committed is what killed the client here: the
                // dereference itself faults, before a single bit is set.
                o.str("guard T page not live, use U\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            *reinterpret_cast<volatile unsigned char*>(slotp) =
                static_cast<unsigned char>(b0 | (1u << bit));
            o.str("guard T after=");
            o.hex(*reinterpret_cast<unsigned char*>(slotp));
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "GUARD");
            cmd[0] = 'k';
        }
        if (cmd[0] == 'U') {
            // Same bit as T, but the page is brought in first. The map is one
            // big MEM_RESERVE, so committing our own index is a normal data
            // commit: no execute rights, nothing for the dynamic-code policy to
            // object to. Then the bit, then the native test.
            Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
            unsigned long long target =
                reinterpret_cast<unsigned long long>(&native_loadstring);
            unsigned long long db = dll.base ? reinterpret_cast<unsigned long long>(dll.base) : 0;
            unsigned long long bitmap = 0;
            if (db) read_u64(db + 0x4c9376ull + 0x9f9622ull, &bitmap);
            unsigned long long slotp = bitmap + (target >> 15);
            unsigned long long page = slotp & ~0xfffull;
            unsigned int bit = static_cast<unsigned int>((target >> 12) & 7);
            o.str("guard U target=");
            o.hex(target);
            o.str(" map=");
            o.hex(bitmap);
            o.str(" byte=");
            o.hex(slotp);
            o.str(" page=");
            o.hex(page);
            o.str(" bit=");
            o.dec(bit);
            o.nl();
            flush_out(a, pipe, o);
            if (!bitmap) {
                o.str("guard U no map\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            Mbi before_q{};
            a.VirtualQuery(reinterpret_cast<const void*>(page), &before_q, sizeof(before_q));
            o.str("guard U q_state=");
            o.hex(before_q.State);
            o.str(" q_prot=");
            o.hex(before_q.Protect);
            o.str(" q_type=");
            o.hex(before_q.Type);
            o.nl();
            if (before_q.State != MEM_COMMIT) {
                void* got = a.VirtualAlloc ? a.VirtualAlloc(reinterpret_cast<void*>(page), 0x1000,
                                                            MEM_COMMIT, PAGE_READWRITE)
                                           : nullptr;
                o.str("guard U commit=");
                o.hex(reinterpret_cast<unsigned long long>(got));
                o.str(" err=");
                o.dec(got ? 0u : static_cast<unsigned int>(a.GetLastError()));
                o.nl();
            }
            flush_out(a, pipe, o);
            Mbi q{};
            if (!a.VirtualQuery(reinterpret_cast<const void*>(page), &q, sizeof(q)) ||
                q.State != MEM_COMMIT || (q.Protect & 0xff) != PAGE_READWRITE) {
                o.str("guard U page still dead state=");
                o.hex(q.State);
                o.str(" prot=");
                o.hex(q.Protect);
                o.nl();
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned char b0 = *reinterpret_cast<unsigned char*>(slotp);
            *reinterpret_cast<volatile unsigned char*>(slotp) =
                static_cast<unsigned char>(b0 | (1u << bit));
            o.str("guard U bit ");
            o.hex(b0);
            o.str(" -> ");
            o.hex(*reinterpret_cast<unsigned char*>(slotp));
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "GUARD");
            cmd[0] = 'k';
        }
        if (cmd[0] == 'S') {
            // The dispatcher at RobloxPlayerBeta.dll+0x4c9360 is stock CFG:
            // `mov r11,[rip+0x9f9622]` loads the bitmap base, then one byte is
            // tested. So the question is not "which stub" but "can a bit be
            // set". Report what the allocator and the bitmap actually allow.
            if (!a.VirtualAlloc) {
                o.str("guard S no alloc\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            void* rx = a.VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
            o.str("guard S rwx=");
            o.hex(reinterpret_cast<unsigned long long>(rx));
            o.str(" err=");
            o.dec(rx ? 0u : static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            flush_out(a, pipe, o);
            void* rw = a.VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            o.str("guard S rw=");
            o.hex(reinterpret_cast<unsigned long long>(rw));
            o.str(" err=");
            o.dec(rw ? 0u : static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            if (rw) {
                DWORD oldp = 0;
                BOOL pr = a.VirtualProtect(rw, 0x1000, PAGE_EXECUTE_READ, &oldp);
                o.str("guard S rw->rx rc=");
                o.dec(pr ? 1u : 0u);
                o.str(" err=");
                o.dec(static_cast<unsigned int>(a.GetLastError()));
                o.nl();
            }
            flush_out(a, pipe, o);

            Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
            o.str("guard S dll=");
            o.hex(reinterpret_cast<unsigned long long>(dll.base));
            o.nl();
            if (dll.base) {
                unsigned long long db = reinterpret_cast<unsigned long long>(dll.base);
                unsigned long long global = db + 0x4c9376ull + 0x9f9622ull;
                unsigned long long bitmap = 0;
                read_u64(global, &bitmap);
                o.str("guard S bitmap_global=");
                o.hex(global);
                o.str(" bitmap=");
                o.hex(bitmap);
                o.nl();
                flush_out(a, pipe, o);
                if (bitmap) {
                    Mbi mbi{};
                    if (a.VirtualQuery(reinterpret_cast<const void*>(bitmap), &mbi, sizeof(mbi))) {
                        o.str("guard S bitmap_prot=");
                        o.hex(mbi.Protect);
                        o.str(" type=");
                        o.hex(mbi.Type);
                        o.str(" state=");
                        o.hex(mbi.State);
                        o.nl();
                        flush_out(a, pipe, o);
                        unsigned long long probe = reinterpret_cast<unsigned long long>(&cap_print);
                        unsigned long long idx = (probe >> 15) & 0x1ffffull;
                        o.str("guard S idx=");
                        o.hex(idx);
                        o.str(" byte=");
                        o.hex(*reinterpret_cast<unsigned char*>(bitmap + idx));
                        o.nl();
                    }
                }
            }
            if (rx) a.VirtualFree(rx, 0, 0x8000);
            if (rw) a.VirtualFree(rw, 0, 0x8000);
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'R') {
            // Private pages are not valid CFG call targets, which is what the
            // earlier registration ran into (87). PAGE_TARGETS_INVALID says so
            // at allocation time, and offsets can then be opted in. Nothing
            // here touches a client page: the page is ours, the stub is
            // `mov eax,42; ret`, and the proof call is direct.
            if (!a.VirtualAlloc || !a.SetProcessValidCallTargets) {
                o.str("guard R api missing\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            const DWORD kTargetsInvalid = 0x40000000;
            void* page = a.VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE | kTargetsInvalid);
            o.str("guard R page=");
            o.hex(reinterpret_cast<unsigned long long>(page));
            o.str(" alloc_err=");
            o.dec(page ? 0u : static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            flush_out(a, pipe, o);
            if (!page) {
                stage_mark(a, "DONE");
                continue;
            }
            unsigned char* pc = static_cast<unsigned char*>(page);
            pc[0] = 0xb8;  // mov eax, 42
            pc[1] = 0x2a;
            pc[2] = 0;
            pc[3] = 0;
            pc[4] = 0;
            pc[5] = 0xc3;  // ret
            static CfgCallTargetInfo rinfo[1];
            rinfo[0].Offset = 0;
            rinfo[0].Flags = 1;
            HANDLE self = reinterpret_cast<HANDLE>(static_cast<long long>(-1));
            BOOL rc = a.SetProcessValidCallTargets(self, page, 0x1000, 1, rinfo);
            o.str("guard R register rc=");
            o.dec(rc ? 1u : 0u);
            o.str(" err=");
            o.dec(static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            int v = reinterpret_cast<int (*)()>(page)();
            o.str("guard R stub_direct=");
            o.dec(static_cast<unsigned int>(v));
            o.nl();
            flush_out(a, pipe, o);
            HANDLE f = a.CreateFileA("D:\\zendo\\work\\trust_page.bin", GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (f != INVALID_HANDLE_VALUE) {
                DWORD w = 0;
                a.WriteFile(f, &page, 8, &w, nullptr);
                a.CloseHandle(f);
            }
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'M') {
            // Run 2 without the walk that killed the client at stage 'x'. The
            // client image names its own dispatch slot in the load config:
            // offset 0x78 is GuardCFDispatchFunctionPointer, the address of
            // that image's __guard_dispatch_icall_fptr. Read it, report what
            // it holds, then point it at ntdll's own `jmp rax` stub. One 8-byte
            // write to a data page: no scan, no code patch, no icache flush.
            // If the slot already holds that stub, nothing is written and the
            // native test runs as-is - which answers the question either way.
            Module ntdll = find_module(fnv1a_w(L"ntdll.dll"));
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (!ntdll.base || dos->e_magic != IMAGE_DOS_SIGNATURE) {
                o.str("guard M bad image\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            auto& lc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            unsigned long long nb = reinterpret_cast<unsigned long long>(ntdll.base);
            auto* ndos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll.base);
            auto* nnt = reinterpret_cast<IMAGE_NT_HEADERS*>(nb + ndos->e_lfanew);
            auto& nlc = nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

            unsigned long long slot = 0, nslot = 0, nop = 0;
            if (lc.VirtualAddress && lc.Size >= 0x80)
                read_u64(base + lc.VirtualAddress + 0x78, &slot);
            if (nlc.VirtualAddress && nlc.Size >= 0x80) {
                read_u64(nb + nlc.VirtualAddress + 0x78, &nslot);
                read_u64(nslot, &nop);
            }
            unsigned char nop0 = 0, nop1 = 0;
            if (nop && readable(reinterpret_cast<const void*>(nop), 2)) {
                nop0 = *reinterpret_cast<unsigned char*>(nop);
                nop1 = *reinterpret_cast<unsigned char*>(nop + 1);
            }
            o.str("guard M client=");
            o.hex(base);
            o.str(" ldcfg=");
            o.hex(lc.VirtualAddress);
            o.str(" slot=");
            o.hex(slot);
            o.str(" ntdll_slot=");
            o.hex(nslot);
            o.str(" stub=");
            o.hex(nop);
            o.str(" stub_ok=");
            o.dec((nop0 == 0xff && nop1 == 0xe0) ? 1 : 0);
            o.nl();
            flush_out(a, pipe, o);
            if (!slot) {
                o.str("guard M no slot\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned long long held = 0;
            read_u64(slot, &held);
            o.str("guard M held=");
            o.hex(held);
            o.str(" rva=");
            o.hex(held >= nb ? held - nb : 0);
            o.str(" head=");
            for (int k = 0; k < 16; ++k) {
                unsigned char b = 0;
                if (readable(reinterpret_cast<const void*>(held + k), 1))
                    b = *reinterpret_cast<unsigned char*>(held + k);
                o.hex(b);
                o.ch(' ');
            }
            o.nl();
            flush_out(a, pipe, o);

            if (nop0 == 0xff && nop1 == 0xe0 && held != nop) {
                DWORD oldp = 0;
                if (!a.VirtualProtect(reinterpret_cast<void*>(slot), 8, PAGE_READWRITE, &oldp)) {
                    o.str("guard M protect failed=");
                    o.dec(static_cast<unsigned int>(a.GetLastError()));
                    o.nl();
                    flush_out(a, pipe, o);
                    stage_mark(a, "DONE");
                    continue;
                }
                wr64(slot, nop);
                DWORD tmp = 0;
                a.VirtualProtect(reinterpret_cast<void*>(slot), 8, oldp, &tmp);
                unsigned long long back = 0;
                read_u64(slot, &back);
                o.str("guard M slot->stub readback=");
                o.hex(back);
                o.nl();
                flush_out(a, pipe, o);
            } else if (held == nop) {
                o.str("guard M slot already stub\n");
                flush_out(a, pipe, o);
            } else {
                // No nop stub in ntdll's own slot: patch the dispatcher body
                // instead. The target arrives in rax (proven by the entry's
                // `mov r10, rax`), so `48 ff e0` is a complete replacement.
                DWORD oldp = 0;
                if (!a.VirtualProtect(reinterpret_cast<void*>(held), 0x10,
                                      PAGE_EXECUTE_READWRITE, &oldp)) {
                    o.str("guard M code protect failed=");
                    o.dec(static_cast<unsigned int>(a.GetLastError()));
                    o.nl();
                    flush_out(a, pipe, o);
                    stage_mark(a, "DONE");
                    continue;
                }
                *reinterpret_cast<unsigned char*>(held) = 0x48;
                *reinterpret_cast<unsigned char*>(held + 1) = 0xff;
                *reinterpret_cast<unsigned char*>(held + 2) = 0xe0;
                if (a.FlushInstructionCache)
                    a.FlushInstructionCache(INVALID_HANDLE_VALUE,
                                            reinterpret_cast<void*>(held), 3);
                DWORD tmp = 0;
                a.VirtualProtect(reinterpret_cast<void*>(held), 0x10, oldp, &tmp);
                o.str("guard M dispatcher patched\n");
                flush_out(a, pipe, o);
            }
            stage_mark(a, "GUARD");
            cmd[0] = 'k';
        }
        if (cmd[0] == 'x') {
            // Disabled after the client died mid-walk. The load config names
            // the same target without touching 16 MB of protected pages.
            o.str("guard x disabled, use M\n");
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'X') {
            // CFG has no bitmap entry for MEM_PRIVATE pages, and the policy
            // cannot be relaxed at runtime (err 5). The check itself lives in
            // ntdll's dispatch stub: every instrumented indirect call is a
            // `call qword ptr [rip+x]` to one shared pointer. Find that pointer
            // by counting which ntdll address the client's call sites point at
            // most often, then replace the stub body with `jmp rax` - the
            // target already arrives in rax.
            Module ntdll = find_module(fnv1a_w(L"ntdll.dll"));
            o.str("guard ntdll=");
            o.hex(reinterpret_cast<unsigned long long>(ntdll.base));
            o.nl();
            flush_out(a, pipe, o);
            if (!ntdll.base) { stage_mark(a, "DONE"); continue; }
            unsigned long long lo = reinterpret_cast<unsigned long long>(ntdll.base);
            unsigned long long hi = lo + ntdll.size;
            unsigned long long cbase = base;
            unsigned long long cend = base + 0x1000000ull;
            unsigned long long hit = 0;
            static unsigned long long cand_p[192];
            static unsigned int cand_n[192];
            unsigned int ncand = 0;
            auto* p = reinterpret_cast<const unsigned char*>(cbase);
            unsigned long long n = cend - cbase;
            // The protector leaves whole pages PAGE_NOACCESS until they run, so
            // a linear read crashes. Walk one page at a time and only touch
            // pages that are actually readable.
            for (unsigned long long i = 0; i + 6 < n; ++i) {
                if ((i & 0xfff) == 0) {
                    Mbi mbi{};
                    if (!a.VirtualQuery(p + i, &mbi, sizeof(mbi))) { i += 0xfff; continue; }
                    DWORD prot = mbi.Protect & 0xff;
                    bool okp = mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
                               (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                                prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                                prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
                    if (!okp) {
                        unsigned long long skip = 0x1000 - (i & 0xfff);
                        i += skip - 1;
                        continue;
                    }
                }
                if (p[i] != 0xff || p[i + 1] != 0x15) continue;
                int disp = *reinterpret_cast<const int*>(p + i + 2);
                unsigned long long slot = cbase + i + 6 + static_cast<long long>(disp);
                if (slot < cbase || slot + 8 > cend) continue;
                unsigned long long tgt = 0;
                if (!read_u64(slot, &tgt)) continue;
                if (tgt < lo || tgt >= hi) continue;
                unsigned int j = 0;
                for (; j < ncand; ++j) {
                    if (cand_p[j] == tgt) { ++cand_n[j]; break; }
                }
                if (j == ncand && ncand < 192) {
                    cand_p[ncand] = tgt;
                    cand_n[ncand] = 1;
                    ++ncand;
                }
                // The dispatch stub always ends in `jmp rax`. A target that has
                // one near its head is the stub itself, so stop right there
                // instead of scanning the rest of the image.
                bool has = false;
                for (int k = 0; k < 0x40; ++k) {
                    unsigned char b0 = *reinterpret_cast<unsigned char*>(tgt + k);
                    unsigned char b1 = *reinterpret_cast<unsigned char*>(tgt + k + 1);
                    if (b0 == 0xff && b1 == 0xe0) { has = true; break; }
                }
                if (has) { hit = tgt; break; }
            }
            unsigned int best = 0;
            for (unsigned int j = 1; j < ncand; ++j)
                if (cand_n[j] > cand_n[best]) best = j;
            if (!hit && !ncand) {
                o.str("guard no candidate\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned long long fn = hit ? hit : cand_p[best];
            o.str("guard fn=");
            o.hex(fn);
            o.str(" hits=");
            o.dec(cand_n[best]);
            o.str(" cands=");
            o.dec(ncand);
            o.str(" bytes=");
            unsigned char pb[8] = {0};
            for (int k = 0; k < 8; ++k) pb[k] = *reinterpret_cast<unsigned char*>(fn + k);
            for (int k = 0; k < 8; ++k) { o.hex(pb[k]); o.str(" "); }
            o.nl();
            flush_out(a, pipe, o);
            // Sanity: a guarded dispatch stub must jump through rax somewhere
            // near its head. Anything else means the histogram picked noise.
            bool looks = false;
            for (int k = 0; k < 0x40; ++k) {
                unsigned char b0 = *reinterpret_cast<unsigned char*>(fn + k);
                unsigned char b1 = *reinterpret_cast<unsigned char*>(fn + k + 1);
                if (b0 == 0xff && b1 == 0xe0) { looks = true; break; }
            }
            if (!looks) {
                o.str("guard no jmp rax in head, not patching\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            DWORD oldp = 0;
            if (!a.VirtualProtect(reinterpret_cast<void*>(fn), 0x1000,
                                  PAGE_EXECUTE_READWRITE, &oldp)) {
                o.str("guard protect failed=");
                o.dec(static_cast<unsigned int>(a.GetLastError()));
                o.nl();
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            *reinterpret_cast<unsigned char*>(fn) = 0x48;
            *reinterpret_cast<unsigned char*>(fn + 1) = 0xff;
            *reinterpret_cast<unsigned char*>(fn + 2) = 0xe0;
            DWORD tmp = 0;
            a.VirtualProtect(reinterpret_cast<void*>(fn), 0x1000, oldp, &tmp);
            o.str("guard patched\n");
            flush_out(a, pipe, o);
            stage_mark(a, "GUARD");
            cmd[0] = 'k';
        }
        if (cmd[0] == 'k') {
            // The whole question in one command: can Luau call into this
            // payload at all? A C closure taken from the globals gets its
            // function pointer swapped for native_loadstring and is then called
            // from a chunk. That call is indirect, through the client image,
            // into a manual-mapped page.
            g_base = base;
            g_cap_closure = 0;
            exec_raw(a, pipe, o, L, base, kChunkKCaptureBody, kChunkKCaptureLen, "kcapture");
            if (!g_cap_closure) {
                o.str("native no C closure captured\n");
                flush_out(a, pipe, o);
                continue;
            }
            unsigned long long old_f = 0;
            read_u64(g_cap_closure + 0x28, &old_f);
            wr64(g_cap_closure + 0x28, reinterpret_cast<unsigned long long>(&native_loadstring));
            o.str("native swapped clo=");
            o.hex(g_cap_closure);
            o.str(" f=");
            o.hex(old_f);
            o.str(" mode=");
            o.dec(static_cast<unsigned int>(g_native_mode));
            o.nl();
            flush_out(a, pipe, o);
            {
                // Read the guard bit right now, not at the time it was set: if
                // the protector resets the map between the write and the call,
                // this is where it shows.
                Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
                unsigned long long tgt =
                    reinterpret_cast<unsigned long long>(&native_loadstring);
                unsigned long long bitmap = 0;
                if (dll.base) {
                    unsigned long long db = reinterpret_cast<unsigned long long>(dll.base);
                    read_u64(db + 0x4c9376ull + 0x9f9622ull, &bitmap);
                }
                if (bitmap) {
                    unsigned long long bp = bitmap + (tgt >> 15);
                    Mbi q{};
                    a.VirtualQuery(reinterpret_cast<const void*>(bp), &q, sizeof(q));
                    unsigned char cur = 0;
                    if (q.State == MEM_COMMIT && (q.Protect & 0xff) == PAGE_READWRITE)
                        cur = *reinterpret_cast<unsigned char*>(bp);
                    o.str("native guard bit=");
                    o.hex(cur);
                    o.str(" want=");
                    o.hex(1u << static_cast<unsigned int>((tgt >> 12) & 7));
                    o.str(" page_state=");
                    o.hex(q.State);
                    o.nl();
                    flush_out(a, pipe, o);
                }
            }
            stage_mark(a, "NATIVE");
            exec_raw(a, pipe, o, L, base, kChunkKNativeBody, kChunkKNativeLen, "knative");
            wr64(g_cap_closure + 0x28, old_f);
            o.str("native restored\n");
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'g') {
            // Everything that decides whether the client VM may call our code:
            // what kind of pages we live on, whether CFG accepts them, and
            // whether the CFG policy can still be relaxed at runtime.
            Mbi mbi{};
            unsigned long long fn = reinterpret_cast<unsigned long long>(&cap_print);
            if (a.VirtualQuery(reinterpret_cast<const void*>(fn), &mbi, sizeof(mbi))) {
                o.str("mitig page state=");
                o.hex(mbi.State);
                o.str(" type=");
                o.hex(mbi.Type);
                o.str(" prot=");
                o.hex(mbi.Protect);
                o.str(" allocbase=");
                o.hex(reinterpret_cast<unsigned long long>(mbi.AllocationBase));
                o.nl();
            }
            int cfg_rc = cfg_register(reinterpret_cast<void*>(fn));
            o.str("mitig cfg_register=");
            o.dec(static_cast<unsigned int>(cfg_rc));
            o.nl();
            flush_out(a, pipe, o);
            struct CfgFlags { unsigned int raw; };
            CfgFlags off{0};
            if (a.SetProcessMitigationPolicy) {
                BOOL r = a.SetProcessMitigationPolicy(7, &off, sizeof(off));
                o.str("mitig cfg_off rc=");
                o.dec(r);
                o.str(" err=");
                o.dec(static_cast<unsigned int>(a.GetLastError()));
                o.nl();
            } else {
                o.str("mitig cfg_off unavailable\n");
            }
            flush_out(a, pipe, o);
            continue;
        }
        if (cmd[0] == 'j' || cmd[0] == 'h' || cmd[0] == 'H' || cmd[0] == 'J') {
            int saved = g_cap_mode;
            g_cap_mode = (cmd[0] == 'j') ? 0 : (cmd[0] == 'h') ? 1 : (cmd[0] == 'H') ? 2 : 3;
            o.str("probe mode=");
            o.dec(g_cap_mode);
            o.str(" clo=");
            o.hex(g_cap_closure);
            o.str(" f=");
            o.hex(g_cap_f);
            o.nl();
            flush_out(a, pipe, o);
            exec_raw(a, pipe, o, L, base, kChunkProbe, kChunkProbeLen, "probe");
            o.str("probe calls=");
            o.dec(g_cap_calls);
            o.str(" cfg=");
            o.dec(static_cast<unsigned int>(g_cfg_status));
            o.nl();
            flush_out(a, pipe, o);
            g_cap_mode = saved;
            continue;
        }
        if (cmd[0] == 'P' || cmd[0] == 'E' || cmd[0] == 'S' || cmd[0] == 'T' || cmd[0] == 'R' || cmd[0] == 'V' || cmd[0] == 'F' || cmd[0] == 'C' || cmd[0] == 'D' || cmd[0] == 'W' || cmd[0] == 'X') {
            const unsigned char* pb = kChunkC33Body;
            unsigned int pl = kChunkC33Len;
            const char* pn = "protected ok";
            if (cmd[0] == 'E') { pb = kChunkC32Body; pl = kChunkC32Len; pn = "protected error"; }
            if (cmd[0] == 'S') { pb = kChunkC35Body; pl = kChunkC35Len; pn = "err plain"; }
            if (cmd[0] == 'T') { pb = kChunkC36Body; pl = kChunkC36Len; pn = "pcall err builtin"; }
            if (cmd[0] == 'R') { pb = kChunkC37Body; pl = kChunkC37Len; pn = "err vm nilindex"; }
            if (cmd[0] == 'V') { pb = kChunkC39Body; pl = kChunkC39Len; pn = "pcall lua err"; }
            if (cmd[0] == 'F') { pb = kChunkC40Body; pl = kChunkC40Len; pn = "pcall fn"; }
            if (cmd[0] == 'C') {
                o.str("RUN raw ok\n");
                flush_out(a, pipe, o);
                exec_raw(a, pipe, o, L, base, kChunkC33Body, kChunkC33Len, "raw ok");
                continue;
            }
            if (cmd[0] == 'D') {
                o.str("RUN raw err\n");
                flush_out(a, pipe, o);
                exec_raw(a, pipe, o, L, base, kChunkC35Body, kChunkC35Len, "raw err");
                continue;
            }
            if (cmd[0] == 'W') {
                o.str("RUN raw nested closure\n");
                flush_out(a, pipe, o);
                exec_raw(a, pipe, o, L, base, kChunkC41Body, kChunkC41Len, "raw c41");
                continue;
            }
            if (cmd[0] == 'X') {
                o.str("RUN raw upval error\n");
                flush_out(a, pipe, o);
                exec_raw(a, pipe, o, L, base, kChunkC42Body, kChunkC42Len, "raw c42");
                continue;
            }
            o.str("RUN ");
            o.str(pn);
            o.nl();
            flush_out(a, pipe, o);
            exec_protected(a, pipe, o, L, base, pb, pl, pn);
            continue;
        }
        const ReplEntry* hit = nullptr;
        for (unsigned int i = 0; i < sizeof(kReplTable) / sizeof(kReplTable[0]); ++i)
            if (kReplTable[i].cmd == cmd[0]) hit = &kReplTable[i];
        if (!hit) {
            o.str("unknown cmd\n");
            flush_out(a, pipe, o);
            continue;
        }
        o.str("RUN ");
        o.str(hit->name);
        o.nl();
        flush_out(a, pipe, o);
        g_veh_phase = hit->name;
        g_sentinel = (hit->cmd == 'z' || hit->cmd == 'Z');
        exec_chunk(a, pipe, o, L, base, hit->body, hit->len, hit->name);
        g_sentinel = false;
    }

    // Session over: the closure slot goes back to the game's own print, and the
    // capture mode is retired with it. The store is guarded: this object is a
    // GC closure, and between sessions the collector may already have taken it
    // back. A blind store there is what ended the payload thread right after
    // `q` and left the client alive with an abandoned mutex.
    if (g_api_live && g_cap_closure && g_cap_f)
        wr64_live(g_cap_closure + 0x28, g_cap_f);
    g_api_live = 0;
    g_cap_mode = 0;
    g_cap_closure = 0;
    g_cap_f = 0;

    g_declared_size = 0;
    g_patch_proto = 0;
    o.str("END\n");
    flush_out(a, pipe, o);
    return 0;
}

// One injection, many sessions. The payload keeps the borrowed thread open and
// waits for the next pipe server instead of returning from DllMain, so the UI
// can push another chunk without re-mapping the image. 90 s with no server at
// all and the thread goes back to the stub, so a dead UI cannot leave a stray
// image pinned in the client forever.
inline DWORD run_repl() {
    DWORD st = resolve_api();
    if (st) {
        stage_mark(api(), "EXIT-API");
        return 100 + st;
    }
    Api& a = api();
    stage_mark(a, "E1-API");
    // No single-instance guard here. A mutex was tried twice and both versions
    // hurt: the first rejected the second injection outright, the second parked
    // the borrowed thread for seconds and the client dropped its websocket. The
    // pipe session is the only authority on who is live, so nothing else talks.
    stage_mark(a, "E2-OWN");

    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    // Every offset below is a number from one specific client build. On any
    // other build those writes land in unrelated code and the client dies with
    // no explanation, so prove the build before touching anything. The build id
    // is the directory name the loader already recorded, which costs no PE
    // parsing and no imports.
    LdrEntry* exe_entry = find_module_entry(fnv1a_w(L"RobloxPlayerBeta.exe"));
    if (!exe_entry || !wide_contains(exe_entry->FullDllName, k_build_tag)) {
        stage_mark(a, "EARGS-BUILD");
        return 120;
    }
    if (!offsets_ok(base, exe)) {
        char tb[12] = {'E', 'A', 'R', 'G', 'S', '-', 'O', 'F', 'F', '0', 0, 0};
        tb[9] = static_cast<char>('0' + g_off_fail);
        stage_mark(a, tb);
        return 121;
    }
    stage_mark(a, "E3-GATE");
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    stage_mark(a, "E4-DM");
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        for (int i = 0; i < 100; ++i) {
            HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev",
                                        GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                        OPEN_EXISTING, 0, nullptr);
            if (pipe == INVALID_HANDLE_VALUE) {
                if (a.Sleep) a.Sleep(100);
                continue;
            }
            static Out o;
            o.reset();
            o.str("no state\nEND\n");
            flush_out(a, pipe, o);
            a.CloseHandle(pipe);
            break;
        }
        stage_mark(a, "EXIT-NOSTATE");
        return 111;
    }

    unsigned int idle = 0;
    stage_mark(a, "SEEK");
    for (;;) {
        HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev",
                                    GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            if ((idle++ % 100) == 0) stage_mark(a, "SEEK");
            // Twenty minutes, not one second. A session is one run; the next run
            // creates a new server and this loop is what connects to it. Bailing
            // out early is what forced a fresh injection (and a fresh image) for
            // every script, which is the opposite of what a repeated test loop
            // needs.
            if (idle > 24000) {
                // Leave DllMain: the stub restores the borrowed thread's
                // original context, so nothing is left parked inside this
                // client for a watchdog to find.
                stage_mark(a, "EXIT-IDLE");
                return 111;
            }
            if (!a.Sleep) {
                stage_mark(a, "EXIT-NOSLEEP");
                return 2;
            }
            a.Sleep(50);
            continue;
        }
        idle = 0;
        beacon(a, "PIPE");
        serve_session(a, pipe, base, L);
        g_cap_pipe = INVALID_HANDLE_VALUE;
        stage_mark(a, "PRE-CLOSE");
        a.CloseHandle(pipe);
        stage_mark(a, "POST");
        loop_mark(a, ++g_loop_n);
        if (g_leave) {
            stage_mark(a, "EXIT-DETACH");
            return 111;
        }
        // The server that just ended is still closing its instance. Give it a
        // moment so this loop reconnects to the next server, not the corpse.
        if (a.Sleep) a.Sleep(150);
        // Heartbeat: the number grows only while this thread keeps looping, so
        // two reads of work/loop.bin a few seconds apart answer "is the payload
        // still alive" without a debugger and without a second injection.
        loop_mark(a, ++g_loop_n);
    }
}

// One line of ground truth about the live mutex: the handle, the CreateMutex
// error, and what a zero-timeout wait says. A wait of 0x102 (WAIT_TIMEOUT)
// means some thread still owns it; 0x80 (WAIT_ABANDONED) means the owner died.
// This file is not overwritten by the seek loop, so it survives a session end.
inline void mutex_diag(Api& a, HANDLE h) {
    char buf[96];
    char* p = buf;
    const char* pre = "h=";
    while (*pre) *p++ = *pre++;
    p = append_hex(p, reinterpret_cast<unsigned long long>(h));
    const char* mid = " e=";
    while (*mid) *p++ = *mid++;
    DWORD e = a.GetLastError ? a.GetLastError() : 0;
    if (e == 0) { *p++ = '0'; } else {
        char tmp[8]; int n = 0;
        while (e) { tmp[n++] = static_cast<char>('0' + (e % 10)); e /= 10; }
        while (n) *p++ = tmp[--n];
    }
    // ReleaseMutex answers the only question that matters: did this thread
    // actually take the mutex? 1 means the create-time owner flag worked and
    // the host will read WAIT_TIMEOUT while this thread lives. 0 means the
    // handle exists without ownership and the host is right to call it dead.
    DWORD r = (h && a.ReleaseMutex) ? a.ReleaseMutex(h) : 0;
    const char* rel = " r=";
    while (*rel) *p++ = *rel++;
    *p++ = static_cast<char>('0' + (r ? 1 : 0));
    if (r && a.WaitForSingleObject) {
        // Take it back: the handle is meant to stay owned for the life of the
        // thread, the release was only a measurement.
        a.WaitForSingleObject(h, 0);
    }
    const char* wt = " w=";
    while (*wt) *p++ = *wt++;
    DWORD w = 0;
    if (h && a.WaitForSingleObject) w = a.WaitForSingleObject(h, 0);
    if (w == 0) { *p++ = '0'; } else {
        char tmp[8]; int n = 0;
        while (w) { tmp[n++] = static_cast<char>('0' + (w % 10)); w /= 10; }
        while (n) *p++ = tmp[--n];
    }
    *p++ = '\n';
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\mutex.bin", GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    a.WriteFile(f, buf, static_cast<DWORD>(p - buf), &wrote, nullptr);
    a.CloseHandle(f);
}

// Same as STAGE_MARK but a different file, and it takes a number: proof that
// the seek loop is still iterating after a session ended. The stage file is
// overwritten by whatever runs last, so it cannot answer that question.
inline void loop_mark(Api& a, unsigned int n) {
    char buf[16];
    char* p = buf;
    unsigned int v = n;
    char tmp[12]; int k = 0;
    if (v == 0) tmp[k++] = '0';
    while (v) { tmp[k++] = static_cast<char>('0' + (v % 10)); v /= 10; }
    while (k) *p++ = tmp[--k];
    *p++ = '\n';
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\loop.bin", GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    a.WriteFile(f, buf, static_cast<DWORD>(p - buf), &wrote, nullptr);
    a.CloseHandle(f);
}

inline DWORD beacon() {
    g_veh_tid = __readgsqword(0x48);
    // Claim the one-payload slot. Nothing else in the image created this
    // mutex, which is why every run of the executor read "no session": the
    // host was asking a question nobody had answered. The handle is never
    // released on purpose - owning it for the life of the thread is what says
    // "a payload is parked here". The kernel abandons it when this thread
    // dies, so a dead payload reads as no session instead of blocking injects.
    //
    // resolve_api first: the table is zeroed until someone fills it, and a
    // null import here is not a failed call, it is a jump to address zero in
    // the middle of a borrowed game thread.
    if (!api().CreateMutexA) resolve_api();
    static HANDLE live = nullptr;
    if (!live && api().CreateMutexA)
        live = api().CreateMutexA(nullptr, TRUE, "zendo-live");
    mutex_diag(api(), live);
#if ZENDO_STAGE == 65
    return 111;
#elif ZENDO_STAGE == 64
    return run_repl();
#elif ZENDO_STAGE == 63
    return run_batch();
#elif ZENDO_STAGE == 62
    return run_opmap_live();
#elif ZENDO_STAGE == 61
    return run_rawexec();
#elif ZENDO_STAGE == 60
    return run_opmap2();
#elif ZENDO_STAGE == 59
    return run_opmap();
#elif ZENDO_STAGE == 57
    return run_dispatch();
#elif ZENDO_STAGE == 56
    return run_optable();
#elif ZENDO_STAGE == 55
    return run_bigexec();
#elif ZENDO_STAGE == 54
    return run_fakesize();
#elif ZENDO_STAGE == 53
    return run_src();
#elif ZENDO_STAGE == 52
    return run_unseal();
#elif ZENDO_STAGE == 51
    return run_loadtest();
#elif ZENDO_STAGE == 50
    return run_verify();
#elif ZENDO_STAGE == 49
    return run_ident();
#elif ZENDO_STAGE == 48
    return run_ctxfields();
#elif ZENDO_STAGE == 47
    return run_id();
#elif ZENDO_STAGE == 46
    return run_slot();
#elif ZENDO_STAGE == 45
    return run_bits();
#elif ZENDO_STAGE == 44
    return run_ctx();
#elif ZENDO_STAGE == 43
    return run_caps();
#elif ZENDO_STAGE == 42
    return run_tls();
#elif ZENDO_STAGE == 41
    return run_protected();
#elif ZENDO_STAGE == 40
    return run_pcall();
#elif ZENDO_STAGE == 39
    return run_seh(0, 13);
#elif ZENDO_STAGE == 38
    return run_seh(0, 12);
#elif ZENDO_STAGE == 37
    return run_seh(0, 11);
#elif ZENDO_STAGE == 36
    return run_seh(0, 10);
#elif ZENDO_STAGE == 35
    return run_seh(0, 9);
#elif ZENDO_STAGE == 34
    return run_seh(0, 8);
#elif ZENDO_STAGE == 33
    return run_seh(0, 7);
#elif ZENDO_STAGE == 32
    return run_seh(0, 6);
#elif ZENDO_STAGE == 31
    return run_seh(0, 5);
#elif ZENDO_STAGE == 30
    return run_seh(0, 4);
#elif ZENDO_STAGE == 29
    return run_seh(0, 3);
#elif ZENDO_STAGE == 28
    return run_seh(0, 2);
#elif ZENDO_STAGE == 27
    return run_seh(0, 1);
#elif ZENDO_STAGE == 26
    return run_seh(2, 0);
#elif ZENDO_STAGE == 25
    return run_seh(0, 0);
#elif ZENDO_STAGE == 24
    return run_seh(1, 0);
#elif ZENDO_STAGE == 23
    return run_step();
#elif ZENDO_STAGE == 21
    return run_diag_call();
#elif ZENDO_STAGE == 20
    return run_diag_only();
#elif ZENDO_STAGE == 19
    return run_exec();
#elif ZENDO_STAGE == 18
    return run_bc();
#elif ZENDO_STAGE == 17
    return run_chunk();
#elif ZENDO_STAGE == 16
    return run_ls();
#elif ZENDO_STAGE == 15
    return run_load();
#elif ZENDO_STAGE == 14
    return run_tree();
#elif ZENDO_STAGE == 13
    return run_probe(false, true);
#elif ZENDO_STAGE == 12
    return run_probe(true, false);
#elif ZENDO_STAGE == 11
    return run_probe(false, false);
#elif ZENDO_STAGE == 1
    return 11;
#elif ZENDO_STAGE == 2
    return 20 + resolve_api();
#elif ZENDO_STAGE == 10
    {
        DWORD st = resolve_api();
        if (st) return 30 + st;
        HANDLE f = api().CreateFileA("C:\\Users\\ezan\\AppData\\Local\\Temp\\zendo_stage.txt",
                                     GENERIC_WRITE, 1, nullptr, 2 /*CREATE_ALWAYS*/, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) return 101;
        DWORD w = 0;
        api().WriteFile(f, "stage10 alive\n", 14, &w, nullptr);
        api().CloseHandle(f);
        return 100;
    }
#elif ZENDO_STAGE == 9
    {
        DWORD st = resolve_api();
        if (st) return 30 + st;
        HANDLE p = api().CreateFileA(nullptr, 0, 0, nullptr, 3, 0, nullptr);
        if (p == INVALID_HANDLE_VALUE) return 90;
        api().CloseHandle(p);
        return 91;
    }
#elif ZENDO_STAGE == 7
    {
        DWORD st = resolve_api();
        if (st) return 30 + st;
        HANDLE p = api().CreateFileA("C:\\Windows\\win.ini", GENERIC_READ,
                                     1, nullptr, OPEN_EXISTING, 0, nullptr);
        if (p == INVALID_HANDLE_VALUE) return 70;
        api().CloseHandle(p);
        return 71;
    }
#elif ZENDO_STAGE == 8
    {
        DWORD st = resolve_api();
        if (st) return 30 + st;
        return (DWORD)((unsigned long long)api().CreateFileA - (unsigned long long)api().Sleep);
    }
#elif ZENDO_STAGE == 5
    {
        DWORD st = resolve_api();
        if (st) return 30 + st;
        api().GetLastError();
        return 50;
    }
#elif ZENDO_STAGE == 6
    {
        DWORD st = resolve_api();
        if (st) return 30 + st;
        api().Sleep(1);
        return 60;
    }
#elif ZENDO_STAGE == 3
    {
        DWORD st = resolve_api();
        if (st) return 30 + st;
        HANDLE p = api().CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                     0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (p == INVALID_HANDLE_VALUE) return 40;
        api().CloseHandle(p);
        return 41;
    }
#else
    DWORD st = resolve_api();
    if (st) return st;
#endif
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    char msg[96];
    char* p = msg;
    const char* pre = "ZEND1 hello from payload base=";
    while (*pre) *p++ = *pre++;
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    p = append_hex(p, reinterpret_cast<unsigned long long>(exe.base));
    *p++ = '\n';
    DWORD written = 0;
    if (!a.WriteFile(pipe, msg, static_cast<DWORD>(p - msg), &written, nullptr)) return 3;
    char buf[128];
    DWORD read = 0;
    DWORD code = 4;
    if (a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr) && read >= 4) {
        const char reply[] = "ZEND1 ack\n";
        a.WriteFile(pipe, reply, sizeof(reply) - 1, &written, nullptr);
        code = 5;
    }
    a.CloseHandle(pipe);
    return code;
}

// The hijack stub hands the saved CONTEXT over as the third DllMain argument,
// so the borrowed game thread does not have to be released by the stub itself.
// The session runs here, and when it ends we reload that context: the thread
// continues in the wait it was taken from instead of staying pinned inside this
// manually mapped image until the client notices and dies.
static unsigned long long g_restore_ctx = 0;

inline void leave_thread() {
    if (!g_restore_ctx) return;
    using RestoreFn = void(WINAPI*)(void*, unsigned char);
    Module nt = find_module(fnv1a_w(L"ntdll.dll"));
    RestoreFn restore = nullptr;
    if (nt.base)
        restore = reinterpret_cast<RestoreFn>(find_export(nt.base, fnv1a("RtlRestoreContext")));
    unsigned long long ctx = g_restore_ctx;
    g_restore_ctx = 0;
    if (restore) restore(reinterpret_cast<void*>(ctx), 0);
}

}  // namespace zendo

extern "C" BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        zendo::g_restore_ctx = reinterpret_cast<unsigned long long>(reserved);
        DWORD code = zendo::beacon();
        zendo::leave_thread();
        return code;
    }
    return TRUE;
}
