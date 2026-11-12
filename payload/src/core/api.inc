
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
    using PeekNamedPipe_t = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
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
    using CreateThread_t = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                           LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using GetExitCodeThread_t = BOOL(WINAPI*)(HANDLE, LPDWORD);

    CreateFileA_t CreateFileA;
    CreateMutexA_t CreateMutexA;
    WaitForSingleObject_t WaitForSingleObject;
    ReleaseMutex_t ReleaseMutex;
    WriteFile_t WriteFile;
    ReadFile_t ReadFile;
    PeekNamedPipe_t PeekNamedPipe;
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
    CreateThread_t CreateThread;
    GetExitCodeThread_t GetExitCodeThread;
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
    a.PeekNamedPipe = reinterpret_cast<Api::PeekNamedPipe_t>(find_export(k32.base, fnv1a("PeekNamedPipe")));
    a.CloseHandle = reinterpret_cast<Api::CloseHandle_t>(find_export(k32.base, fnv1a("CloseHandle")));
    a.Sleep = reinterpret_cast<Api::Sleep_t>(find_export(k32.base, fnv1a("Sleep")));
    a.GetLastError = reinterpret_cast<Api::GetLastError_t>(find_export(k32.base, fnv1a("GetLastError")));
    a.VirtualQuery = reinterpret_cast<Api::VirtualQuery_t>(find_export(k32.base, fnv1a("VirtualQuery")));
    a.VirtualProtect = reinterpret_cast<Api::VirtualProtect_t>(find_export(k32.base, fnv1a("VirtualProtect")));
    a.VirtualAlloc = reinterpret_cast<Api::VirtualAlloc_t>(find_export(k32.base, fnv1a("VirtualAlloc")));
    a.VirtualFree = reinterpret_cast<Api::VirtualFree_t>(find_export(k32.base, fnv1a("VirtualFree")));
    a.CreateThread = reinterpret_cast<Api::CreateThread_t>(find_export(k32.base, fnv1a("CreateThread")));
    a.GetExitCodeThread =
        reinterpret_cast<Api::GetExitCodeThread_t>(find_export(k32.base, fnv1a("GetExitCodeThread")));
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

