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

// One translation unit, assembled from role files. The order below is the
// order the code grew in, and it must not change: everything here is
// "inline" in one namespace, so a definition has to precede its use.
#include "core/api.inc"
#include "core/mem.inc"
#include "luau/out.inc"
#include "probes.inc"
#include "core/proto.inc"
#include "core/veh.inc"
#include "diag.inc"
#include "luau/exec.inc"
#include "luau/protected.inc"
#include "luau/capture.inc"
#include "luau/loadstring.inc"
#include "luau/native.inc"
#include "luau/execraw.inc"
#include "luau/gc.inc"
#include "luau/caps.inc"
#include "stages.inc"
#include "ipc/repl.inc"
#include "core/trace.inc"
#include "boot/boot.inc"

}  // namespace zendo

extern "C" BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        zendo::g_restore_ctx = reinterpret_cast<unsigned long long>(reserved);
        zendo::resolve_api();
        // The borrowed thread is given back before the first byte hits the
        // pipe. It may well be the client's main thread - the hijack prefers an
        // alertable wait, and that is the message pump - so holding it for a
        // session is a frozen window, not a session.
        unsigned long long start =
            zendo::thread_trampoline(reinterpret_cast<void*>(&zendo::session_thread));
        zendo::stage_mark(zendo::api(), start ? "D2-TRAMP" : "D2-NOTRAMP");
        DWORD tid = 0;
        HANDLE worker = (start && zendo::api().CreateThread)
            ? zendo::api().CreateThread(nullptr, 0,
                  reinterpret_cast<LPTHREAD_START_ROUTINE>(start), nullptr, 0, &tid)
            : nullptr;
        zendo::stage_mark(zendo::api(), worker ? "D3-OK" : "D3-NULL");
        if (worker) {
            if (zendo::api().CloseHandle) zendo::api().CloseHandle(worker);
            return TRUE;
        }
        // No worker means no session; run it inline rather than lose the
        // injection. The stub reloads the context once this returns. The name
        // is dropped here too: the image is never unmapped, so a handle left
        // open would block every later injection from claiming the slot.
        zendo::beacon();
        zendo::release_live();
    }
    return TRUE;
}
