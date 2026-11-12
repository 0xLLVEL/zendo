inline DWORD beacon() {
    g_veh_tid = __readgsqword(0x48);
    // No one-payload claim. A named mutex was tried three times and every
    // version hurt the same way: the handle is process-wide, so when the
    // client kills or suspends this thread the name keeps existing with no
    // thread to serve it. A later injection then reads "a payload is already
    // here", parks, and the run has nobody to talk to. Measured: the seek
    // loop stopped 4 s after a clean session (loop.bin frozen at 00:01:36)
    // while the mutex handle outlived it, and the second Execute timed out
    // with the client alive and idle.
    //
    // The pipe is the semaphore. One server instance, one accepted client, so
    // only one image can be inside a session at a time; a second image's
    // CreateFile blocks until that instance is gone. Nothing else needs to
    // gate entry, and nothing can stay stuck holding a claim.
    if (!api().CreateFileA) resolve_api();
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

// The hijack stub hands the saved CONTEXT over as the third DllMain argument.
// That argument is still recorded, but the stub is now the one that reloads it:
// DllMain starts a thread of our own and returns immediately, so the `call rax`
// in the stub lands on the restore path within milliseconds. Keeping the game
// thread parked here instead was the reason a frozen client could not be
// terminated - one pinned thread and the loader lock were enough for
// TerminateProcess to give up.
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

// The whole session lives on this thread. DllMain used to host it, which meant
// the borrowed client thread never returned to its wait; here the client gets
// its thread back before the first pipe is even opened.
//
// When the seek loop ends (ten minutes without a server, or an explicit
// detach) the thread parks instead of exiting. Exiting would run the loader's
// thread-detach path, which this client has already killed threads for
// (STATUS_BAD_TLS_INDEX); a parked thread costs one stack and holds nothing.
// It also holds no claim, which is the point: the pipe decides who serves, so
// a thread the client kills or suspends cannot block a later injection.
inline DWORD WINAPI session_thread(void*) {
    DWORD code = beacon();
    Api& a = api();
    if (a.Sleep) a.Sleep(0x7fffffff);
    return code;
}

// A start routine inside a manually mapped image is not a legal call target.
// Measured: CreateThread returned a handle, the handle read STILL_ACTIVE, the
// thread never executed one byte of session_thread - and a control thread
// whose start routine was kernel32!Sleep ran to completion in the same call.
// The thread exists, it is simply stopped at the call-target check.
//
// A page allocated with PAGE_TARGETS_INVALID starts with no valid targets and
// can opt individual offsets back in, which is the one path that worked for
// the print hook. The thread starts on this trampoline - a legal target - and
// the trampoline jumps into the real function with a raw jump no dispatcher
// checks.
inline unsigned long long thread_trampoline(void* fn) {
    Api& a = api();
    if (!a.VirtualAlloc || !a.SetProcessValidCallTargets || !fn) return 0;
    constexpr DWORD kTargetsInvalid = 0x40000000;
    unsigned char* page = static_cast<unsigned char*>(
        a.VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE | kTargetsInvalid));
    if (!page) return 0;
    page[0] = 0x48;  // mov rax, imm64
    page[1] = 0xB8;
    unsigned long long target = reinterpret_cast<unsigned long long>(fn);
    for (int i = 0; i < 8; ++i)
        page[2 + i] = static_cast<unsigned char>(target >> (8 * i));
    page[10] = 0xFF;  // jmp rax
    page[11] = 0xE0;
    HANDLE self = reinterpret_cast<HANDLE>(static_cast<long long>(-1));
    if (a.FlushInstructionCache) a.FlushInstructionCache(self, page, 0x1000);
    static CfgCallTargetInfo info[1];
    info[0].Offset = 0;
    info[0].Flags = 1;  // CFG_CALL_TARGET_VALID
    if (!a.SetProcessValidCallTargets(self, page, 0x1000, 1, info)) {
        a.VirtualFree(page, 0, MEM_RELEASE);
        return 0;
    }
    return reinterpret_cast<unsigned long long>(page);
}

