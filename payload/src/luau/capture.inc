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
// Set once the Lua-side print capture chunk has run in this process. A raw
// chunk installs it on first use; a deferred session never does, so the
// client's own `print` keeps writing to CreatorOutput where the host reads it.
static int g_capi_ready = 0;
// Raw-only setup (closure capture, CFG arm, global bindings) runs once, on the
// first chunk that actually needs it. A deferred session must not trigger it.
static int g_bind_ready = 0;
// Set by the `x` command. It means "detach for good": unwind out of the REPL
// so DllMain can restore the borrowed thread. A payload that stays parked keeps
// the process in a state the anti-cheat refuses to terminate - the window dies
// but the pid survives, and only a reboot clears it.
static int g_leave = 0;
// Counts completed sessions. Written to work/loop.bin after each one, which is
// how "the seek loop is alive" is proven instead of assumed.
static unsigned int g_loop_n = 0;
// Bumped every second by the seek loop while no server is listening. Its mtime
// is the host's liveness oracle: a mutex can read free while the owner lives,
// a file that stops being touched cannot.
static unsigned int g_seek_n = 0;
static int g_cap_mode = 0;   // 0 = untouched, 1 = swap only, 2 = +read args, 3 = +pipe
static int g_api_live = 0;   // the closure slot currently carries our C function
// Set once the door is installed for good. A deferred body runs after the
// window that ran its wrapper has closed, so restoring the entry pointer would
// take the dispatcher away from it. cap_print's non-zendo branch is the game's
// own function, so the client's print path pays one comparison and nothing else.
static int g_door_perm = 0;
static unsigned int g_cap_calls = 0;
// The closure is swapped only for the window a chunk of ours is running, and
// only on the thread running it. Everything else in the client - the game's own
// prints, CoreGui chatter, the scheduler - takes the untouched function pointer
// and pays one branch. Leaving the swap in place for the whole session is what
// put a CreateFile/WriteFile/CloseHandle in the client's print path.
static int g_cap_capture = 0;
static int g_cap_depth = 0;
static unsigned long long g_cap_tid = 0;
static int g_cfg_done = 0;
// Diagnostics write files. Off by default: the hook path must never touch disk.
static int g_diag = 0;

inline void cap_put(const char* s, unsigned int n) {
    if (!g_cap_capture || g_cap_pipe == INVALID_HANDLE_VALUE) return;
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
    if (!g_diag) return;
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
