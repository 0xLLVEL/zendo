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
// Per-thread trace file (work/trace-<tid>.log). repl_stage.bin is one file for
// every copy in the process, so a duplicate image erases the previous copy's
// last step; this one cannot.
inline void trace_tag(Api& a, const char* tag);
inline void trace_kv(Api& a, const char* tag, unsigned long long v);
inline void trace_text(Api& a, const char* text, unsigned int n);

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
    // The pipe is gone the instant the session ends, and the faults that matter
    // arrive seconds later. Land the record on disk too.
    if (fatal) trace_text(api(), h.buf, h.n);
    if (in_payload && fatal) stage_mark(api(), "FAULT-INPAY");
    g_veh_depth = 0;
    return EXCEPTION_CONTINUE_SEARCH;
}

// Stage 20/21: diagnostics around the proven load path. do_call=false stops
// before any VM entry; do_call=true attempts exactly one luaD_call and nothing
// else, so a hang is attributable to that single call.
