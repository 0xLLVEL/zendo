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
