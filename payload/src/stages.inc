inline void flush_capture(Api& a, Out& o, unsigned long long L, unsigned long long base) {
    if (g_cap_pipe == INVALID_HANDLE_VALUE) return;
    static Out quiet;
    quiet.reset();
    // cap_print already wrote every line straight to the pipe as it happened.
    // The flush chunk only clears the Luau-side buffer; re-emitting its return
    // value is what printed each line twice.
    g_flush_next = false;
    exec_raw(a, INVALID_HANDLE_VALUE, quiet, L, base, kChunkFlush, kChunkFlushLen, "flush");
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
