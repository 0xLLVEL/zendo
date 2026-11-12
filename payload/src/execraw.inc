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
    trace_kv(a, "load-ret", static_cast<unsigned int>(ret));
    trace_kv(a, "load-top", t1 - top0);
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
    trace_tag(a, "prot-in");
    int st = prot(reinterpret_cast<void*>(L),
                  reinterpret_cast<void*>(base + 0x2632230), &ctx);
    trace_kv(a, "prot-st", static_cast<unsigned int>(st));
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

// Six strings in, one frame out: url, method, header block, body, body path,
// header path. The host does the round trip and writes both files, so the only
// thing that crosses back into Lua is a status code and an ok flag. Two numbers
// are pushed in that order; anything else is the host saying it did not try.
int zendo_http_op(unsigned long long l) {
    HANDLE pipe = g_cap_pipe;
    Api& a = api();
    if (pipe == INVALID_HANDLE_VALUE || !g_base) return 0;

    struct Part { char* p; unsigned int n; };
    Part parts[6];
    const unsigned int caps[6] = {8192u, 16u, 65536u, 8u << 20, 512u, 512u};
    for (int i = 0; i < 6; ++i) {
        unsigned int n = 0;
        char* p = lua_arg_str(l, i + 1, &n);
        if (!p || n > caps[i]) return 0;
        parts[i].p = p;
        parts[i].n = n;
    }
    if (!parts[0].n || !parts[4].n || !parts[5].n) return 0;

    char head[128];
    unsigned int hn = 0, q = 0;
    char digits[12];
    head[hn++] = 'Q';
    for (int i = 0; i < 6; ++i) {
        head[hn++] = ' ';
        unsigned int v = parts[i].n;
        q = 0;
        do { digits[q++] = static_cast<char>('0' + (v % 10)); v /= 10; } while (v);
        while (q) head[hn++] = digits[--q];
    }
    head[hn++] = '\n';

    DWORD w = 0;
    if (!a.WriteFile(pipe, head, hn, &w, nullptr)) return 0;
    for (int i = 0; i < 6; ++i) {
        if (parts[i].n && !a.WriteFile(pipe, parts[i].p, parts[i].n, &w, nullptr)) return 0;
    }

    char line[64];
    if (!pipe_line(a, pipe, line, sizeof(line))) return 0;
    if (line[0] != 'R') return 0;
    const char* s = line + 2;
    unsigned long long status = 0;
    while (*s >= '0' && *s <= '9') { status = status * 10 + static_cast<unsigned>(*s - '0'); ++s; }
    while (*s == ' ') ++s;
    const unsigned int ok = (*s == '1') ? 1u : 0u;
    int r = lua_ret_num(l, static_cast<double>(status));
    r += lua_ret_num(l, static_cast<double>(ok));
    return r;
}

