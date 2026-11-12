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
