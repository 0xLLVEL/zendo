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

// Same file as stage_mark, with one number appended as hex. The stall between
// two marks is a fact; the pointer behind it is what turns the fact into a
// diagnosis. No separator, no newline: the file is one line by contract.
inline void stage_mark_val(Api& a, const char* s, unsigned long long v) {
    char buf[64];
    unsigned int n = 0;
    while (s[n] && n < 32) { buf[n] = s[n]; ++n; }
    buf[n++] = '=';
    char* p = append_hex(buf + n, v);
    *p = 0;
    n = static_cast<unsigned int>(p - buf);
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\repl_stage.bin", GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    a.WriteFile(f, buf, n, &w, nullptr);
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
