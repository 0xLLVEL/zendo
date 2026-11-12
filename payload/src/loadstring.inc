// --- loadstring -------------------------------------------------------------
// The client ships without a Luau compiler, so source cannot be compiled in
// process. What it can do is load bytecode, and that is all loadstring really
// needs: the executor compiles offline, the bytes travel, the VM turns them into
// a callable closure. This is the door those bytes come through.

// Staging area for the magic prefix plus the caller's bytecode. One page block,
// allocated once per payload instance, never freed: the loader keeps pointers
// into the proto it builds and the process dies with us anyway.
inline unsigned long long load_stage(unsigned int need) {
    static unsigned long long stage = 0;
    if (!stage) {
        void* p = api().VirtualAlloc ? api().VirtualAlloc(nullptr, 1u << 20,
                                                          MEM_COMMIT | MEM_RESERVE,
                                                          PAGE_READWRITE)
                                     : nullptr;
        if (p) stage = reinterpret_cast<unsigned long long>(p);
    }
    if (!stage || need > (1u << 20)) return 0;
    return stage;
}

// Prepends the guard magic to whatever already sits at buf+8 and hands the blob
// to LuaVMLoad. The loader pushes the resulting closure onto L's stack, so a
// caller that returns 1 gives it straight to the script.
//
// The loader has a watermark gate on `size - 8 >= 0x118`: at 288 bytes or more
// it takes the validating path and rejects a chunk the executor built itself.
// The undump parser does not bounds-check, so a small declared size skips the
// gate while the whole real buffer is still parsed - the same trick exec_raw
// uses for the injection chunk.
inline int lua_load_stage(unsigned long long l, unsigned long long buf, unsigned int blen) {
    if (!buf || !blen || !g_base) return 0;
    const unsigned long long magic = 0xE009325B4A107A52ull;
    char* p = reinterpret_cast<char*>(buf);
    for (int i = 0; i < 8; ++i) p[i] = static_cast<char>(magic >> (8 * i));
    ChunkName src;
    src.data = p;
    src.pad = 0;
    src.size = (8ull + blen >= 0x120ull) ? 64ull : (8ull + blen);
    src.cap = 8ull + blen;
    typedef int (*LoadFn)(void*, void*, const char*, int);
    LoadFn load = reinterpret_cast<LoadFn>(g_base + 0x426A570);
    int ret = load(reinterpret_cast<void*>(l), &src, "=zendo", 0);
    return ret == 0 ? 1 : 0;
}

inline int lua_load_bytes(unsigned long long l, const char* body, unsigned int blen) {
    if (!body || !blen || blen > (1u << 20) - 8) return 0;
    unsigned long long buf = load_stage(blen + 8);
    if (!buf) return 0;
    char* p = reinterpret_cast<char*>(buf);
    for (unsigned int i = 0; i < blen; ++i)
        *reinterpret_cast<volatile char*>(p + 8 + i) = body[i];
    return lua_load_stage(l, buf, blen);
}

// Reads a compiled chunk from disk into the staging buffer and loads it.
inline int lua_load_file(unsigned long long l, const char* path) {
    HANDLE f = api().CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return 0;
    unsigned long long buf = load_stage((1u << 20));
    if (!buf) {
        api().CloseHandle(f);
        return 0;
    }
    DWORD got = 0;
    char* p = reinterpret_cast<char*>(buf);
    if (!api().ReadFile(f, p + 8, (1u << 20) - 8, &got, nullptr) || !got) {
        api().CloseHandle(f);
        return 0;
    }
    api().CloseHandle(f);
    return lua_load_stage(l, buf, got);
}

// Reads one newline terminated field from the session pipe.
inline unsigned int pipe_line(Api& a, HANDLE pipe, char* dst, unsigned int cap) {
    unsigned int n = 0;
    for (;;) {
        char c = 0;
        DWORD rd = 0;
        if (!a.ReadFile(pipe, &c, 1, &rd, nullptr) || rd == 0) return 0;
        if (c == '\n') break;
        if (n + 1 < cap) dst[n++] = c;
    }
    dst[n] = 0;
    return n;
}

inline unsigned int parse_dec(const char* s) {
    unsigned int v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + static_cast<unsigned int>(*s++ - '0');
    return v;
}

// Reply-path diagnostic: a failed loadstring has to say where it stopped.
inline void ls_log(const char* tag, unsigned long long v) {
    Api& a = api();
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\ls.bin", FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    char b[96];
    char* p = b;
    while (*tag) *p++ = *tag++;
    *p++ = ' ';
    p = append_hex(p, v);
    *p++ = '\n';
    DWORD w = 0;
    a.WriteFile(f, b, static_cast<DWORD>(p - b), &w, nullptr);
    a.CloseHandle(f);
}

// Live loadstring. The client has no compiler, so the source goes out on the
// session pipe exactly as Lua handed it over; the executor compiles and remaps
// it offline and answers with the blob. The reply lands in the staging buffer
// and LuaVMLoad turns it into the closure the script asked for.
//
// Wire, payload -> endpoint:  "C <len>\n" + source bytes
//       endpoint -> payload:  "K <len>\n" + bytecode  |  "E <len>\n" + message
inline int lua_compile_remote(unsigned long long l, const char* src, unsigned int slen) {
    HANDLE pipe = g_cap_pipe;
    Api& a = api();
    if (pipe == INVALID_HANDLE_VALUE || !src || !slen || slen > 262144) return 0;
    char head[24];
    unsigned int n = 0;
    head[n++] = 'C';
    head[n++] = ' ';
    char d[12];
    unsigned int k = 0, v = slen;
    do { d[k++] = static_cast<char>('0' + (v % 10)); v /= 10; } while (v);
    while (k) head[n++] = d[--k];
    head[n++] = '\n';
    DWORD w = 0;
    if (!a.WriteFile(pipe, head, n, &w, nullptr)) return 0;
    if (!a.WriteFile(pipe, src, slen, &w, nullptr)) return 0;

    char line[64];
    if (!pipe_line(a, pipe, line, sizeof(line))) {
        ls_log("no-reply", 0);
        return 0;
    }
    unsigned int rlen = parse_dec(line + 2);
    ls_log("line", static_cast<unsigned long long>(static_cast<unsigned char>(line[0])));
    ls_log("rlen", rlen);
    if (rlen > (1u << 20) - 8) rlen = 0;
    if (line[0] == 'K' && rlen) {
        unsigned long long buf = load_stage(rlen + 8);
        if (!buf) return 0;
        if (!read_all(a, pipe, reinterpret_cast<void*>(buf + 8), rlen)) {
            ls_log("short-body", rlen);
            return 0;
        }
        int r = lua_load_stage(l, buf, rlen);
        ls_log("load", static_cast<unsigned long long>(r));
        if (r == 0) {
            HANDLE f = a.CreateFileA("D:\\zendo\\work\\ls_blob.bin", GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (f != INVALID_HANDLE_VALUE) {
                DWORD w2 = 0;
                a.WriteFile(f, reinterpret_cast<void*>(buf + 8), rlen, &w2, nullptr);
                a.CloseHandle(f);
            }
        }
        return r;
    }
    if (line[0] == 'E' && rlen) {
        static char err[256];
        unsigned int keep = rlen < sizeof(err) - 1 ? rlen : sizeof(err) - 1;
        read_all(a, pipe, err, rlen);
        err[keep] = 0;
        char out[300];
        const char* pre = "Ploadstring: ";
        unsigned int q = 0;
        while (*pre) out[q++] = *pre++;
        for (unsigned int i = 0; i < keep && q < sizeof(out) - 2; ++i) out[q++] = err[i];
        out[q++] = '\n';
        a.WriteFile(pipe, out, q, &w, nullptr);
    }
    return 0;
}

// Defined after exec_raw, next to the call machinery it borrows.
int zendo_file_op(unsigned long long l, const char* op, unsigned int oplen);
int zendo_http_op(unsigned long long l);
int zendo_gc_op(unsigned long long l, bool walk);
int zendo_gcfill_op(unsigned long long l);
int zendo_gspage_op(unsigned long long l);
int zendo_gcforce_op(unsigned long long l);

