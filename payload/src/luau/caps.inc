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
