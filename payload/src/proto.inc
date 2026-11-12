inline void flush_out(Api& a, HANDLE pipe, Out& o) {
    if (o.n == 0) return;
    DWORD written = 0;
    a.WriteFile(pipe, o.buf, o.n, &written, nullptr);
    o.reset();
}

// Pipe reads are message-mode: each WriteFile on the far side is one message.
// Drain until the caller's byte count is satisfied or the pipe dies.
inline bool read_all(Api& a, HANDLE pipe, void* dst, unsigned int len) {
    unsigned char* p = static_cast<unsigned char*>(dst);
    unsigned int got = 0;
    while (got < len) {
        DWORD rd = 0;
        if (!a.ReadFile(pipe, p + got, len - got, &rd, nullptr) || rd == 0)
            return false;
        got += rd;
    }
    return true;
}

inline void diag_line(Out& o, const char* tag, unsigned long long v) {
    o.str("  ");
    o.str(tag);
    o.str("=");
    o.hex(v);
    o.nl();
}

inline void diag_ci(Out& o, unsigned long long ci_addr) {
    unsigned long long base = 0, top = 0, func = 0, p = 0, pc = 0;
    unsigned int nresults = 0, flags = 0;
    bool ok = read_u64(ci_addr, &base) && read_u64(ci_addr + 8, &top) &&
              read_u64(ci_addr + 0x10, &func) && read_u64(ci_addr + 0x18, &p) &&
              read_u64(ci_addr + 0x20, &pc);
    read_u32(ci_addr + 0x28, &nresults);
    read_u32(ci_addr + 0x2C, &flags);
    o.str("    ci ");
    o.hex(ci_addr);
    if (!ok) {
        o.str(" unreadable");
        o.nl();
        return;
    }
    o.str(" base=");
    o.hex(base);
    o.str(" top=");
    o.hex(top);
    o.str(" func=");
    o.hex(func);
    o.str(" p=");
    o.hex(p);
    o.str(" pc=");
    o.hex(pc);
    o.str(" nr=");
    o.dec(nresults);
    o.str(" fl=");
    o.hex(flags);
    o.nl();
}

inline void diag_proto(Out& o, unsigned long long p) {
    if (!p || !readable(reinterpret_cast<const void*>(p), 0xE8)) {
        o.str("  proto unreadable");
        o.nl();
        return;
    }
    unsigned int u = 0;
    unsigned long long q = 0;
    o.str("  proto=");
    o.hex(p);
    read_u32(p + 3, &u);
    o.str(" vararg=");
    o.dec(u & 0xff);
    read_u32(p + 4, &u);
    o.str(" maxstack=");
    o.dec(u & 0xff);
    read_u32(p + 5, &u);
    o.str(" nups=");
    o.dec(u & 0xff);
    read_u32(p + 6, &u);
    o.str(" flags=");
    o.dec(u & 0xff);
    read_u32(p + 7, &u);
    o.str(" nparams=");
    o.dec(u & 0xff);
    o.nl();

    o.str("    execdata=");
    read_u64(p + 0x08, &q);
    o.hex(q);
    o.str(" exectarget=");
    read_u64(p + 0x10, &q);
    o.hex(q);
    read_u32(p + 0x18, &u);
    o.str(" execflags=");
    o.hex(u & 0xff);
    read_u32(p + 0x28, &u);
    o.str(" execcount=");
    o.dec(u);
    o.nl();

    o.str("    code=");
    read_u64(p + 0x68, &q);
    o.hex(q);
    o.str(" codeentry=");
    read_u64(p + 0x90, &q);
    o.hex(q);
    read_u32(p + 0x98, &u);
    o.str(" sizeupvalues=");
    o.dec(u);
    read_u32(p + 0xA0, &u);
    o.str(" sizep=");
    o.dec(u);
    read_u32(p + 0xA4, &u);
    o.str(" linedefined=");
    o.dec(u);
    o.nl();

    read_u32(p + 0xA8, &u);
    o.str("    sizecode=");
    o.dec(u);
    unsigned int sizecode = u;
    read_u32(p + 0xAC, &u);
    o.str(" sizek=");
    o.dec(u);
    read_u32(p + 0xB0, &u);
    o.str(" size_lineinfo=");
    o.dec(u);
    read_u32(p + 0xB4, &u);
    o.str(" bytecodeid=");
    o.dec(u);
    read_u32(p + 0xB8, &u);
    o.str(" sizetypeinfo=");
    o.dec(u);
    o.nl();

    read_u32(p + 0xC8, &u);
    o.str("    feedbackvecsize=");
    o.dec(u);
    read_u32(p + 0xCC, &u);
    o.str(" funid=");
    o.dec(u);
    o.str(" optimized=");
    read_u64(p + 0xD0, &q);
    o.hex(q);
    o.str(" deoptimized=");
    read_u64(p + 0xD8, &q);
    o.hex(q);
    o.nl();

    unsigned long long code = 0;
    read_u64(p + 0x68, &code);
    if (code && sizecode && sizecode < 512 &&
        readable(reinterpret_cast<const void*>(code), 4ull * sizecode)) {
        unsigned int n = sizecode < 10 ? sizecode : 10;
        o.str("    insn:");
        for (unsigned int i = 0; i < n; ++i) {
            unsigned int ins = 0;
            read_u32(code + 4ull * i, &ins);
            o.str(" ");
            o.hex(ins);
        }
        o.nl();
    }
}

// The VM can fault (or throw) inside client code with our manual-mapped frame
// on the stack, where no .pdata exists and nothing can unwind. A vectored
// handler still runs first, so it writes the fault address and the VM's own
// frame state to the pipe before the process dies.
