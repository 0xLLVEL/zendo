struct Out {
    char buf[16384];
    DWORD n;

    void reset() { n = 0; }
    void ch(char c) {
        if (n + 1 < sizeof(buf)) buf[n++] = c;
    }
    void str(const char* s) {
        while (*s) ch(*s++);
    }
    void hex(unsigned long long v) {
        char* p = append_hex(buf + n, v);
        n = static_cast<DWORD>(p - buf);
        if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    }
    void dec(unsigned int v) {
        char tmp[10];
        int k = 0;
        if (!v) tmp[k++] = '0';
        while (v) {
            tmp[k++] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
        while (k) ch(tmp[--k]);
    }
    void nl() { ch('\n'); }
};

inline void dump_state(Out& o, unsigned long long L) {
    o.str("      L=");
    o.hex(L);
    unsigned long long gs = 0, gt = 0, stk = 0, top = 0, ci = 0, extra = 0, identity = 0, mt = 0;
    unsigned int cap = 0;
    bool ok = read_u64(L + 0x50, &gs) && read_u64(L + 0x10, &gt) && read_u64(L + 0x48, &stk) &&
              read_u64(L + 0x60, &top) && read_u64(L + 0x70, &ci) && read_u64(L + 0x8, &extra);
    o.str(" gs=");
    o.hex(gs);
    if (gs) {
        read_u32(gs + 0x640, &cap);
        read_u64(gs + 0x78, &mt);
    }
    if (extra) read_u64(extra + 0x70, &identity);
    o.str(" cap=");
    o.hex(cap);
    o.str(" id=");
    o.hex(identity);
    o.str(" mt=");
    o.hex(mt);
    o.str(" gt=");
    o.hex(gt);
    o.str(" stk=");
    o.hex(stk);
    o.str(" top=");
    o.hex(top);
    o.str(" ci=");
    o.hex(ci);
    if (!ok) o.str(" partial");
    o.nl();
}

inline void probe_object(Out& o, char tag, unsigned long long obj) {
    o.str("  ");
    o.ch(tag);
    o.str(" obj=");
    o.hex(obj);
    if (!obj) {
        o.nl();
        return;
    }
    unsigned int state = 0;
    unsigned long long vt = 0, cls = 0;
    read_u64(obj, &vt);
    read_u64(obj + 0x18, &cls);
    read_u32(obj + 0x1628, &state);
    o.str(" vt=");
    o.hex(vt);
    o.str(" cls=");
    o.hex(cls);
    o.str(" st=");
    o.hex(state);
    o.nl();

    const unsigned long long slots[2] = {k_slot_a, k_slot_b};
    const char* names[2] = {"s210", "s520"};
    for (int i = 0; i < 2; ++i) {
        unsigned long long slot = obj + slots[i];
        unsigned long long enc = 0;
        if (!read_u64(slot, &enc)) {
            o.str("    ");
            o.str(names[i]);
            o.str(" unreadable");
            o.nl();
            continue;
        }
        unsigned long long d32 = decode_split(slot);
        unsigned long long d64 = slot - enc;
        o.str("    ");
        o.str(names[i]);
        o.str(" enc=");
        o.hex(enc);
        o.str(" d32=");
        o.hex(d32);
        o.str(" d64=");
        o.hex(d64);
        o.nl();
        dump_state(o, d32);
        if (d64 != d32) dump_state(o, d64);
    }
}

inline int find_by_vtable(unsigned long long target, unsigned long long* hits, int cap) {
    int n = 0;
    unsigned long long addr = 0x10000;
    for (;;) {
        Mbi mbi;
        if (!api().VirtualQuery(reinterpret_cast<const void*>(addr), &mbi, sizeof(mbi))) break;
        unsigned long long begin = reinterpret_cast<unsigned long long>(mbi.BaseAddress);
        unsigned long long next = begin + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
        if (mbi.State != MEM_COMMIT) continue;
        DWORD prot = mbi.Protect & 0xFF;
        if (prot != PAGE_READWRITE && prot != PAGE_EXECUTE_READWRITE &&
            prot != PAGE_WRITECOPY && prot != PAGE_EXECUTE_WRITECOPY) continue;
        unsigned long long p = (begin + 7) & ~7ull;
        unsigned long long end = begin + mbi.RegionSize;
        for (; p + 8 <= end; p += 8) {
            if (*reinterpret_cast<volatile unsigned long long*>(p) == target) {
                hits[n++] = p;
                if (n >= cap) return n;
            }
        }
    }
    return n;
}

inline int scan_for_vtable(unsigned long long begin, unsigned long long limit,
                           unsigned long long target, unsigned long long* fields,
                           unsigned long long* objs, int cap) {
    int n = 0;
    for (unsigned long long off = 0; off + 8 <= limit; off += 8) {
        unsigned long long v = 0, vt = 0;
        if (!read_u64(begin + off, &v)) break;
        if (v < 0x10000 || v > 0x7fffffffffffull) continue;
        if (!read_u64(v, &vt)) continue;
        if (vt == target) {
            fields[n] = begin + off;
            objs[n] = v;
            if (++n >= cap) return n;
        }
    }
    return n;
}

// The service map is an MSVC std::map<uint64 classId, shared_ptr<Instance>>:
// head node at [provider + 0xB0], root at [head + 8], node = {left, parent,
// right, colour, pad, key @+0x20, shared_ptr value @+0x28}.
inline void tree_report(Out& o, unsigned long long dm) {
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("  dm=");
    o.hex(dm);
    unsigned long long head = 0, root = 0, cls = 0;
    read_u64(dm + 0xB0, &head);
    read_u64(head + 8, &root);
    read_u64(base + 0x8D7EAE0, &cls);
    o.str(" head=");
    o.hex(head);
    o.str(" root=");
    o.hex(root);
    o.str(" classIdStatic=");
    o.hex(cls);
    o.nl();
    if (!head || !root) return;

    unsigned long long stack[128];
    int sp = 0;
    stack[sp++] = root;
    int seen = 0, hits = 0, sc_key = -1;
    while (sp > 0 && seen < 160) {
        unsigned long long n = stack[--sp];
        if (!n || n == head) continue;
        unsigned long long key = 0, val = 0, left = 0, right = 0;
        if (!read_u64(n + 0x20, &key)) continue;
        read_u64(n + 0x28, &val);
        read_u64(n, &left);
        read_u64(n + 0x10, &right);
        if (left && left != head && sp < 128) stack[sp++] = left;
        if (right && right != head && sp < 128) stack[sp++] = right;
        ++seen;
        unsigned long long vt = 0;
        if (val) read_u64(val, &vt);
        unsigned long long vt_rva = (vt > base && vt < base + 0x20000000) ? vt - base : 0;
        o.str("    n=");
        o.hex(n);
        o.str(" key=");
        o.hex(key);
        o.str(" val=");
        o.hex(val);
        o.str(" vt+");
        o.hex(vt_rva);
        if (vt_rva == k_script_context_vtable) {
            o.str("  <== ScriptContext");
            sc_key = hits;
        }
        o.nl();
        if (vt_rva == k_script_context_vtable) {
            ++hits;
            if (hits == 1) {
                probe_object(o, 'S', val);
                unsigned long long l0 = decode_split(val + k_slot_a);
                unsigned long long l1 = decode_split(val + k_slot_b);
                o.str("    L210=");
                o.hex(l0);
                o.str(" L520=");
                o.hex(l1);
                o.nl();
                if (l0) dump_state(o, l0);
                if (l1 && l1 != l0) dump_state(o, l1);
            }
        }
    }
    o.str("  nodes=");
    o.dec(static_cast<unsigned int>(seen));
    o.str(" sc=");
    o.dec(static_cast<unsigned int>(hits));
    o.str(" sc_key=");
    o.dec(static_cast<unsigned int>(sc_key));
    o.nl();
}

inline void probe_report(Out& o, bool scan, bool local) {
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 probe base=");
    o.hex(base);
    o.nl();

    unsigned long long fake_static = 0, ve = 0;
    read_u64(base + k_fake_dm_static, &fake_static);
    read_u64(base + k_ve_static, &ve);
    o.str("  fake_static=");
    o.hex(fake_static);
    o.str(" ve=");
    o.hex(ve);
    o.nl();

    unsigned long long fake_from_ve = 0, dm_a = 0, dm_c = 0, dm_b = fake_static, dm_d = 0;
    if (ve) read_u64(ve + k_ve_to_fake_dm, &fake_from_ve);
    if (fake_from_ve) read_u64(fake_from_ve + k_fake_dm_to_dm, &dm_c);
    if (fake_static) read_u64(fake_static + k_fake_dm_to_dm, &dm_a);
    dm_d = fake_from_ve;

    o.str("  dmA=");
    o.hex(dm_a);
    o.str(" dmB=");
    o.hex(dm_b);
    o.str(" dmC=");
    o.hex(dm_c);
    o.str(" dmD=");
    o.hex(dm_d);
    o.nl();

    probe_object(o, 'A', dm_a);
    probe_object(o, 'B', dm_b);
    probe_object(o, 'C', dm_c);
    probe_object(o, 'D', dm_d);

    unsigned long long sc_a = 0, sc_b = 0, sc_c = 0, sc_d = 0;
    if (dm_a) read_u64(dm_a + k_dm_to_script_context, &sc_a);
    if (dm_b) read_u64(dm_b + k_dm_to_script_context, &sc_b);
    if (dm_c) read_u64(dm_c + k_dm_to_script_context, &sc_c);
    if (dm_d) read_u64(dm_d + k_dm_to_script_context, &sc_d);
    o.str("  scA=");
    o.hex(sc_a);
    o.str(" scB=");
    o.hex(sc_b);
    o.str(" scC=");
    o.hex(sc_c);
    o.str(" scD=");
    o.hex(sc_d);
    o.nl();

    probe_object(o, 'a', sc_a);
    probe_object(o, 'b', sc_b);
    probe_object(o, 'c', sc_c);
    probe_object(o, 'd', sc_d);

    unsigned long long hits[3] = {0, 0, 0};
    if (scan) {
        int nh = find_by_vtable(base + k_script_context_vtable, hits, 3);
        o.str("  scan vt=");
        o.hex(base + k_script_context_vtable);
        o.str(" hits=");
        o.dec(static_cast<unsigned int>(nh));
        o.nl();
        for (int i = 0; i < nh; ++i) probe_object(o, 'S', hits[i]);
    }
    if (local) {
        const unsigned long long roots[2] = {dm_a, dm_b};
        const char* names[2] = {"dmA", "dmB"};
        for (int r = 0; r < 2; ++r) {
            unsigned long long root = roots[r];
            if (!root) continue;
            unsigned long long limit = 0x8000;
            Mbi mbi;
            if (api().VirtualQuery(reinterpret_cast<const void*>(root), &mbi, sizeof(mbi))) {
                unsigned long long region_end =
                    reinterpret_cast<unsigned long long>(mbi.BaseAddress) + mbi.RegionSize;
                if (region_end > root && region_end - root < limit) limit = region_end - root;
            }
            unsigned long long fields[4] = {0, 0, 0, 0};
            unsigned long long objs[4] = {0, 0, 0, 0};
            int nh = scan_for_vtable(root, limit, base + k_script_context_vtable, fields, objs, 4);
            o.str("  local ");
            o.str(names[r]);
            o.str("=");
            o.hex(root);
            o.str(" limit=");
            o.hex(limit);
            o.str(" hits=");
            o.dec(static_cast<unsigned int>(nh));
            o.nl();
            for (int i = 0; i < nh; ++i) {
                o.str("    field=+");
                o.hex(fields[i] - root);
                o.nl();
                probe_object(o, 'L', objs[i]);
            }
        }
    }
    o.str("END\n");
}

// Walks the DataModel service map (std::map keyed by class id at +0xB0) and
// returns the first instance whose vtable matches.
inline unsigned long long find_service(unsigned long long base, unsigned long long target,
                                       unsigned long long dm) {
    unsigned long long head = 0, root = 0;
    if (!dm || !read_u64(dm + 0xB0, &head) || !head) return 0;
    if (!read_u64(head + 8, &root) || !root) return 0;
    unsigned long long stack[128];
    int sp = 0, seen = 0;
    stack[sp++] = root;
    while (sp > 0 && seen < 256) {
        unsigned long long n = stack[--sp];
        if (!n || n == head) continue;
        unsigned long long val = 0, left = 0, right = 0;
        read_u64(n + 0x28, &val);
        read_u64(n, &left);
        read_u64(n + 0x10, &right);
        if (left && left != head && sp < 128) stack[sp++] = left;
        if (right && right != head && sp < 128) stack[sp++] = right;
        ++seen;
        if (!val) continue;
        unsigned long long vt = 0;
        if (!read_u64(val, &vt)) continue;
        if (vt == target) return val;
    }
    (void)base;
    return 0;
}

