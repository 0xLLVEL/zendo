// --- GC pages -------------------------------------------------------------
// This collector has no intrusive object list. Every GCO lives inside a
// lua_Page and the pages are chained through listprev/listnext at +0x10/+0x18.
// The page of a known object is recovered by walking the block grid backwards
// from that object, and the head of the list by following listprev, so getgc
// never has to trust a global_State offset. Nothing here calls the VM, and
// every dereference is checked against the committed region map.

// One VirtualQuery per region instead of one per read: a scan touching
// thousands of blocks would otherwise spend its time in the page table.
struct GcWindow {
    bool live;
    unsigned long long base;
    unsigned long long end;
};

inline bool gc_ok(unsigned long long p, SIZE_T len, GcWindow* w) {
    if (p < 0x10000) return false;
    if (w->live && p >= w->base && p + len <= w->end) return true;
    Mbi mbi;
    if (!api().VirtualQuery) return false;
    if (!api().VirtualQuery(reinterpret_cast<const void*>(p), &mbi, sizeof(mbi))) {
        w->live = false;
        return false;
    }
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
        w->live = false;
        return false;
    }
    w->base = reinterpret_cast<unsigned long long>(mbi.BaseAddress);
    w->end = w->base + mbi.RegionSize;
    w->live = true;
    return p + len <= w->end;
}

inline bool gc_u64(unsigned long long p, unsigned long long* v, GcWindow* w) {
    if (!gc_ok(p, 8, w)) return false;
    *v = *reinterpret_cast<volatile unsigned long long*>(p);
    return true;
}

struct GcPage {
    unsigned long long base;
    unsigned long long prev;
    unsigned long long next;
    unsigned int pageSize;
    unsigned int blockSize;
    unsigned int busy;
    int freeNext;
};

struct GcProbe {
    unsigned long long page;
    unsigned long long head;
    unsigned long long index;
    unsigned int pageSize;
    unsigned int blockSize;
    unsigned int busy;
    unsigned int pages;
    unsigned int stage;
    unsigned int ttbyte;
    unsigned int tag;
};

inline bool gc_page_read(unsigned long long p, GcWindow* w, GcPage* pg) {
    if (!gc_ok(p, 0x40, w)) return false;
    const char* b = reinterpret_cast<const char*>(p);
    const unsigned int ps = *reinterpret_cast<const volatile unsigned int*>(b + 0x20);
    const unsigned int bs = *reinterpret_cast<const volatile unsigned int*>(b + 0x24);
    if (bs < 8 || bs > 0x10000 || ps < 0x40 + bs || ps > 0x400000) return false;
    const unsigned long long blocks = (ps - 0x40ull) / bs;
    if (!blocks || blocks > 0x40000) return false;
    const unsigned int busy = *reinterpret_cast<const volatile unsigned int*>(b + 0x34);
    if (busy > blocks) return false;
    const int fn = *reinterpret_cast<const volatile int*>(b + 0x30);
    if (fn < -static_cast<int>(bs) || fn > static_cast<int>((blocks - 1) * bs)) return false;
    if (fn % static_cast<int>(bs)) return false;
    unsigned long long prev = 0, next = 0;
    if (!gc_u64(p + 0x10, &prev, w) || !gc_u64(p + 0x18, &next, w)) return false;
    pg->base = p;
    pg->prev = prev;
    pg->next = next;
    pg->pageSize = ps;
    pg->blockSize = bs;
    pg->busy = busy;
    pg->freeNext = fn;
    return true;
}

// A page is reachable from its own block grid: data starts at +0x40, blocks
// are blockSize apart, and pages are 16-byte aligned heap blocks. Candidate
// bases are rejected unless the neighbouring pages point back at them, which
// is what separates a real page header from a table full of pointers.
inline bool gc_page_linked(unsigned long long p, GcWindow* w) {
    GcPage pg;
    if (!gc_page_read(p, w, &pg)) return false;
    unsigned long long cur = p;
    for (int i = 0; i < 64; ++i) {
        if (!pg.prev) break;
        GcPage pp;
        if (!gc_page_read(pg.prev, w, &pp)) return false;
        if (pp.next != cur) return false;
        cur = pg.prev;
        pg = pp;
    }
    if (!gc_page_read(p, w, &pg)) return false;
    cur = p;
    for (int i = 0; i < 64; ++i) {
        if (!pg.next) break;
        GcPage nn;
        if (!gc_page_read(pg.next, w, &nn)) return false;
        if (nn.prev != cur) return false;
        cur = pg.next;
        pg = nn;
    }
    return true;
}

inline bool gc_find_page(unsigned long long obj, unsigned int tag, GcWindow* w,
                         GcPage* out) {
    for (unsigned long long back = 0x40; back <= 0x8000; back += 8) {
        if (obj < back) break;
        const unsigned long long p = obj - back;
        GcPage pg;
        if (!gc_page_read(p, w, &pg)) continue;
        const unsigned long long off = back - 0x40;
        if (off % pg.blockSize) continue;
        if (off / pg.blockSize >= (pg.pageSize - 0x40ull) / pg.blockSize) continue;
        // A header that validates is not proof: a run of pointers inside a big
        // table can satisfy the same shape. The block at the target's index
        // must also carry the collector tag the caller saw, which a wrong page
        // cannot fake at the right grid offset.
        if (tag) {
            const unsigned int b0 = *reinterpret_cast<const volatile unsigned char*>(obj);
            const unsigned int b1 = *reinterpret_cast<const volatile unsigned char*>(obj + 1);
            if (b1 != tag && b0 != tag) continue;
        }
        if (!gc_page_linked(p, w)) continue;
        *out = pg;
        return true;
    }
    return false;
}

inline void gc_probe(unsigned long long target, unsigned int tag, GcProbe* pr) {
    pr->page = pr->head = pr->index = 0;
    pr->pageSize = pr->blockSize = pr->busy = pr->pages = 0;
    pr->stage = 0;
    pr->ttbyte = 1; // measured here: mark byte at +0, type byte at +1
    pr->tag = 0;
    if (!target) return;

    GcWindow w{false, 0, 0};
    if (!gc_ok(target, 2, &w)) return;
    const unsigned int b0 = *reinterpret_cast<const volatile unsigned char*>(target);
    const unsigned int b1 = *reinterpret_cast<const volatile unsigned char*>(target + 1);
    if (tag && b1 == tag) pr->ttbyte = 1;
    else if (tag && b0 == tag) pr->ttbyte = 0;
    pr->tag = pr->ttbyte ? b1 : b0;
    pr->stage |= 1;

    GcPage pg;
    if (!gc_find_page(target, tag, &w, &pg)) return;
    pr->page = pg.base;
    pr->pageSize = pg.pageSize;
    pr->blockSize = pg.blockSize;
    pr->busy = pg.busy;
    pr->index = (target - (pg.base + 0x40)) / pg.blockSize;
    pr->stage |= 2;

    unsigned long long cur = pg.base;
    for (unsigned int i = 0; i < 200000 && cur; ++i) {
        GcPage c;
        if (!gc_page_read(cur, &w, &c)) break;
        if (!c.prev) { pr->head = cur; break; }
        GcPage pp;
        if (!gc_page_read(c.prev, &w, &pp) || pp.next != cur) break;
        cur = c.prev;
    }
    if (!pr->head) return;
    pr->stage |= 4;

    unsigned int n = 0;
    cur = pr->head;
    while (cur && n < 200000) {
        GcPage c;
        if (!gc_page_read(cur, &w, &c)) break;
        ++n;
        if (!c.next) break;
        GcPage nn;
        if (!gc_page_read(c.next, &w, &nn) || nn.prev != cur) break;
        cur = c.next;
    }
    pr->pages = n;
    if (n) pr->stage |= 8;
}

// Measured on this client (s59): a live table reads `04 07 00 ff`, a string
// `02 06 ...`, a closure `01 08 ...`. So CommonHeader here is marked at byte 0
// and tt at byte 1 - the opposite of the open-source Luau order. luaM_freegco_
// writes tt = LUA_TNIL there before a block joins the free list, which makes
// byte 1 authoritative: live blocks name a collector tag, freed blocks read 0.
inline unsigned int gc_block_tt(unsigned long long p, GcWindow* w) {
    if (!gc_ok(p, 2, w)) return 0;
    const unsigned int b1 = *reinterpret_cast<const volatile unsigned char*>(p + 1);
    return (b1 >= 6 && b1 <= 13) ? b1 : 0;
}

// Same frame accounting as lua_ret_num, but the value qword and the type tag
// are written as given. tag 7/8/9/10 is what the collector itself calls a
// table, a closure, a userdata and a thread, so the VM sees an ordinary value.
inline int lua_ret_gc(unsigned long long L, unsigned long long obj, unsigned int tag) {
    unsigned long long top = 0;
    if (!read_u64(L + 0x60, &top) || !top) return 0;
    unsigned long long last = 0, ci = 0, citop = 0;
    read_u64(L + 0x68, &last);
    if (read_u64(L + 0x70, &ci) && ci) read_u64(ci + 0x8, &citop);
    unsigned long long limit = last;
    if (citop && citop < limit) limit = citop;
    if (limit && top + 16 > limit) return 0;
    wr64(top, obj);
    wr64(top + 8, static_cast<unsigned long long>(tag) << 32);
    wr64(L + 0x60, top + 16);
    return 1;
}

inline unsigned int gc_room(unsigned long long L) {
    unsigned long long top = 0, last = 0, ci = 0, citop = 0;
    if (!read_u64(L + 0x60, &top) || !top) return 0;
    read_u64(L + 0x68, &last);
    if (read_u64(L + 0x70, &ci) && ci) read_u64(ci + 0x8, &citop);
    unsigned long long limit = last;
    if (citop && citop < limit) limit = citop;
    if (!limit || top >= limit) return 0;
    return static_cast<unsigned int>((limit - top) / 16);
}

// zendo:gclock / zendo:gcunlock
//
// The collector fires when totalbytes >= GCthreshold (global_State+0x60,
// measured from the struct dump, not guessed from a disassembly). Raising the
// threshold parks the collector without touching its state machine: nothing is
// stopped, swept or invalidated, the trigger simply never arrives. Putting the
// old value back re-arms it. One qword each way, no VM call, so it is safe to
// do from inside a borrowed frame.
int zendo_gclock_op(unsigned long long l, bool lock) {
    unsigned long long gs = 0;
    if (!read_u64(l + 0x50, &gs) || !gs) return 0;
    if (lock) {
        unsigned long long cur = 0, total = 0;
        if (!read_u64(gs + 0x60, &cur)) return 0;
        if (!read_u64(gs + 0x68, &total)) return 0;
        g_saved_threshold = cur;
        wr64(gs + 0x60, total + (1ull << 40));
        return lua_ret_num(l, 1.0);
    }
    if (g_saved_threshold) {
        wr64(gs + 0x60, g_saved_threshold);
        g_saved_threshold = 0;
    }
    return lua_ret_num(l, 1.0);
}

// probe: stage, ttbyte, page, pageSize, blockSize, busy, head, pages, index, tag
// page: page, startBlock, want -> n, nextBlock, nextPage, then the objects.
int zendo_gc_op(unsigned long long l, bool walk) {
    if (!walk) {
        double tf = 0.0, tgf = 0.0;
        unsigned long long target = 0;
        unsigned int tag = 0;
        if (lua_arg_num(l, 1, &tf) && tf > 0x10000)
            target = static_cast<unsigned long long>(tf);
        if (lua_arg_num(l, 2, &tgf) && tgf >= 0 && tgf < 32)
            tag = static_cast<unsigned int>(tgf);
        GcProbe pr;
        gc_probe(target, tag, &pr);
        int r = lua_ret_num(l, static_cast<double>(pr.stage));
        r += lua_ret_num(l, static_cast<double>(pr.ttbyte));
        r += lua_ret_num(l, static_cast<double>(pr.page));
        r += lua_ret_num(l, static_cast<double>(pr.pageSize));
        r += lua_ret_num(l, static_cast<double>(pr.blockSize));
        r += lua_ret_num(l, static_cast<double>(pr.busy));
        r += lua_ret_num(l, static_cast<double>(pr.head));
        r += lua_ret_num(l, static_cast<double>(pr.pages));
        r += lua_ret_num(l, static_cast<double>(pr.index));
        r += lua_ret_num(l, static_cast<double>(pr.tag));
        return r;
    }

    double pf = 0.0, bf = 0.0, wf = 16.0, rf = 0.0, ff = 0.0;
    if (!lua_arg_num(l, 1, &pf) || pf < 0x10000) return 0;
    if (!lua_arg_num(l, 2, &bf) || bf < 0) bf = 0;
    if (!lua_arg_num(l, 3, &wf) || wf < 1) wf = 16;
    lua_arg_num(l, 4, &rf);
    lua_arg_num(l, 5, &ff);
    const bool raw = rf > 0.5;
    // A filter of 0 keeps tables, closures and userdata. Anything else keeps
    // only that collector tag, so a caller can ask for one class at a time -
    // which is also how a suspect class gets isolated without a crash fest.
    const unsigned int keep_tt = (ff >= 6 && ff <= 13) ? static_cast<unsigned int>(ff) : 0;
    const unsigned long long page = static_cast<unsigned long long>(pf);
    unsigned int start = static_cast<unsigned int>(bf);
    unsigned int want = static_cast<unsigned int>(wf);

    const unsigned int room = gc_room(l);
    const unsigned int per = raw ? 1u : 2u;
    if (room < 8) return 0;
    const unsigned int capwant = (room - 6) / per;
    if (want > capwant) want = capwant;
    if (want < 1) want = 1;
    if (want > 48 / per) want = 48 / per;

    GcWindow w{false, 0, 0};
    GcPage pg;
    if (!gc_page_read(page, &w, &pg)) return 0;
    const unsigned long long blocks = (pg.pageSize - 0x40ull) / pg.blockSize;
    // luaM_getpagewalkinfo, verbatim: blocks are handed out from the top of the
    // page downward, so the walked region is [data + freeNext + blockSize,
    // data + blockCount*blockSize). Everything below that was never handed out
    // and holds uninitialised heap - reading it as objects fed garbage tags
    // into the VM and killed the client.
    unsigned int alloc_begin = 0;
    const long long fn = static_cast<long long>(pg.freeNext);
    if (fn >= 0) {
        alloc_begin = static_cast<unsigned int>(static_cast<unsigned long long>(fn) / pg.blockSize) + 1;
        if (alloc_begin > blocks) alloc_begin = static_cast<unsigned int>(blocks);
    }
    const unsigned int alloc_end = static_cast<unsigned int>(blocks);

    unsigned int i = start;
    if (i < alloc_begin) i = alloc_begin;
    if (i > alloc_end) i = alloc_end;

    unsigned long long objs[48];
    unsigned int tags[48];
    unsigned int got = 0;
    while (i < alloc_end && got < want) {
        const unsigned long long p = page + 0x40 + static_cast<unsigned long long>(i) * pg.blockSize;
        const unsigned int tt = gc_block_tt(p, &w);
        if (tt >= 7 && tt <= 9 && (!keep_tt || tt == keep_tt)) {
            objs[got] = p;
            tags[got] = tt;
            ++got;
        }
        ++i;
    }

    const unsigned int nextb = i >= alloc_end ? 0u : i;
    int r = lua_ret_num(l, static_cast<double>(got));
    r += lua_ret_num(l, static_cast<double>(nextb));
    r += lua_ret_num(l, static_cast<double>(pg.next));
    r += lua_ret_num(l, static_cast<double>(pg.pageSize));
    r += lua_ret_num(l, static_cast<double>(pg.blockSize));
    r += lua_ret_num(l, static_cast<double>(pg.busy));
    for (unsigned int k = 0; k < got; ++k) {
        if (raw)
            r += lua_ret_gc(l, objs[k], tags[k]);
        else {
            r += lua_ret_num(l, static_cast<double>(objs[k]));
            r += lua_ret_num(l, static_cast<double>(tags[k]));
        }
    }
    return r;
}

// zendo:gcfill(table, slot, page, startBlock, maxCount, filter)
//
// Fills the array part of an existing Lua table with collector objects taken
// from one GC page. The destination is the table's own TValue array (+0x28)
// with its capacity at +0x08, so nothing is pushed on the VM stack: one call
// can import hundreds of objects while the borrowed frame stays untouched.
//
// Free blocks are the one lie the page grid tells: their first word is a
// pointer to the next free block, and the low bytes of that pointer can land on
// any value, including a valid collector tag. The page free list is walked
// first and every node it names is skipped, which leaves only blocks the
// allocator currently believes are live.
int zendo_gcfill_op(unsigned long long l) {
    LuaArg tab{};
    double sf = 0.0, pf = 0.0, bf = 0.0, wf = 1.0, ff = 0.0;
    if (!lua_arg(l, 1, &tab) || ((tab.w >> 32) & 0xff) != 7 || !tab.v) return 0;
    if (!lua_arg_num(l, 2, &sf) || sf < 1) return 0;
    if (!lua_arg_num(l, 3, &pf) || pf < 0x10000) return 0;
    if (!lua_arg_num(l, 4, &bf) || bf < 0) bf = 0;
    if (!lua_arg_num(l, 5, &wf) || wf < 1) wf = 1;
    lua_arg_num(l, 6, &ff);

    unsigned long long array = 0;
    unsigned int size = 0;
    read_u64(tab.v + 0x28, &array);
    read_u32(tab.v + 0x08, &size);
    if (!array || !size) return 0;

    unsigned int slot = static_cast<unsigned int>(sf);
    if (slot > size) return 0;
    unsigned int want = static_cast<unsigned int>(wf);
    const unsigned int room = size - slot + 1;
    if (want > room) want = room;
    if (want > 1024) want = 1024;

    const unsigned int keep_tt = (ff >= 6 && ff <= 13) ? static_cast<unsigned int>(ff) : 0;
    const unsigned long long page = static_cast<unsigned long long>(pf);

    unsigned int got = 0, nextb = 0;
    unsigned long long nextPage = 0;
    GcWindow w{false, 0, 0};
    GcPage pg;
    if (!gc_page_read(page, &w, &pg)) return 0;
    nextPage = pg.next;
    if (!gc_ok(array + 16ull * (slot - 1), 16, &w)) return 0;

    const unsigned long long blocks = (pg.pageSize - 0x40ull) / pg.blockSize;
    // Same region luaM_visitpage walks: freeNext is the bump pointer that moves
    // downward, so only [freeNext + blockSize, blockCount*blockSize) was ever
    // handed out. Free blocks keep tt = LUA_TNIL (luaM_freegco_), which is the
    // exact test the collector's own visitor uses - no free-list chase needed.
    unsigned int alloc_begin = 0;
    const long long fn = static_cast<long long>(pg.freeNext);
    if (fn >= 0) {
        alloc_begin = static_cast<unsigned int>(static_cast<unsigned long long>(fn) / pg.blockSize) + 1;
        if (alloc_begin > blocks) alloc_begin = static_cast<unsigned int>(blocks);
    }
    const unsigned int alloc_end = static_cast<unsigned int>(blocks);

    unsigned int i = static_cast<unsigned int>(bf);
    if (i < alloc_begin) i = alloc_begin;
    if (i > alloc_end) i = alloc_end;
    while (i < alloc_end && got < want) {
        const unsigned long long p = page + 0x40 + static_cast<unsigned long long>(i) * pg.blockSize;
        const unsigned int tt = gc_block_tt(p, &w);
        if (tt >= 7 && tt <= 9 && (!keep_tt || tt == keep_tt)) {
            const unsigned long long dst = array + 16ull * (slot - 1 + got);
            if (!gc_ok(dst, 16, &w)) break;
            *reinterpret_cast<volatile unsigned long long*>(dst) = p;
            *reinterpret_cast<volatile unsigned long long*>(dst + 8) =
                static_cast<unsigned long long>(tt) << 32;
            ++got;
        }
        ++i;
    }
    nextb = i >= alloc_end ? 0u : i;

    int r = lua_ret_num(l, static_cast<double>(got));
    r += lua_ret_num(l, static_cast<double>(nextb));
    r += lua_ret_num(l, static_cast<double>(nextPage));
    return r;
}

// zendo:gspage(page) -> stage, head, offset, pages, busy, global, prev, alive
//
// The all-pages list is a doubly linked list threaded through listprev/listnext
// (+0x10/+0x18). Starting from any page that belongs to it, listprev walks to
// the head; then global_State is searched for the qword that names that head.
// Nothing is assumed: the offset is whatever this client's global_State reports,
// and a bad guess simply fails to match and reports stage 0 for that bit.
int zendo_gspage_op(unsigned long long l) {
    double pf = 0.0;
    if (!lua_arg_num(l, 1, &pf) || pf < 0x10000) return 0;
    const unsigned long long page = static_cast<unsigned long long>(pf);

    GcWindow w{false, 0, 0};
    GcPage pg;
    if (!gc_page_read(page, &w, &pg)) return 0;

    unsigned int stage = 1;

    // The anchor page itself may be mid-list; listprev walks to whatever head it
    // can reach. This part is kept because it is cheap, but it is not trusted:
    // the field order of lua_Page is being measured, not assumed.
    unsigned long long ahead = page, aprev = pg.prev;
    for (unsigned int i = 0; i < 200000 && aprev; ++i) {
        GcPage pp;
        if (!gc_page_read(aprev, &w, &pp) || pp.next != ahead) break;
        ahead = aprev;
        aprev = pp.prev;
    }
    unsigned int apages = 0;
    {
        unsigned long long cur = ahead;
        for (unsigned int i = 0; i < 200000 && cur; ++i) {
            GcPage c;
            if (!gc_page_read(cur, &w, &c)) break;
            ++apages;
            if (!c.next) break;
            GcPage nn;
            if (!gc_page_read(c.next, &w, &nn) || nn.prev != cur) break;
            cur = c.next;
        }
    }
    if (apages) stage |= 8;

    // global_State scan: every qword that points at a readable page is a
    // candidate field. The real all-pages head is the one whose +0x18 chain is
    // longest, which no incidental pointer can satisfy.
    unsigned long long gs = 0, best = 0, bestoff = 0;
    unsigned int bestpages = 0, bestbusy = 0;
    read_u64(l + 0x50, &gs);
    if (gs) {
        for (unsigned long long off = 0; off + 8 <= 0x8000; off += 8) {
            unsigned long long v = 0;
            if (!gc_u64(gs + off, &v, &w)) break;
            if (v < 0x10000) continue;
            GcPage c;
            if (!gc_page_read(v, &w, &c)) continue;
            unsigned int n = 1, busy = c.busy;
            unsigned long long cur = v, prev2 = 0;
            while (n < 200000) {
                GcPage cc;
                if (!gc_page_read(cur, &w, &cc)) break;
                if (!cc.next || cc.next == cur || cc.next == v || cc.next == prev2) break;
                GcPage nn;
                if (!gc_page_read(cc.next, &w, &nn)) break;
                ++n;
                busy += nn.busy;
                prev2 = cur;
                cur = cc.next;
            }
            if (n > bestpages) { bestpages = n; best = v; bestoff = off; bestbusy = busy; }
        }
    }
    if (bestpages > 1) stage |= 2;
    if (bestoff) stage |= 4;

    int r = lua_ret_num(l, static_cast<double>(stage));
    r += lua_ret_num(l, static_cast<double>(best));
    r += lua_ret_num(l, static_cast<double>(bestoff));
    r += lua_ret_num(l, static_cast<double>(bestpages));
    r += lua_ret_num(l, static_cast<double>(bestbusy));
    r += lua_ret_num(l, static_cast<double>(gs));
    r += lua_ret_num(l, static_cast<double>(ahead));
    r += lua_ret_num(l, static_cast<double>(apages));
    return r;
}

// collectgarbage("collect") is this call: registration RVA 0x71b8290 names the
// C function at 0x4320A80, whose collect path passes only L to 0x265D9F0. Call
// the callee, not the registration: no string argument to build, no table walk.
int zendo_gcforce_op(unsigned long long l) {
    if (!g_base) return 0;
    typedef void (*FullGcFn)(void*);
    FullGcFn fullgc = reinterpret_cast<FullGcFn>(g_base + 0x265D9F0);
    fullgc(reinterpret_cast<void*>(l));
    return lua_ret_num(l, 1.0);
}

// Runs the flush chunk with the report pipe muted: the payload's chatter would
// otherwise flood the UI on every script. Only `P` lines survive.
