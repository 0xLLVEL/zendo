inline bool state_is_ours(unsigned long long l) {
    for (int i = 0; i < g_ours_n; ++i) {
        if (g_ours[i] == l) return true;
    }
    return false;
}

// A call may reach the dispatcher from a marked state, or when it announces
// itself. `mark` is the one op that has to work before the state is known -
// it is what makes the state known - and it only appends an address.
inline bool call_authorized(unsigned long long l) {
    if (state_is_ours(l)) return true;
    unsigned int oplen = 0;
    char* op = lua_arg_str(l, 0, &oplen);
    return op && op_is(op, oplen, "zendo:mark");
}

inline int native_api(void* L) {
    unsigned long long l = reinterpret_cast<unsigned long long>(L);
    // The window is the narrow answer: a chunk of ours is running right now.
    // The wide answer is a state we have marked. A deferred body outlives the
    // window its wrapper ran in, and the scheduler resumes it on a state the
    // wrapper registered before handing it over. A call from anywhere else is
    // a stale reference and still gets nothing.
    if (!g_cap_capture && !call_authorized(l)) return 0;
    // A dedicated page, not a static in the image: the write op changes page
    // protection, and touching the page our own code lives on is a variable
    // this test does not need.
    static unsigned long long scratch = 0;
    if (!scratch) {
        void* p = api().VirtualAlloc ? api().VirtualAlloc(nullptr, 0x1000,
                                                          MEM_COMMIT | MEM_RESERVE,
                                                          PAGE_READWRITE)
                                     : nullptr;
        if (p) {
            scratch = reinterpret_cast<unsigned long long>(p);
            const char init[] = "ZENDO-API-OK";
            for (unsigned int i = 0; i < sizeof(init); ++i)
                *reinterpret_cast<char*>(scratch + i) = init[i];
        }
    }
    // Every entry is recorded, matched or not: the fallback prints, so the log
    // cannot tell "dispatcher ran and fell through" from "never called".
    if (g_diag) {
        HANDLE f = api().CreateFileA("D:\\zendo\\work\\api.bin", GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            char b[4] = {'A', ' ', static_cast<char>('0' + (g_api_hits % 10)), '\n'};
            DWORD w = 0;
            ++g_api_hits;
            api().WriteFile(f, b, 4, &w, nullptr);
            api().CloseHandle(f);
        }
    }

    unsigned int oplen = 0;
    char* op = lua_arg_str(l, 0, &oplen);
    if (op) {
        if (op_is(op, oplen, "zendo:ping")) {
            api_step('S', 1);
            int r = lua_ret_num(l, 4080.0);
            api_step('E', 1);
            return r;
        }
        if (op_is(op, oplen, "zendo:scratch")) {
            api_step('S', 2);
            int r = lua_ret_num(l, static_cast<double>(scratch));
            api_step('E', 2);
            return r;
        }

        // The identity lives on the state's extras block, the same +0x70 the
        // session gate writes 8 into. Reading it from the caller's own state is
        // what checkcaller needs: a thread we lifted answers 8, a plain game
        // callback answers its own level.
        if (op_is(op, oplen, "zendo:caller")) {
            api_step('S', 23);
            for (int i = 0; i < g_ours_n; ++i) {
                if (g_ours[i] == l) {
                    api_step('E', 23);
                    return lua_ret_num(l, 1.0);
                }
            }
            unsigned long long ex = 0, ident = 0;
            if (read_u64(l + 8, &ex) && ex) read_u64(ex + 0x70, &ident);
            api_step('E', 23);
            return lua_ret_num(l, ident >= 8.0 ? 2.0 : 0.0);
        }

        // The identity the caller's state carries, straight off the extras block.
        // The session gate writes 8 there; the game's own callbacks carry their
        // own level. Reading it is the honest half of getthreadidentity - the
        // write side would also have to raise the capability mask, and a false
        // identity with no capabilities is worse than none.
        if (op_is(op, oplen, "zendo:ident")) {
            api_step('S', 32);
            unsigned long long ex = 0, ident = 0;
            if (read_u64(l + 8, &ex) && ex) read_u64(ex + 0x70, &ident);
            int r = lua_ret_num(l, static_cast<double>(ident));
            api_step('P', 32);
            return r;
        }

        // Same op the other way round: the chunk announces the state it runs on.
        if (op_is(op, oplen, "zendo:mark")) {
            api_step('S', 24);
            bool known = false;
            for (int i = 0; i < g_ours_n; ++i) {
                if (g_ours[i] == l) { known = true; break; }
            }
            if (!known) {
                if (g_ours_n == 16) {
                    for (int i = 1; i < 16; ++i) g_ours[i - 1] = g_ours[i];
                    g_ours[15] = l;
                } else {
                    g_ours[g_ours_n++] = l;
                }
            }
            api_step('E', 24);
            return lua_ret_num(l, static_cast<double>(g_ours_n));
        }

        if (op_is(op, oplen, "zendo:file") || op_is(op, oplen, "zendo:filew") ||
            op_is(op, oplen, "zendo:isfile") || op_is(op, oplen, "zendo:listfiles") ||
            op_is(op, oplen, "zendo:isfolder") || op_is(op, oplen, "zendo:mkdir") ||
            op_is(op, oplen, "zendo:del")) {
            api_step('S', 25);
            int r = zendo_file_op(l, op, oplen);
            api_step('E', 25);
            return r;
        }

        // HTTP is a host job. The payload cannot build a Luau string, so it
        // only forwards the request and receives two file paths the script can
        // read back; no socket is opened inside the client.
        if (op_is(op, oplen, "zendo:req")) {
            api_step('S', 34);
            int r = zendo_http_op(l);
            api_step('E', 34);
            return r;
        }

        // The GC object list. probe answers with the offsets it proved, walk
        // hands back the objects themselves as ordinary Lua values.
        // No api_step here: this op runs in tight loops (one call per batch of
        // objects), and two file writes per call dominated the run time and
        // widened the window where the collector could move under the walk.
        if (op_is(op, oplen, "zendo:gcprobe") || op_is(op, oplen, "zendo:gcpage")) {
            return zendo_gc_op(l, op_is(op, oplen, "zendo:gcpage"));
        }

        // Park and re-arm the collector around a walk that imports raw objects.
        if (op_is(op, oplen, "zendo:gclock")) return zendo_gclock_op(l, true);
        if (op_is(op, oplen, "zendo:gcunlock")) return zendo_gclock_op(l, false);

        // Bulk collector read: writes objects straight into a Lua table array
        // instead of pushing each one through the frame. Same live-heap rules as
        // the page walk, but the imported surface is one table instead of a
        // borrowed stack window, which is what a full getgc needs.
        if (op_is(op, oplen, "zendo:gcfill")) {
            return zendo_gcfill_op(l);
        }

        // List geometry, measured against the live global_State instead of
        // assumed: gspage walks listprev to the head of allgcopages and then
        // reports the offset inside global_State that points at it.
        if (op_is(op, oplen, "zendo:gspage")) {
            return zendo_gspage_op(l);
        }

        // collectgarbage("collect") without going through the registration
        // table: the same C entry, called directly on the caller's thread.
        if (op_is(op, oplen, "zendo:gcforce")) {
            return zendo_gcforce_op(l);
        }

        // A raw window into a closure's Proto. Nothing here interprets the
        // fields - it hands back the first words so a script can show which
        // offset is which, and the reading is decided from that, not guessed.
        // FNV-1a over the proto's instruction words. Two functions compiled from
        // the same source have identical code and therefore the same hash; an
        // edited body differs on the first changed instruction. Constants and
        // constants order are deliberately not folded in: the sUNC contract is a
        // stable identity for the bytecode, and a name or string constant can be
        // mutated at runtime without changing what the function does.
        if (op_is(op, oplen, "zendo:fnhash")) {
            api_step('S', 27);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) return 0;
            unsigned long long proto = 0, code = 0;
            if (!read_u64(a.v + 0x18, &proto) || !proto) return 0;
            if (!read_u64(proto + 0x68, &code) || !code) return 0;
            unsigned int sizecode = 0;
            if (!read_u32(proto + 0xA8, &sizecode) || !sizecode) return 0;
            if (sizecode > 0x40000) sizecode = 0x40000;
            unsigned int h = 2166136261u;
            for (unsigned int i = 0; i < sizecode; ++i) {
                unsigned int w = 0;
                if (!read_u32(code + 4ull * i, &w)) break;
                h ^= w & 0xffu;
                h *= 16777619u;
                h ^= (w >> 8) & 0xffu;
                h *= 16777619u;
                h ^= (w >> 16) & 0xffu;
                h *= 16777619u;
                h ^= (w >> 24) & 0xffu;
                h *= 16777619u;
            }
            api_step('E', 27);
            return lua_ret_num(l, static_cast<double>(h));
        }

        if (op_is(op, oplen, "zendo:proto")) {
            api_step('S', 26);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) return 0;
            unsigned long long proto = 0;
            if (!read_u64(a.v + 0x18, &proto) || !proto) return 0;
            double startf = 0;
            unsigned int start = 0;
            if (lua_arg_num(l, 2, &startf) && startf > 0 && startf < 0x200) {
                start = static_cast<unsigned int>(startf) & ~3u;
            }
            int pushed = 0;
            for (unsigned int i = 0; i < 24; ++i) {
                unsigned int w = 0;
                if (!read_u32(proto + start + 4ull * i, &w)) break;
                pushed += lua_ret_num(l, static_cast<double>(w));
            }
            api_step('E', 26);
            return pushed;
        }

        // Copy a TValue out of the proto's constants array. The value already
        // lives in the VM heap, so moving its 16 bytes onto the result stack
        // gives the script a real string or number without constructing one.
        if (op_is(op, oplen, "zendo:kget")) {
            api_step('S', 28);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) return 0;
            double idxf = 0;
            if (!lua_arg_num(l, 2, &idxf) || idxf < 0 || idxf > 4096) return 0;
            unsigned long long proto = 0, k = 0;
            if (!read_u64(a.v + 0x18, &proto) || !proto) return 0;
            if (!read_u64(proto + 0x60, &k) || !k) return 0;
            unsigned int sizek = 0;
            read_u32(proto + 0xac, &sizek);
            unsigned int i = static_cast<unsigned int>(idxf);
            if (i >= sizek) return 0;
            unsigned long long src = k + 16ull * i;
            unsigned long long v = 0, w = 0;
            if (!read_u64(src, &v) || !read_u64(src + 8, &w)) return 0;

            unsigned long long top = 0;
            if (!read_u64(l + 0x60, &top) || !top) return 0;
            unsigned long long last = 0, ci = 0, citop = 0;
            read_u64(l + 0x68, &last);
            if (read_u64(l + 0x70, &ci) && ci) read_u64(ci + 0x8, &citop);
            unsigned long long limit = last;
            if (citop && citop < limit) limit = citop;
            if (limit && top + 16 > limit) return 0;
            wr64(top, v);
            wr64(top + 8, w);
            wr64(l + 0x60, top + 16);
            api_step('E', 28);
            return 1;
        }
        // The write half of kget: a constant is a TValue in the proto's k array,
        // so a number, boolean or nil can be stored with the same shape the
        // reader already understands. Strings stay refused for the same reason
        // setupvalue refuses them - a collectable needs a write barrier whose
        // address has not been measured in this build.
        if (op_is(op, oplen, "zendo:kset")) {
            api_step('S', 33);
            LuaArg a{};
            LuaArg val{};
            double idxf = 0;
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v ||
                !lua_arg_num(l, 2, &idxf) || idxf < 0 || idxf > 4096 ||
                !lua_arg(l, 3, &val))
                return 0;
            unsigned int tt = static_cast<unsigned int>((val.w >> 32) & 0xff);
            if (tt != 0 && tt != 1 && tt != 3) {
                api_step('E', 33);
                return lua_ret_num(l, 0.0);
            }
            unsigned long long proto = 0, k = 0;
            if (!read_u64(a.v + 0x18, &proto) || !proto) return 0;
            if (!read_u64(proto + 0x60, &k) || !k) return 0;
            unsigned int sizek = 0;
            read_u32(proto + 0xac, &sizek);
            unsigned int i = static_cast<unsigned int>(idxf);
            if (i >= sizek) return 0;
            char tv[16];
            for (int q = 0; q < 8; ++q) {
                tv[q] = static_cast<char>((val.v >> (8 * q)) & 0xff);
                tv[8 + q] = static_cast<char>((val.w >> (8 * q)) & 0xff);
            }
            if (!api_write(k + 16ull * i, tv, 16)) {
                api_step('E', 33);
                return lua_ret_num(l, 0.0);
            }
            api_step('P', 33);
            return lua_ret_num(l, 1.0);
        }

        // Upvalues. Measured on a live chunk, not taken from a layout doc: a
        // Luau closure keeps the capture count in the low byte of the word at
        // +0x4, and the captures themselves start at +0x20, one TValue each.
        // A capture by value holds the value inline. A capture by reference
        // holds an UpVal pointer in that TValue's value word under tag 0x10,
        // and UpVal+0x8 is the cell shared with the stack. Both kinds showed up
        // in the same chunk, so the tag is what decides which read applies.
        // Tags are hex in every dump this was measured from: a REF slot prints
        // "tt=10" and that is 16, not ten. Comparing against ten keeps tag 0x10
        // flowing to the VM as a value, which the interpreter reads as a type
        // it has no case for and dies on.
        if (op_is(op, oplen, "zendo:ucount")) {
            api_step('S', 30);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) return 0;
            unsigned int head = 0;
            if (!read_u32(a.v + 4, &head)) return 0;
            int r = lua_ret_num(l, static_cast<double>(head & 0xff));
            api_step('P', 30);
            return r;
        }

        if (op_is(op, oplen, "zendo:uget")) {
            api_step('S', 29);
            LuaArg a{};
            double idxf = 0;
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v ||
                !lua_arg_num(l, 2, &idxf) || idxf < 0 || idxf > 255)
                return 0;
            unsigned int head = 0;
            if (!read_u32(a.v + 4, &head)) return 0;
            unsigned int nup = head & 0xff;
            unsigned int i = static_cast<unsigned int>(idxf);
            if (i >= nup) return 0;
            unsigned long long slot = a.v + 0x20 + 16ull * i;
            unsigned long long v = 0, w = 0;
            if (!read_u64(slot, &v) || !read_u64(slot + 8, &w)) return 0;
            if (((w >> 32) & 0xff) == 0x10) {
                unsigned long long cell = 0;
                if (!v || !read_u64(v + 8, &cell) || !cell) return 0;
                if (!read_u64(cell, &v) || !read_u64(cell + 8, &w)) return 0;
            }

            unsigned long long top = 0;
            if (!read_u64(l + 0x60, &top) || !top) return 0;
            unsigned long long last = 0, ci = 0, citop = 0;
            read_u64(l + 0x68, &last);
            if (read_u64(l + 0x70, &ci) && ci) read_u64(ci + 8, &citop);
            unsigned long long limit = last;
            if (citop && citop < limit) limit = citop;
            if (limit && top + 16 > limit) return 0;
            wr64(top, v);
            wr64(top + 8, w);
            wr64(l + 0x60, top + 16);
            api_step('P', 29);
            return 1;
        }

        // Writing an upvalue. Numbers, booleans and nil only: a collectable
        // value stored into a GC object needs a write barrier, and the address
        // of the barrier in this build has not been measured yet. Refusing the
        // collectable tags is the difference between a patch and a crash.
        if (op_is(op, oplen, "zendo:uset")) {
            api_step('S', 31);
            LuaArg a{};
            LuaArg val{};
            double idxf = 0;
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v ||
                !lua_arg_num(l, 2, &idxf) || idxf < 0 || idxf > 255 ||
                !lua_arg(l, 3, &val))
                return 0;
            unsigned int tt = static_cast<unsigned int>((val.w >> 32) & 0xff);
            if (tt != 0 && tt != 1 && tt != 3) {
                api_step('E', 31);
                return lua_ret_num(l, 0.0);
            }
            unsigned int head = 0;
            if (!read_u32(a.v + 4, &head)) return 0;
            unsigned int nup = head & 0xff;
            unsigned int i = static_cast<unsigned int>(idxf);
            if (i >= nup) return 0;
            unsigned long long slot = a.v + 0x20 + 16ull * i;
            unsigned long long v = 0, w = 0;
            if (!read_u64(slot, &v) || !read_u64(slot + 8, &w)) return 0;
            unsigned long long dst = slot;
            if (((w >> 32) & 0xff) == 0x10) {
                if (!v || !read_u64(v + 8, &dst) || !dst) return 0;
            }
            // The cell is usually a stack slot or a live heap page, both already
            // writable. api_write only asks the kernel for a protection change
            // when the page really is read-only, and it sizes the range from the
            // page the address sits in - a hardcoded two page span can walk off
            // the end of the region and come back false on a healthy write.
            char tv[16];
            for (int k = 0; k < 8; ++k) {
                tv[k] = static_cast<char>((val.v >> (8 * k)) & 0xff);
                tv[8 + k] = static_cast<char>((val.w >> (8 * k)) & 0xff);
            }
            if (!api_write(dst, tv, 16)) {
                api_step('E', 31);
                return lua_ret_num(l, 0.0);
            }
            api_step('P', 31);
            return lua_ret_num(l, 1.0);
        }

        // the tag found at each pointer, so the constants array can be found by
        // looking for tag 6 at the address a word holds - not by assuming an
        // offset from a layout doc.
        if (op_is(op, oplen, "zendo:protoscan")) {
            api_step('S', 27);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) return 0;
            unsigned long long proto = 0;
            if (!read_u64(a.v + 0x18, &proto) || !proto) return 0;
            int pushed = 0;
            for (unsigned int i = 0; i < 24; ++i) {
                unsigned long long word = 0;
                if (!read_u64(proto + 8ull * i, &word)) break;
                unsigned int code = 0;
                if (word && readable(reinterpret_cast<const void*>(word), 16)) {
                    unsigned long long w2 = 0;
                    read_u64(word + 8, &w2);
                    unsigned int tt = static_cast<unsigned int>((w2 >> 32) & 0xff);
                    code = 1u | (tt << 1);
                }
                pushed += lua_ret_num(l, static_cast<double>(code));
            }
            api_step('E', 27);
            return pushed;
        }

        if (op_is(op, oplen, "zendo:strinfo")) {
            api_step('S', 3);
            unsigned int slen = 0;
            unsigned long long t = lua_arg_tstr(l, 1, &slen);
            if (t) api_strinfo(t, slen);
            int r = lua_ret_num(l, static_cast<double>(slen));
            api_step('E', 3);
            return r;
        }

        // Raw identity of any Lua value: the pointer inside the TValue and its
        // type tag. Every introspection path starts here - a closure, a table
        // and a userdata all answer with the address of the object the value
        // points at, which is what the GC walk and the proto readers need. The
        // pointer fits a double exactly below 2^48, so it round-trips through
        // the Lua number without losing bits.
        if (op_is(op, oplen, "zendo:ref")) {
            api_step('S', 21);
            LuaArg a{};
            if (!lua_arg(l, 1, &a)) {
                api_step('E', 21);
                return 0;
            }
            int pushed = lua_ret_num(l, static_cast<double>(a.v));
            pushed += lua_ret_num(l, static_cast<double>((a.w >> 32) & 0xff));
            api_step('P', 21);
            return pushed;
        }

        // Closure shape, for the layout probe. A C closure and a Luau closure
        // are different objects behind the same type tag, and the only honest
        // way to tell them apart is to look: the entry candidate at +0x28 and
        // the proto candidate at +0x18 are checked against the page protection
        // they point into. Executable means C; a mapped, non-executable heap
        // page means a proto. The three header bytes go back untouched so the
        // script can print them next to a known C closure and a known Luau one
        // and read the real layout off the two rows.
        if (op_is(op, oplen, "zendo:probe")) {
            api_step('S', 22);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) {
                api_step('E', 22);
                return 0;
            }
            unsigned long long entry = 0, proto = 0;
            read_u64(a.v + 0x28, &entry);
            read_u64(a.v + 0x18, &proto);
            int entry_exec = 0;
            if (entry) {
                Mbi mbi{};
                if (api().VirtualQuery(reinterpret_cast<void*>(entry), &mbi,
                                       sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT) {
                    DWORD prot = mbi.Protect & 0xff;
                    if (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
                        prot == PAGE_EXECUTE_READWRITE ||
                        prot == PAGE_EXECUTE_WRITECOPY)
                        entry_exec = 1;
                }
            }
            unsigned int head = 0;
            read_u32(a.v + 4, &head);
            int pushed = lua_ret_num(l, static_cast<double>(a.v));
            pushed += lua_ret_num(l, static_cast<double>(entry));
            pushed += lua_ret_num(l, static_cast<double>(entry_exec));
            pushed += lua_ret_num(l, static_cast<double>(proto));
            pushed += lua_ret_num(l, static_cast<double>(head & 0xff));
            pushed += lua_ret_num(l, static_cast<double>((head >> 8) & 0xff));
            pushed += lua_ret_num(l, static_cast<double>((head >> 16) & 0xff));
            api_step('P', 22);
            return pushed;
        }

        // Function identity for the Lua layer. A function TValue carries a
        // pointer to a GC closure object; the isC byte sits at +5 and, for a C
        // closure, the entry point at +0x28. Both offsets were measured on this
        // build: the dispatcher swap already writes +0x28 to take over print.
        // Handing them to the script is what lets hookfunction patch and
        // restore a real entry point instead of shadowing a global name.
        if (op_is(op, oplen, "zendo:fninfo")) {
            api_step('S', 19);
            LuaArg a{};
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v) {
                api_step('E', 19);
                return 0;
            }
            unsigned long long head = 0;
            if (!read_u64(a.v + 4, &head)) {
                api_step('E', 19);
                return 0;
            }
            unsigned int isC = static_cast<unsigned int>((head >> 8) & 0xff);
            unsigned long long entry = 0;
            if (isC && !read_u64(a.v + 0x28, &entry)) {
                api_step('E', 19);
                return 0;
            }
            int pushed = lua_ret_num(l, static_cast<double>(a.v));
            pushed += lua_ret_num(l, static_cast<double>(entry));
            pushed += lua_ret_num(l, static_cast<double>(isC));
            api_step('P', 19);
            return pushed;
        }

        // Patch the entry point of a C closure in place. One 8 byte store, so a
        // second thread either sees the old pointer or the new one, never half
        // of each. The page a closure lives on belongs to the GC heap and is
        // writable, but the protect call keeps this honest if that ever changes.
        if (op_is(op, oplen, "zendo:fnset")) {
            api_step('S', 20);
            LuaArg a{};
            double entry = 0;
            if (!lua_arg(l, 1, &a) || ((a.w >> 32) & 0xff) != 8 || !a.v ||
                !lua_arg_num(l, 2, &entry) || entry == 0) {
                api_step('E', 20);
                return 0;
            }
            unsigned long long head = 0;
            if (!read_u64(a.v + 4, &head)) {
                api_step('E', 20);
                return 0;
            }
            if (((head >> 8) & 0xff) != 1) {
                api_step('E', 20);
                return 0;
            }
            unsigned long long slot = a.v + 0x28;
            unsigned long long start = slot & ~0xfffull;
            DWORD oldp = 0;
            if (!api().VirtualProtect(reinterpret_cast<void*>(start), 0x2000,
                                      PAGE_READWRITE, &oldp)) {
                api_step('E', 20);
                return 0;
            }
            *reinterpret_cast<volatile unsigned long long*>(slot) =
                static_cast<unsigned long long>(entry);
            DWORD back = 0;
            api().VirtualProtect(reinterpret_cast<void*>(start), 0x2000, oldp,
                                 &back);
            int r = lua_ret_num(l, 1.0);
            api_step('P', 20);
            return r;
        }

        // loadstring: the loader pushes the closure, so returning 1 hands it
        // back to the script as the result of the call.
        if (op_is(op, oplen, "zendo:load")) {
            api_step('S', 11);
            unsigned int blen = 0;
            char* body = lua_arg_str(l, 1, &blen);
            int n = body ? lua_load_bytes(l, body, blen) : 0;
            api_step(n ? 'P' : 'E', 11);
            return n;
        }

        // Live compile: source in, callable closure out. The executor answers on
        // the same pipe it is already streaming this chunk over.
        if (op_is(op, oplen, "zendo:loadstring")) {
            api_step('S', 13);
            unsigned int slen = 0;
            char* src = lua_arg_str(l, 1, &slen);
            int n = 0;
            if (src && slen) n = lua_compile_remote(l, src, slen);
            api_step(n ? 'P' : 'E', 13);
            return n;
        }

        if (op_is(op, oplen, "zendo:loadf")) {
            api_step('S', 12);
            unsigned int plen = 0;
            char* path = lua_arg_str(l, 1, &plen);
            int n = 0;
            if (path && plen && plen < 240) {
                char tmp[256];
                for (unsigned int i = 0; i < plen; ++i)
                    *reinterpret_cast<volatile char*>(tmp + i) = path[i];
                tmp[plen] = 0;
                n = lua_load_file(l, tmp);
            }
            api_step(n ? 'P' : 'E', 12);
            return n;
        }

        // Chunk-side reporting. The script hands the values it wants recorded to
        // this op, so the numbers are read from a live call frame instead of from
        // the pcall result area, which can sit in a stack block that was
        // reallocated by the call.
        if (op_is(op, oplen, "zendo:logv")) {
            unsigned long long raw[4] = {0, 0, 0, 0};
            for (int i = 1; i <= 4; ++i) {
                LuaArg a{};
                if (!lua_arg(l, i, &a)) continue;
                raw[i - 1] = a.v;
            }
            api_line('V', raw[0], raw[1], raw[2], raw[3]);
            return lua_ret_num(l, 1.0);
        }

        // Frame probe: records L, base, top, ci->top as the script sees the call
        // arrive. Runs before and after other ops in a chunk, so a frame that
        // goes bad can be pinned to the call that broke it.
        if (op_is(op, oplen, "zendo:mark")) {
            unsigned long long top = 0, base = 0, ci = 0, citop = 0;
            read_u64(l + 0x60, &top);
            read_u64(l + 0x58, &base);
            if (read_u64(l + 0x70, &ci) && ci) read_u64(ci + 0x8, &citop);
            api_line('M', l, base, top, citop);
            return 0;
        }

        // Reads five numeric arguments and returns their sum. No memory access
        // at all: this isolates argument marshalling from the store itself.
        if (op_is(op, oplen, "zendo:argsum")) {
            api_step('S', 9);
            double sum = 0, v = 0;
            int got = 0;
            for (int i = 1; i <= 5; ++i) {
                if (!lua_arg_num(l, i, &v)) break;
                sum += v;
                ++got;
            }
            int r = lua_ret_num(l, sum);
            api_step('P', 9);
            return r;
        }

        // Plain write, no protection change: this is the same store the poke op
        // does, with VirtualProtect taken out of the picture, so a crash can be
        // blamed on one of the two.
        if (op_is(op, oplen, "zendo:wr8")) {
            api_step('S', 8);
            double addr = 0;
            if (!lua_arg_num(l, 1, &addr)) {
                api_step('E', 8);
                return 0;
            }
            unsigned long long a = static_cast<unsigned long long>(addr);
            if (!readable(reinterpret_cast<const void*>(a), 4)) {
                api_step('E', 8);
                return 0;
            }
            int written = 0;
            for (int i = 2; i <= 9; ++i) {
                double v = 0;
                if (!lua_arg_num(l, i, &v)) break;
                *reinterpret_cast<volatile unsigned char*>(a + written) =
                    static_cast<unsigned char>(static_cast<unsigned long long>(v) & 0xff);
                ++written;
            }
            int r = lua_ret_num(l, static_cast<double>(written));
            api_step('P', 8);
            return r;
        }

        // The output path that matters: copy memory into a caller-supplied
        // script string. A long string stores its bytes inline at +0x18, so this
        // is a straight memcpy into the GC heap - no allocation, no interning,
        // no return marshalling for strings.
        if (op_is(op, oplen, "zendo:readn")) {
            api_step('S', 10);
            double addr = 0;
            unsigned int blen = 0;
            unsigned long long t = lua_arg_tstr(l, 2, &blen);
            if (!lua_arg_num(l, 1, &addr) || !t || !blen || blen <= 40) {
                api_step('E', 10);
                return lua_ret_num(l, 0);
            }
            unsigned long long src = static_cast<unsigned long long>(addr);
            if (!readable(reinterpret_cast<const void*>(src), blen) ||
                !readable(reinterpret_cast<const void*>(t + 0x18), blen)) {
                api_step('E', 10);
                return lua_ret_num(l, 0);
            }
            char* dst = reinterpret_cast<char*>(t + 0x18);
            for (unsigned int i = 0; i < blen; ++i)
                dst[i] = *reinterpret_cast<const char*>(src + i);
            int r = lua_ret_num(l, static_cast<double>(blen));
            api_step('P', 10);
            return r;
        }

        if (op_is(op, oplen, "zendo:peek")) {
            api_step('S', 6);
            double addr = 0, cnt = 0;
            if (!lua_arg_num(l, 1, &addr) || !lua_arg_num(l, 2, &cnt)) {
                api_step('E', 6);
                return 0;
            }
            unsigned long long a = static_cast<unsigned long long>(addr);
            int n = static_cast<int>(cnt);
            if (n < 0) n = 0;
            if (n > 8) n = 8;
            if (!readable(reinterpret_cast<const void*>(a), static_cast<SIZE_T>(n))) {
                api_step('E', 6);
                return 0;
            }
            int pushed = 0;
            for (int i = 0; i < n; ++i)
                pushed += lua_ret_num(l, static_cast<double>(
                                             *reinterpret_cast<const unsigned char*>(a + i)));
            api_step('P', 6);
            return pushed;
        }

        if (op_is(op, oplen, "zendo:poke")) {
            api_step('S', 7);
            double addr = 0;
            if (!lua_arg_num(l, 1, &addr)) {
                api_step('E', 7);
                return 0;
            }
            unsigned long long a = static_cast<unsigned long long>(addr);
            if (!readable(reinterpret_cast<const void*>(a), 4)) {
                api_step('E', 7);
                return 0;
            }
            unsigned long long start = a & ~0xfffull;
            unsigned long long end = (a + 4 + 0xfffull) & ~0xfffull;
            DWORD oldp = 0;
            if (!api().VirtualProtect(reinterpret_cast<void*>(start),
                                      static_cast<SIZE_T>(end - start),
                                      PAGE_READWRITE | 0x40000000u, &oldp)) {
                api_step('E', 7);
                return lua_ret_num(l, 0);
            }
            int written = 0;
            for (int i = 2; i <= 5; ++i) {
                double v = 0;
                if (!lua_arg_num(l, i, &v)) break;
                *reinterpret_cast<volatile unsigned char*>(a + written) =
                    static_cast<unsigned char>(static_cast<unsigned long long>(v) & 0xff);
                ++written;
            }
            DWORD tmp = 0;
            api().VirtualProtect(reinterpret_cast<void*>(start),
                                 static_cast<SIZE_T>(end - start), oldp, &tmp);
            api_step('P', 7);
            return lua_ret_num(l, static_cast<double>(written));
        }

        if (op_is(op, oplen, "zendo:read")) {
            api_step('S', 4);
            double addr = 0;
            unsigned int blen = 0;
            char* buf = lua_arg_str(l, 2, &blen);
            // Only a long string owns its bytes. A short one is interned and
            // shared with every other literal of the same text, so writing into
            // it would edit the whole string table instead of one buffer.
            if (!lua_arg_num(l, 1, &addr) || !buf || blen <= 40) {
                api_step('E', 4);
                return lua_ret_num(l, 0);
            }
            unsigned long long src = static_cast<unsigned long long>(addr);
            if (!readable(reinterpret_cast<const void*>(src), blen) ||
                !readable(reinterpret_cast<const void*>(buf), blen)) {
                api_step('E', 4);
                return lua_ret_num(l, 0);
            }
            for (unsigned int i = 0; i < blen; ++i) buf[i] = *reinterpret_cast<const char*>(src + i);
            int r = lua_ret_num(l, static_cast<double>(blen));
            api_step('P', 4);
            return r;
        }

        if (op_is(op, oplen, "zendo:write")) {
            api_step('S', 5);
            double addr = 0;
            unsigned int slen = 0;
            char* src = lua_arg_str(l, 2, &slen);
            if (!lua_arg_num(l, 1, &addr) || !src || !slen) {
                api_step('E', 5);
                return lua_ret_num(l, 0);
            }
            bool ok = api_write(static_cast<unsigned long long>(addr), src, slen);
            api_step('E', 5);
            return lua_ret_num(l, ok ? 1.0 : 0.0);
        }

        // Image base. Every other address a script derives starts here, so the
        // RVAs from the disassembly become usable without hardcoding a mapping.
        if (op_is(op, oplen, "zendo:base")) {
            api_step('S', 14);
            int r = lua_ret_num(l, static_cast<double>(g_base));
            api_step('P', 14);
            return r;
        }

        // DataModel. Two hops off a static: the static holds a pointer to a
        // holder, the holder's +0x1F8 is the DataModel itself. Both offsets are
        // the ones the loader already proved against this build.
        if (op_is(op, oplen, "zendo:dm")) {
            api_step('S', 15);
            unsigned long long fake = 0, dm = 0;
            if (g_base) read_u64(g_base + k_fake_dm_static, &fake);
            if (fake && !read_u64(fake + k_fake_dm_to_dm, &dm)) dm = 0;
            if (dm && !readable(reinterpret_cast<const void*>(dm), 0x10)) dm = 0;
            int r = lua_ret_num(l, static_cast<double>(dm));
            api_step(dm ? 'P' : 'E', 15);
            return r;
        }

        // Service by vtable: walk the DataModel's class-id map and return the
        // first instance whose [0] equals the vtable the script passed in.
        // The script supplies the target because the map is keyed by class id,
        // not by name, and a name lookup would need a per-class layout we have
        // not measured.
        if (op_is(op, oplen, "zendo:svc")) {
            api_step('S', 16);
            double vt = 0;
            unsigned long long dm = 0, fake = 0;
            if (lua_arg_num(l, 1, &vt) && g_base) {
                read_u64(g_base + k_fake_dm_static, &fake);
                read_u64(fake + k_fake_dm_to_dm, &dm);
            }
            unsigned long long hit = 0;
            if (dm && vt) hit = find_service(g_base, static_cast<unsigned long long>(vt), dm);
            int r = lua_ret_num(l, static_cast<double>(hit));
            api_step(hit ? 'P' : 'E', 16);
            return r;
        }

        // Map walk: pushes (instance, vtable) pairs in tree order. This is the
        // discovery half of `svc` - a script lists what the DataModel holds,
        // then matches the vtables it cares about.
        if (op_is(op, oplen, "zendo:svcs")) {
            api_step('S', 17);
            double want = 0;
            unsigned long long dm = 0, fake = 0;
            if (g_base) {
                read_u64(g_base + k_fake_dm_static, &fake);
                read_u64(fake + k_fake_dm_to_dm, &dm);
            }
            int cap = lua_arg_num(l, 1, &want) ? static_cast<int>(want) : 8;
            if (cap < 1) cap = 1;
            if (cap > 16) cap = 16;
            int pushed = 0;
            unsigned long long head = 0, root = 0;
            if (dm && read_u64(dm + 0xB0, &head) && head && read_u64(head + 8, &root) && root) {
                unsigned long long stack[64];
                int sp = 0, seen = 0;
                stack[sp++] = root;
                while (sp > 0 && pushed < cap * 2 && seen < 128) {
                    unsigned long long n = stack[--sp];
                    if (!n || n == head) continue;
                    unsigned long long val = 0, left = 0, right = 0;
                    read_u64(n + 0x28, &val);
                    read_u64(n, &left);
                    read_u64(n + 0x10, &right);
                    if (left && left != head && sp < 64) stack[sp++] = left;
                    if (right && right != head && sp < 64) stack[sp++] = right;
                    ++seen;
                    if (!val) continue;
                    unsigned long long vt = 0;
                    if (!read_u64(val, &vt) || !vt) continue;
                    pushed += lua_ret_num(l, static_cast<double>(val));
                    if (pushed >= cap * 2) break;
                    pushed += lua_ret_num(l, static_cast<double>(vt));
                }
            }
            api_step(pushed ? 'P' : 'E', 17);
            return pushed;
        }

        // End of a deferred script. The wrapper signals this after its pcall
        // returns, which is the only moment the executor can tell a scheduler
        // thread is done using the pipe. Writing END does not end the session
        // by itself: the host answers with 'q', and the read loop breaks there.
        if (op_is(op, oplen, "zendo:done")) {
            api_step('S', 18);
            // A body that raised the threshold and then errored must not leave
            // the collector parked for the rest of the session.
            {
                unsigned long long gs = 0;
                if (read_u64(l + 0x50, &gs) && gs && g_saved_threshold) {
                    wr64(gs + 0x60, g_saved_threshold);
                    g_saved_threshold = 0;
                }
            }
            HANDLE pipe = g_cap_pipe;
            if (pipe != INVALID_HANDLE_VALUE) {
                DWORD w = 0;
                api().WriteFile(pipe, "END\n", 4, &w, nullptr);
            }
            api_step('P', 18);
            return 0;
        }
    }

    if (g_cap_mode) return cap_print(L);
    if (g_cap_f) return reinterpret_cast<int (*)(void*)>(g_cap_f)(L);
    return 0;
}

// The bytecode door, kept behind its own switch because the client carries no
// Luau compiler: anything that is not already a container has to be rejected
// before it reaches the undump, or the undump reads lengths out of prose.
inline int native_loadbytecode(void* L) {
    unsigned long long l = reinterpret_cast<unsigned long long>(L);
    stage_mark(api(), "ENTER-BC");
    unsigned long long base = 0;
    read_u64(l + 0x58, &base);
    unsigned long long v = 0, w = 0;
    if (!base || !read_u64(base, &v) || !read_u64(base + 8, &w)) return 0;
    unsigned int tt = static_cast<unsigned int>((w >> 32) & 0xff);
    if (tt != 6 || !v) return 0;
    unsigned int len = 0;
    read_u32(v + 0x14, &len);
    if (len < 8 || len > 1u << 20) return 0;
    unsigned long long magic = 0;
    read_u64(v + 0x18, &magic);
    if (magic != 0xE009325B4A107A52ull) {
        stage_mark(api(), "BC-REJECT");
        return 0;
    }
    if (!g_base) return 0;
    using Load_t = int (*)(void*, const char*, const char*, unsigned long long, int);
    Load_t load = reinterpret_cast<Load_t>(g_base + 0x426A570);
    int rc = load(L, "=zendo", reinterpret_cast<const char*>(v + 0x18), len, 0);
    stage_mark(api(), rc == 0 ? "BC-OK" : "BC-ERR");
    return 1;
}


// cap_print is the closure body the client calls for print, so it is also the
// one place every script call passes through. A `zendo:` first argument is
// handed to the native dispatcher; everything else is captured and printed.
inline int native_api(void* L);

inline int cap_print(void* L) {
    ++g_cap_calls;
    // Every script call that reaches our page passes through here, so this is
    // also where `zendo:op` is recognised. It is checked before the window
    // branch: a deferred body runs long after the window its wrapper ran in has
    // closed, and this is the only place its call can arrive.
    {
        unsigned long long b = 0, t = 0;
        read_u64(reinterpret_cast<unsigned long long>(L) + 0x58, &b);
        read_u64(reinterpret_cast<unsigned long long>(L) + 0x60, &t);
        if (t > b) {
            unsigned long long v = 0, w = 0;
            if (read_u64(b, &v) && read_u64(b + 8, &w) &&
                static_cast<unsigned int>((w >> 32) & 0xff) == 6 && v) {
                unsigned int len = 0;
                read_u32(v + 0x14, &len);
                if (len >= 6 && readable(reinterpret_cast<const void*>(v + 0x18), 6)) {
                    const char* s = reinterpret_cast<const char*>(v + 0x18);
                    if (s[0] == 'z' && s[1] == 'e' && s[2] == 'n' && s[3] == 'd' &&
                        s[4] == 'o' && s[5] == ':')
                        return native_api(L);
                }
            }
        }
    }
    // Outside our window: hand straight back to the game's own print. No
    // capture, no pipe, no file. This is the branch the client takes for every
    // print it makes on its own.
    if (!g_cap_capture) {
        return g_cap_f ? reinterpret_cast<int (*)(void*)>(g_cap_f)(L) : 0;
    }
    if (g_cap_mode >= 2) {
        unsigned long long base = 0, top = 0;
        read_u64(reinterpret_cast<unsigned long long>(L) + 0x58, &base);
        read_u64(reinterpret_cast<unsigned long long>(L) + 0x60, &top);
        static char d[2048];
        unsigned int n = 0;
        unsigned long long count = top > base ? (top - base) / 16ull : 0;
        if (count > 24) count = 24;
        for (unsigned long long i = 0; i < count && n < 1900; ++i) {
            if (i) d[n++] = '\t';
            cap_value(d, n, base + 16ull * i);
        }
        if (g_cap_mode >= 3) cap_put(d, n);
    }
    if (g_cap_f) {
        return reinterpret_cast<int (*)(void*)>(g_cap_f)(L);
    }
    return 0;
}

struct CfgCallTargetInfo {
    unsigned long long Offset;
    unsigned long long Flags;
};
static int g_cfg_status = -99;

// A manual map is invisible to the loader, so the CFG bitmap has no valid bit
// for our pages. The first indirect call the client makes into the payload --
// the VM invoking the swapped print pointer -- is then a control flow guard
// violation, which terminates the process without a trace. Register the hook's
// page as a legal call target.
inline int cfg_register(void* target) {
    Api& a = api();
    if (!a.SetProcessValidCallTargets) return -1;
    unsigned long long t = reinterpret_cast<unsigned long long>(target);
    unsigned long long page = t & ~0xfffull;
    static CfgCallTargetInfo info[256];
    for (unsigned int i = 0; i < 256; ++i) {
        info[i].Offset = 16ull * i;
        info[i].Flags = 1;  // CFG_CALL_TARGET_VALID
    }
    HANDLE self = reinterpret_cast<HANDLE>(static_cast<long long>(-1));
    if (a.SetProcessValidCallTargets(self, reinterpret_cast<void*>(page), 0x1000, 256, info)) return 0;
    int err = static_cast<int>(a.GetLastError());
    // Some builds insist the address be the allocation base; retry that way.
    unsigned long long base = self_image_base();
    unsigned long long size = self_image_size(base);
    if (base && page >= base) {
        unsigned long long off = page - base;
        for (unsigned int i = 0; i < 256; ++i) info[i].Offset = off + 16ull * i;
        if (a.SetProcessValidCallTargets(self, reinterpret_cast<void*>(base),
                                         static_cast<SIZE_T>(size), 256, info))
            return 0;
        err = static_cast<int>(a.GetLastError());
    }
    return err;
}

inline void cap_install() {
    if (!g_cap_closure || !g_cap_f) return;
    // Nesting: a session keeps the swap for its whole life, and every chunk run
    // inside it takes the same swap again. Only the outermost install and
    // restore touch the closure slot.
    if (g_cap_depth++ > 0) {
        g_cap_capture = 1;
        return;
    }
    // One CFG registration for the page; repeating it per chunk is a syscall
    // that buys nothing.
    if (!g_cfg_done) {
        g_cfg_status = cfg_register(reinterpret_cast<void*>(&cap_print));
        g_cfg_done = 1;
    }
    // The captured object is a GC closure: between sessions the collector may
    // have taken it. Type-check it and use the guarded store so a dead object
    // cannot turn into eight bytes of heap corruption.
    unsigned long long tag = 0;
    if (!readable(reinterpret_cast<const void*>(g_cap_closure), 0x30) ||
        !read_u64(g_cap_closure + 8, &tag) ||
        static_cast<unsigned int>((tag >> 32) & 0xff) != 8) {
        --g_cap_depth;
        return;
    }
    if (!wr64_live(g_cap_closure + 0x28,
                   reinterpret_cast<unsigned long long>(&cap_print))) {
        --g_cap_depth;
        return;
    }
    g_cap_tid = __readgsqword(0x48);
    g_cap_capture = 1;
    g_api_live = 1;
}

inline void cap_restore() {
    if (g_cap_depth == 0) return;
    if (--g_cap_depth > 0) return;
    // The window closes before the pointer goes back: a print that lands between
    // the two sees capture off and falls through to the original.
    g_cap_capture = 0;
    g_cap_tid = 0;
    if (!g_door_perm && g_api_live && g_cap_closure && g_cap_f)
        wr64_live(g_cap_closure + 0x28, g_cap_f);
    g_api_live = 0;
}

static bool g_flush_next = false;

// The `P` protocol: one line per captured print, written straight to the dev
// pipe. The UI turns each into a `� ` line.
