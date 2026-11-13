struct ReplEntry {
    char cmd;
    const char* name;
    const unsigned char* body;
    unsigned int len;
};

static const ReplEntry kReplTable[] = {
    {'a', "A-math", kChunkALBody, kChunkALLen},
    {'c', "C-closure", kChunkCLBody, kChunkCLLen},
    {'d', "D-capture", kChunkDLBody, kChunkDLLen},
    {'1', "C+D", kChunkC1Body, kChunkC1Len},
    {'2', "D+pcall(error)", kChunkC2Body, kChunkC2Len},
    {'6', "D+pcall(lua)", kChunkC6Body, kChunkC6Len},
    {'3', "D+pcall(prop)", kChunkC3Body, kChunkC3Len},
    {'7', "pcall(prop)+D", kChunkC7Body, kChunkC7Len},
    {'4', "pcall(prop)", kChunkC4Body, kChunkC4Len},
    {'8', "closure+pcall(prop), no call", kChunkC8Body, kChunkC8Len},
    {'9', "pcall(prop) then closure", kChunkC9Body, kChunkC9Len},
    {'0', "plain closure+pcall(prop)", kChunkC10Body, kChunkC10Len},
    {'b', "pcall(prop)+C call", kChunkC11Body, kChunkC11Len},
    {'e', "lua call then pcall(prop)", kChunkC12Body, kChunkC12Len},
    {'f', "pcall(prop)+lua noarg call", kChunkC13Body, kChunkC13Len},
    {'g', "pcall(prop)+table", kChunkC14Body, kChunkC14Len},
    {'h', "pcall(prop) ignored+lua call", kChunkC15Body, kChunkC15Len},
    {'j', "pcall(prop)+pcall(error)", kChunkC17Body, kChunkC17Len},
    {'i', "pcall(prop)+pcall(f,3)", kChunkC16Body, kChunkC16Len},
    {'k', "pcall(prop)+table{f()}", kChunkC18Body, kChunkC18Len},
    {'o', "type(f) after pcall(prop)", kChunkC20Body, kChunkC20Len},
    {'m', "err text upvalue", kChunkC19Body, kChunkC19Len},
    {'n', "err text no upvalue", kChunkC21Body, kChunkC21Len},
    {'p', "regs after pcall(prop)", kChunkC22Body, kChunkC22Len},
    {'r', "regs after pcall(type,1)", kChunkC23Body, kChunkC23Len},
    {'s', "regs after pcall(error)", kChunkC24Body, kChunkC24Len},
    {'t', "regs after pcall(lua fn)", kChunkC25Body, kChunkC25Len},
    {'u', "const ret after pcall(prop)", kChunkC26Body, kChunkC26Len},
    {'v', "const ret control", kChunkC27Body, kChunkC27Len},
    {'w', "window after pcall(prop)", kChunkC28Body, kChunkC28Len},
    {'y', "window control", kChunkC29Body, kChunkC29Len},
    {'z', "sentinel plain", kChunkC31Body, kChunkC31Len},
    {'Z', "sentinel pcall prop", kChunkC28Body, kChunkC28Len},
    {'5', "live1", kChunkL1Body, kChunkL1Len},
};

// Place id the host read from the client's own log, sent as `G` before a chunk.
// A chunk that lands between a leave and the next join writes into a DataModel
// the transition is already freeing; this is the number the payload checks
// before it touches the VM.
static unsigned long long g_want_place = 0;

inline DWORD serve_session(Api& a, HANDLE pipe, unsigned long long base,
                           unsigned long long L) {    static Out o;
    o.reset();
    o.str("ZEND1 repl L=");
    o.hex(L);
    o.nl();
    flush_out(a, pipe, o);

    caps_open(base, L, o, pipe, a, "REPL");
    g_base = base;
    g_declared_size = 64;
    g_patch_proto = 1;
    g_veh_pipe = pipe;
    g_veh_base = base;
    g_veh_L = L;

    // print capture is installed lazily: only a raw chunk needs the pipe to
    // carry its print traffic. A deferred body runs on the scheduler and its
    // print has to reach the client's own log, so the global `print` must stay
    // the client's, not our buffering wrapper.
    g_cap_pipe = pipe;
    // The place the host read from the client's own log. Zero means the host had
    // nothing to say, and the guard stays fail-open.
    g_want_place = 0;
    // Nothing else is armed here on purpose. A `d` session must touch the VM
    // exactly once - the wrapper that hands the body to the scheduler. Capture
    // setup and global bindings are raw-only and happen in that branch below.

    // Nothing is armed here on purpose. Every VM entry below happens inside
    // exec_raw's window, on this thread, with the closure swapped back the
    // moment the call returns. Leaving the swap installed for the whole session
    // - or entering the VM from here to install global bindings - is a second
    // writer beside the client's own scheduler, and that race is what killed
    // the client seconds after a session ended with its body never running.

    // A deferred body finishes on the client's scheduler, so the host waits on
    // the client's own log for the completion line. This thread has nothing
    // left to do at that point: holding it for even one extra second is a
    // second of a client thread that the engine may be waiting on during a
    // place load. Raw chunks still keep the short grace below so the host can
    // close the session without a broken-pipe error.
    for (;;) {
        stage_mark(a, "RDY");
        o.str("RDY\n");
        flush_out(a, pipe, o);
        char cmd[16];
        DWORD rd = 0;
        // Peek before reading. A blocking ReadFile on a connection whose server
        // is already gone parks this thread forever, and a parked payload is
        // worse than a missing one: the host reads "no session", maps a second
        // image, and two payloads end up in one client.
        if (a.PeekNamedPipe && a.Sleep) {
            bool ready = false;
            // After a raw chunk there is exactly one thing left: the host
            // closing the session. Give it three seconds to do that, then go
            // home. A deferred chunk never gets here - it leaves the moment
            // its body is queued.
            const int spins = 60;
            for (int spin = 0; spin < spins; ++spin) {
                DWORD avail = 0;
                if (!a.PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr)) {
                    trace_tag(a, "peek-gone");
                    break;
                }
                if (avail) { ready = true; break; }
                a.Sleep(50);
            }
            if (!ready) {
                beacon(a, "PEEKIDLE");
                break;
            }
        }
        if (!a.ReadFile(pipe, cmd, 1, &rd, nullptr) || rd == 0) {
            beacon(a, "EOF");
            break;
        }
        cmd[1] = 0;
        trace_tag(a, cmd);
        stage_mark(a, cmd);
        // Detach: leave the client with no payload thread parked inside it.
        if (cmd[0] == 'x') {
            g_leave = 1;
            break;
        }
        // Session over. Unwind back to the seek loop so this payload thread can
        // serve the next run instead of forcing a second image into the same
        // client. Only the idle timeout leaves DllMain for good, and that path
        // restores the borrowed thread's saved context on the way out.
        if (cmd[0] == 'q') break;
        // Place hint: eight bytes, no reply. It has to land before the chunk it
        // guards, and it must never disturb the session, so silence and
        // `continue` - a malformed hint leaves the guard fail-open.
        if (cmd[0] == 'G') {
            unsigned long long want = 0;
            if (read_all(a, pipe, &want, 8)) g_want_place = want;
            continue;
        }
        if (cmd[0] == 'L' || cmd[0] == 'i' || cmd[0] == 'd') {
            unsigned int want_id = 7;
            if (cmd[0] == 'i') {
                char idb[1];
                DWORD idr = 0;
                if (!a.ReadFile(pipe, idb, 1, &idr, nullptr) || idr == 0) continue;
                want_id = static_cast<unsigned char>(idb[0]);
                if (want_id > 15 && want_id != 0xFF) want_id = 7;
            }
            unsigned int blen = 0;
            if (!read_all(a, pipe, &blen, 4) || blen == 0 || blen > 262144) {
                o.str("dyn bad len\n");
                flush_out(a, pipe, o);
                continue;
            }
            static unsigned char lbuf[262144];
            if (!read_all(a, pipe, lbuf, blen)) {
                o.str("dyn read short\n");
                flush_out(a, pipe, o);
                continue;
            }
            stage_mark(a, "BODY");
            o.str("RUN raw dyn len=");
            o.dec(blen);
            o.nl();
            flush_out(a, pipe, o);
            // Identity swap for the synchronous test path: run this chunk on the
            // borrowed thread as identity 7 and put the old value back before
            // returning, so a failed experiment cannot leave a game thread
            // carrying an identity the scheduler did not give it.
            unsigned long long E2 = 0, oldid = 0;
            bool swapped = false;
            if (cmd[0] == 'i') {
                read_u64(L + 8, &E2);
                if (E2 && read_u64(E2 + 0x70, &oldid)) {
                    swapped = true;
                    o.str("ident was=");
                    o.dec(static_cast<unsigned int>(oldid));
                    o.nl();
                    flush_out(a, pipe, o);
                }
            }
            if (swapped && want_id == 0xFF) {
                // One session, every identity: the loadstring refusal changes
                // wording with identity, so the whole table is worth having.
                for (unsigned int id = 0; id <= 9; ++id) {
                    wr64(E2 + 0x70, id);
                    unsigned long long rb = 0;
                    read_u64(E2 + 0x70, &rb);
                    o.str("sweep id=");
                    o.dec(id);
                    o.str(" readback=");
                    o.dec(static_cast<unsigned int>(rb));
                    o.nl();
                    flush_out(a, pipe, o);
                    exec_raw(a, pipe, o, L, base, lbuf, blen, "sweep");
                    flush_capture(a, o, L, base);
                }
                wr64(E2 + 0x70, oldid);
                o.str("ident restored=");
                o.dec(static_cast<unsigned int>(oldid));
                o.nl();
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            if (swapped) {
                wr64(E2 + 0x70, want_id);
            }
            stage_mark(a, "EXEC");
            // The state was resolved before this pipe connected. A place change
            // tears the DataModel down and builds a new script context: writing
            // into the old one means allocating in a VM whose heap is being
            // freed, which surfaces later as an unrelated thread dying inside
            // ntdll's heap code. Re-resolve and refuse instead.
            {
                unsigned long long fake2 = 0, dm2 = 0, sc2 = 0, L2 = 0;
                if (read_u64(base + k_fake_dm_static, &fake2) && fake2 &&
                    read_u64(fake2 + k_fake_dm_to_dm, &dm2) && dm2) {
                    sc2 = find_service(base, base + k_script_context_vtable, dm2);
                    if (sc2) L2 = decode_split(sc2 + k_slot_a);
                }
                if (L2 != L) {
                    o.str("stale state: the script context moved under this run\n");
                    o.str("wait for the place to finish loading, then Execute\nEND\n");
                    flush_out(a, pipe, o);
                    stage_mark(a, "STALE");
                    if (swapped) wr64(E2 + 0x70, oldid);
                    continue;
                }
                // Same failure, one step earlier: the script context survived
                // but it belongs to another place. A transition swaps the
                // DataModel first and the context later, so this window exists
                // even when L2 == L. Fail open when the field is zero - a wrong
                // offset must never brick a working build.
                unsigned long long dplace = 0, dloaded = 0;
                read_u64(dm2 + 0x180, &dplace);
                read_u64(dm2 + 0x588, &dloaded);
                trace_kv(a, "want", g_want_place);
                trace_kv(a, "place", dplace);
                trace_kv(a, "loaded", dloaded);
                if (g_want_place && dplace && dplace != g_want_place) {
                    o.str("place mismatch: client log says place ");
                    o.dec64(g_want_place);
                    o.str(", DataModel says ");
                    o.dec64(dplace);
                    o.str(" loaded=");
                    o.dec(static_cast<unsigned int>(dloaded & 0xFF));
                    o.str("\nwait for the join to finish, then Execute\nEND\n");
                    flush_out(a, pipe, o);
                    stage_mark(a, "PLACE");
                    if (swapped) wr64(E2 + 0x70, oldid);
                    continue;
                }
            }
            // The door: one captured C closure of the client's own, with our
            // dispatcher installed as its entry. It is installed for good, not
            // for the window, because a deferred body runs after the window
            // that handed it over has closed. cap_print falls back to the
            // original function for anything that is not a zendo op, so the
            // client's own print path is unchanged.
            if (!g_cap_closure)
                exec_raw(a, pipe, o, L, base, kChunkKCaptureBody, kChunkKCaptureLen, "zcapture");
            if (g_cap_closure && g_cap_f && !g_door_perm) {
                arm_cfg(a, o, reinterpret_cast<unsigned long long>(&cap_print), "door cfg");
                g_door_perm = 1;
                wr64_live(g_cap_closure + 0x28,
                          reinterpret_cast<unsigned long long>(&cap_print));
                o.str("door installed clo=");
                o.hex(g_cap_closure);
                o.str(" f=");
                o.hex(g_cap_f);
                o.nl();
                flush_out(a, pipe, o);
            }
            if (cmd[0] != 'd' && !g_bind_ready) {
                if (g_cap_closure && g_cap_f)
                    arm_cfg(a, o, reinterpret_cast<unsigned long long>(&native_api), "api cfg");
                if (g_cap_closure && g_cap_f)
                    exec_raw(a, pipe, o, L, base, kZGlobalBody, kZGlobalLen, "gbind");
                g_bind_ready = 1;
            }
            if (cmd[0] != 'd' && !g_capi_ready) {
                exec_raw(a, pipe, o, L, base, kChunkCapi, kChunkCapiLen, "capi");
                g_capi_ready = 1;
            }
            // A raw chunk is the only place print traffic is captured, and it
            // owns the pipe while it runs. A deferred body never captures: its
            // print has to reach the client's log where the host reads it.
            if (cmd[0] != 'd') g_cap_mode = 3;
            exec_raw(a, pipe, o, L, base, lbuf, blen,
                     cmd[0] == 'i' ? "ident" : (cmd[0] == 'd' ? "defer" : "raw dyn"));
            if (cmd[0] != 'd') g_cap_mode = 0;
            if (swapped) {
                wr64(E2 + 0x70, oldid);
                o.str("ident restored=");
                o.dec(static_cast<unsigned int>(oldid));
                o.nl();
                flush_out(a, pipe, o);
            }
            // A deferred chunk hands its body to the client scheduler and is
            // done: the queue owns the closure now, so this thread leaves the
            // client immediately instead of holding a borrowed game thread for
            // a second that a place load may be waiting on. A raw chunk drains
            // its capture first, then waits out the host's close.
            if (cmd[0] == 'd') {
                stage_mark(a, "DONE");
                break;
            }
            flush_capture(a, o, L, base);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'N') {
            // Run 1 of the guard work: read only. The CFG dispatch stub is a
            // fixed byte pattern in ntdll, not something to guess. Take the
            // address from the image's own load config, then confirm it against
            // every `jmp rax` in .text so the patch target in stage 'x' is
            // picked from bytes instead of a histogram of call sites. Nothing
            // is written here - no VirtualProtect, no store.
            Module ntdll = find_module(fnv1a_w(L"ntdll.dll"));
            if (!ntdll.base) {
                o.str("ntdll missing\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned long long nb = reinterpret_cast<unsigned long long>(ntdll.base);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll.base);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(nb + dos->e_lfanew);
            o.str("ntdll base=");
            o.hex(nb);
            o.str(" image=");
            o.hex(nt->OptionalHeader.SizeOfImage);
            o.str(" sections=");
            o.dec(nt->FileHeader.NumberOfSections);
            o.nl();

            unsigned long long check = 0, dispatch = 0, table = 0, count = 0;
            unsigned int gflags = 0, lsz = 0;
            auto& lc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (!lc.VirtualAddress) {
                o.str("ldcfg none\n");
            } else {
                auto* lp = reinterpret_cast<unsigned char*>(nb + lc.VirtualAddress);
                lsz = *reinterpret_cast<unsigned int*>(lp);
                if (lsz > lc.Size) lsz = lc.Size;
                o.str("ldcfg rva=");
                o.hex(lc.VirtualAddress);
                o.str(" size=");
                o.dec(lsz);
                o.nl();
                if (lsz >= 0x80) {
                    check = *reinterpret_cast<unsigned long long*>(lp + 0x70);
                    dispatch = *reinterpret_cast<unsigned long long*>(lp + 0x78);
                }
                if (lsz >= 0x88) table = *reinterpret_cast<unsigned long long*>(lp + 0x80);
                if (lsz >= 0x90) count = *reinterpret_cast<unsigned long long*>(lp + 0x88);
                if (lsz >= 0x94) gflags = *reinterpret_cast<unsigned int*>(lp + 0x90);
            }

            const unsigned long long ptrs[2] = {check, dispatch};
            const char* names[2] = {"cf_check   ", "cf_dispatch"};
            for (int i = 0; i < 2; ++i) {
                o.str("guard ");
                o.str(names[i]);
                o.str("=");
                o.hex(ptrs[i]);
                if (ptrs[i] >= nb && ptrs[i] < nb + ntdll.size) {
                    o.str(" rva=");
                    o.hex(ptrs[i] - nb);
                }
                o.str(" head=");
                for (int k = 0; k < 24; ++k) {
                    unsigned char b = 0;
                    if (readable(reinterpret_cast<const void*>(ptrs[i] + k), 1))
                        b = *reinterpret_cast<unsigned char*>(ptrs[i] + k);
                    o.hex(b);
                    o.ch(' ');
                }
                o.nl();
            }
            o.str("guard flags=");
            o.hex(gflags);
            o.str(" table=");
            o.hex(table);
            o.str(" count=");
            o.dec(static_cast<unsigned int>(count));
            o.nl();
            flush_out(a, pipe, o);

            auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                reinterpret_cast<unsigned char*>(&nt->OptionalHeader) +
                nt->FileHeader.SizeOfOptionalHeader);
            unsigned char* text = nullptr;
            unsigned int text_rva = 0, text_sz = 0;
            for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
                const char* nm = reinterpret_cast<const char*>(sec->Name);
                if (nm[0] == '.' && nm[1] == 't' && nm[2] == 'e' && nm[3] == 'x' && nm[4] == 't') {
                    text = reinterpret_cast<unsigned char*>(nb + sec->VirtualAddress);
                    text_rva = sec->VirtualAddress;
                    text_sz = sec->Misc.VirtualSize;
                    break;
                }
            }
            if (!text || !text_sz) {
                o.str("text missing\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            o.str("text rva=");
            o.hex(text_rva);
            o.str(" size=");
            o.hex(text_sz);
            o.nl();
            flush_out(a, pipe, o);

            unsigned int hits = 0, rex = 0, shown = 0, first = 0;
            for (unsigned int i = 0; i + 1 < text_sz; ++i) {
                if (text[i] != 0xff || text[i + 1] != 0xe0) continue;
                if (!hits) first = text_rva + i;
                ++hits;
                bool has_rex = i > 0 && text[i - 1] == 0x48;
                if (has_rex) ++rex;
                if (shown >= 40) continue;
                ++shown;
                o.str("  hit rva=");
                o.hex(text_rva + i);
                o.str(" va=");
                o.hex(nb + text_rva + i);
                o.str(" rex=");
                o.dec(has_rex ? 1 : 0);
                o.str(" pre=");
                for (int k = 16; k >= 1; --k) {
                    if (i < static_cast<unsigned int>(k)) continue;
                    o.hex(text[i - k]);
                    o.ch(' ');
                }
                o.nl();
            }
            o.str("scan_ff_e0 total=");
            o.dec(hits);
            o.str(" rex=");
            o.dec(rex);
            o.str(" first=");
            o.hex(first);
            o.nl();
            // Which of these hits is the load config's own dispatch pointer?
            // The one whose VA matches is the stub the compiler's guarded
            // indirect calls go through; anything else is an ordinary thunk.
            if (dispatch) {
                bool found = false;
                for (unsigned int i = 0; i + 1 < text_sz; ++i) {
                    if (text[i] != 0xff || text[i + 1] != 0xe0) continue;
                    if (nb + text_rva + i != dispatch) continue;
                    found = true;
                    break;
                }
                o.str("dispatch_is_jmp_rax=");
                o.dec(found ? 1 : 0);
                o.str(" dispatch_rva=");
                o.hex(dispatch >= nb ? dispatch - nb : 0);
                o.nl();
            }
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'y') {
            // The CFG dispatch stub is named in the PE load config, not in the
            // import table. GuardCFDispatchFunctionPointer (+0x78) is exactly
            // the address every instrumented indirect call routes through, so
            // one qword replaces the whole image scan. Report only - patching
            // waits for a second look at the prologue.
            unsigned int lfanew = 0;
            // The client's own PE directories are stripped by the protector, so
            // read the load config from a system module instead: every guarded
            // module in this process points at the same ntdll stub.
            Module sys = find_module(fnv1a_w(L"kernel32.dll"));
            unsigned long long pb0 = reinterpret_cast<unsigned long long>(sys.base);
            if (!pb0 || !read_u32(pb0 + 0x3C, &lfanew)) { stage_mark(a, "DONE"); continue; }
            unsigned long long opt = pb0 + lfanew + 0x18;
            unsigned long long ddir = opt + 0x70 + 10 * 8;
            unsigned int lc_rva = 0, lc_size = 0;
            read_u32(ddir, &lc_rva);
            read_u32(ddir + 4, &lc_size);
            o.str("lc rva=");
            o.hex(lc_rva);
            o.str(" size=");
            o.hex(lc_size);
            o.nl();
            flush_out(a, pipe, o);
            if (!lc_rva) { stage_mark(a, "DONE"); continue; }
            unsigned long long lc = pb0 + lc_rva;
            unsigned long long chk = 0, disp = 0;
            read_u64(lc + 0x70, &chk);
            read_u64(lc + 0x78, &disp);
            o.str("cf check=");
            o.hex(chk);
            o.str(" dispatch=");
            o.hex(disp);
            o.nl();
            unsigned char pb[16] = {0};
            bool jmpr = false;
            if (disp) {
                for (int k = 0; k < 16; ++k) pb[k] = *reinterpret_cast<unsigned char*>(disp + k);
                for (int k = 0; k + 1 < 16; ++k)
                    if (pb[k] == 0xff && pb[k + 1] == 0xe0) jmpr = true;
            }
            o.str("dispatch prologue=");
            for (int k = 0; k < 16; ++k) { o.hex(pb[k]); o.str(" "); }
            o.str(jmpr ? "has_jmp_rax" : "no_jmp_rax");
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'Q') {
            // Read-only follow-up to M. M proved the client's dispatch slot is
            // not writable (VirtualProtect err 5) and that its value points
            // somewhere that is not our image. Name that module before deciding
            // anything else: a protector stub and a CFG dispatcher need
            // different answers, and guessing between them killed the client
            // once already.
            auto mod_of = [](unsigned long long addr, char* out, unsigned int cap) {
                out[0] = 0;
                auto* peb = reinterpret_cast<Peb*>(__readgsqword(0x60));
                auto* head = &peb->Ldr->InLoadOrderModuleList;
                for (auto* it = head->Flink; it != head; it = it->Flink) {
                    auto* e = CONTAINING_RECORD(it, LdrEntry, InLoadOrderLinks);
                    unsigned long long b = reinterpret_cast<unsigned long long>(e->DllBase);
                    if (!b || addr < b || addr >= b + e->SizeOfImage) continue;
                    unsigned int n = e->BaseDllName.Length / sizeof(wchar_t);
                    if (n >= cap) n = cap - 1;
                    for (unsigned int i = 0; i < n; ++i) {
                        wchar_t c = e->BaseDllName.Buffer[i];
                        out[i] = (c >= 32 && c < 127) ? static_cast<char>(c) : '?';
                    }
                    out[n] = 0;
                    return b;
                }
                return 0ull;
            };
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                o.str("guard Q bad image\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            auto& lc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            unsigned int lsz = 0, flags = 0;
            unsigned long long slot_c = 0, slot_d = 0, val_c = 0, val_d = 0;
            if (lc.VirtualAddress) {
                read_u32(base + lc.VirtualAddress, &lsz);
                if (lsz > lc.Size) lsz = lc.Size;
                if (lsz >= 0x80) {
                    read_u64(base + lc.VirtualAddress + 0x70, &slot_c);
                    read_u64(base + lc.VirtualAddress + 0x78, &slot_d);
                }
                if (lsz >= 0x94) read_u32(base + lc.VirtualAddress + 0x90, &flags);
            }
            if (slot_c) read_u64(slot_c, &val_c);
            if (slot_d) read_u64(slot_d, &val_d);
            char name[64];
            o.str("guard Q client=");
            o.hex(base);
            o.str(" lc_rva=");
            o.hex(lc.VirtualAddress);
            o.str(" lc_size=");
            o.dec(lsz);
            o.str(" dir_size=");
            o.hex(lc.Size);
            o.str(" flags=");
            o.hex(flags);
            o.nl();
            const unsigned long long addrs[4] = {slot_c, val_c, slot_d, val_d};
            const char* tags[4] = {"slot_c", "val_c ", "slot_d", "val_d "};
            for (int i = 0; i < 4; ++i) {
                if (!addrs[i]) continue;
                unsigned long long mb = mod_of(addrs[i], name, sizeof(name));
                o.str("guard Q ");
                o.str(tags[i]);
                o.str("=");
                o.hex(addrs[i]);
                o.str(" mod=");
                o.str(name);
                o.str("+");
                o.hex(mb ? addrs[i] - mb : 0);
                o.nl();
            }
            o.str("guard Q val_d_head=");
            for (int k = 0; k < 16; ++k) {
                unsigned char b = 0;
                if (readable(reinterpret_cast<const void*>(val_d + k), 1))
                    b = *reinterpret_cast<unsigned char*>(val_d + k);
                o.hex(b);
                o.ch(' ');
            }
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'z') {
            // Capture print's closure, leave its f pointing at the dispatcher,
            // then hand the same object to a chunk as an argument. The chunk
            // calls it with the sentinel; if 4080 comes back, the loop is
            // closed: Lua -> value -> closure -> CFG dispatcher -> our page.
            g_base = base;
            g_cap_closure = 0;
            exec_raw(a, pipe, o, L, base, kChunkKCaptureBody, kChunkKCaptureLen, "zcapture");
            if (!g_cap_closure) {
                o.str("api no closure\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            wr64(g_cap_closure + 0x28, reinterpret_cast<unsigned long long>(&native_api));
            o.str("api swapped clo=");
            o.hex(g_cap_closure);
            o.str(" f=");
            o.hex(g_cap_f);
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "API");
            if (!arm_cfg(a, o, reinterpret_cast<unsigned long long>(&native_api), "api cfg"))
                o.str("api cfg unarmed, calling anyway\n");
            flush_out(a, pipe, o);
            exec_protected(a, pipe, o, L, base, kZCallBody, kZCallLen, "zapi", g_cap_closure);
            o.str("api left in place\n");
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'v' || cmd[0] == 'u') {
            // Same bitmap write as U, different native body. 'v' returns the
            // moment it is entered, so a crash on 'v' can only mean the call
            // never arrived. 'u' runs the real load. One build, both answers.
            g_native_mode = (cmd[0] == 'v') ? 1 : 0;
            o.str("guard mode=");
            o.dec(static_cast<unsigned int>(g_native_mode));
            o.nl();
            flush_out(a, pipe, o);
            cmd[0] = 'U';
        }
        if (cmd[0] == 'T') {
            // The dispatcher at RobloxPlayerBeta.dll+0x4c9360 is stock CFG and
            // reads one bit out of a bitmap that measures PAGE_READWRITE in
            // this process. Dynamic code is blocked (1655) and private pages
            // cannot be opted in, so setting that bit by hand is the remaining
            // route: byte = addr >> 15, bit = (addr >> 12) & 7, exactly the
            // way the dispatcher reads it. Then the same native test as 'k'.
            Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
            unsigned long long target =
                reinterpret_cast<unsigned long long>(&native_loadstring);
            o.str("guard T target=");
            o.hex(target);
            o.nl();
            flush_out(a, pipe, o);
            if (!dll.base) {
                o.str("guard T no dll\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned long long db = reinterpret_cast<unsigned long long>(dll.base);
            unsigned long long bitmap = 0;
            read_u64(db + 0x4c9376ull + 0x9f9622ull, &bitmap);
            unsigned long long slotp = bitmap + (target >> 15);
            unsigned int bit = static_cast<unsigned int>((target >> 12) & 7);
            o.str("guard T bitmap=");
            o.hex(bitmap);
            o.str(" slot=");
            o.hex(slotp);
            o.str(" bit=");
            o.dec(bit);
            o.nl();
            flush_out(a, pipe, o);
            Mbi mbi{};
            if (!bitmap ||
                !a.VirtualQuery(reinterpret_cast<const void*>(slotp), &mbi, sizeof(mbi))) {
                o.str("guard T unreadable\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned char b0 = 0;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xff) == PAGE_READWRITE) {
                b0 = *reinterpret_cast<unsigned char*>(slotp);
            }
            o.str("guard T prot=");
            o.hex(mbi.Protect);
            o.str(" state=");
            o.hex(mbi.State);
            o.str(" region=");
            o.hex(mbi.RegionSize);
            o.str(" before=");
            o.hex(b0);
            o.nl();
            flush_out(a, pipe, o);
            if (mbi.State != MEM_COMMIT || (mbi.Protect & 0xff) != PAGE_READWRITE) {
                // The map is a 4 GB reservation covering the whole user space;
                // pages only exist where loaded images put targets. Indexing one
                // that was never committed is what killed the client here: the
                // dereference itself faults, before a single bit is set.
                o.str("guard T page not live, use U\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            *reinterpret_cast<volatile unsigned char*>(slotp) =
                static_cast<unsigned char>(b0 | (1u << bit));
            o.str("guard T after=");
            o.hex(*reinterpret_cast<unsigned char*>(slotp));
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "GUARD");
            cmd[0] = 'k';
        }
        if (cmd[0] == 'U') {
            // Same bit as T, but the page is brought in first. The map is one
            // big MEM_RESERVE, so committing our own index is a normal data
            // commit: no execute rights, nothing for the dynamic-code policy to
            // object to. Then the bit, then the native test.
            Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
            unsigned long long target =
                reinterpret_cast<unsigned long long>(&native_loadstring);
            unsigned long long db = dll.base ? reinterpret_cast<unsigned long long>(dll.base) : 0;
            unsigned long long bitmap = 0;
            if (db) read_u64(db + 0x4c9376ull + 0x9f9622ull, &bitmap);
            unsigned long long slotp = bitmap + (target >> 15);
            unsigned long long page = slotp & ~0xfffull;
            unsigned int bit = static_cast<unsigned int>((target >> 12) & 7);
            o.str("guard U target=");
            o.hex(target);
            o.str(" map=");
            o.hex(bitmap);
            o.str(" byte=");
            o.hex(slotp);
            o.str(" page=");
            o.hex(page);
            o.str(" bit=");
            o.dec(bit);
            o.nl();
            flush_out(a, pipe, o);
            if (!bitmap) {
                o.str("guard U no map\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            Mbi before_q{};
            a.VirtualQuery(reinterpret_cast<const void*>(page), &before_q, sizeof(before_q));
            o.str("guard U q_state=");
            o.hex(before_q.State);
            o.str(" q_prot=");
            o.hex(before_q.Protect);
            o.str(" q_type=");
            o.hex(before_q.Type);
            o.nl();
            if (before_q.State != MEM_COMMIT) {
                void* got = a.VirtualAlloc ? a.VirtualAlloc(reinterpret_cast<void*>(page), 0x1000,
                                                            MEM_COMMIT, PAGE_READWRITE)
                                           : nullptr;
                o.str("guard U commit=");
                o.hex(reinterpret_cast<unsigned long long>(got));
                o.str(" err=");
                o.dec(got ? 0u : static_cast<unsigned int>(a.GetLastError()));
                o.nl();
            }
            flush_out(a, pipe, o);
            Mbi q{};
            if (!a.VirtualQuery(reinterpret_cast<const void*>(page), &q, sizeof(q)) ||
                q.State != MEM_COMMIT || (q.Protect & 0xff) != PAGE_READWRITE) {
                o.str("guard U page still dead state=");
                o.hex(q.State);
                o.str(" prot=");
                o.hex(q.Protect);
                o.nl();
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned char b0 = *reinterpret_cast<unsigned char*>(slotp);
            *reinterpret_cast<volatile unsigned char*>(slotp) =
                static_cast<unsigned char>(b0 | (1u << bit));
            o.str("guard U bit ");
            o.hex(b0);
            o.str(" -> ");
            o.hex(*reinterpret_cast<unsigned char*>(slotp));
            o.nl();
            flush_out(a, pipe, o);
            stage_mark(a, "GUARD");
            cmd[0] = 'k';
        }
        if (cmd[0] == 'S') {
            // The dispatcher at RobloxPlayerBeta.dll+0x4c9360 is stock CFG:
            // `mov r11,[rip+0x9f9622]` loads the bitmap base, then one byte is
            // tested. So the question is not "which stub" but "can a bit be
            // set". Report what the allocator and the bitmap actually allow.
            if (!a.VirtualAlloc) {
                o.str("guard S no alloc\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            void* rx = a.VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
            o.str("guard S rwx=");
            o.hex(reinterpret_cast<unsigned long long>(rx));
            o.str(" err=");
            o.dec(rx ? 0u : static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            flush_out(a, pipe, o);
            void* rw = a.VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            o.str("guard S rw=");
            o.hex(reinterpret_cast<unsigned long long>(rw));
            o.str(" err=");
            o.dec(rw ? 0u : static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            if (rw) {
                DWORD oldp = 0;
                BOOL pr = a.VirtualProtect(rw, 0x1000, PAGE_EXECUTE_READ, &oldp);
                o.str("guard S rw->rx rc=");
                o.dec(pr ? 1u : 0u);
                o.str(" err=");
                o.dec(static_cast<unsigned int>(a.GetLastError()));
                o.nl();
            }
            flush_out(a, pipe, o);

            Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
            o.str("guard S dll=");
            o.hex(reinterpret_cast<unsigned long long>(dll.base));
            o.nl();
            if (dll.base) {
                unsigned long long db = reinterpret_cast<unsigned long long>(dll.base);
                unsigned long long global = db + 0x4c9376ull + 0x9f9622ull;
                unsigned long long bitmap = 0;
                read_u64(global, &bitmap);
                o.str("guard S bitmap_global=");
                o.hex(global);
                o.str(" bitmap=");
                o.hex(bitmap);
                o.nl();
                flush_out(a, pipe, o);
                if (bitmap) {
                    Mbi mbi{};
                    if (a.VirtualQuery(reinterpret_cast<const void*>(bitmap), &mbi, sizeof(mbi))) {
                        o.str("guard S bitmap_prot=");
                        o.hex(mbi.Protect);
                        o.str(" type=");
                        o.hex(mbi.Type);
                        o.str(" state=");
                        o.hex(mbi.State);
                        o.nl();
                        flush_out(a, pipe, o);
                        unsigned long long probe = reinterpret_cast<unsigned long long>(&cap_print);
                        unsigned long long idx = (probe >> 15) & 0x1ffffull;
                        o.str("guard S idx=");
                        o.hex(idx);
                        o.str(" byte=");
                        o.hex(*reinterpret_cast<unsigned char*>(bitmap + idx));
                        o.nl();
                    }
                }
            }
            if (rx) a.VirtualFree(rx, 0, 0x8000);
            if (rw) a.VirtualFree(rw, 0, 0x8000);
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'R') {
            // Private pages are not valid CFG call targets, which is what the
            // earlier registration ran into (87). PAGE_TARGETS_INVALID says so
            // at allocation time, and offsets can then be opted in. Nothing
            // here touches a client page: the page is ours, the stub is
            // `mov eax,42; ret`, and the proof call is direct.
            if (!a.VirtualAlloc || !a.SetProcessValidCallTargets) {
                o.str("guard R api missing\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            const DWORD kTargetsInvalid = 0x40000000;
            void* page = a.VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE | kTargetsInvalid);
            o.str("guard R page=");
            o.hex(reinterpret_cast<unsigned long long>(page));
            o.str(" alloc_err=");
            o.dec(page ? 0u : static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            flush_out(a, pipe, o);
            if (!page) {
                stage_mark(a, "DONE");
                continue;
            }
            unsigned char* pc = static_cast<unsigned char*>(page);
            pc[0] = 0xb8;  // mov eax, 42
            pc[1] = 0x2a;
            pc[2] = 0;
            pc[3] = 0;
            pc[4] = 0;
            pc[5] = 0xc3;  // ret
            static CfgCallTargetInfo rinfo[1];
            rinfo[0].Offset = 0;
            rinfo[0].Flags = 1;
            HANDLE self = reinterpret_cast<HANDLE>(static_cast<long long>(-1));
            BOOL rc = a.SetProcessValidCallTargets(self, page, 0x1000, 1, rinfo);
            o.str("guard R register rc=");
            o.dec(rc ? 1u : 0u);
            o.str(" err=");
            o.dec(static_cast<unsigned int>(a.GetLastError()));
            o.nl();
            int v = reinterpret_cast<int (*)()>(page)();
            o.str("guard R stub_direct=");
            o.dec(static_cast<unsigned int>(v));
            o.nl();
            flush_out(a, pipe, o);
            HANDLE f = a.CreateFileA("D:\\zendo\\work\\trust_page.bin", GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (f != INVALID_HANDLE_VALUE) {
                DWORD w = 0;
                a.WriteFile(f, &page, 8, &w, nullptr);
                a.CloseHandle(f);
            }
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'M') {
            // Run 2 without the walk that killed the client at stage 'x'. The
            // client image names its own dispatch slot in the load config:
            // offset 0x78 is GuardCFDispatchFunctionPointer, the address of
            // that image's __guard_dispatch_icall_fptr. Read it, report what
            // it holds, then point it at ntdll's own `jmp rax` stub. One 8-byte
            // write to a data page: no scan, no code patch, no icache flush.
            // If the slot already holds that stub, nothing is written and the
            // native test runs as-is - which answers the question either way.
            Module ntdll = find_module(fnv1a_w(L"ntdll.dll"));
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (!ntdll.base || dos->e_magic != IMAGE_DOS_SIGNATURE) {
                o.str("guard M bad image\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            auto& lc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            unsigned long long nb = reinterpret_cast<unsigned long long>(ntdll.base);
            auto* ndos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll.base);
            auto* nnt = reinterpret_cast<IMAGE_NT_HEADERS*>(nb + ndos->e_lfanew);
            auto& nlc = nnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

            unsigned long long slot = 0, nslot = 0, nop = 0;
            if (lc.VirtualAddress && lc.Size >= 0x80)
                read_u64(base + lc.VirtualAddress + 0x78, &slot);
            if (nlc.VirtualAddress && nlc.Size >= 0x80) {
                read_u64(nb + nlc.VirtualAddress + 0x78, &nslot);
                read_u64(nslot, &nop);
            }
            unsigned char nop0 = 0, nop1 = 0;
            if (nop && readable(reinterpret_cast<const void*>(nop), 2)) {
                nop0 = *reinterpret_cast<unsigned char*>(nop);
                nop1 = *reinterpret_cast<unsigned char*>(nop + 1);
            }
            o.str("guard M client=");
            o.hex(base);
            o.str(" ldcfg=");
            o.hex(lc.VirtualAddress);
            o.str(" slot=");
            o.hex(slot);
            o.str(" ntdll_slot=");
            o.hex(nslot);
            o.str(" stub=");
            o.hex(nop);
            o.str(" stub_ok=");
            o.dec((nop0 == 0xff && nop1 == 0xe0) ? 1 : 0);
            o.nl();
            flush_out(a, pipe, o);
            if (!slot) {
                o.str("guard M no slot\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned long long held = 0;
            read_u64(slot, &held);
            o.str("guard M held=");
            o.hex(held);
            o.str(" rva=");
            o.hex(held >= nb ? held - nb : 0);
            o.str(" head=");
            for (int k = 0; k < 16; ++k) {
                unsigned char b = 0;
                if (readable(reinterpret_cast<const void*>(held + k), 1))
                    b = *reinterpret_cast<unsigned char*>(held + k);
                o.hex(b);
                o.ch(' ');
            }
            o.nl();
            flush_out(a, pipe, o);

            if (nop0 == 0xff && nop1 == 0xe0 && held != nop) {
                DWORD oldp = 0;
                if (!a.VirtualProtect(reinterpret_cast<void*>(slot), 8, PAGE_READWRITE, &oldp)) {
                    o.str("guard M protect failed=");
                    o.dec(static_cast<unsigned int>(a.GetLastError()));
                    o.nl();
                    flush_out(a, pipe, o);
                    stage_mark(a, "DONE");
                    continue;
                }
                wr64(slot, nop);
                DWORD tmp = 0;
                a.VirtualProtect(reinterpret_cast<void*>(slot), 8, oldp, &tmp);
                unsigned long long back = 0;
                read_u64(slot, &back);
                o.str("guard M slot->stub readback=");
                o.hex(back);
                o.nl();
                flush_out(a, pipe, o);
            } else if (held == nop) {
                o.str("guard M slot already stub\n");
                flush_out(a, pipe, o);
            } else {
                // No nop stub in ntdll's own slot: patch the dispatcher body
                // instead. The target arrives in rax (proven by the entry's
                // `mov r10, rax`), so `48 ff e0` is a complete replacement.
                DWORD oldp = 0;
                if (!a.VirtualProtect(reinterpret_cast<void*>(held), 0x10,
                                      PAGE_EXECUTE_READWRITE, &oldp)) {
                    o.str("guard M code protect failed=");
                    o.dec(static_cast<unsigned int>(a.GetLastError()));
                    o.nl();
                    flush_out(a, pipe, o);
                    stage_mark(a, "DONE");
                    continue;
                }
                *reinterpret_cast<unsigned char*>(held) = 0x48;
                *reinterpret_cast<unsigned char*>(held + 1) = 0xff;
                *reinterpret_cast<unsigned char*>(held + 2) = 0xe0;
                if (a.FlushInstructionCache)
                    a.FlushInstructionCache(INVALID_HANDLE_VALUE,
                                            reinterpret_cast<void*>(held), 3);
                DWORD tmp = 0;
                a.VirtualProtect(reinterpret_cast<void*>(held), 0x10, oldp, &tmp);
                o.str("guard M dispatcher patched\n");
                flush_out(a, pipe, o);
            }
            stage_mark(a, "GUARD");
            cmd[0] = 'k';
        }
        if (cmd[0] == 'x') {
            // Disabled after the client died mid-walk. The load config names
            // the same target without touching 16 MB of protected pages.
            o.str("guard x disabled, use M\n");
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'X') {
            // CFG has no bitmap entry for MEM_PRIVATE pages, and the policy
            // cannot be relaxed at runtime (err 5). The check itself lives in
            // ntdll's dispatch stub: every instrumented indirect call is a
            // `call qword ptr [rip+x]` to one shared pointer. Find that pointer
            // by counting which ntdll address the client's call sites point at
            // most often, then replace the stub body with `jmp rax` - the
            // target already arrives in rax.
            Module ntdll = find_module(fnv1a_w(L"ntdll.dll"));
            o.str("guard ntdll=");
            o.hex(reinterpret_cast<unsigned long long>(ntdll.base));
            o.nl();
            flush_out(a, pipe, o);
            if (!ntdll.base) { stage_mark(a, "DONE"); continue; }
            unsigned long long lo = reinterpret_cast<unsigned long long>(ntdll.base);
            unsigned long long hi = lo + ntdll.size;
            unsigned long long cbase = base;
            unsigned long long cend = base + 0x1000000ull;
            unsigned long long hit = 0;
            static unsigned long long cand_p[192];
            static unsigned int cand_n[192];
            unsigned int ncand = 0;
            auto* p = reinterpret_cast<const unsigned char*>(cbase);
            unsigned long long n = cend - cbase;
            // The protector leaves whole pages PAGE_NOACCESS until they run, so
            // a linear read crashes. Walk one page at a time and only touch
            // pages that are actually readable.
            for (unsigned long long i = 0; i + 6 < n; ++i) {
                if ((i & 0xfff) == 0) {
                    Mbi mbi{};
                    if (!a.VirtualQuery(p + i, &mbi, sizeof(mbi))) { i += 0xfff; continue; }
                    DWORD prot = mbi.Protect & 0xff;
                    bool okp = mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
                               (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                                prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                                prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
                    if (!okp) {
                        unsigned long long skip = 0x1000 - (i & 0xfff);
                        i += skip - 1;
                        continue;
                    }
                }
                if (p[i] != 0xff || p[i + 1] != 0x15) continue;
                int disp = *reinterpret_cast<const int*>(p + i + 2);
                unsigned long long slot = cbase + i + 6 + static_cast<long long>(disp);
                if (slot < cbase || slot + 8 > cend) continue;
                unsigned long long tgt = 0;
                if (!read_u64(slot, &tgt)) continue;
                if (tgt < lo || tgt >= hi) continue;
                unsigned int j = 0;
                for (; j < ncand; ++j) {
                    if (cand_p[j] == tgt) { ++cand_n[j]; break; }
                }
                if (j == ncand && ncand < 192) {
                    cand_p[ncand] = tgt;
                    cand_n[ncand] = 1;
                    ++ncand;
                }
                // The dispatch stub always ends in `jmp rax`. A target that has
                // one near its head is the stub itself, so stop right there
                // instead of scanning the rest of the image.
                bool has = false;
                for (int k = 0; k < 0x40; ++k) {
                    unsigned char b0 = *reinterpret_cast<unsigned char*>(tgt + k);
                    unsigned char b1 = *reinterpret_cast<unsigned char*>(tgt + k + 1);
                    if (b0 == 0xff && b1 == 0xe0) { has = true; break; }
                }
                if (has) { hit = tgt; break; }
            }
            unsigned int best = 0;
            for (unsigned int j = 1; j < ncand; ++j)
                if (cand_n[j] > cand_n[best]) best = j;
            if (!hit && !ncand) {
                o.str("guard no candidate\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            unsigned long long fn = hit ? hit : cand_p[best];
            o.str("guard fn=");
            o.hex(fn);
            o.str(" hits=");
            o.dec(cand_n[best]);
            o.str(" cands=");
            o.dec(ncand);
            o.str(" bytes=");
            unsigned char pb[8] = {0};
            for (int k = 0; k < 8; ++k) pb[k] = *reinterpret_cast<unsigned char*>(fn + k);
            for (int k = 0; k < 8; ++k) { o.hex(pb[k]); o.str(" "); }
            o.nl();
            flush_out(a, pipe, o);
            // Sanity: a guarded dispatch stub must jump through rax somewhere
            // near its head. Anything else means the histogram picked noise.
            bool looks = false;
            for (int k = 0; k < 0x40; ++k) {
                unsigned char b0 = *reinterpret_cast<unsigned char*>(fn + k);
                unsigned char b1 = *reinterpret_cast<unsigned char*>(fn + k + 1);
                if (b0 == 0xff && b1 == 0xe0) { looks = true; break; }
            }
            if (!looks) {
                o.str("guard no jmp rax in head, not patching\n");
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            DWORD oldp = 0;
            if (!a.VirtualProtect(reinterpret_cast<void*>(fn), 0x1000,
                                  PAGE_EXECUTE_READWRITE, &oldp)) {
                o.str("guard protect failed=");
                o.dec(static_cast<unsigned int>(a.GetLastError()));
                o.nl();
                flush_out(a, pipe, o);
                stage_mark(a, "DONE");
                continue;
            }
            *reinterpret_cast<unsigned char*>(fn) = 0x48;
            *reinterpret_cast<unsigned char*>(fn + 1) = 0xff;
            *reinterpret_cast<unsigned char*>(fn + 2) = 0xe0;
            DWORD tmp = 0;
            a.VirtualProtect(reinterpret_cast<void*>(fn), 0x1000, oldp, &tmp);
            o.str("guard patched\n");
            flush_out(a, pipe, o);
            stage_mark(a, "GUARD");
            cmd[0] = 'k';
        }
        if (cmd[0] == 'k') {
            // The whole question in one command: can Luau call into this
            // payload at all? A C closure taken from the globals gets its
            // function pointer swapped for native_loadstring and is then called
            // from a chunk. That call is indirect, through the client image,
            // into a manual-mapped page.
            g_base = base;
            g_cap_closure = 0;
            exec_raw(a, pipe, o, L, base, kChunkKCaptureBody, kChunkKCaptureLen, "kcapture");
            if (!g_cap_closure) {
                o.str("native no C closure captured\n");
                flush_out(a, pipe, o);
                continue;
            }
            unsigned long long old_f = 0;
            read_u64(g_cap_closure + 0x28, &old_f);
            wr64(g_cap_closure + 0x28, reinterpret_cast<unsigned long long>(&native_loadstring));
            o.str("native swapped clo=");
            o.hex(g_cap_closure);
            o.str(" f=");
            o.hex(old_f);
            o.str(" mode=");
            o.dec(static_cast<unsigned int>(g_native_mode));
            o.nl();
            flush_out(a, pipe, o);
            {
                // Read the guard bit right now, not at the time it was set: if
                // the protector resets the map between the write and the call,
                // this is where it shows.
                Module dll = find_module(fnv1a_w(L"RobloxPlayerBeta.dll"));
                unsigned long long tgt =
                    reinterpret_cast<unsigned long long>(&native_loadstring);
                unsigned long long bitmap = 0;
                if (dll.base) {
                    unsigned long long db = reinterpret_cast<unsigned long long>(dll.base);
                    read_u64(db + 0x4c9376ull + 0x9f9622ull, &bitmap);
                }
                if (bitmap) {
                    unsigned long long bp = bitmap + (tgt >> 15);
                    Mbi q{};
                    a.VirtualQuery(reinterpret_cast<const void*>(bp), &q, sizeof(q));
                    unsigned char cur = 0;
                    if (q.State == MEM_COMMIT && (q.Protect & 0xff) == PAGE_READWRITE)
                        cur = *reinterpret_cast<unsigned char*>(bp);
                    o.str("native guard bit=");
                    o.hex(cur);
                    o.str(" want=");
                    o.hex(1u << static_cast<unsigned int>((tgt >> 12) & 7));
                    o.str(" page_state=");
                    o.hex(q.State);
                    o.nl();
                    flush_out(a, pipe, o);
                }
            }
            stage_mark(a, "NATIVE");
            exec_raw(a, pipe, o, L, base, kChunkKNativeBody, kChunkKNativeLen, "knative");
            wr64(g_cap_closure + 0x28, old_f);
            o.str("native restored\n");
            flush_out(a, pipe, o);
            stage_mark(a, "DONE");
            continue;
        }
        if (cmd[0] == 'g') {
            // Everything that decides whether the client VM may call our code:
            // what kind of pages we live on, whether CFG accepts them, and
            // whether the CFG policy can still be relaxed at runtime.
            Mbi mbi{};
            unsigned long long fn = reinterpret_cast<unsigned long long>(&cap_print);
            if (a.VirtualQuery(reinterpret_cast<const void*>(fn), &mbi, sizeof(mbi))) {
                o.str("mitig page state=");
                o.hex(mbi.State);
                o.str(" type=");
                o.hex(mbi.Type);
                o.str(" prot=");
                o.hex(mbi.Protect);
                o.str(" allocbase=");
                o.hex(reinterpret_cast<unsigned long long>(mbi.AllocationBase));
                o.nl();
            }
            int cfg_rc = cfg_register(reinterpret_cast<void*>(fn));
            o.str("mitig cfg_register=");
            o.dec(static_cast<unsigned int>(cfg_rc));
            o.nl();
            flush_out(a, pipe, o);
            struct CfgFlags { unsigned int raw; };
            CfgFlags off{0};
            if (a.SetProcessMitigationPolicy) {
                BOOL r = a.SetProcessMitigationPolicy(7, &off, sizeof(off));
                o.str("mitig cfg_off rc=");
                o.dec(r);
                o.str(" err=");
                o.dec(static_cast<unsigned int>(a.GetLastError()));
                o.nl();
            } else {
                o.str("mitig cfg_off unavailable\n");
            }
            flush_out(a, pipe, o);
            continue;
        }
        if (cmd[0] == 'j' || cmd[0] == 'h' || cmd[0] == 'H' || cmd[0] == 'J') {
            int saved = g_cap_mode;
            g_cap_mode = (cmd[0] == 'j') ? 0 : (cmd[0] == 'h') ? 1 : (cmd[0] == 'H') ? 2 : 3;
            o.str("probe mode=");
            o.dec(g_cap_mode);
            o.str(" clo=");
            o.hex(g_cap_closure);
            o.str(" f=");
            o.hex(g_cap_f);
            o.nl();
            flush_out(a, pipe, o);
            exec_raw(a, pipe, o, L, base, kChunkProbe, kChunkProbeLen, "probe");
            o.str("probe calls=");
            o.dec(g_cap_calls);
            o.str(" cfg=");
            o.dec(static_cast<unsigned int>(g_cfg_status));
            o.nl();
            flush_out(a, pipe, o);
            g_cap_mode = saved;
            continue;
        }
        if (cmd[0] == 'P' || cmd[0] == 'E' || cmd[0] == 'S' || cmd[0] == 'T' || cmd[0] == 'R' || cmd[0] == 'V' || cmd[0] == 'F' || cmd[0] == 'C' || cmd[0] == 'D' || cmd[0] == 'W' || cmd[0] == 'X') {
            const unsigned char* pb = kChunkC33Body;
            unsigned int pl = kChunkC33Len;
            const char* pn = "protected ok";
            if (cmd[0] == 'E') { pb = kChunkC32Body; pl = kChunkC32Len; pn = "protected error"; }
            if (cmd[0] == 'S') { pb = kChunkC35Body; pl = kChunkC35Len; pn = "err plain"; }
            if (cmd[0] == 'T') { pb = kChunkC36Body; pl = kChunkC36Len; pn = "pcall err builtin"; }
            if (cmd[0] == 'R') { pb = kChunkC37Body; pl = kChunkC37Len; pn = "err vm nilindex"; }
            if (cmd[0] == 'V') { pb = kChunkC39Body; pl = kChunkC39Len; pn = "pcall lua err"; }
            if (cmd[0] == 'F') { pb = kChunkC40Body; pl = kChunkC40Len; pn = "pcall fn"; }
            if (cmd[0] == 'C') {
                o.str("RUN raw ok\n");
                flush_out(a, pipe, o);
                exec_raw(a, pipe, o, L, base, kChunkC33Body, kChunkC33Len, "raw ok");
                continue;
            }
            if (cmd[0] == 'D') {
                o.str("RUN raw err\n");
                flush_out(a, pipe, o);
                exec_raw(a, pipe, o, L, base, kChunkC35Body, kChunkC35Len, "raw err");
                continue;
            }
            if (cmd[0] == 'W') {
                o.str("RUN raw nested closure\n");
                flush_out(a, pipe, o);
                exec_raw(a, pipe, o, L, base, kChunkC41Body, kChunkC41Len, "raw c41");
                continue;
            }
            if (cmd[0] == 'X') {
                o.str("RUN raw upval error\n");
                flush_out(a, pipe, o);
                exec_raw(a, pipe, o, L, base, kChunkC42Body, kChunkC42Len, "raw c42");
                continue;
            }
            o.str("RUN ");
            o.str(pn);
            o.nl();
            flush_out(a, pipe, o);
            exec_protected(a, pipe, o, L, base, pb, pl, pn);
            continue;
        }
        const ReplEntry* hit = nullptr;
        for (unsigned int i = 0; i < sizeof(kReplTable) / sizeof(kReplTable[0]); ++i)
            if (kReplTable[i].cmd == cmd[0]) hit = &kReplTable[i];
        if (!hit) {
            o.str("unknown cmd\n");
            flush_out(a, pipe, o);
            continue;
        }
        o.str("RUN ");
        o.str(hit->name);
        o.nl();
        flush_out(a, pipe, o);
        g_veh_phase = hit->name;
        g_sentinel = (hit->cmd == 'z' || hit->cmd == 'Z');
        exec_chunk(a, pipe, o, L, base, hit->body, hit->len, hit->name);
        g_sentinel = false;
    }

    // Session over: the closure slot goes back to the game's own print, and the
    // capture mode is retired with it. The store is guarded: this object is a
    // GC closure, and between sessions the collector may already have taken it
    // back. A blind store there is what ended the payload thread right after
    // `q` and left the client alive with an abandoned mutex.
    cap_restore();
    g_cap_depth = 0;
    g_api_live = 0;
    g_cap_mode = 0;
    g_cap_closure = 0;
    g_cap_f = 0;

    g_declared_size = 0;
    g_patch_proto = 0;
    o.str("END\n");
    flush_out(a, pipe, o);
    return 0;
}

// One injection, as many sessions as the image survives. The session thread
// waits for the next pipe server instead of ending after one chunk, so a
// second Execute can reuse the image instead of mapping another one. It is a
// best-effort reuse: this client kills or suspends foreign threads within
// seconds of DllMain returning (measured: loop.bin frozen 4 s after a clean
// session while the process kept running), and when that happens the host
// injects again, which is safe because the pipe admits one client at a time.
inline DWORD run_repl() {
    DWORD st = resolve_api();
    if (st) {
        stage_mark(api(), "EXIT-API");
        return 100 + st;
    }
    Api& a = api();
    stage_mark(a, "E1-API");
    trace_tag(a, "enter");
    // No single-instance claim. Every version of it deadlocked the same way:
    // the claim outlives the thread the client kills. The pipe is the
    // semaphore - one server instance accepts one payload, so two images can
    // never be inside a session at once - and the host's liveness oracle for
    // a parked payload is still loop.bin.
    stage_mark(a, "E2-OWN");

    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    // Every offset below is a number from one specific client build. On any
    // other build those writes land in unrelated code and the client dies with
    // no explanation, so prove the build before touching anything. The build id
    // is the directory name the loader already recorded, which costs no PE
    // parsing and no imports.
    LdrEntry* exe_entry = find_module_entry(fnv1a_w(L"RobloxPlayerBeta.exe"));
    if (!exe_entry || !wide_contains(exe_entry->FullDllName, k_build_tag)) {
        stage_mark(a, "EARGS-BUILD");
        return 120;
    }
    if (!offsets_ok(base, exe)) {
        char tb[12] = {'E', 'A', 'R', 'G', 'S', '-', 'O', 'F', 'F', '0', 0, 0};
        tb[9] = static_cast<char>('0' + g_off_fail);
        stage_mark(a, tb);
        return 121;
    }
    stage_mark(a, "E3-GATE");
    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    stage_mark_val(a, "E4-DM", dm);
    stage_mark(a, "E4a-FS");
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    if (!sc) {
        stage_mark_val(a, "E4b-FS0", dm);
    } else {
        stage_mark_val(a, "E4b-FS1", sc);
    }
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    if (!L) {
        if (sc) stage_mark_val(a, "E4c-SCOK", decode_split(sc + k_slot_a));
        stage_mark(a, "E4c-NOSTATE");
        for (int i = 0; i < 100; ++i) {
            stage_mark(a, "E4d-PIPE");
            HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev",
                                        GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                        OPEN_EXISTING, 0, nullptr);
            if (pipe == INVALID_HANDLE_VALUE) {
                if (a.Sleep) a.Sleep(100);
                continue;
            }
            static Out o;
            o.reset();
            o.str("no state\nEND\n");
            flush_out(a, pipe, o);
            a.CloseHandle(pipe);
            break;
        }
        stage_mark(a, "EXIT-NOSTATE");
        return 111;
    }

    unsigned int idle = 0;
    stage_mark(a, "SEEK");
    for (;;) {
        HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev",
                                    GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            if ((idle++ % 100) == 0) stage_mark(a, "SEEK");
            // Heartbeat: the mtime of loop.bin answers "is a payload thread
            // still hunting for a server" from the host, without a mutex that
            // can be read free while the owner is alive. Only the seek loop
            // writes it, so a stale stamp means the thread is gone.
            if ((idle % 20) == 0) loop_mark(a, ++g_seek_n);
            if ((idle % 100) == 0) trace_tag(a, "seek");
            // One injection, one session. Eight seconds is the host's own
            // connect window; after that there is no server to serve, and
            // holding a hijacked client thread any longer is how a place
            // transition ends up killing a thread mid-DllMain.
            if (idle > 160) {
                // Leave DllMain: the stub restores the borrowed thread's
                // original context, so nothing is left parked inside this
                // client for a watchdog to find.
                stage_mark(a, "EXIT-IDLE");
                return 111;
            }
            if (!a.Sleep) {
                stage_mark(a, "EXIT-NOSLEEP");
                return 2;
            }
            a.Sleep(50);
            continue;
        }
        idle = 0;
        beacon(a, "PIPE");
        trace_tag(a, "conn");
        DWORD served = serve_session(a, pipe, base, L);
        trace_tag(a, "ret");
        stage_mark_val(a, "SESS-RET", served);
        g_cap_pipe = INVALID_HANDLE_VALUE;
        stage_mark(a, "PRE-CLOSE");
        a.CloseHandle(pipe);
        stage_mark(a, "POST");
        loop_mark(a, ++g_loop_n);
        if (g_leave) {
            stage_mark(a, "EXIT-DETACH");
            return 111;
        }
        // One session per injection, then the thread goes back to the client.
        // A resident payload was tried and cost far more than it saved: the
        // client kills foreign threads on its own schedule (a place change is
        // the reliable one), and a thread killed inside DllMain is a thread
        // killed while it may hold a lock the next place needs. The host
        // already injects on every run because the resident rarely survived;
        // this makes that explicit instead of leaving a 10-minute thread
        // parked behind every Execute.
        stage_mark(a, "EXIT-ONE");
        return 0;
    }
}

// One line of ground truth about the live mutex: the handle, the CreateMutex
// error, and what a zero-timeout wait says. A wait of 0x102 (WAIT_TIMEOUT)
// means some thread still owns it; 0x80 (WAIT_ABANDONED) means the owner died.
// This file is not overwritten by the seek loop, so it survives a session end.
