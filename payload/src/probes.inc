inline DWORD run_load() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 load base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    o.str("  sc=");
    o.hex(sc);
    if (!sc) {
        o.str("  no ScriptContext\n");
    } else {
        unsigned long long L = decode_split(sc + k_slot_a);
        unsigned int guard = 0;
        read_u32(sc + 0x1628, &guard);
        unsigned long long top0 = 0, stack = 0;
        read_u64(L + 0x60, &top0);
        read_u64(L + 0x48, &stack);
        o.str("  L=");
        o.hex(L);
        o.str(" guard=");
        o.hex(guard);
        o.str(" top=");
        o.hex(top0);
        o.str(" stack=");
        o.hex(stack);
        o.nl();

        unsigned long long cache[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        typedef int (*LoadFn)(void*, void*, const char*, unsigned int, int);
        LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
        const char* tests[5] = {
            "",
            "x",
            "local x = 1",
            "return 1 + 1",
            "local x = 1 + 1 return x",
        };
        for (int ti = 0; ti < 5; ++ti) {
            const char* src = tests[ti];
            unsigned int len = 0;
            while (src[len]) ++len;
            unsigned long long t0 = 0;
            read_u64(L + 0x60, &t0);
            int ret = load(reinterpret_cast<void*>(L), cache, src, len, 0);
            unsigned long long t1 = 0;
            read_u64(L + 0x60, &t1);
            o.str("  t");
            o.dec(static_cast<unsigned int>(ti));
            o.str(" len=");
            o.dec(len);
            o.str(" ret=");
            o.dec(static_cast<unsigned int>(ret));
            o.str(" d=");
            o.hex(t1 - t0);
            o.str(" src='");
            o.str(src);
            o.str("'");
            o.nl();
            if (t1 > t0 && t1 - t0 >= 16) {
                unsigned long long v = 0, hi = 0;
                read_u64(t0, &v);
                read_u64(t0 + 8, &hi);
                o.str("    v=");
                o.hex(v);
                o.str(" w=");
                o.hex(hi);
                o.str(" tt=");
                o.dec(static_cast<unsigned int>((hi >> 32) & 0xffff));
                o.nl();
                if (v && readable(reinterpret_cast<const void*>(v + 0x18), 4)) {
                    unsigned int slen = 0;
                    read_u32(v + 0x14, &slen);
                    o.str("    s len=");
                    o.dec(slen);
                    o.str(" '");
                    if (slen < 120) {
                        for (unsigned int k = 0; k < slen; ++k)
                            o.ch(*reinterpret_cast<char*>(v + 0x18 + k));
                    }
                    o.str("'");
                    o.nl();
                }
            }
        }
    }
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

inline void dump_tv(Out& o, unsigned long long slot, const char* tag);

inline void dump_tv(Out& o, unsigned long long slot, const char* tag) {
    unsigned long long v = 0, w = 0;
    if (!read_u64(slot, &v) || !read_u64(slot + 8, &w)) {
        o.str(tag);
        o.str(" unreadable");
        o.nl();
        return;
    }
    o.str(tag);
    o.str(" v=");
    o.hex(v);
    o.str(" w=");
    o.hex(w);
    o.str(" tt=");
    o.dec(static_cast<unsigned int>((w >> 32) & 0xff));
    if (v && readable(reinterpret_cast<const void*>(v + 0x18), 4)) {
        unsigned int slen = 0;
        read_u32(v + 0x14, &slen);
        if (slen < 90) {
            o.str(" '");
            for (unsigned int k = 0; k < slen; ++k) o.ch(*reinterpret_cast<char*>(v + 0x18 + k));
            o.str("'");
        }
    }
    o.nl();
}

// MSVC std::string: inline buffer / heap pointer at +0, size at +0x10,
// capacity at +0x18. LuaVMLoad checks size>8 and capacity>=16, then reads
// the data pointer from +0.
struct ChunkName {
    const char* data;
    unsigned long long pad;
    unsigned long long size;
    unsigned long long cap;
};

// Loads plain Luau source with a well formed chunkname and reports exactly
// what the loader pushed. No task machinery, no unproven calls.
inline DWORD run_chunk() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 chunk base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("  sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    unsigned int flag = 0;
    read_u32(base + 0x81967B0, &flag);
    o.str("  byte_81967B0=");
    o.hex(flag & 0xff);
    o.nl();
    if (!L) {
        o.str("  no state\n");
    } else {
        unsigned long long top0 = 0;
        read_u64(L + 0x60, &top0);

        static char name_buf[32];
        const char* nm = "=zendo.chunk";
        int k = 0;
        while (nm[k]) { name_buf[k] = nm[k]; ++k; }
        name_buf[k] = 0;

        ChunkName cn;
        cn.data = name_buf;
        cn.pad = 0;
        cn.size = static_cast<unsigned long long>(k);
        cn.cap = 31;

        const char* src = "return 1 + 1";
        unsigned int len = 0;
        while (src[len]) ++len;
        o.str("  cn len=");
        o.dec(k);
        o.str(" src len=");
        o.dec(len);
        o.nl();

        typedef int (*LoadFn)(void*, void*, const char*, int);
        LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
        int ret = load(reinterpret_cast<void*>(L), &cn, src, 0);
        unsigned long long t1 = 0;
        read_u64(L + 0x60, &t1);
        o.str("  ret=");
        o.dec(static_cast<unsigned int>(ret));
        o.str(" top=");
        o.hex(t1);
        o.str(" d=");
        o.hex(t1 - top0);
        o.nl();
        if (t1 > top0) dump_tv(o, top0, "  val:");
        if (t1 > top0 && t1 - top0 >= 16) {
            unsigned long long v = 0, w = 0;
            read_u64(top0, &v);
            read_u64(top0 + 8, &w);
            if (v && readable(reinterpret_cast<const void*>(v), 0x40)) {
                o.str("  raw:");
                for (int i = 0; i < 0x40; i += 8) {
                    unsigned long long q = 0;
                    read_u64(v + static_cast<unsigned long long>(i), &q);
                    o.str(" ");
                    o.hex(q);
                }
                o.nl();
            }
        }
    }
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Stage 18: real bytecode. LuaVMLoad's raw path compares the first qword of
// the std::string against 0xE009325B4A107A52 (rodata 0x6AF9FF0) and, on match,
// hands data+8 / size-8 to the protected undump. Body compiled offline by
// luau-compile; header is the build's 8 byte magic.
#include "chunk.inc"
#include "probe.inc"
#include "raw.inc"
#include "../chunks/live_a.inc"
#include "../chunks/live_b.inc"
#include "../chunks/live_c.inc"
#include "../chunks/live_d.inc"
#include "../chunks/c1.inc"
#include "../chunks/c2.inc"
#include "../chunks/c3.inc"
#include "../chunks/c4.inc"
#include "../chunks/c6.inc"
#include "../chunks/c7.inc"
#include "../chunks/live1.inc"
#include "../chunks/c8.inc"
#include "../chunks/c9.inc"
#include "../chunks/c10.inc"
#include "../chunks/c11.inc"
#include "../chunks/c12.inc"
#include "../chunks/c13.inc"
#include "../chunks/c14.inc"
#include "../chunks/c15.inc"
#include "../chunks/c16.inc"
#include "../chunks/c17.inc"
#include "../chunks/c18.inc"
#include "../chunks/c19.inc"
#include "../chunks/c20.inc"
#include "../chunks/c21.inc"
#include "../chunks/c22.inc"
#include "../chunks/c23.inc"
#include "../chunks/c24.inc"
#include "../chunks/c25.inc"
#include "../chunks/c26.inc"
#include "../chunks/c27.inc"
#include "../chunks/c28.inc"
#include "../chunks/c29.inc"
#include "../chunks/c31.inc"
#include "../chunks/c32.inc"
#include "../chunks/c33.inc"
#include "../chunks/c34.inc"
#include "../chunks/gbind.inc"
#include "../chunks/c35.inc"
#include "../chunks/c36.inc"
#include "../chunks/c37.inc"
#include "../chunks/c39.inc"
#include "../chunks/c40.inc"
#include "../chunks/c41.inc"
#include "../chunks/c42.inc"
#include "../chunks/kcapture.inc"
#include "../chunks/knative.inc"
#include "../chunks/z42.inc"
#include "../chunks/zapi.inc"
#include "../chunks/zbind.inc"
#include "../chunks/zcall.inc"

inline DWORD run_bc() {
    DWORD st = resolve_api();
    if (st) return 30 + st;
    Api& a = api();
    HANDLE pipe = a.CreateFileA("\\\\.\\pipe\\zendo-dev", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 2;

    static Out o;
    o.reset();
    Module exe = find_module(fnv1a_w(L"RobloxPlayerBeta.exe"));
    unsigned long long base = reinterpret_cast<unsigned long long>(exe.base);
    o.str("ZEND1 bc base=");
    o.hex(base);
    o.nl();

    unsigned long long fake = 0, dm = 0;
    read_u64(base + k_fake_dm_static, &fake);
    read_u64(fake + k_fake_dm_to_dm, &dm);
    unsigned long long sc = find_service(base, base + k_script_context_vtable, dm);
    unsigned long long L = sc ? decode_split(sc + k_slot_a) : 0;
    o.str("  sc=");
    o.hex(sc);
    o.str(" L=");
    o.hex(L);
    o.nl();
    if (!L) {
        o.str("  no state\n");
    } else {
        static unsigned char container[8 + kChunkLen];
        const unsigned long long magic = 0xE009325B4A107A52ull;
        for (int i = 0; i < 8; ++i) container[i] = static_cast<unsigned char>(magic >> (8 * i));
        for (unsigned int i = 0; i < kChunkLen; ++i) container[8 + i] = kChunkBody[i];

        ChunkName src;
        src.data = reinterpret_cast<const char*>(container);
        src.pad = 0;
        src.size = 8ull + kChunkLen;
        src.cap = 8ull + kChunkLen;

        unsigned long long top0 = 0;
        read_u64(L + 0x60, &top0);

        o.str("  body=");
        o.dec(kChunkLen);
        o.str(" bytes, hdr=");
        o.hex(container[0]);
        o.hex(container[1]);
        o.hex(container[2]);
        o.hex(container[3]);
        o.nl();

        typedef int (*LoadFn)(void*, void*, const char*, int);
        LoadFn load = reinterpret_cast<LoadFn>(base + k_lua_vm_load);
        int ret = load(reinterpret_cast<void*>(L), &src, "=zendo", 0);
        unsigned long long t1 = 0;
        read_u64(L + 0x60, &t1);
        o.str("  ret=");
        o.dec(static_cast<unsigned int>(ret));
        o.str(" top=");
        o.hex(t1);
        o.str(" d=");
        o.hex(t1 - top0);
        o.nl();
        if (t1 > top0) dump_tv(o, top0, "  val:");
    }
    o.str("END\n");

    DWORD written = 0;
    if (!a.WriteFile(pipe, o.buf, o.n, &written, nullptr)) {
        a.CloseHandle(pipe);
        return 3;
    }
    char buf[64];
    DWORD read = 0;
    a.ReadFile(pipe, buf, sizeof(buf), &read, nullptr);
    a.CloseHandle(pipe);
    return 111;
}

// Writes whatever the report buffer holds and empties it. Stage diagnostics
// flush after every section so a crash still leaves a trail on the pipe.
