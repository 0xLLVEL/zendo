// ---------------------------------------------------------------------------
// Runtime probe: find the real lua_State from live process memory.
//
// The capability helper at RVA 0x4274D10 reads an encoded pointer from
// <object>+0x210 and <object>+0x520. The encoding is split into two halves,
// each relative to the low 32 bits of the slot's own address:
//     lo = (u32)slot - (u32)enc
//     hi = (u32)slot - (u32)(enc >> 32)
// A plain 64-bit subtraction is reported too, so the wrong hypothesis is
// visible instead of assumed.
// ---------------------------------------------------------------------------

constexpr unsigned long long k_fake_dm_static = 0x8EB6960;
constexpr unsigned long long k_ve_static = 0x8942E38;
constexpr unsigned long long k_fake_dm_to_dm = 0x1F8;
constexpr unsigned long long k_dm_to_script_context = 0x440;
constexpr unsigned long long k_ve_to_fake_dm = 0xAF0;
constexpr unsigned long long k_slot_a = 0x210;
constexpr unsigned long long k_slot_b = 0x520;

// Primary vtable of ScriptContext, extracted from the image's RTTI:
// type descriptor ".?AVScriptContext@RBX@@" -> COL 0x78bc9e8 (offset 0)
// -> vtable[-1] at 0x71b0fe0, so the object's [0] is base + 0x71b0fe8.
constexpr unsigned long long k_script_context_vtable = 0x71B0FE8;
constexpr unsigned long long k_lua_vm_load = 0x426A570;

inline bool readable(const void* p, SIZE_T len) {
    if (reinterpret_cast<unsigned long long>(p) < 0x10000) return false;
    Mbi mbi;
    if (!api().VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return false;
    unsigned long long begin = reinterpret_cast<unsigned long long>(mbi.BaseAddress);
    unsigned long long at = reinterpret_cast<unsigned long long>(p);
    return at + len <= begin + mbi.RegionSize;
}

// A pinned address cannot be validated by asking whether its page is mapped:
// the protector commits and releases code pages on demand, so a healthy client
// reports FREE at an address that works the moment it is executed. What is
// stable is the image itself - a valid PE header at the base we resolved and a
// plausible size. Which build it is, the path tag already says precisely.
static int g_off_fail = -1;

inline bool offsets_ok(unsigned long long base, const Module& m) {
    (void)m;
    g_off_fail = 0;
    if (base < 0x10000) return false;
    if (!readable(reinterpret_cast<const void*>(base), 0x40)) return false;
    auto* dos = reinterpret_cast<const unsigned char*>(base);
    if (dos[0] != 'M' || dos[1] != 'Z') return false;
    unsigned int lfanew = *reinterpret_cast<const volatile unsigned int*>(base + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x1000) return false;
    if (!readable(reinterpret_cast<const void*>(base + lfanew), 0x58)) return false;
    auto* nt = reinterpret_cast<const unsigned char*>(base + lfanew);
    if (nt[0] != 'P' || nt[1] != 'E') return false;
    unsigned short machine = *reinterpret_cast<const volatile unsigned short*>(nt + 4);
    if (machine != 0x8664) return false;
    unsigned int size_of_image = *reinterpret_cast<const volatile unsigned int*>(nt + 0x50);
    if (size_of_image < 0x100000 || size_of_image > 0x40000000) return false;
    g_off_fail = -1;
    return true;
}

inline bool read_u64(unsigned long long addr, unsigned long long* out) {
    if (!addr || !readable(reinterpret_cast<const void*>(addr), 8)) return false;
    *out = *reinterpret_cast<volatile unsigned long long*>(addr);
    return true;
}

inline bool read_u32(unsigned long long addr, unsigned int* out) {
    if (!addr || !readable(reinterpret_cast<const void*>(addr), 4)) return false;
    *out = *reinterpret_cast<volatile unsigned int*>(addr);
    return true;
}

inline unsigned long long decode_split(unsigned long long slot) {
    unsigned long long enc = 0;
    if (!read_u64(slot, &enc)) return 0;
    unsigned int slot_lo = static_cast<unsigned int>(slot);
    unsigned long long lo = static_cast<unsigned int>(slot_lo - static_cast<unsigned int>(enc));
    unsigned long long hi = static_cast<unsigned int>(slot_lo - static_cast<unsigned int>(enc >> 32));
    return (hi << 32) | lo;
}

inline void wr64(unsigned long long addr, unsigned long long v) {
    *reinterpret_cast<volatile unsigned long long*>(addr) = v;
}

// Every offset the payload writes to belongs to an object the game's own GC
// owns. Between two sessions that object can be collected and the page handed
// to something else, so a blind store is a write into whatever lives there now
// - a crash the client reports as nothing at all. This variant refuses unless
// the page is committed and writable, and says whether it wrote.
inline bool wr64_live(unsigned long long addr, unsigned long long v) {
    if (addr < 0x10000) return false;
    Mbi mbi;
    if (!api().VirtualQuery || !api().VirtualQuery(reinterpret_cast<void*>(addr), &mbi,
                                                   sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    DWORD prot = mbi.Protect & 0xff;
    if (prot != PAGE_READWRITE && prot != PAGE_WRITECOPY &&
        prot != PAGE_EXECUTE_READWRITE && prot != PAGE_EXECUTE_WRITECOPY)
        return false;
    *reinterpret_cast<volatile unsigned long long*>(addr) = v;
    return true;
}

inline void wr32(unsigned long long addr, unsigned int v) {
    *reinterpret_cast<volatile unsigned int*>(addr) = v;
}

