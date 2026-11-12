inline void mutex_diag(Api& a, HANDLE h) {
    char buf[96];
    char* p = buf;
    const char* pre = "h=";
    while (*pre) *p++ = *pre++;
    p = append_hex(p, reinterpret_cast<unsigned long long>(h));
    const char* mid = " e=";
    while (*mid) *p++ = *mid++;
    DWORD e = a.GetLastError ? a.GetLastError() : 0;
    if (e == 0) { *p++ = '0'; } else {
        char tmp[8]; int n = 0;
        while (e) { tmp[n++] = static_cast<char>('0' + (e % 10)); e /= 10; }
        while (n) *p++ = tmp[--n];
    }
    // ReleaseMutex answers the only question that matters: did this thread
    // actually take the mutex? 1 means the create-time owner flag worked and
    // the host will read WAIT_TIMEOUT while this thread lives. 0 means the
    // handle exists without ownership and the host is right to call it dead.
    DWORD r = (h && a.ReleaseMutex) ? a.ReleaseMutex(h) : 0;
    const char* rel = " r=";
    while (*rel) *p++ = *rel++;
    *p++ = static_cast<char>('0' + (r ? 1 : 0));
    if (r && a.WaitForSingleObject) {
        // Take it back: the handle is meant to stay owned for the life of the
        // thread, the release was only a measurement.
        a.WaitForSingleObject(h, 0);
    }
    const char* wt = " w=";
    while (*wt) *p++ = *wt++;
    DWORD w = 0;
    if (h && a.WaitForSingleObject) w = a.WaitForSingleObject(h, 0);
    if (w == 0) { *p++ = '0'; } else {
        char tmp[8]; int n = 0;
        while (w) { tmp[n++] = static_cast<char>('0' + (w % 10)); w /= 10; }
        while (n) *p++ = tmp[--n];
    }
    *p++ = '\n';
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\mutex.bin", GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    a.WriteFile(f, buf, static_cast<DWORD>(p - buf), &wrote, nullptr);
    a.CloseHandle(f);
}

// Same as STAGE_MARK but a different file, and it takes a number: proof that
// the seek loop is still iterating after a session ended. The stage file is
// overwritten by whatever runs last, so it cannot answer that question.
// Written by the seek loop only; the host reads its mtime as the liveness
// heartbeat ("a payload thread is still hunting for a server").
// Written by the seek loop only; the host reads its mtime as the liveness
// heartbeat ("a payload thread is still hunting for a server").
inline void loop_mark(Api& a, unsigned int n) {
    char buf[16];
    char* p = buf;
    unsigned int v = n;
    char tmp[12]; int k = 0;
    if (v == 0) tmp[k++] = '0';
    while (v) { tmp[k++] = static_cast<char>('0' + (v % 10)); v /= 10; }
    while (k) *p++ = tmp[--k];
    *p++ = '\n';
    HANDLE f = a.CreateFileA("D:\\zendo\\work\\loop.bin", GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    a.WriteFile(f, buf, static_cast<DWORD>(p - buf), &wrote, nullptr);
    a.CloseHandle(f);
}

inline HANDLE trace_open(Api& a) {
    // One file per step, not an append: the payload has no SetFilePointer and
    // CREATE_ALWAYS truncates. Sorted by mtime the files read as a timeline,
    // and each thread id keeps its own column.
    //
    // The image id is in the name because the OS reuses thread ids: two images
    // in one client produced byte-identical names and the second silently
    // erased the first. Twelve bits of this function's own address is enough
    // to tell one mapping from the next.
    static unsigned int seq = 0;
    char buf[96];
    char* p = buf;
    const char pre[] = "D:\\zendo\\work\\tr-";
    for (unsigned i = 0; pre[i]; ++i) *p++ = pre[i];
    unsigned long long img =
        reinterpret_cast<unsigned long long>(&trace_open) >> 12 & 0xffffull;
    p = append_hex(p, img);
    *p++ = '-';
    p = append_hex(p, __readgsqword(0x48));
    *p++ = '-';
    unsigned int v = ++seq;
    char tmp[12]; int k = 0;
    while (v) { tmp[k++] = static_cast<char>('0' + (v % 10)); v /= 10; }
    while (k) *p++ = tmp[--k];
    const char post[] = ".log";
    for (unsigned i = 0; post[i]; ++i) *p++ = post[i];
    *p = 0;
    return a.CreateFileA(buf, GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

inline void trace_tag(Api& a, const char* tag) {
    HANDLE f = trace_open(a);
    if (f == INVALID_HANDLE_VALUE) return;
    unsigned int n = 0;
    while (tag[n] && n < 48) ++n;
    DWORD wrote = 0;
    a.WriteFile(f, tag, n, &wrote, nullptr);
    a.CloseHandle(f);
}

inline void trace_text(Api& a, const char* text, unsigned int n) {
    HANDLE f = trace_open(a);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    a.WriteFile(f, text, n, &wrote, nullptr);
    a.CloseHandle(f);
}

// tag=hexdeadbeef. Numeric steps file the value where a human can read it
// without a live pipe: a session that dies mid-call has no pipe left.
inline void trace_kv(Api& a, const char* tag, unsigned long long v) {
    HANDLE f = trace_open(a);
    if (f == INVALID_HANDLE_VALUE) return;
    char buf[64];
    char* p = buf;
    unsigned int n = 0;
    while (tag[n] && n < 24) { *p++ = tag[n]; ++n; }
    *p++ = '=';
    p = append_hex(p, v);
    DWORD wrote = 0;
    a.WriteFile(f, buf, static_cast<unsigned int>(p - buf), &wrote, nullptr);
    a.CloseHandle(f);
}

