/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Accelerated UDP for Windows (ADR-0006): the ksl_udp_* contract of ksl.h over Winsock. WSASendMsg / WSARecvMsg (from
 * SIO_GET_EXTENSION_FUNCTION_POINTER), ECN through the IP_ECN / IPV6_ECN socket option and per-message cmsg, DF through
 * IP_DONTFRAGMENT / IPV6_DONTFRAG (+ IP_MTU_DISCOVER = PROBE where the system has it), USO (UDP_SEND_MSG_SIZE) and URO
 * (UDP_RECV_MAX_COALESCED_SIZE) only where the system answers the probe. Readiness is WSAPoll over the socket and a wake socket
 * (a loopback UDP socket connected to itself): no pipes on Windows. IPv6 sockets are dual-stack; v4-mapped peers are reported and
 * addressed as family 4. A wildcard 0.0.0.0 opens the same dual-stack socket on :: (as ksl_udp.c and NIO), so a client bound to
 * 0.0.0.0:0 reaches IPv6 servers too; without IPv6 it falls back to AF_INET. DF is IP_DONTFRAGMENT / IPV6_DONTFRAG, as msquic
 * sets it; IP_MTU_DISCOVER = PROBE is added where the system takes it (some Windows 11 builds refuse the option, msquic never
 * sets it) and WSAEMSGSIZE on a send only loses that slot, so a cached path MTU never fails the socket. REUSEPORT is never granted: SO_REUSEADDR on Windows lets another socket take the port over, so the
 * socket is bound with SO_EXCLUSIVEADDRUSE instead. Options and their order cross-checked with msquic
 * src/platform/datapath_winuser.c. The whole file is Windows-only; the other platforms live in ksl_udp*.c. */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600   /* WSAPoll, WSASendMsg */
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include "ksl_internal.h"
#include <stdio.h>
#include <string.h>

/* Windows SDK values the older mingw-w64 headers lack (ws2ipdef.h, ws2tcpip.h, mstcpip.h) */
#ifndef IP_ECN
#define IP_ECN 50
#endif
#ifndef IPV6_ECN
#define IPV6_ECN 50
#endif
#ifndef IP_MTU_DISCOVER
#define IP_MTU_DISCOVER 71
#endif
#ifndef IPV6_MTU_DISCOVER
#define IPV6_MTU_DISCOVER 71
#endif
#ifndef IP_PMTUDISC_PROBE
#define IP_PMTUDISC_PROBE 3
#endif
#ifndef UDP_SEND_MSG_SIZE
#define UDP_SEND_MSG_SIZE 2
#endif
#ifndef UDP_RECV_MAX_COALESCED_SIZE
#define UDP_RECV_MAX_COALESCED_SIZE 3
#endif
#ifndef UDP_COALESCED_INFO
#define UDP_COALESCED_INFO 3
#endif
#ifndef SIO_UDP_NETRESET
#define SIO_UDP_NETRESET _WSAIOW(IOC_VENDOR, 15)
#endif
#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

#define GRO_MAX 65535
/* the most UDP payload one IP datagram carries, which a USO send must not exceed: IPv4 65535 - 20 - 8, IPv6 65535 - 8 */
#define GSO_JOIN_MAX(addr) ((addr)[0] == 4 ? 65507u : 65527u)
#define URO_MAX (GRO_MAX - 48)   /* coalesced payload never exceeds the scratch buffer (IPv6 + UDP headers off 64 KiB) */
#define GSO_SEGMENTS 64
#define WAKE_SLICE_MS 50         /* without a wake socket, a blocked receive notices a shutdown within one slice */

struct ksl_udp {
    SOCKET fd, wake; int family;
    struct sockaddr_in wake_sa;
    LPFN_WSARECVMSG recv_msg; LPFN_WSASENDMSG send_msg;
    uint32_t requested, granted; uint16_t gso_max; uint16_t batch;
    int gso_on, ecn_cmsg_on, df_probe, dual;   /* df_probe: IP_MTU_DISCOVER = PROBE taken; dual: AF_INET6 on :: for a 0.0.0.0 bind */
    int ce_refused;   /* Windows refused the CE codepoint in the IP_ECN / IPV6_ECN cmsg (WSAEINVAL): CE leaves unmarked, ECT stays on */
    uint32_t last_errno; char last_msg[KSL_MSG]; SRWLOCK err_mu;   /* err_mu guards the pair; initialised in ksl_udp_open */
    uint8_t local[KSL_UDP_ADDR_LEN];
    /* the receiver thread owns scratch (a URO train and its segments not yet handed out), the sender thread owns tx (a joined USO run) */
    uint8_t *scratch; uint8_t *tx; uint32_t pend_off, pend_len, pend_seg; uint8_t pend_addr[KSL_UDP_ADDR_LEN]; uint8_t pend_ecn;
    volatile int closed; volatile int in_recv;
    uint32_t sends, recvs, gso_fallbacks;
    volatile LONG64 emsgsize; volatile LONG emsgsize_last;   /* sends lost to WSAEMSGSIZE (ksl_udp_emsgsize) */
#ifdef KSL_TEST
    int fail_next_gso, fail_next_send, fail_next_recv, fake_pollerr; uint32_t polls;   /* error injection, test builds only */
#endif
};

static void be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
/* the sender and the receiver thread both record errors and ksl_udp_get reads them: err_mu keeps errno and text one error's (as in
   ksl_udp_internal.h; an SRWLOCK needs no destruction) */
static void err_lock(ksl_udp *u) { AcquireSRWLockExclusive(&u->err_mu); }
static void err_unlock(ksl_udp *u) { ReleaseSRWLockExclusive(&u->err_mu); }
static void set_err(ksl_udp *u, int e, const char *what) {
    char m[KSL_MSG]; snprintf(m, sizeof m, "%s: WSA error %d", what, e);
    err_lock(u); u->last_errno = (uint32_t)e; memcpy(u->last_msg, m, KSL_MSG); err_unlock(u);
}
static void fail(uint32_t *err, uint32_t code, char *msg, size_t msglen, const char *what, int wsa) { if (err) *err = code; if (msg && msglen) snprintf(msg, msglen, "%s: WSA error %d", what, wsa); }

/* WSAStartup once per process (reference counted by Winsock; never undone, like the OpenSSL init). Kotlin/Native code reaches
   getaddrinfo (ktor-network's InetSocketAddress.resolveAddress) before any socket exists, and ktor-network starts Winsock only
   when it creates a socket: every Winsock call before that failed with WSANOTINITIALISED (10093). The Kotlin/Native runtime
   starts it before any Kotlin code runs (an eager property in kuicksilver-native's mingwMain, `who` 1); ksl_init (2) and
   ksl_udp_open (3) start it too, for the JVM's dll and C callers. Never from a C constructor: in a DLL (a Kotlin/Native
   sharedLib, the JNI dll) constructors run under the loader lock, where WSAStartup must not be called.
   A host that calls WSACleanup once more than its own WSAStartup takes our reference away: ksl_udp_open then sees
   WSANOTINITIALISED, starts Winsock once more and retries (wsa_restart). */
static volatile LONG wsa_state = 0;   /* 0 not started, 1 starting, 2 ready, 3 failed */
static volatile LONG wsa_first = 0;   /* who started it first */
int ksl_win_sockets_start(int who) {
    LONG s = InterlockedCompareExchange(&wsa_state, 1, 0);
    if (s == 0) { WSADATA d; LONG r = WSAStartup(MAKEWORD(2, 2), &d) == 0 ? 2 : 3; if (r == 2) InterlockedCompareExchange(&wsa_first, (LONG)who, 0); InterlockedExchange(&wsa_state, r); return r == 2; }
    while ((s = InterlockedCompareExchange(&wsa_state, 1, 1)) == 1) Sleep(0);
    return s == 2;
}
int ksl_win_sockets_started_by(void) { return (int)InterlockedCompareExchange(&wsa_first, 0, 0); }
int ksl_win_sockets_init(void) { return ksl_win_sockets_start(2); }   /* ksl_init */
/* our reference was cleaned up by the host: forget the once-state and start again (other threads wait in ksl_win_sockets_start) */
static int wsa_restart(void) { InterlockedCompareExchange(&wsa_state, 0, 2); return ksl_win_sockets_start(3); }
static int wsa_ready(void) { return ksl_win_sockets_start(3); }

static int is_wildcard(const uint8_t *a) { for (int i = 3; i < (a[0] == 4 ? 7 : 19); i++) if (a[i]) return 0; return 1; }
#ifdef KSL_TEST
static int no_ipv6_for_test;   /* simulates a host without IPv6: WSASocketW(AF_INET6) fails */
void ksl_udp_no_ipv6_for_test(int on) { no_ipv6_for_test = on; }
#endif
static int is_mapped(const uint8_t *a16) { static const uint8_t pre[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }; return memcmp(a16, pre, 12) == 0; }
/* the 20-byte address as this socket's sockaddr: family 4 on an IPv6 (dual-stack) socket becomes v4-mapped; -1 when the socket cannot reach that family */
static int to_sockaddr(const ksl_udp *u, const uint8_t a[KSL_UDP_ADDR_LEN], struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof *ss);
    if (u->family == AF_INET) {
        if (a[0] != 4) return -1;
        struct sockaddr_in *in = (struct sockaddr_in *)ss; in->sin_family = AF_INET; memcpy(&in->sin_port, a + 1, 2); memcpy(&in->sin_addr, a + 3, 4); return (int)sizeof *in;
    }
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss; in6->sin6_family = AF_INET6; memcpy(&in6->sin6_port, a + 1, 2);
    if (a[0] == 4) { uint8_t *p = (uint8_t *)&in6->sin6_addr; p[10] = 0xff; p[11] = 0xff; memcpy(p + 12, a + 3, 4); } else memcpy(&in6->sin6_addr, a + 3, 16);
    return (int)sizeof *in6;
}
static void from_sockaddr(const struct sockaddr_storage *ss, uint8_t a[KSL_UDP_ADDR_LEN]) {
    memset(a, 0, KSL_UDP_ADDR_LEN);
    if (ss->ss_family == AF_INET) { const struct sockaddr_in *in = (const struct sockaddr_in *)ss; a[0] = 4; memcpy(a + 1, &in->sin_port, 2); memcpy(a + 3, &in->sin_addr, 4); return; }
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss; const uint8_t *p = (const uint8_t *)&in6->sin6_addr;
    if (is_mapped(p)) { a[0] = 4; memcpy(a + 1, &in6->sin6_port, 2); memcpy(a + 3, p + 12, 4); return; }
    a[0] = 6; memcpy(a + 1, &in6->sin6_port, 2); memcpy(a + 3, p, 16);
}

/* a UDP socket on 127.0.0.1 connected to itself: shutdown sends it one byte, WSAPoll sees it; connected, it takes datagrams
   from itself only, and bound with SO_EXCLUSIVEADDRUSE, so no other local process can fake a wake-up */
static SOCKET open_wake(struct sockaddr_in *sa) {
    SOCKET w = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT); if (w == INVALID_SOCKET) return w;
    memset(sa, 0, sizeof *sa); sa->sin_family = AF_INET; sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK); int sl = (int)sizeof *sa; u_long nb = 1; BOOL yes = TRUE;
    /* exclusive, as the data socket: a local process binding the port with SO_REUSEADDR could otherwise share it */
    if (setsockopt(w, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&yes, sizeof yes) != 0 || bind(w, (struct sockaddr *)sa, sl) != 0 || getsockname(w, (struct sockaddr *)sa, &sl) != 0 || connect(w, (struct sockaddr *)sa, sl) != 0 || ioctlsocket(w, FIONBIO, &nb) != 0) { closesocket(w); return INVALID_SOCKET; }
    return w;
}

/* socket, the options bind needs first, bind: INVALID_SOCKET with the WSA error and the failed step. dual: AF_INET6 on :: with
   IPV6_V6ONLY off for a 0.0.0.0 request */
static SOCKET open_bound(ksl_udp *u, const uint8_t addr[KSL_UDP_ADDR_LEN], int dual, int *wsa, const char **step) {
    u->family = dual || addr[0] == 6 ? AF_INET6 : AF_INET; u->dual = dual; *step = "WSASocketW";
#ifdef KSL_TEST
    if (u->family == AF_INET6 && no_ipv6_for_test) { *wsa = WSAEAFNOSUPPORT; return INVALID_SOCKET; }
#endif
    /* overlapped, as socket() makes it: a synchronous socket handle serialises its operations, so a send waited for the receiving
       thread's WSAPoll to return (up to a whole receive slice per send) */
    SOCKET fd = WSASocketW(u->family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (fd == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED && wsa_restart()) fd = WSASocketW(u->family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);   /* once */
    if (fd == INVALID_SOCKET) { *wsa = WSAGetLastError(); return fd; }
    GUID rg = WSAID_WSARECVMSG, sg = WSAID_WSASENDMSG; DWORD got = 0;
    if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &rg, sizeof rg, &u->recv_msg, sizeof u->recv_msg, &got, NULL, NULL) != 0 ||
        WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &sg, sizeof sg, &u->send_msg, sizeof u->send_msg, &got, NULL, NULL) != 0 || !u->recv_msg || !u->send_msg) {
        *wsa = WSAGetLastError(); *step = "WSARecvMsg/WSASendMsg"; closesocket(fd); return INVALID_SOCKET;
    }
    BOOL yes = TRUE, no = FALSE;
    setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&yes, sizeof yes);   /* nobody binds over this port (msquic does the same) */
    if (u->family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&no, sizeof no) != 0 && dual) { *wsa = WSAGetLastError(); *step = "IPV6_V6ONLY"; closesocket(fd); return INVALID_SOCKET; }
    uint8_t any6[KSL_UDP_ADDR_LEN] = { 6 }; any6[1] = addr[1]; any6[2] = addr[2];   /* :: on the requested port (0.0.0.0:P binds P) */
    struct sockaddr_storage ss; int sl = to_sockaddr(u, dual ? any6 : addr, &ss);
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0) { *wsa = WSAGetLastError(); *step = "bind"; closesocket(fd); return INVALID_SOCKET; }
    return fd;
}

ksl_udp *ksl_udp_open(const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, uint32_t *err, char *msg, size_t msglen) {
    if (!addr || (addr[0] != 4 && addr[0] != 6)) { if (err) *err = KSL_E_BAD_ARG; if (msg && msglen) snprintf(msg, msglen, "ksl_udp: bad address"); return NULL; }
    if (!wsa_ready()) { fail(err, KSL_E_NOT_SUPPORTED, msg, msglen, "WSAStartup", 0); return NULL; }
    ksl_udp *u = calloc(1, sizeof *u); if (!u) { if (err) *err = KSL_E_BAD_ARG; return NULL; }
    InitializeSRWLock(&u->err_mu);
    u->requested = (uint32_t)flags; u->wake = INVALID_SOCKET;
    /* 0.0.0.0 takes both families on one dual-stack socket on :: (ksl_udp.c does the same on Linux and Apple); without IPv6, or
       with :: refused, the requested family alone */
    int dual = addr[0] == 4 && is_wildcard(addr), wsa = 0; const char *step = "WSASocketW";
    u->fd = open_bound(u, addr, dual, &wsa, &step);
    if (u->fd == INVALID_SOCKET && dual) u->fd = open_bound(u, addr, 0, &wsa, &step);
    if (u->fd == INVALID_SOCKET) { fail(err, step[0] == 'b' ? KSL_E_BAD_ARG : KSL_E_NOT_SUPPORTED, msg, msglen, step, wsa); free(u); return NULL; }
    BOOL yes = TRUE, no = FALSE;
    u_long nb = 1; ioctlsocket(u->fd, FIONBIO, &nb);
    DWORD ret = 0; WSAIoctl(u->fd, SIO_UDP_CONNRESET, &no, sizeof no, NULL, 0, &ret, NULL, NULL);   /* an ICMP unreachable must not fail the next receive */
    WSAIoctl(u->fd, SIO_UDP_NETRESET, &no, sizeof no, NULL, 0, &ret, NULL, NULL);
    int buf = 7 * 1024 * 1024; setsockopt(u->fd, SOL_SOCKET, SO_RCVBUF, (const char *)&buf, sizeof buf); setsockopt(u->fd, SOL_SOCKET, SO_SNDBUF, (const char *)&buf, sizeof buf);
    if (flags & KSL_UDP_ECN) {   /* granted only where Windows accepts the option (verified on Windows 11): marks read through the option, written per message as the IP_ECN / IPV6_ECN cmsg */
        int ok = u->family == AF_INET ? setsockopt(u->fd, IPPROTO_IP, IP_ECN, (const char *)&yes, sizeof yes) : setsockopt(u->fd, IPPROTO_IPV6, IPV6_ECN, (const char *)&yes, sizeof yes);
        if (u->family == AF_INET6 && ok == 0) setsockopt(u->fd, IPPROTO_IP, IP_ECN, (const char *)&yes, sizeof yes);   /* the v4-mapped half of a dual-stack socket */
        if (ok == 0) { u->granted |= KSL_UDP_ECN; u->ecn_cmsg_on = 1; }
    }
    if (flags & KSL_UDP_DF) {   /* DF on, and where the system has it PROBE: no path MTU cache drives the sizes (quic-go CVE-2024-53259) */
        int probe = IP_PMTUDISC_PROBE, ok;
        if (u->family == AF_INET) { ok = setsockopt(u->fd, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&yes, sizeof yes); u->df_probe = setsockopt(u->fd, IPPROTO_IP, IP_MTU_DISCOVER, (const char *)&probe, sizeof probe) == 0; }
        else { ok = setsockopt(u->fd, IPPROTO_IPV6, IPV6_DONTFRAG, (const char *)&yes, sizeof yes); setsockopt(u->fd, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&yes, sizeof yes);
               setsockopt(u->fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (const char *)&probe, sizeof probe); u->df_probe = setsockopt(u->fd, IPPROTO_IP, IP_MTU_DISCOVER, (const char *)&probe, sizeof probe) == 0; }
        if (ok == 0) u->granted |= KSL_UDP_DF;   /* DF alone where PROBE is refused: what msquic runs with */
    }
    if (flags & KSL_UDP_GSO) { DWORD v = 0; int l = (int)sizeof v; if (getsockopt(u->fd, IPPROTO_UDP, UDP_SEND_MSG_SIZE, (char *)&v, &l) == 0) { u->granted |= KSL_UDP_GSO; u->gso_on = 1; u->gso_max = GSO_SEGMENTS; } }
    if (flags & KSL_UDP_GRO) { DWORD v = URO_MAX; if (setsockopt(u->fd, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, (const char *)&v, sizeof v) == 0) u->granted |= KSL_UDP_GRO; }
    u->batch = 16;
    u->wake = open_wake(&u->wake_sa);   /* INVALID_SOCKET: the receive waits in slices instead */
    u->scratch = malloc(GRO_MAX); u->tx = malloc(GRO_MAX);
    if (!u->scratch || !u->tx) { if (err) *err = KSL_E_BAD_ARG; free(u->scratch); free(u->tx); closesocket(u->fd); if (u->wake != INVALID_SOCKET) closesocket(u->wake); free(u); return NULL; }
    struct sockaddr_storage ss; int sl = (int)sizeof ss;
    if (getsockname(u->fd, (struct sockaddr *)&ss, &sl) == 0) {
        if (u->dual) { const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&ss; u->local[0] = 4; memcpy(u->local + 1, &in6->sin6_port, 2); }   /* 0.0.0.0 asked: 0.0.0.0 reported, the port Windows chose */
        else if (u->family == AF_INET) from_sockaddr(&ss, u->local);
        else { const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&ss; u->local[0] = 6; memcpy(u->local + 1, &in6->sin6_port, 2); memcpy(u->local + 3, &in6->sin6_addr, 16); }   /* the socket's own family, never unmapped */
    }
    ksl_live_add(KSL_LIVE_UDP, 1); ksl_live_add(KSL_LIVE_WAKE, u->wake != INVALID_SOCKET);
    return u;
}

int ksl_udp_get(ksl_udp *u, int what, uint8_t *out, size_t cap, size_t *len) {
    if (!u || !out || !len) return KSL_ERROR;
    switch (what) {
    case KSL_UDP_GET_FD: if (cap < 4) return KSL_ERROR; be32(out, (uint32_t)u->fd); *len = 4; return KSL_OK;   /* SOCKET handles fit 32 bits (documented for 32/64-bit interop) */
    case KSL_UDP_GET_CAPS: if (cap < 8) return KSL_ERROR; be32(out, u->granted); be16(out + 4, u->gso_on ? u->gso_max : 0); be16(out + 6, u->batch); *len = 8; return KSL_OK;
    case KSL_UDP_GET_LOCAL: if (cap < KSL_UDP_ADDR_LEN) return KSL_ERROR; memcpy(out, u->local, KSL_UDP_ADDR_LEN); *len = KSL_UDP_ADDR_LEN; return KSL_OK;
    case KSL_UDP_GET_STATS: if (cap < 12) return KSL_ERROR; be32(out, u->sends); be32(out + 4, u->recvs); be32(out + 8, u->gso_fallbacks); *len = 12; return KSL_OK;
    case KSL_UDP_GET_ERROR: { if (cap < 4) return KSL_ERROR; char msg[KSL_MSG]; err_lock(u); uint32_t e = u->last_errno; memcpy(msg, u->last_msg, KSL_MSG); err_unlock(u);
        msg[KSL_MSG - 1] = 0; be32(out, e); size_t m = strlen(msg); if (m > cap - 4) m = cap - 4; memcpy(out + 4, msg, m); *len = 4 + m; return KSL_OK; }
    default: return KSL_ERROR;
    }
}

/* ---- sending ---- */
static int send_one(ksl_udp *u, const uint8_t *buf, uint32_t len, const uint8_t *addr, uint8_t ecn, uint32_t seg, int *e) {
    struct sockaddr_storage ss; int sl = to_sockaddr(u, addr, &ss); if (sl < 0) { *e = WSAEAFNOSUPPORT; return -1; }
    WSABUF wb; wb.len = len; wb.buf = (CHAR *)buf;
    union { WSACMSGHDR align; char b[WSA_CMSG_SPACE(sizeof(INT)) + WSA_CMSG_SPACE(sizeof(DWORD))]; } cb; memset(&cb, 0, sizeof cb);   /* zeroed: NXTHDR reads the next header's length */
    WSAMSG m; memset(&m, 0, sizeof m); m.name = (LPSOCKADDR)&ss; m.namelen = sl; m.lpBuffers = &wb; m.dwBufferCount = 1; m.Control.buf = cb.b; m.Control.len = sizeof cb.b;
    WSACMSGHDR *c = WSA_CMSG_FIRSTHDR(&m); ULONG used = 0;
    if (ecn && u->ecn_cmsg_on && !(ecn == 3 && u->ce_refused) && c) {   /* the level follows the destination: a v4-mapped peer of a dual-stack socket takes IP_ECN (as msquic) */
        INT v = ecn & 3; c->cmsg_level = addr[0] == 4 ? IPPROTO_IP : IPPROTO_IPV6; c->cmsg_type = addr[0] == 4 ? IP_ECN : IPV6_ECN; c->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
        memcpy(WSA_CMSG_DATA(c), &v, sizeof v); used += WSA_CMSG_SPACE(sizeof(INT)); c = WSA_CMSG_NXTHDR(&m, c);
    }
    if (seg && c) { DWORD s = seg; c->cmsg_level = IPPROTO_UDP; c->cmsg_type = UDP_SEND_MSG_SIZE; c->cmsg_len = WSA_CMSG_LEN(sizeof(DWORD)); memcpy(WSA_CMSG_DATA(c), &s, sizeof s); used += WSA_CMSG_SPACE(sizeof(DWORD)); }
    m.Control.len = used; if (!used) m.Control.buf = NULL;   /* Winsock refuses a non-NULL control buffer of length 0 */
    u->sends++;
#ifdef KSL_TEST
    if (u->fail_next_gso && seg) { *e = u->fail_next_gso; u->fail_next_gso = 0; return -1; }
    if (u->fail_next_send && !seg) { *e = u->fail_next_send; u->fail_next_send = 0; return -1; }
#endif
    DWORD n = 0; if (u->send_msg(u->fd, &m, 0, &n, NULL, NULL) == SOCKET_ERROR) { *e = WSAGetLastError(); return -1; } return 0;
}
static void gso_off(ksl_udp *u) { u->gso_on = 0; u->granted &= ~(uint32_t)KSL_UDP_GSO; u->gso_fallbacks++; }
/* the destination's fault (port 0, link-local IPv6 without a scope id, a family the socket cannot reach): that datagram cannot leave */
static int dest_error(int e) { return e == WSAEINVAL || e == WSAEAFNOSUPPORT || e == WSAEADDRNOTAVAIL || e == WSAEDESTADDRREQ; }
/* this datagram is lost on the wire: the socket lives, loss detection repairs it */
static int slot_lost(int e) { return dest_error(e) || e == WSAEMSGSIZE || e == WSAEACCES || e == WSAENETUNREACH || e == WSAEHOSTUNREACH || e == WSAENOBUFS || e == WSAECONNRESET || e == WSAENETRESET || e == WSAECONNREFUSED || e == WSAENETDOWN; }

int ksl_udp_send(ksl_udp *u, uint8_t *const *bufs, const uint32_t *lens, const uint8_t *addrs, const uint8_t *ecn, uint32_t n, uint32_t *sent) {
    if (!u || u->closed) { if (sent) *sent = 0; return KSL_ERROR; } *sent = 0; uint32_t i = 0;
    int gso_probe = 0;   /* a USO send failed with WSAEINVAL: the first datagram of that run, sent alone, tells USO's fault from the destination's */
    uint32_t solo = 0;   /* datagrams of a refused USO run still to send one by one; USO itself stays on */
    while (i < n) {
        /* the same run rule as Linux: two equal lengths start it, the last segment may be shorter, one address, one mark */
        uint32_t run = 1;
        if (u->gso_on && !gso_probe && !solo && i + 1 < n && lens[i + 1] == lens[i]) while (i + run < n && run < u->gso_max && lens[i + run] <= lens[i] && !memcmp(addrs + (i + run) * KSL_UDP_ADDR_LEN, addrs + i * KSL_UDP_ADDR_LEN, KSL_UDP_ADDR_LEN) && ecn[i + run] == ecn[i]) { run++; if (lens[i + run - 1] < lens[i]) break; }
        if (run > 1 && lens[i] > 0) {
            size_t total = 0, cap = GSO_JOIN_MAX(addrs + i * KSL_UDP_ADDR_LEN); for (uint32_t k = 0; k < run; k++) { if (total + lens[i + k] > cap) { run = k; break; } memcpy(u->tx + total, bufs[i + k], lens[i + k]); total += lens[i + k]; }
            int e = 0;
            if (run > 1 && send_one(u, u->tx, (uint32_t)total, addrs + i * KSL_UDP_ADDR_LEN, ecn[i], lens[i], &e) == 0) { i += run; *sent += run; continue; }
            if (run > 1) {
                if (e == WSAEWOULDBLOCK) return KSL_OK;
                if ((e == WSAEINVAL || e == WSAEMSGSIZE) && lens[i] > 1200) solo = run;   /* the segment size, not USO, was refused: this run one by one, USO stays */
                else if (e == WSAEINVAL) gso_probe = 1;   /* the USO cmsg or the destination: the first datagram alone decides */
                else if (e == WSAEOPNOTSUPP || e == WSAENOPROTOOPT || e == WSAEPROTONOSUPPORT) gso_off(u);   /* USO itself refused */
                else solo = run;   /* transient (WSAENOBUFS, unreachable, WSAEACCES, a small WSAEMSGSIZE, ...): this run one by one, USO stays for the next */
            }
        }
        if (solo) solo--;
        int e = 0;
        if (send_one(u, bufs[i], lens[i], addrs + i * KSL_UDP_ADDR_LEN, ecn[i], 0, &e) == 0) { if (gso_probe) gso_off(u); gso_probe = 0; i++; (*sent)++; continue; }
        if (e == WSAEWOULDBLOCK) return KSL_OK;
        if (e == WSAEINVAL && u->ecn_cmsg_on && ecn[i] && !(ecn[i] == 3 && u->ce_refused)) {   /* the ECN cmsg or the destination: the same datagram without the mark decides */
            if (send_one(u, bufs[i], lens[i], addrs + i * KSL_UDP_ADDR_LEN, 0, 0, &e) == 0) {
                /* Windows 11 refuses CE in the cmsg (a sender never sets it, RFC 9000 section 13.4.1; msquic and quic-go never send it): only
                   CE goes unmarked from now on. Before, this refusal turned ECN off for the whole socket, so every later ECT(0) left Not-ECT */
                if (ecn[i] == 3) u->ce_refused = 1; else { u->ecn_cmsg_on = 0; u->granted &= ~(uint32_t)KSL_UDP_ECN; }
                gso_probe = 0; i++; (*sent)++; continue;
            }
            if (e == WSAEWOULDBLOCK) return KSL_OK;
        }
        gso_probe = 0;
        if (e == WSAEMSGSIZE) { InterlockedIncrement64(&u->emsgsize); InterlockedExchange(&u->emsgsize_last, (LONG)lens[i]); }   /* a DPLPMTUD hint */
        if (slot_lost(e)) { i++; (*sent)++; continue; }
        set_err(u, e, "WSASendMsg"); return KSL_ERROR;
    }
    return KSL_OK;
}

/* ---- receiving ---- */
static uint32_t hand_out(ksl_udp *u, uint8_t *const *bufs, const uint32_t *caps, uint32_t *lens, uint8_t *addrs, uint8_t *ecnv, uint32_t n, uint32_t filled) {
    while (u->pend_len && filled < n) {
        uint32_t seg = u->pend_seg ? u->pend_seg : u->pend_len; if (seg > u->pend_len) seg = u->pend_len;
        if (seg <= caps[filled]) { memcpy(bufs[filled], u->scratch + u->pend_off, seg); lens[filled] = seg; memcpy(addrs + filled * KSL_UDP_ADDR_LEN, u->pend_addr, KSL_UDP_ADDR_LEN); ecnv[filled] = u->pend_ecn; filled++; }
        u->pend_off += seg; u->pend_len -= seg;
    }
    return filled;
}
/* one received datagram (or URO train) of r bytes in scratch: the segment size from UDP_COALESCED_INFO, the ECN mark, the source;
   0 when it carries nothing for QUIC (empty, or link-local: no scope id in the address, no reply could reach it) */
static int take_datagram(ksl_udp *u, WSAMSG *m, uint32_t r, const struct sockaddr_storage *ss) {
    uint32_t seg = 0; uint8_t mark = 0;
    for (WSACMSGHDR *c = WSA_CMSG_FIRSTHDR(m); c; c = WSA_CMSG_NXTHDR(m, c)) {
        if (c->cmsg_level == IPPROTO_UDP && c->cmsg_type == UDP_COALESCED_INFO) { DWORD g; memcpy(&g, WSA_CMSG_DATA(c), sizeof g); if (g > 0) seg = (uint32_t)g; }
        else if ((c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_ECN) || (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_ECN)) { INT v = 0; memcpy(&v, WSA_CMSG_DATA(c), sizeof v); mark = (uint8_t)(v & 3); }
    }
    if (r == 0) return 0;
    if (ss->ss_family == AF_INET6) { const uint8_t *p = (const uint8_t *)&((const struct sockaddr_in6 *)ss)->sin6_addr; if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80) return 0; }
    u->pend_off = 0; u->pend_len = r; u->pend_seg = seg; from_sockaddr(ss, u->pend_addr); u->pend_ecn = mark;
    return 1;
}
/* waits out the rest of this slice on the wake socket alone: an error condition that answers every poll must not spin */
static void idle_slice(ksl_udp *u, int timeout_ms, ULONGLONG deadline) {
    int w = WAKE_SLICE_MS;
    if (timeout_ms >= 0) { ULONGLONG now = GetTickCount64(); w = now >= deadline ? 0 : (deadline - now < (ULONGLONG)WAKE_SLICE_MS ? (int)(deadline - now) : WAKE_SLICE_MS); }
    if (w <= 0) return;
    if (u->wake != INVALID_SOCKET) { WSAPOLLFD p; memset(&p, 0, sizeof p); p.fd = u->wake; p.events = POLLRDNORM; WSAPoll(&p, 1, w); } else Sleep((DWORD)w);
}
/* datagrams taken in a row without filling a slot (empty, link-local source, truncated, larger than the slot) between two looks
   at the clock */
#define DROP_CHECK 64
/* the network is down or out of buffers right now: nothing arrives this slice, the socket itself is fine */
static int recv_transient(int e) { return e == WSAENETDOWN || e == WSAENOBUFS; }
int ksl_udp_recv(ksl_udp *u, uint8_t *const *bufs, const uint32_t *caps, uint32_t *lens, uint8_t *addrs, uint8_t *ecnv, uint32_t n, uint32_t *received, int timeout_ms) {
    if (!u || u->closed) { if (received) *received = 0; return KSL_ERROR; } *received = 0; if (!n) return KSL_OK;
    __atomic_add_fetch(&u->in_recv, 1, __ATOMIC_SEQ_CST);
    uint32_t filled = hand_out(u, bufs, caps, lens, addrs, ecnv, n, 0);
    int rc = KSL_OK; ULONGLONG deadline = timeout_ms < 0 ? 0 : GetTickCount64() + (ULONGLONG)timeout_ms; uint32_t dropped = 0;
    while (filled < n) {
        if (u->closed) { rc = filled ? KSL_OK : KSL_ERROR; break; }
        /* a run of datagrams that all get dropped (from a sender faster than the drain, so the poll never times out) still ends at
           the deadline; a call that may not wait (timeout 0) or already holds datagrams stops after DROP_CHECK of them. Checked
           before the receive: a datagram once taken is always looked at (as in ksl_udp_recv.c) */
        if (dropped >= DROP_CHECK && timeout_ms >= 0) {
            if (filled || timeout_ms == 0 || GetTickCount64() >= deadline) { if (!filled) rc = KSL_WANT_READ; break; }
            dropped = 0;
        }
        int wait;
        if (filled) wait = 0;
        else if (timeout_ms < 0) wait = -1;
        else { ULONGLONG now = GetTickCount64(); wait = now >= deadline ? 0 : (int)(deadline - now); }
        int nf = u->wake != INVALID_SOCKET ? 2 : 1;
        if (nf == 1 && (wait < 0 || wait > WAKE_SLICE_MS)) wait = WAKE_SLICE_MS;
        WSAPOLLFD pf[2]; memset(pf, 0, sizeof pf); pf[0].fd = u->fd; pf[0].events = POLLRDNORM; pf[1].fd = u->wake; pf[1].events = POLLRDNORM;
        int pr;
#ifdef KSL_TEST
        u->polls++;
        if (u->fake_pollerr) { pr = 1; pf[0].revents = POLLERR; } else
#endif
        pr = WSAPoll(pf, (ULONG)nf, wait);
        if (pr == 0) {
            if (filled) break;
            if (timeout_ms >= 0 && GetTickCount64() >= deadline) { rc = KSL_WANT_READ; break; }
            continue;   /* a slice without a wake socket */
        }
        if (pr < 0) { int e = WSAGetLastError(); if (e == WSAEINTR) continue; set_err(u, e, "WSAPoll"); rc = filled ? KSL_OK : KSL_ERROR; break; }
        if (nf == 2 && pf[1].revents) {
            if (u->closed) { rc = filled ? KSL_OK : KSL_ERROR; break; }   /* shut down from another thread */
            char d[8]; recv(u->wake, d, sizeof d, 0); continue;   /* not ours to act on: drained */
        }
        if (pf[0].revents & POLLNVAL) { set_err(u, WSAENOTSOCK, "WSAPoll"); rc = filled ? KSL_OK : KSL_ERROR; break; }
        if ((pf[0].revents & (POLLERR | POLLHUP)) && !(pf[0].revents & POLLRDNORM)) {
            /* a pending socket error (an ICMP report): reading SO_ERROR clears it; when nothing was pending, the slice idles instead of spinning */
            int soe = 0, sl = (int)sizeof soe; if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, (char *)&soe, &sl) != 0) soe = 0;
            if (soe == 0) { if (filled) break; idle_slice(u, timeout_ms, deadline); if (timeout_ms >= 0 && GetTickCount64() >= deadline) { rc = KSL_WANT_READ; break; } }
            continue;
        }
        struct sockaddr_storage ss; WSABUF wb; wb.len = GRO_MAX; wb.buf = (CHAR *)u->scratch;
        union { WSACMSGHDR align; char b[256]; } cb;
        WSAMSG m; memset(&m, 0, sizeof m); m.name = (LPSOCKADDR)&ss; m.namelen = sizeof ss; m.lpBuffers = &wb; m.dwBufferCount = 1; m.Control.buf = cb.b; m.Control.len = sizeof cb.b;
        DWORD r = 0; u->recvs++; int got_err = 0;
#ifdef KSL_TEST
        if (u->fail_next_recv) { got_err = u->fail_next_recv; u->fail_next_recv = 0; } else
#endif
        if (u->recv_msg(u->fd, &m, &r, NULL, NULL) == SOCKET_ERROR) got_err = WSAGetLastError();
        if (got_err) {
            int e = got_err;
            if (e == WSAEMSGSIZE) { dropped++; continue; }   /* truncated, dropped whole */
            if (e == WSAEWOULDBLOCK || e == WSAEINTR || e == WSAECONNRESET || e == WSAENETRESET) continue;
            if (u->closed) { rc = filled ? KSL_OK : KSL_ERROR; break; }
            if (recv_transient(e)) { if (filled) break; idle_slice(u, timeout_ms, deadline); rc = KSL_WANT_READ; break; }   /* nothing received this slice */
            set_err(u, e, "WSARecvMsg"); rc = filled ? KSL_OK : KSL_ERROR; break;
        }
        if (m.dwFlags & MSG_TRUNC) { dropped++; continue; }
        if (!take_datagram(u, &m, (uint32_t)r, &ss)) { dropped++; continue; }   /* empty, or from a link-local source */
        uint32_t before = filled; filled = hand_out(u, bufs, caps, lens, addrs, ecnv, n, filled);
        if (filled > before) dropped = 0; else dropped++;   /* a datagram whose every segment was larger than its slot: one drop */
    }
    *received = filled;
    __atomic_sub_fetch(&u->in_recv, 1, __ATOMIC_SEQ_CST);
    return rc;
}

/* ---- shutdown and close ---- */
void ksl_udp_shutdown(ksl_udp *u) {
    if (!u || u->closed) return;
    u->closed = 1;
    if (u->wake != INVALID_SOCKET) { char b = 1; send(u->wake, &b, 1, 0); }
    if (u->fd != INVALID_SOCKET) shutdown(u->fd, SD_BOTH);
}
void ksl_udp_close(ksl_udp *u) {
    if (!u) return;
    ksl_udp_shutdown(u);
    for (int i = 0; i < 1000 && __atomic_load_n(&u->in_recv, __ATOMIC_SEQ_CST) > 0; i++) Sleep(1);   /* a receiver woke up and leaves the object */
    ksl_live_add(KSL_LIVE_UDP, -1); ksl_live_add(KSL_LIVE_WAKE, -(u->wake != INVALID_SOCKET));
    if (u->fd != INVALID_SOCKET) closesocket(u->fd); if (u->wake != INVALID_SOCKET) closesocket(u->wake);
    free(u->scratch); free(u->tx); memset(u, 0, sizeof *u); free(u);
}

/* Windows reports ICMP through IP_RECVERR as ICMP_ERROR_INFO without the MTU or a quote of our datagram: nothing a caller could
   validate (RFC 9000 section 14.2.1), so no Packet Too Big here; WSAEMSGSIZE on a send is the only hint */
int ksl_udp_take_ptb(ksl_udp *u, uint8_t *quote, uint32_t cap, uint32_t *quote_len, uint8_t dst[KSL_UDP_ADDR_LEN], uint32_t *mtu) { (void)u; (void)quote; (void)cap; (void)quote_len; (void)dst; (void)mtu; return 0; }
uint64_t ksl_udp_emsgsize(ksl_udp *u, uint32_t *last_size) {
    if (!u) return 0;
    if (last_size) *last_size = (uint32_t)InterlockedCompareExchange(&u->emsgsize_last, 0, 0);
    return (uint64_t)InterlockedCompareExchange64(&u->emsgsize, 0, 0);
}

#ifdef KSL_TEST
void ksl_udp_push_ptb_for_test(ksl_udp *u, const uint8_t *quote, uint32_t len, const uint8_t dst[KSL_UDP_ADDR_LEN], uint32_t mtu) { (void)u; (void)quote; (void)len; (void)dst; (void)mtu; }
uint32_t ksl_udp_ptb_dropped_for_test(ksl_udp *u) { (void)u; return 0; }
uint32_t ksl_udp_errqueue_reads_for_test(ksl_udp *u) { (void)u; return 0; }
int ksl_udp_recverr_for_test(ksl_udp *u) { (void)u; return 0; }
uint32_t ksl_udp_syscalls_for_test(ksl_udp *u) { return u->sends; }
void ksl_udp_fail_next_gso_for_test(ksl_udp *u, int err) { u->fail_next_gso = err; }
void ksl_udp_fail_next_send_for_test(ksl_udp *u, int err) { u->fail_next_send = err; }
void ksl_udp_set_err_for_test(ksl_udp *u, int e, const char *what) { set_err(u, e, what); }
/* IP_MTU_DISCOVER of the socket's IPv4 half (3 = PROBE); -1 where the system refuses the option */
int ksl_udp_df_mode_for_test(int fd) { DWORD v = 0; int l = (int)sizeof v; if (getsockopt((SOCKET)(UINT_PTR)(uint32_t)fd, IPPROTO_IP, IP_MTU_DISCOVER, (char *)&v, &l) != 0) return -1; return (int)v; }
/* IP_DONTFRAGMENT of the socket's IPv4 half: 1 when set, 0 when clear, -1 when it cannot be read */
int ksl_udp_df_bit_for_test(int fd) { DWORD v = 0; int l = (int)sizeof v; if (getsockopt((SOCKET)(UINT_PTR)(uint32_t)fd, IPPROTO_IP, IP_DONTFRAGMENT, (char *)&v, &l) != 0) return -1; return v ? 1 : 0; }
int ksl_udp_df_probe_for_test(ksl_udp *u) { return u->df_probe; }
static DWORD WINAPI blocked_recv(LPVOID arg) { ksl_udp *u = arg; uint8_t buf[64]; uint8_t *bufs[1] = { buf }; uint32_t caps[1] = { 64 }, lens[1], got; uint8_t a[KSL_UDP_ADDR_LEN], e[1]; ksl_udp_recv(u, bufs, caps, lens, a, e, 1, &got, 5000); return 0; }
int ksl_udp_has_wake_for_test(ksl_udp *u) { return u->wake != INVALID_SOCKET; }
void ksl_udp_fail_next_recv_for_test(ksl_udp *u, int err) { u->fail_next_recv = err; }
void ksl_udp_fake_pollerr_for_test(ksl_udp *u, int on) { u->fake_pollerr = on; }
uint32_t ksl_udp_polls_for_test(ksl_udp *u) { return u->polls; }
/* the URO splitter alone: `len` bytes of `train` as if WSARecvMsg had returned them from 127.0.0.1:port with UDP_COALESCED_INFO = seg
   (0: no cmsg) and IP_ECN = mark, handed out into n slots; leftovers stay pending for the next call (seg_len = 0, len = 0) */
uint32_t ksl_udp_split_for_test(ksl_udp *u, const uint8_t *train, uint32_t len, uint32_t seg, uint8_t mark, uint16_t port,
                                uint8_t *const *bufs, const uint32_t *caps, uint32_t *lens, uint8_t *addrs, uint8_t *ecnv, uint32_t n) {
    if (len) {
        if (len > GRO_MAX) return 0;
        memcpy(u->scratch, train, len);
        struct sockaddr_storage ss; memset(&ss, 0, sizeof ss); struct sockaddr_in *in = (struct sockaddr_in *)&ss; in->sin_family = AF_INET; in->sin_port = htons(port); in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        union { WSACMSGHDR align; char b[WSA_CMSG_SPACE(sizeof(DWORD)) + WSA_CMSG_SPACE(sizeof(INT))]; } cb; memset(&cb, 0, sizeof cb);
        WSAMSG m; memset(&m, 0, sizeof m); m.Control.buf = cb.b; m.Control.len = sizeof cb.b; ULONG used = 0;
        WSACMSGHDR *c = WSA_CMSG_FIRSTHDR(&m);
        if (seg) { DWORD g = seg; c->cmsg_level = IPPROTO_UDP; c->cmsg_type = UDP_COALESCED_INFO; c->cmsg_len = WSA_CMSG_LEN(sizeof(DWORD)); memcpy(WSA_CMSG_DATA(c), &g, sizeof g); used += WSA_CMSG_SPACE(sizeof(DWORD)); c = WSA_CMSG_NXTHDR(&m, c); }
        if (mark && c) { INT v = mark; c->cmsg_level = IPPROTO_IP; c->cmsg_type = IP_ECN; c->cmsg_len = WSA_CMSG_LEN(sizeof(INT)); memcpy(WSA_CMSG_DATA(c), &v, sizeof v); used += WSA_CMSG_SPACE(sizeof(INT)); }
        m.Control.len = used;
        if (!take_datagram(u, &m, len, &ss)) return 0;
    }
    return hand_out(u, bufs, caps, lens, addrs, ecnv, n, 0);
}
int ksl_udp_close_wakes_for_test(ksl_udp *u) {
    HANDLE t = CreateThread(NULL, 0, blocked_recv, u, 0, NULL); if (!t) return 100000;
    Sleep(20);
    ULONGLONG t0 = GetTickCount64(); ksl_udp_shutdown(u); WaitForSingleObject(t, INFINITE); ULONGLONG t1 = GetTickCount64(); CloseHandle(t); ksl_udp_close(u);
    return (int)(t1 - t0);
}
#endif
#else
typedef int ksl_udp_win_empty_unit;   /* ISO C: a translation unit declares something */
#endif /* _WIN32 */
