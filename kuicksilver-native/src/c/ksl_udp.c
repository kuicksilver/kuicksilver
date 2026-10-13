/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Accelerated UDP for Linux and Apple (ADR-0006; threat-model 3.12, 3.16): one socket, batched sendmsg with UDP_SEGMENT,
 * recvmsg with UDP_GRO split into the caller's slots inside C, ECN through IP_TOS / IP_RECVTOS, DF in PROBE mode (never DO),
 * SO_REUSEPORT. A wildcard address (0.0.0.0 or ::) opens one dual-stack AF_INET6 socket on :: (IPV6_V6ONLY off), v4-mapped peers
 * reported as IPv4, as NIO and ksl_udp_win.c do; a specific address keeps its own family. Apple: the same socket without GSO/GRO (a batch is a loop of sendmsg), DF through IP_DONTFRAG/IPV6_DONTFRAG
 * (Darwin has no PMTUDISC modes), pipe + fcntl instead of pipe2. No allocation after open; errors stay in the object.
 * Other platforms (Windows): KSL_E_NOT_SUPPORTED.
 * The socket's life (open, get, shutdown, close) lives here, sending in ksl_udp_send.c, receiving in ksl_udp_recv.c. */
#include "ksl_udp_internal.h"

#ifdef KSL_UDP_ACCEL
#ifndef __linux__   /* Darwin has neither SOCK_CLOEXEC/SOCK_NONBLOCK nor pipe2 */
static int cloexec_nonblock(int fd) { int fl = fcntl(fd, F_GETFL); if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) return -1; int fd_fl = fcntl(fd, F_GETFD); return fd_fl < 0 || fcntl(fd, F_SETFD, fd_fl | FD_CLOEXEC) != 0 ? -1 : 0; }
#endif
static void be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

#ifdef KSL_TEST
static int no_ipv6_for_test;   /* simulates a host without IPv6: socket(AF_INET6) fails */
void ksl_udp_no_ipv6_for_test(int on) { no_ipv6_for_test = on; }
#endif
static int is_wildcard(const uint8_t *a) { for (int i = 3; i < (a[0] == 4 ? 7 : 19); i++) if (a[i]) return 0; return 1; }
/* socket, the options bind needs first, bind; -1 with errno and the failed step. dual: AF_INET6 bound to :: with IPV6_V6ONLY off */
static int bind_socket(ksl_udp *u, const uint8_t addr[KSL_UDP_ADDR_LEN], int dual, int flags, const char **step) {
    int family = dual || addr[0] == 6 ? AF_INET6 : AF_INET, fd = -1; *step = "socket";
#ifdef KSL_TEST
    if (family == AF_INET6 && no_ipv6_for_test) { errno = EAFNOSUPPORT; return -1; }
#endif
#ifdef __linux__
    fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else   /* Darwin has no SOCK_CLOEXEC/SOCK_NONBLOCK: set them right after creation */
    fd = socket(family, SOCK_DGRAM, 0);
    if (fd >= 0 && cloexec_nonblock(fd) != 0) { int e = errno; close(fd); fd = -1; errno = e; }
#endif
    if (fd < 0) return -1;
    int one = 1, v6only = !dual;
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);   /* Darwin: an error never raises SIGPIPE in the host process */
#endif
#ifdef __linux__   /* Darwin has SO_REUSEPORT but hands unicast UDP to one of the sockets only (no flow hashing): loops would starve, so never granted there */
    if (flags & KSL_UDP_REUSEPORT) { if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == 0) u->granted |= KSL_UDP_REUSEPORT; }
#else
    (void)flags;
#endif
    uint8_t any[KSL_UDP_ADDR_LEN] = { 6 }; any[1] = addr[1]; any[2] = addr[2];
    struct sockaddr_storage ss; socklen_t sl = to_sockaddr(dual ? any : addr, &ss);
    if (family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only) != 0 && dual) { *step = "IPV6_V6ONLY"; }
    else if (bind(fd, (struct sockaddr *)&ss, sl) == 0) { u->family = family; u->dual = dual; return fd; }
    else *step = "bind";
    int e = errno; close(fd); errno = e; return -1;
}
static ksl_udp *open_failed(ksl_udp *u, uint32_t code, const char *what, int e, uint32_t *err, char *msg, size_t msglen) {
    if (err) *err = code; if (msg && msglen) snprintf(msg, msglen, "%s: %s", what, strerror(e));
    if (u->fd >= 0) close(u->fd); if (u->wake[0] >= 0) close(u->wake[0]); if (u->wake[1] >= 0) close(u->wake[1]);
    free(u->scratch); free(u->tx); free(u); return NULL;
}

ksl_udp *ksl_udp_open(const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, uint32_t *err, char *msg, size_t msglen) {
    if (!addr || (addr[0] != 4 && addr[0] != 6)) { if (err) *err = KSL_E_BAD_ARG; if (msg && msglen) snprintf(msg, msglen, "ksl_udp: bad address"); return NULL; }
    ksl_udp *u = calloc(1, sizeof *u); if (!u) { if (err) *err = KSL_E_BAD_ARG; return NULL; }
    u->requested = (uint32_t)flags; u->wake[0] = u->wake[1] = -1; u->fd = -1;
    /* a wildcard (0.0.0.0 or ::) takes both families on one dual-stack socket, as NIO's DatagramChannel: a client bound to 0.0.0.0
       reaches IPv6 servers and a server on 0.0.0.0 answers IPv6 clients. Without IPv6 (or with :: taken) the requested family alone. */
    const char *step = "socket";
    if (is_wildcard(addr)) u->fd = bind_socket(u, addr, 1, flags, &step);
    if (u->fd < 0) { u->granted = 0; u->fd = bind_socket(u, addr, 0, flags, &step); }
    if (u->fd < 0) return open_failed(u, step[0] == 's' ? KSL_E_NOT_SUPPORTED : KSL_E_BAD_ARG, step, errno, err, msg, msglen);
    int one = 1, v4 = u->family == AF_INET || u->dual, v6 = u->family == AF_INET6;
    /* 7 MB; Darwin refuses more than kern.ipc.maxsockbuf (8 MB less overhead by default), so halve until the kernel takes it */
    for (int rcv = 7 * 1024 * 1024; rcv >= 256 * 1024 && setsockopt(u->fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv) != 0; rcv /= 2) {}
    for (int snd = 7 * 1024 * 1024; snd >= 256 * 1024 && setsockopt(u->fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd) != 0; snd /= 2) {}
    if (flags & KSL_UDP_ECN) {   /* read marks on the way in; marks on the way out travel as a per-message cmsg */
        int ok = 1;
        if (v6) ok = ok && setsockopt(u->fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &one, sizeof one) == 0;
#ifdef __APPLE__   /* Darwin refuses IP_RECVTOS on an AF_INET6 socket (EINVAL) and reports v4-mapped marks through IPV6_TCLASS */
        if (!v6)
#endif
        if (v4) ok = ok && setsockopt(u->fd, IPPROTO_IP, IP_RECVTOS, &one, sizeof one) == 0;   /* Linux: on AF_INET6 it covers v4-mapped traffic */
        if (ok) { u->granted |= KSL_UDP_ECN; u->tos_cmsg_on = 1; }
    }
    if (flags & KSL_UDP_DF) {   /* DF set; never DO mode: the kernel's path MTU cache must not drive sizes (an attacker's ICMP would shrink it: quic-go CVE-2024-53259) */
        int ok = 1;
#ifdef __APPLE__   /* Darwin has only the DF bit, as in quic-go sys_conn_df_darwin.go; on AF_INET6 IPV6_DONTFRAG covers v4-mapped traffic too (IP_DONTFRAG: EINVAL).
                      It does cache a path MTU from an ICMPv6 Packet Too Big (clamped to >= 1280): a larger datagram then fails with EMSGSIZE,
                      a lost slot, and QUIC's 1248-byte IPv6 floor (1200 + headers) still fits, so a forged PTB cannot stop sending */
        ok = v6 ? setsockopt(u->fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one) == 0 : setsockopt(u->fd, IPPROTO_IP, IP_DONTFRAG, &one, sizeof one) == 0;
#else
        int probe = IP_PMTUDISC_PROBE, p6 = IPV6_PMTUDISC_PROBE;
        if (v4) ok = ok && setsockopt(u->fd, IPPROTO_IP, IP_MTU_DISCOVER, &probe, sizeof probe) == 0;   /* on AF_INET6: the v4-mapped half */
        if (v6) { ok = ok && setsockopt(u->fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &p6, sizeof p6) == 0; if (ok) setsockopt(u->fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one); }
#endif
        if (ok) u->granted |= KSL_UDP_DF;
    }
#ifdef __linux__   /* Darwin has no UDP_SEGMENT/UDP_GRO: the caps never grant them and every datagram is its own sendmsg/recvmsg */
    if (flags & KSL_UDP_GSO) { int zero = 0; if (setsockopt(u->fd, SOL_UDP, UDP_SEGMENT, &zero, sizeof zero) == 0) { u->granted |= KSL_UDP_GSO; u->gso_on = 1; u->gso_max = GSO_SEGMENTS; } }
    if (flags & KSL_UDP_GRO) { if (setsockopt(u->fd, SOL_UDP, UDP_GRO, &one, sizeof one) == 0) u->granted |= KSL_UDP_GRO; }
#endif
    u->batch = 16;
#ifdef __linux__
    if (pipe2(u->wake, O_CLOEXEC | O_NONBLOCK) != 0) { u->wake[0] = u->wake[1] = -1; }
#else   /* Darwin: shutdown(2) does not wake a poll on a UDP socket, the pipe is the only way to end a blocked receive: no pipe, no socket */
    if (pipe(u->wake) != 0 || cloexec_nonblock(u->wake[0]) != 0 || cloexec_nonblock(u->wake[1]) != 0) return open_failed(u, KSL_E_NOT_SUPPORTED, "wake pipe", errno, err, msg, msglen);
#endif
    u->scratch = malloc(GRO_MAX); u->tx = malloc(GRO_MAX); if (!u->scratch || !u->tx) return open_failed(u, KSL_E_BAD_ARG, "malloc", ENOMEM, err, msg, msglen);
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    if (getsockname(u->fd, (struct sockaddr *)&ss, &sl) == 0) from_sockaddr(&ss, u->local);
    if (u->dual && addr[0] == 4) { memset(u->local + 3, 0, KSL_UDP_ADDR_LEN - 3); u->local[0] = 4; }   /* 0.0.0.0 asked: 0.0.0.0 reported, the port the kernel chose */
    ksl_live_add(KSL_LIVE_UDP, 1); ksl_live_add(KSL_LIVE_WAKE, (u->wake[0] >= 0) + (u->wake[1] >= 0));
    return u;
}

int ksl_udp_get(ksl_udp *u, int what, uint8_t *out, size_t cap, size_t *len) {
    if (!u || !out || !len) return KSL_ERROR;
    switch (what) {
    case KSL_UDP_GET_FD: if (cap < 4) return KSL_ERROR; be32(out, (uint32_t)u->fd); *len = 4; return KSL_OK;
    case KSL_UDP_GET_CAPS: if (cap < 8) return KSL_ERROR; be32(out, u->granted); be16(out + 4, u->gso_on ? u->gso_max : 0); be16(out + 6, u->batch); *len = 8; return KSL_OK;
    case KSL_UDP_GET_LOCAL: if (cap < KSL_UDP_ADDR_LEN) return KSL_ERROR; memcpy(out, u->local, KSL_UDP_ADDR_LEN); *len = KSL_UDP_ADDR_LEN; return KSL_OK;
    case KSL_UDP_GET_STATS: if (cap < 12) return KSL_ERROR; be32(out, u->sends); be32(out + 4, u->recvs); be32(out + 8, u->gso_fallbacks); *len = 12; return KSL_OK;
    case KSL_UDP_GET_ERROR: { if (cap < 4) return KSL_ERROR; be32(out, u->last_errno); size_t m = strlen(u->last_msg); if (m > cap - 4) m = cap - 4; memcpy(out + 4, u->last_msg, m); *len = 4 + m; return KSL_OK; }
    default: return KSL_ERROR;
    }
}

void ksl_udp_shutdown(ksl_udp *u) {
    if (!u || u->closed) return;
    u->closed = 1; if (u->wake[1] >= 0) { uint8_t b = 1; ssize_t w = write(u->wake[1], &b, 1); (void)w; }
    if (u->fd >= 0) { shutdown(u->fd, SHUT_RDWR); }
}
void ksl_udp_close(ksl_udp *u) {
    if (!u) return;
    ksl_udp_shutdown(u);
    for (int i = 0; i < 1000 && __atomic_load_n(&u->in_recv, __ATOMIC_SEQ_CST) > 0; i++) { struct timespec ts = { 0, 1000000 }; nanosleep(&ts, NULL); }   /* a receiver woke up and leaves the object */
    ksl_live_add(KSL_LIVE_UDP, -1); ksl_live_add(KSL_LIVE_WAKE, -((u->wake[0] >= 0) + (u->wake[1] >= 0)));
    if (u->fd >= 0) close(u->fd); if (u->wake[0] >= 0) close(u->wake[0]); if (u->wake[1] >= 0) close(u->wake[1]);
    free(u->scratch); free(u->tx); memset(u, 0, sizeof *u); free(u);
}

#ifdef KSL_TEST
uint32_t ksl_udp_syscalls_for_test(ksl_udp *u) { return u->sends; }
void ksl_udp_fail_next_gso_for_test(ksl_udp *u, int err) { u->fail_next_gso = err; }
void ksl_udp_fail_next_send_for_test(ksl_udp *u, int err) { u->fail_next_send = err; }
#ifdef __APPLE__
int ksl_udp_df_mode_for_test(int fd) { int v = -1; socklen_t l = sizeof v; if (getsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &v, &l) != 0 && getsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &v, (l = sizeof v, &l)) != 0) return -1; return v; }   /* AF_INET6: IPV6_DONTFRAG */
#else
int ksl_udp_df_mode_for_test(int fd) { int v = -1; socklen_t l = sizeof v; if (getsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &v, &l) != 0) return -1; return v; }
#endif
static void *blocked_recv(void *arg) { ksl_udp *u = arg; uint8_t buf[64]; uint8_t *bufs[1] = { buf }; uint32_t caps[1] = { 64 }, lens[1], got; uint8_t a[KSL_UDP_ADDR_LEN], e[1]; ksl_udp_recv(u, bufs, caps, lens, a, e, 1, &got, 5000); return NULL; }
int ksl_udp_close_wakes_for_test(ksl_udp *u) {
    pthread_t t; if (pthread_create(&t, NULL, blocked_recv, u) != 0) return 100000;
    struct timespec ts = { 0, 20000000 }; nanosleep(&ts, NULL);
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0); ksl_udp_shutdown(u); pthread_join(t, NULL); clock_gettime(CLOCK_MONOTONIC, &t1); ksl_udp_close(u);
    return (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
}
#endif

#elif !defined(_WIN32) /* neither Linux, Apple nor Windows (ksl_udp_win.c): the portable DatagramIo does the work */
ksl_udp *ksl_udp_open(const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, uint32_t *err, char *msg, size_t msglen) { (void)addr; (void)flags; if (err) *err = KSL_E_NOT_SUPPORTED; if (msg && msglen) snprintf(msg, msglen, "ksl_udp: accelerated UDP needs Linux, Apple or Windows"); return NULL; }
int ksl_udp_get(ksl_udp *u, int what, uint8_t *out, size_t cap, size_t *len) { (void)u; (void)what; (void)out; (void)cap; (void)len; return KSL_ERROR; }
void ksl_udp_shutdown(ksl_udp *u) { (void)u; }
void ksl_udp_close(ksl_udp *u) { (void)u; }
#ifdef KSL_TEST
uint32_t ksl_udp_syscalls_for_test(ksl_udp *u) { (void)u; return 0; }
void ksl_udp_fail_next_gso_for_test(ksl_udp *u, int err) { (void)u; (void)err; }
void ksl_udp_fail_next_send_for_test(ksl_udp *u, int err) { (void)u; (void)err; }
int ksl_udp_df_mode_for_test(int fd) { (void)fd; return -1; }
int ksl_udp_close_wakes_for_test(ksl_udp *u) { (void)u; return 0; }
void ksl_udp_no_ipv6_for_test(int on) { (void)on; }
#endif
#endif
