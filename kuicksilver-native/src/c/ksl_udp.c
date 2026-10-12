/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Accelerated UDP for Linux and Apple (ADR-0006; threat-model 3.12, 3.16): one socket, batched sendmsg with UDP_SEGMENT,
 * recvmsg with UDP_GRO split into the caller's slots inside C, ECN through IP_TOS / IP_RECVTOS, DF in PROBE mode (never DO),
 * SO_REUSEPORT. Apple: the same socket without GSO/GRO (a batch is a loop of sendmsg), DF through IP_DONTFRAG/IPV6_DONTFRAG
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

ksl_udp *ksl_udp_open(const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, uint32_t *err, char *msg, size_t msglen) {
    if (!addr || (addr[0] != 4 && addr[0] != 6)) { if (err) *err = KSL_E_BAD_ARG; if (msg && msglen) snprintf(msg, msglen, "ksl_udp: bad address"); return NULL; }
    ksl_udp *u = calloc(1, sizeof *u); if (!u) { if (err) *err = KSL_E_BAD_ARG; return NULL; }
    u->family = addr[0] == 4 ? AF_INET : AF_INET6; u->requested = (uint32_t)flags; u->wake[0] = u->wake[1] = -1; u->fd = -1;
#ifdef __linux__
    u->fd = socket(u->family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else   /* Darwin has no SOCK_CLOEXEC/SOCK_NONBLOCK: set them right after creation */
    u->fd = socket(u->family, SOCK_DGRAM, 0);
    if (u->fd >= 0 && cloexec_nonblock(u->fd) != 0) { int e = errno; close(u->fd); u->fd = -1; errno = e; }
#endif
    if (u->fd < 0) { int e = errno; if (err) *err = KSL_E_NOT_SUPPORTED; if (msg && msglen) snprintf(msg, msglen, "socket: %s", strerror(e)); free(u); return NULL; }
    int one = 1;
#ifdef SO_NOSIGPIPE
    setsockopt(u->fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);   /* Darwin: an error never raises SIGPIPE in the host process */
#endif
#ifdef __linux__   /* Darwin has SO_REUSEPORT but hands unicast UDP to one of the sockets only (no flow hashing): loops would starve, so never granted there */
    if (flags & KSL_UDP_REUSEPORT) { if (setsockopt(u->fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == 0) u->granted |= KSL_UDP_REUSEPORT; }
#endif
    if (u->family == AF_INET6) setsockopt(u->fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    struct sockaddr_storage ss; socklen_t sl = to_sockaddr(addr, &ss);
    if (bind(u->fd, (struct sockaddr *)&ss, sl) != 0) { int e = errno; if (err) *err = KSL_E_BAD_ARG; if (msg && msglen) snprintf(msg, msglen, "bind: %s", strerror(e)); close(u->fd); free(u); return NULL; }
    /* 7 MB; Darwin refuses more than kern.ipc.maxsockbuf (8 MB less overhead by default), so halve until the kernel takes it */
    for (int rcv = 7 * 1024 * 1024; rcv >= 256 * 1024 && setsockopt(u->fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv) != 0; rcv /= 2) {}
    for (int snd = 7 * 1024 * 1024; snd >= 256 * 1024 && setsockopt(u->fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd) != 0; snd /= 2) {}
    if (flags & KSL_UDP_ECN) {   /* read marks on the way in; marks on the way out travel as a per-message cmsg */
        int ok = u->family == AF_INET ? setsockopt(u->fd, IPPROTO_IP, IP_RECVTOS, &one, sizeof one) : setsockopt(u->fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &one, sizeof one);
        if (ok == 0) { u->granted |= KSL_UDP_ECN; u->tos_cmsg_on = 1; }
    }
    if (flags & KSL_UDP_DF) {   /* PROBE: DF set, no kernel path MTU cache driving sizes (an attacker's ICMP would shrink it: quic-go CVE-2024-53259) */
        int ok;
#ifdef __APPLE__   /* Darwin has only the DF bit (IP_DONTFRAG, IPV6_DONTFRAG on an IPv6-only socket), as in quic-go sys_conn_df_darwin.go */
        ok = u->family == AF_INET ? setsockopt(u->fd, IPPROTO_IP, IP_DONTFRAG, &one, sizeof one) : setsockopt(u->fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one);
#else
        int probe = IP_PMTUDISC_PROBE;
        if (u->family == AF_INET) ok = setsockopt(u->fd, IPPROTO_IP, IP_MTU_DISCOVER, &probe, sizeof probe);
        else { int p6 = IPV6_PMTUDISC_PROBE; ok = setsockopt(u->fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &p6, sizeof p6); if (ok == 0) setsockopt(u->fd, IPPROTO_IPV6, IPV6_DONTFRAG, &one, sizeof one); }
#endif
        if (ok == 0) u->granted |= KSL_UDP_DF;
    }
#ifdef __linux__   /* Darwin has no UDP_SEGMENT/UDP_GRO: the caps never grant them and every datagram is its own sendmsg/recvmsg */
    if (flags & KSL_UDP_GSO) { int zero = 0; if (setsockopt(u->fd, SOL_UDP, UDP_SEGMENT, &zero, sizeof zero) == 0) { u->granted |= KSL_UDP_GSO; u->gso_on = 1; u->gso_max = GSO_SEGMENTS; } }
    if (flags & KSL_UDP_GRO) { if (setsockopt(u->fd, SOL_UDP, UDP_GRO, &one, sizeof one) == 0) u->granted |= KSL_UDP_GRO; }
#endif
    u->batch = 16;
#ifdef __linux__
    if (pipe2(u->wake, O_CLOEXEC | O_NONBLOCK) != 0) { u->wake[0] = u->wake[1] = -1; }
#else
    /* Darwin: shutdown(2) does not wake a poll on a UDP socket, the pipe is the only way to end a blocked receive: no pipe, no socket */
    if (pipe(u->wake) != 0 || cloexec_nonblock(u->wake[0]) != 0 || cloexec_nonblock(u->wake[1]) != 0) {
        int e = errno; if (err) *err = KSL_E_NOT_SUPPORTED; if (msg && msglen) snprintf(msg, msglen, "wake pipe: %s", strerror(e));
        if (u->wake[0] >= 0) close(u->wake[0]); if (u->wake[1] >= 0) close(u->wake[1]); close(u->fd); free(u); return NULL;
    }
#endif
    u->scratch = malloc(GRO_MAX); u->tx = malloc(GRO_MAX);
    if (!u->scratch || !u->tx) { if (err) *err = KSL_E_BAD_ARG; free(u->scratch); free(u->tx); close(u->fd); if (u->wake[0] >= 0) close(u->wake[0]); if (u->wake[1] >= 0) close(u->wake[1]); free(u); return NULL; }
    sl = sizeof ss; if (getsockname(u->fd, (struct sockaddr *)&ss, &sl) == 0) from_sockaddr(&ss, u->local);
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
    if (u->fd >= 0) close(u->fd); if (u->wake[0] >= 0) close(u->wake[0]); if (u->wake[1] >= 0) close(u->wake[1]);
    free(u->scratch); free(u->tx); memset(u, 0, sizeof *u); free(u);
}

#ifdef KSL_TEST
uint32_t ksl_udp_syscalls_for_test(ksl_udp *u) { return u->sends; }
void ksl_udp_fail_next_gso_for_test(ksl_udp *u, int err) { u->fail_next_gso = err; }
void ksl_udp_fail_next_send_for_test(ksl_udp *u, int err) { u->fail_next_send = err; }
#ifdef __APPLE__
int ksl_udp_df_mode_for_test(int fd) { int v = -1; socklen_t l = sizeof v; if (getsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &v, &l) != 0) return -1; return v; }
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

#else /* neither Linux nor Apple: the portable DatagramIo does the work */
ksl_udp *ksl_udp_open(const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, uint32_t *err, char *msg, size_t msglen) { (void)addr; (void)flags; if (err) *err = KSL_E_NOT_SUPPORTED; if (msg && msglen) snprintf(msg, msglen, "ksl_udp: accelerated UDP needs Linux or Apple"); return NULL; }
int ksl_udp_get(ksl_udp *u, int what, uint8_t *out, size_t cap, size_t *len) { (void)u; (void)what; (void)out; (void)cap; (void)len; return KSL_ERROR; }
void ksl_udp_shutdown(ksl_udp *u) { (void)u; }
void ksl_udp_close(ksl_udp *u) { (void)u; }
#ifdef KSL_TEST
uint32_t ksl_udp_syscalls_for_test(ksl_udp *u) { (void)u; return 0; }
void ksl_udp_fail_next_gso_for_test(ksl_udp *u, int err) { (void)u; (void)err; }
void ksl_udp_fail_next_send_for_test(ksl_udp *u, int err) { (void)u; (void)err; }
int ksl_udp_df_mode_for_test(int fd) { (void)fd; return -1; }
int ksl_udp_close_wakes_for_test(ksl_udp *u) { (void)u; return 0; }
#endif
#endif
