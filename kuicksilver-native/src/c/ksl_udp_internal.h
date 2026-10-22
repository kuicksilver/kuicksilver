/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Private to the ksl_udp*.c translation units (accelerated UDP, ADR-0006): the socket object and the address helpers.
 * Not part of the ABI. Include it first: it sets _GNU_SOURCE before any system header. */
#ifndef KSL_UDP_INTERNAL_H
#define KSL_UDP_INTERNAL_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1   /* pipe2, recvmmsg-era socket flags, clock_gettime */
#endif
#include "ksl_internal.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__) || defined(__APPLE__)
#define KSL_UDP_ACCEL 1   /* Linux: GSO, GRO, ECN, DF probe mode; Apple: the same socket without GSO/GRO, DF through IP_DONTFRAG */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#ifdef __linux__
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#endif
#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 62
#endif
#ifdef __linux__
#include <linux/errqueue.h>
#endif

#define GRO_MAX 65535
#define PTB_RING 16      /* Packet Too Big messages kept between two ksl_udp_take_ptb calls */
#define ERRQUEUE_BATCH 16   /* error-queue messages read per drain */
#define GSO_SEGMENTS 64
/* the most UDP payload one IP datagram carries, which a GSO send must not exceed: IPv4 65535 - 20 (IP header) - 8 (UDP header)
   (Linux __ip_append_data answers EMSGSIZE above it), IPv6 65535 - 8 (the payload length counts the UDP header) */
#define GSO_JOIN_MAX(addr) ((addr)[0] == 4 ? 65507u : 65527u)

struct ksl_udp {
    int fd; int family; int dual; int wake[2];   /* dual: AF_INET6 on :: with IPV6_V6ONLY off, IPv4 peers as v4-mapped addresses */
    uint32_t requested, granted; uint16_t gso_max; uint16_t batch;
    int gso_on, tos_cmsg_on, eperm_retried;
    uint32_t last_errno; char last_msg[KSL_MSG]; pthread_mutex_t err_mu;   /* err_mu guards the pair; initialised in ksl_udp_open */
    uint8_t local[KSL_UDP_ADDR_LEN];
    /* GRO scratch: one received message and the segments of it not yet handed out */
    /* two scratch buffers: the receiver thread owns scratch (GRO train), the sender thread owns tx (joined GSO run) — they never share */
    uint8_t *scratch; uint8_t *tx; uint32_t pend_off, pend_len, pend_seg; uint8_t pend_addr[KSL_UDP_ADDR_LEN]; uint8_t pend_ecn;
    volatile int closed; volatile int in_recv;
    uint32_t sends, recvs, gso_fallbacks, polls;
    /* ICMP hints (ADR-0006): recverr is on with DF on Linux; the receiver fills the Packet Too Big ring, ksl_udp_take_ptb empties it
       (ptb_mu); the sender counts EMSGSIZE (atomics) */
    int recverr; pthread_mutex_t ptb_mu;
    struct ksl_ptb { uint8_t quote[KSL_UDP_PTB_QUOTE]; uint32_t quote_len, mtu; uint8_t dst[KSL_UDP_ADDR_LEN]; } ptb[PTB_RING];
    uint32_t ptb_head, ptb_count, ptb_dropped, errqueue_reads;
    uint64_t emsgsize; uint32_t emsgsize_last;
#ifdef KSL_TEST
    int fail_next_gso, fail_next_send;   /* error injection, test builds only */
#endif
};

void ksl_udp_push_ptb(ksl_udp *u, const uint8_t *quote, uint32_t len, const uint8_t dst[KSL_UDP_ADDR_LEN], uint32_t mtu);   /* ksl_udp.c */

/* strerror is not thread-safe; strerror_r is the XSI one (int) or, with _GNU_SOURCE on glibc and on bionic from API 23, the GNU one
   (char *, maybe not buf): _Generic picks the matching reader, NULL when the XSI call failed */
static inline const char *ksl_sr_gnu(char *r, char *buf) { (void)buf; return r; }
static inline const char *ksl_sr_xsi(int r, char *buf) { return r == 0 ? buf : NULL; }
#define ksl_strerror_r(e, buf, n) _Generic(strerror_r((e), (buf), (n)), char *: ksl_sr_gnu, default: ksl_sr_xsi)(strerror_r((e), (buf), (n)), (buf))
static inline void ksl_errtext(int e, char *buf, size_t n) { char t[128]; const char *s = ksl_strerror_r(e, t, sizeof t); if (s) snprintf(buf, n, "%s", s); else snprintf(buf, n, "errno %d", e); }
/* the sender and the receiver thread both record errors and ksl_udp_get reads them: err_mu keeps errno and text one error's (the
   text is formatted outside it, so the lock is held for a copy of KSL_MSG bytes) */
static inline void err_lock(ksl_udp *u) { pthread_mutex_lock(&u->err_mu); }
static inline void err_unlock(ksl_udp *u) { pthread_mutex_unlock(&u->err_mu); }
static inline void set_err(ksl_udp *u, int e, const char *what) {
    char t[128], m[KSL_MSG]; ksl_errtext(e, t, sizeof t); snprintf(m, sizeof m, "%s: %s", what, t);
    err_lock(u); u->last_errno = (uint32_t)e; memcpy(u->last_msg, m, KSL_MSG); err_unlock(u);
}

static inline socklen_t to_sockaddr(const uint8_t a[KSL_UDP_ADDR_LEN], struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof *ss);
    if (a[0] == 4) {
        struct sockaddr_in *in = (struct sockaddr_in *)ss; in->sin_family = AF_INET; memcpy(&in->sin_port, a + 1, 2); memcpy(&in->sin_addr, a + 3, 4);
#ifdef __APPLE__
        in->sin_len = sizeof *in;   /* BSD sockaddr carries its own length */
#endif
        return sizeof *in;
    }
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss; in6->sin6_family = AF_INET6; memcpy(&in6->sin6_port, a + 1, 2); memcpy(&in6->sin6_addr, a + 3, 16);
#ifdef __APPLE__
    in6->sin6_len = sizeof *in6;
#endif
    return sizeof *in6;
}
static inline void from_sockaddr(const struct sockaddr_storage *ss, uint8_t a[KSL_UDP_ADDR_LEN]) {
    memset(a, 0, KSL_UDP_ADDR_LEN);
    if (ss->ss_family == AF_INET) { const struct sockaddr_in *in = (const struct sockaddr_in *)ss; a[0] = 4; memcpy(a + 1, &in->sin_port, 2); memcpy(a + 3, &in->sin_addr, 4); }
    else {
        static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }; const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss; const uint8_t *p = (const uint8_t *)&in6->sin6_addr;
        if (!memcmp(p, mapped, 12)) { a[0] = 4; memcpy(a + 1, &in6->sin6_port, 2); memcpy(a + 3, p + 12, 4); }   /* a dual-stack socket's IPv4 peer: IPv4, as ksl_udp_win.c */
        else { a[0] = 6; memcpy(a + 1, &in6->sin6_port, 2); memcpy(a + 3, p, 16); }
    }
}
/* a destination as this socket's sockaddr: IPv4 on a dual-stack socket becomes v4-mapped */
static inline socklen_t dest_sockaddr(const ksl_udp *u, const uint8_t a[KSL_UDP_ADDR_LEN], struct sockaddr_storage *ss) {
    if (!u->dual || a[0] != 4) return to_sockaddr(a, ss);
    uint8_t m[KSL_UDP_ADDR_LEN] = { 6 }; m[1] = a[1]; m[2] = a[2]; m[13] = 0xff; m[14] = 0xff; memcpy(m + 15, a + 3, 4); return to_sockaddr(m, ss);
}
#endif /* __linux__ || __APPLE__ */
#endif
