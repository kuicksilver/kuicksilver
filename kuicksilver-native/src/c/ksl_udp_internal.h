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

#ifdef __linux__
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
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 62
#endif

#define GRO_MAX 65535
#define GSO_SEGMENTS 64

struct ksl_udp {
    int fd; int family; int wake[2];
    uint32_t requested, granted; uint16_t gso_max; uint16_t batch;
    int gso_on, tos_cmsg_on, eperm_retried;
    uint32_t last_errno; char last_msg[KSL_MSG];
    uint8_t local[KSL_UDP_ADDR_LEN];
    /* GRO scratch: one received message and the segments of it not yet handed out */
    /* two scratch buffers: the receiver thread owns scratch (GRO train), the sender thread owns tx (joined GSO run) — they never share */
    uint8_t *scratch; uint8_t *tx; uint32_t pend_off, pend_len, pend_seg; uint8_t pend_addr[KSL_UDP_ADDR_LEN]; uint8_t pend_ecn;
    volatile int closed; volatile int in_recv;
    uint32_t sends, recvs, gso_fallbacks;
#ifdef KSL_TEST
    int fail_next_gso, fail_next_send;   /* error injection, test builds only */
#endif
};

static inline void set_err(ksl_udp *u, int e, const char *what) { u->last_errno = (uint32_t)e; snprintf(u->last_msg, KSL_MSG, "%s: %s", what, strerror(e)); }

static inline socklen_t to_sockaddr(const uint8_t a[KSL_UDP_ADDR_LEN], struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof *ss);
    if (a[0] == 4) { struct sockaddr_in *in = (struct sockaddr_in *)ss; in->sin_family = AF_INET; memcpy(&in->sin_port, a + 1, 2); memcpy(&in->sin_addr, a + 3, 4); return sizeof *in; }
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss; in6->sin6_family = AF_INET6; memcpy(&in6->sin6_port, a + 1, 2); memcpy(&in6->sin6_addr, a + 3, 16); return sizeof *in6;
}
static inline void from_sockaddr(const struct sockaddr_storage *ss, uint8_t a[KSL_UDP_ADDR_LEN]) {
    memset(a, 0, KSL_UDP_ADDR_LEN);
    if (ss->ss_family == AF_INET) { const struct sockaddr_in *in = (const struct sockaddr_in *)ss; a[0] = 4; memcpy(a + 1, &in->sin_port, 2); memcpy(a + 3, &in->sin_addr, 4); }
    else { const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss; a[0] = 6; memcpy(a + 1, &in6->sin6_port, 2); memcpy(a + 3, &in6->sin6_addr, 16); }
}
#endif /* __linux__ */
#endif
