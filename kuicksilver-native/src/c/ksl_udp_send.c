/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Accelerated UDP, sending (ADR-0006): batched sendmsg, runs of equal datagrams joined with UDP_SEGMENT (GSO), the ECN mark
 * as a per-message cmsg, and the fallbacks when the kernel refuses either. Apple has no GSO: gso_on stays 0 and every datagram is its own sendmsg. */
#include "ksl_udp_internal.h"

#ifdef KSL_UDP_ACCEL
static int send_one(ksl_udp *u, const uint8_t *buf, uint32_t len, const uint8_t *addr, uint8_t ecn, uint16_t gso_size, int *errnum) {
    struct sockaddr_storage ss; socklen_t sl = dest_sockaddr(u, addr, &ss);
    struct iovec iov = { (void *)buf, len };
    uint8_t cbuf[CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(int))]; memset(cbuf, 0, sizeof cbuf);   /* CMSG_NXTHDR reads the next header's length: garbage there answers NULL and the TOS cmsg would be lost */
    struct msghdr m; memset(&m, 0, sizeof m); m.msg_name = &ss; m.msg_namelen = sl; m.msg_iov = &iov; m.msg_iovlen = 1; m.msg_control = cbuf; m.msg_controllen = sizeof cbuf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m); size_t used = 0;
#ifndef __linux__
    (void)gso_size;   /* no UDP_SEGMENT: callers never join a run */
#else
    if (gso_size) { c->cmsg_level = SOL_UDP; c->cmsg_type = UDP_SEGMENT; c->cmsg_len = CMSG_LEN(sizeof(uint16_t)); memcpy(CMSG_DATA(c), &gso_size, sizeof gso_size); used += CMSG_SPACE(sizeof(uint16_t)); c = CMSG_NXTHDR(&m, c); }
#endif
    /* the level follows the destination: Linux ignores IPV6_TCLASS for a v4-mapped peer of a dual-stack socket, IP_TOS works on both */
    if (ecn && u->tos_cmsg_on && c) { int tos = ecn & 3; c->cmsg_level = addr[0] == 4 ? IPPROTO_IP : IPPROTO_IPV6; c->cmsg_type = addr[0] == 4 ? IP_TOS : IPV6_TCLASS; c->cmsg_len = CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(c), &tos, sizeof tos); used += CMSG_SPACE(sizeof(int)); }
    m.msg_controllen = used; if (!used) m.msg_control = NULL;
    u->sends++;
#ifdef KSL_TEST
    if (u->fail_next_gso && gso_size) { int e = u->fail_next_gso; u->fail_next_gso = 0; *errnum = e; return -1; }
    if (u->fail_next_send && !gso_size) { int e = u->fail_next_send; u->fail_next_send = 0; *errnum = e; return -1; }
#endif
    ssize_t r = sendmsg(u->fd, &m, 0); if (r < 0) { *errnum = errno; return -1; } return 0;
}

static void gso_off(ksl_udp *u) { u->gso_on = 0; u->granted &= ~(uint32_t)KSL_UDP_GSO; u->gso_fallbacks++; }
/* errors a destination causes (port 0, a link-local IPv6 address without its scope id, a family the socket cannot reach): that datagram
   cannot leave, the socket and its options are fine */
static int dest_error(int e) { return e == EINVAL || e == EAFNOSUPPORT || e == EADDRNOTAVAIL || e == EDESTADDRREQ; }
/* the kernel's queue is full (EAGAIN; ENOBUFS when Darwin's interface queue or Linux's qdisc is): stop, the caller sends the rest later */
static int backpressure(int e) { return e == EAGAIN || e == EWOULDBLOCK || e == ENOBUFS; }
/* this datagram is lost on the wire: the socket lives, loss detection repairs it */
/* an ICMP error about an earlier datagram that the kernel reports on this send (sk_err with IP_RECVERR), not this datagram's fault */
static int pending_icmp(int e) { return e == ECONNREFUSED || e == EHOSTUNREACH || e == ENETUNREACH || e == EHOSTDOWN; }
static void count_emsgsize(ksl_udp *u, uint32_t len) { __atomic_add_fetch(&u->emsgsize, 1, __ATOMIC_RELAXED); __atomic_store_n(&u->emsgsize_last, len, __ATOMIC_RELAXED); }
static int slot_lost(int e) { return dest_error(e) || e == EMSGSIZE || e == EPERM || e == EACCES || e == ENETUNREACH || e == EHOSTUNREACH || e == ENETDOWN || e == EHOSTDOWN || e == ENOMEM || e == ECONNREFUSED; }

int ksl_udp_send(ksl_udp *u, uint8_t *const *bufs, const uint32_t *lens, const uint8_t *addrs, const uint8_t *ecn, uint32_t n, uint32_t *sent) {
    if (!u || u->closed) return KSL_ERROR; *sent = 0; uint32_t i = 0; int icmp_retried = 0;
    int gso_probe = 0;   /* a GSO send failed with EINVAL: the first datagram of that run, sent alone, tells GSO's fault from the destination's */
    while (i < n) {
        /* a run of equal-size datagrams to one address with one mark leaves in a single sendmsg when GSO is on */
        uint32_t run = 1;
        /* a run starts only with two equal lengths: a larger first datagram (a PMTU probe) would set gso_size for every segment behind it,
           which a narrower link answers with EINVAL; the last segment of a run may be shorter (kernel rule) */
        if (u->gso_on && !gso_probe && i + 1 < n && lens[i + 1] == lens[i]) while (i + run < n && run < u->gso_max && lens[i + run] <= lens[i] && !memcmp(addrs + (i + run) * KSL_UDP_ADDR_LEN, addrs + i * KSL_UDP_ADDR_LEN, KSL_UDP_ADDR_LEN) && ecn[i + run] == ecn[i]) { run++; if (lens[i + run - 1] < lens[i]) break; }
        if (run > 1 && lens[i] > 0) {
            uint8_t *joined = u->tx; size_t total = 0, cap = GSO_JOIN_MAX(addrs + i * KSL_UDP_ADDR_LEN); for (uint32_t k = 0; k < run; k++) { if (total + lens[i + k] > cap) { run = k; break; } memcpy(joined + total, bufs[i + k], lens[i + k]); total += lens[i + k]; }
            int e = 0;
            if (run > 1 && send_one(u, joined, (uint32_t)total, addrs + i * KSL_UDP_ADDR_LEN, ecn[i], (uint16_t)lens[i], &e) == 0) { i += run; *sent += run; continue; }
            if (run > 1) {
                if (backpressure(e)) return KSL_OK;
                if ((e == EINVAL || e == EMSGSIZE) && lens[i] > 1200) { /* the segment size, not GSO itself, was refused (a narrow link): the run goes out one by one, GSO stays */ }
                else if (e == EINVAL) gso_probe = 1;   /* GSO, the TOS cmsg or the destination: decided by the single send below */
                else if (e == EIO || e == ENOTSUP || e == EOPNOTSUPP) gso_off(u);
                else if (e == EPERM && !u->eperm_retried) { u->eperm_retried = 1; }
                else if (u->recverr && pending_icmp(e)) { /* sk_err of an ICMP message about another datagram: the run goes one by one, GSO stays */ }
                else { set_err(u, e, "sendmsg(gso)"); gso_off(u); }
            }
            /* fall through: the segments go one by one */
        }
        int e = 0;
        if (send_one(u, bufs[i], lens[i], addrs + i * KSL_UDP_ADDR_LEN, ecn[i], 0, &e) == 0) { if (gso_probe) gso_off(u); gso_probe = 0; i++; (*sent)++; u->eperm_retried = 0; icmp_retried = 0; continue; }
        if (backpressure(e)) return KSL_OK;
        if (e == EINVAL && u->tos_cmsg_on && ecn[i]) {   /* the TOS cmsg or the destination: the same datagram without the mark decides */
            if (send_one(u, bufs[i], lens[i], addrs + i * KSL_UDP_ADDR_LEN, 0, 0, &e) == 0) { u->tos_cmsg_on = 0; u->granted &= ~(uint32_t)KSL_UDP_ECN; gso_probe = 0; i++; (*sent)++; u->eperm_retried = 0; icmp_retried = 0; continue; }   /* the kernel rejected the TOS cmsg: never send it again */
            if (backpressure(e)) return KSL_OK;
        }
        gso_probe = 0;   /* the datagram failed alone too: GSO was not the cause */
        if (e == EPERM && !u->eperm_retried) { u->eperm_retried = 1; continue; }   /* a filter hiccup: one retry, then the datagram is given up like any other transient error */
        /* sk_err from an ICMP message about another datagram is reported (and cleared) by this send: the datagram goes once more */
        if (u->recverr && pending_icmp(e) && !icmp_retried) { icmp_retried = 1; continue; }
        if (e == EMSGSIZE) count_emsgsize(u, lens[i]);   /* larger than the path MTU the kernel knows: a DPLPMTUD hint (ksl_udp_emsgsize) */
        if (slot_lost(e)) { i++; (*sent)++; icmp_retried = 0; continue; }
        set_err(u, e, "sendmsg"); return KSL_ERROR;
    }
    return KSL_OK;
}

#elif !defined(_WIN32) /* neither Linux, Apple nor Windows (ksl_udp_win.c): the portable DatagramIo does the work */
int ksl_udp_send(ksl_udp *u, uint8_t *const *bufs, const uint32_t *lens, const uint8_t *addrs, const uint8_t *ecn, uint32_t n, uint32_t *sent) { (void)u; (void)bufs; (void)lens; (void)addrs; (void)ecn; (void)n; if (sent) *sent = 0; return KSL_ERROR; }
#endif
