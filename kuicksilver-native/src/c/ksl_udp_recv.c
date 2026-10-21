/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Accelerated UDP, receiving (ADR-0006): recvmsg (with UDP_GRO on Linux) into a scratch buffer, the segments handed out to the
 * caller's slots with their address and ECN mark; a shutdown from another thread wakes a blocked receive. */
#include "ksl_udp_internal.h"

#ifdef KSL_UDP_ACCEL
static uint32_t hand_out(ksl_udp *u, uint8_t *const *bufs, const uint32_t *caps, uint32_t *lens, uint8_t *addrs, uint8_t *ecnv, uint32_t n, uint32_t from) {
    uint32_t filled = from;
    while (u->pend_len && filled < n) {
        uint32_t seg = u->pend_seg ? u->pend_seg : u->pend_len; if (seg > u->pend_len) seg = u->pend_len;
        if (seg <= caps[filled]) { memcpy(bufs[filled], u->scratch + u->pend_off, seg); lens[filled] = seg; memcpy(addrs + filled * KSL_UDP_ADDR_LEN, u->pend_addr, KSL_UDP_ADDR_LEN); ecnv[filled] = u->pend_ecn; filled++; }
        u->pend_off += seg; u->pend_len -= seg;
    }
    return filled;
}
/* milliseconds since an arbitrary fixed point, never going back */
static int64_t now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000; }
/* datagrams taken in a row without filling a slot (empty, link-local source, truncated, larger than the slot) between two looks
   at the clock */
#define DROP_CHECK 64
int ksl_udp_recv(ksl_udp *u, uint8_t *const *bufs, const uint32_t *caps, uint32_t *lens, uint8_t *addrs, uint8_t *ecnv, uint32_t n, uint32_t *received, int timeout_ms) {
    if (!u || u->closed) return KSL_ERROR; *received = 0; if (!n) return KSL_OK;
    __atomic_add_fetch(&u->in_recv, 1, __ATOMIC_SEQ_CST);
    uint32_t filled = hand_out(u, bufs, caps, lens, addrs, ecnv, n, 0);
    int rc = KSL_OK; uint32_t dropped = 0;
    /* the timeout is one deadline for the whole call, as in ksl_udp_win.c: a datagram dropped below does not restart the wait, else
       a trickle of empty datagrams (any off-path sender, spoofed or not) keeps the call from ever answering KSL_WANT_READ */
    const int64_t deadline = timeout_ms > 0 ? now_ms() + timeout_ms : 0;
    /* recvmsg first, poll only when the queue is empty and nothing was taken yet: one system call per datagram, not two (a sender
       whose datagrams arrive one by one, without GSO, cost a poll and a recvmsg each) */
    while (filled < n) {
        if (u->closed) { rc = KSL_ERROR; break; }
        /* a run of datagrams that all get dropped (from a sender faster than the drain, so recvmsg never answers EAGAIN) still ends
           at the deadline; a call that may not wait (timeout 0) or already holds datagrams stops after DROP_CHECK of them. Checked
           before recvmsg: a datagram once taken is always looked at, never lost to the bound */
        if (dropped >= DROP_CHECK && timeout_ms >= 0) {
            if (filled || timeout_ms == 0 || now_ms() >= deadline) { if (!filled) rc = KSL_WANT_READ; break; }
            dropped = 0;
        }
        struct sockaddr_storage ss; struct iovec iov = { u->scratch, GRO_MAX }; uint8_t cbuf[256];
        struct msghdr m; memset(&m, 0, sizeof m); m.msg_name = &ss; m.msg_namelen = sizeof ss; m.msg_iov = &iov; m.msg_iovlen = 1; m.msg_control = cbuf; m.msg_controllen = sizeof cbuf;
        ssize_t r = recvmsg(u->fd, &m, MSG_DONTWAIT); u->recvs++;
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (filled || timeout_ms == 0) { if (!filled) rc = KSL_WANT_READ; break; }
            int wait = timeout_ms;
            if (timeout_ms > 0) { int64_t left = deadline - now_ms(); if (left <= 0) { rc = KSL_WANT_READ; break; } wait = (int)left; }
            struct pollfd pf[2] = { { u->fd, POLLIN, 0 }, { u->wake[0], POLLIN, 0 } };
            int pr = poll(pf, u->wake[0] >= 0 ? 2 : 1, wait); u->polls++;
            if (pr == 0) { rc = KSL_WANT_READ; break; }
            if (pr < 0) { if (errno == EINTR) continue; set_err(u, errno, "poll"); rc = KSL_ERROR; break; }
            if (pf[1].revents) { rc = KSL_ERROR; break; }   /* closed from another thread */
            continue;
        }
        if (r < 0) { set_err(u, errno, "recvmsg"); rc = filled ? KSL_OK : KSL_ERROR; break; }
        if (m.msg_flags & MSG_TRUNC) { dropped++; continue; }   /* bigger than the scratch: dropped whole */
        uint32_t gso = 0; uint8_t mark = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
#ifdef __linux__
            if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_GRO) { int g; memcpy(&g, CMSG_DATA(c), sizeof g); if (g > 0) gso = (uint32_t)g; }
            else
#endif
            /* Darwin labels the received TOS cmsg IP_RECVTOS (one byte), Linux IP_TOS; as in msquic datapath_kqueue.c and quic-go sys_conn_helper_darwin.go */
            if ((c->cmsg_level == IPPROTO_IP && (c->cmsg_type == IP_TOS || c->cmsg_type == IP_RECVTOS)) || (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_TCLASS)) { int tos = 0; if (c->cmsg_len >= CMSG_LEN(sizeof(int))) memcpy(&tos, CMSG_DATA(c), sizeof tos); else tos = *(uint8_t *)CMSG_DATA(c); mark = (uint8_t)(tos & 3); }
        }
        u->pend_off = 0; u->pend_len = (uint32_t)r; u->pend_seg = gso; from_sockaddr(&ss, u->pend_addr); u->pend_ecn = mark;
        if (r == 0) { u->pend_len = 0; dropped++; continue; }   /* an empty datagram carries nothing for QUIC */
        if (ss.ss_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)&ss)->sin6_addr)) { u->pend_len = 0; dropped++; continue; }   /* the address format has no scope id: no reply could reach a link-local peer */
        uint32_t before = filled; filled = hand_out(u, bufs, caps, lens, addrs, ecnv, n, filled);
        if (filled > before) dropped = 0; else dropped++;   /* every segment larger than its slot */
    }
    *received = filled;
    __atomic_sub_fetch(&u->in_recv, 1, __ATOMIC_SEQ_CST);
    return rc;
}

#elif !defined(_WIN32) /* neither Linux, Apple nor Windows (ksl_udp_win.c): the portable DatagramIo does the work */
int ksl_udp_recv(ksl_udp *u, uint8_t *const *bufs, const uint32_t *caps, uint32_t *lens, uint8_t *addrs, uint8_t *ecn, uint32_t n, uint32_t *received, int timeout_ms) { (void)u; (void)bufs; (void)caps; (void)lens; (void)addrs; (void)ecn; (void)n; (void)timeout_ms; if (received) *received = 0; return KSL_ERROR; }
#endif
