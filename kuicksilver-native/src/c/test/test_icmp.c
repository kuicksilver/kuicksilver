/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_icmp_*: the ICMP Packet Too Big of a CONNECT-UDP proxy (RFC 9298 section 6.1): the message's fields, checksums, quote
 * and length limits, its refusals, and the raw socket's probe (a privilege the tests usually lack). */
#if defined(__linux__)
#define _GNU_SOURCE 1 /* unshare, struct in6_pktinfo */
#endif
#include "test_common.h"
#if defined(__linux__)
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static void addr(uint8_t a[KSL_UDP_ADDR_LEN], int fam, const uint8_t *ip, unsigned port) {
    memset(a, 0, KSL_UDP_ADDR_LEN);
    a[0] = (uint8_t)fam;
    a[1] = (uint8_t)(port >> 8);
    a[2] = (uint8_t)port;
    memcpy(a + 3, ip, fam == 6 ? 16 : 4);
}

/* the RFC 1071 sum folded: 0 when the checksummed data (its checksum field included) is intact */
static unsigned verify(uint32_t s, const uint8_t *p, size_t n) {
    for (size_t i = 0; i + 1 < n; i += 2)
        s += (uint32_t)p[i] << 8 | p[i + 1];
    if (n & 1)
        s += (uint32_t)p[n - 1] << 8;
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (~s) & 0xffff;
}

static uint32_t pseudo(const uint8_t *src, const uint8_t *dst, int alen, uint32_t proto, uint32_t len) {
    uint32_t s = 0;
    for (int i = 0; i < alen; i += 2)
        s += (uint32_t)src[i] << 8 | src[i + 1];
    for (int i = 0; i < alen; i += 2)
        s += (uint32_t)dst[i] << 8 | dst[i + 1];
    return s + proto + (len >> 16) + (len & 0xffff);
}

static unsigned be16at(const uint8_t *p) {
    return (unsigned)p[0] << 8 | p[1];
}

/* ksl_udp.c, the receiver's note of an ICMP unreachable (the Linux error queue calls it; a test calls it directly) */
void ksl_udp_note_unreachable(ksl_udp *u, const uint8_t dst[KSL_UDP_ADDR_LEN], const uint8_t *quote, uint32_t quote_len,
                              uint32_t kind);

#if defined(__linux__)
/* ---- Linux, privileged: the raw path, the error queue and IP_PKTINFO end to end (tools/interop/icmp-linux-check.sh) ---- */

static int lo_up(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;
    struct ifreq r;
    memset(&r, 0, sizeof r);
    snprintf(r.ifr_name, IFNAMSIZ, "lo");
    int ok = ioctl(s, SIOCGIFFLAGS, &r) == 0;
    r.ifr_flags |= IFF_UP;
    ok = ok && ioctl(s, SIOCSIFFLAGS, &r) == 0;
    close(s);
    return ok ? 0 : -1;
}

static ksl_udp *lo_sock(int fam, int flags, uint8_t local[KSL_UDP_ADDR_LEN]) {
    static const uint8_t lo4[4] = {127, 0, 0, 1};
    static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t a[KSL_UDP_ADDR_LEN];
    addr(a, fam, fam == 6 ? lo6 : lo4, 0);
    uint32_t err = 0;
    char msg[128];
    ksl_udp *u = ksl_udp_open(a, flags, &err, msg, sizeof msg);
    size_t n = 0;
    if (u && (ksl_udp_get(u, KSL_UDP_GET_LOCAL, local, KSL_UDP_ADDR_LEN, &n) != KSL_OK || n != KSL_UDP_ADDR_LEN)) {
        ksl_udp_close(u);
        return NULL;
    }
    return u;
}

static int send_to(ksl_udp *u, const uint8_t to[KSL_UDP_ADDR_LEN], const uint8_t *d, uint32_t len) {
    uint8_t *bufs[1] = {(uint8_t *)d};
    uint32_t lens[1] = {len}, sent = 0;
    uint8_t ecn[1] = {0};
    return ksl_udp_send(u, bufs, lens, to, ecn, 1, &sent) == KSL_OK && sent == 1 ? 0 : -1;
}

/* one receive call (which drains the error queue), [ms] at most */
static void udp_pump(ksl_udp *u, int ms) {
    uint8_t buf[2048];
    uint8_t *bufs[1] = {buf};
    uint32_t caps[1] = {sizeof buf}, lens[1], got = 0;
    uint8_t ra[KSL_UDP_ADDR_LEN], re[1];
    (void)ksl_udp_recv(u, bufs, caps, lens, ra, re, 1, &got, ms);
}

static int take_unreach(ksl_udp *u, uint8_t dst[KSL_UDP_ADDR_LEN], uint8_t *q, uint32_t *ql, uint32_t *kind) {
    for (int i = 0; i < 40; i++) {
        udp_pump(u, 25);
        if (ksl_udp_take_unreachable(u, dst, q, KSL_UDP_PTB_QUOTE, ql, kind))
            return 1;
    }
    return 0;
}

/* An ICMP destination unreachable of [code] (3 port, 1 host), as a forger would send it: quoting the IPv4 and UDP header of a
   datagram 127.0.0.1:[from port] -> 127.0.0.1:[port] and [payload] as its start. 0 when sent */
static int inject_unreach(const uint8_t from[KSL_UDP_ADDR_LEN], unsigned port, int code, const char *payload) {
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw < 0)
        return -1;
    size_t pl = strlen(payload);
    uint8_t pkt[8 + 20 + 8 + 64];
    size_t n = 8 + 20 + 8 + pl;
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 3;
    pkt[1] = (uint8_t)code;
    uint8_t *ip = pkt + 8;
    ip[0] = 0x45;
    ip[2] = (uint8_t)((28 + pl) >> 8);
    ip[3] = (uint8_t)(28 + pl);
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = IPPROTO_UDP;
    ip[12] = 127;
    ip[15] = 1;
    ip[16] = 127;
    ip[19] = 1;
    unsigned ic = verify(0, ip, 20);
    ip[10] = (uint8_t)(ic >> 8);
    ip[11] = (uint8_t)ic;
    uint8_t *uh = ip + 20;
    uh[0] = from[1];
    uh[1] = from[2];
    uh[2] = (uint8_t)(port >> 8);
    uh[3] = (uint8_t)port;
    uh[4] = (uint8_t)((8 + pl) >> 8);
    uh[5] = (uint8_t)(8 + pl);
    memcpy(uh + 8, payload, pl);
    unsigned c = verify(0, pkt, n);
    pkt[2] = (uint8_t)(c >> 8);
    pkt[3] = (uint8_t)c;
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ssize_t w = sendto(raw, pkt, n, 0, (struct sockaddr *)&to, sizeof to);
    close(raw);
    return w == (ssize_t)n ? 0 : -1;
}

/* Port and host unreachable through the error queue: the kernel's own for a closed port (its quote: our payload), and forged
   ones, which are reported as they are (the caller checks the quote). Exit 0 pass, else the failed step. */
static int unreach_cases(void) {
    uint8_t la[KSL_UDP_ADDR_LEN], lc[KSL_UDP_ADDR_LEN], dst[KSL_UDP_ADDR_LEN], q[KSL_UDP_PTB_QUOTE];
    uint32_t ql = 0, kind = 0;
    ksl_udp *a = lo_sock(4, KSL_UDP_DF, la), *c = lo_sock(4, 0, lc);
    if (!a || !c)
        return 30;
    ksl_udp_close(c); /* its port is closed now: a datagram to it draws the kernel's port unreachable */
    if (send_to(a, lc, (const uint8_t *)"HELLO-PAYLOAD", 13) != 0)
        return 31;
    if (!take_unreach(a, dst, q, &ql, &kind))
        return 32;
    if (kind != KSL_UNREACH_PORT || ql != 13 || memcmp(q, "HELLO-PAYLOAD", 13) || memcmp(dst, lc, KSL_UDP_ADDR_LEN))
        return 33;
    unsigned port = (unsigned)lc[1] << 8 | lc[2];
    if (inject_unreach(la, port, 3, "FORGED") != 0)
        return 34;
    if (!take_unreach(a, dst, q, &ql, &kind) || kind != KSL_UNREACH_PORT || ql != 6 || memcmp(q, "FORGED", 6))
        return 35;
    if (inject_unreach(la, port, 1, "HOST") != 0)
        return 36;
    if (!take_unreach(a, dst, q, &ql, &kind) || kind != KSL_UNREACH_HOST || ql != 4)
        return 37;
    if (inject_unreach(la, port, 3, "") != 0)
        return 38;
    if (!take_unreach(a, dst, q, &ql, &kind) || kind != KSL_UNREACH_PORT || ql != 0)
        return 39; /* the headers only: an empty quote */
    ksl_udp_close(a);
    return 0;
}

/* ksl_icmp_open/ptb_build/send of family [fam] from the proxy's address (IP_PKTINFO, IPV6_PKTINFO) to a target on loopback:
   a second raw socket sees the message as sent (type, code, MTU, checksum, quote, source) and the target's socket takes it from
   its error queue, so the kernel accepted it as a Packet Too Big for that datagram. Exit 0 pass, 79 no IPv6, else the step */
static int ptb_cases(int fam) {
    uint8_t lt[KSL_UDP_ADDR_LEN], lp[KSL_UDP_ADDR_LEN];
    ksl_udp *t = lo_sock(fam, KSL_UDP_DF, lt), *p = lo_sock(fam, 0, lp);
    if (!t || !p) {
        if (t)
            ksl_udp_close(t);
        if (p)
            ksl_udp_close(p);
        return fam == 6 ? 79 : 40;
    }
    uint8_t payload[1400];
    for (unsigned i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)(0x40 + i % 64);
    /* the target sends the datagram the proxy cannot pass on (and the proxy receives it, as it would) */
    if (send_to(t, lp, payload, sizeof payload) != 0)
        return 41;
    int cap = socket(fam == 6 ? AF_INET6 : AF_INET, SOCK_RAW, fam == 6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (cap < 0)
        return 42;
    int err = 0;
    int fd = ksl_icmp_open(fam, &err);
    if (fd < 0)
        return 43;
    uint32_t mtu = fam == 6 ? 1300 : 1200;
    uint8_t msg[KSL_ICMP_PTB_MAX];
    uint32_t n = ksl_icmp_ptb_build(msg, sizeof msg, lt, lp, payload, sizeof payload, mtu);
    if (!n)
        return 44;
    if (!ksl_icmp_send(fd, msg, n, lt, lp))
        return 45;
    /* the copy the capture socket got: IPv4 with its IP header, ICMPv6 without */
    uint8_t got[2048];
    int found = 0;
    for (int i = 0; i < 40 && !found; i++) {
        struct pollfd pf = {cap, POLLIN, 0};
        if (poll(&pf, 1, 25) <= 0)
            continue;
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t r = recvfrom(cap, got, sizeof got, 0, (struct sockaddr *)&from, &fl);
        if (r <= 0)
            continue;
        const uint8_t *m = got;
        size_t mn = (size_t)r;
        if (fam == 4) {
            size_t ihl = (size_t)(got[0] & 0x0f) * 4;
            if (mn < ihl + 8 || got[9] != IPPROTO_ICMP)
                continue;
            if (memcmp(got + 12, lp + 3, 4))
                return 46; /* the source is the proxy's address */
            m += ihl;
            mn -= ihl;
            if (m[0] != 3)
                continue; /* another ICMP message of the host */
            if (m[1] != 4 || be16at(m + 6) != mtu || verify(0, m, mn) != 0)
                return 47;
        } else {
            if (mn < 8 || m[0] != 2)
                continue;
            if (((unsigned)m[4] << 24 | (unsigned)m[5] << 16 | be16at(m + 6)) != mtu)
                return 47;
            /* the kernel checksums ICMPv6 itself; verified against the pseudo-header of ::1 -> ::1 */
            if (verify(pseudo(lp + 3, lt + 3, 16, 58, (uint32_t)mn), m, mn) != 0)
                return 48;
        }
        size_t hdr = 8 + (fam == 6 ? 40 : 20) + 8;
        if (mn != n || memcmp(m + hdr, payload, mn - hdr))
            return 49; /* the quote: the datagram's start, unchanged */
        found = 1;
    }
    close(cap);
    ksl_icmp_close(fd);
    if (!found)
        return 50;
    uint8_t q[KSL_UDP_PTB_QUOTE], dst[KSL_UDP_ADDR_LEN];
    uint32_t ql = 0, pmtu = 0;
    int took = 0;
    for (int i = 0; i < 40 && !took; i++) {
        udp_pump(t, 25);
        took = ksl_udp_take_ptb(t, q, sizeof q, &ql, dst, &pmtu);
    }
    if (!took)
        return 51;
    if (pmtu != mtu || ql == 0 || memcmp(q, payload, ql) || memcmp(dst, lp, KSL_UDP_ADDR_LEN))
        return 52;
    ksl_udp_close(t);
    ksl_udp_close(p);
    return 0;
}

/* in a fresh user and network namespace, or, where that is refused (Docker's seccomp), in this one when it may open raw sockets
   (root with CAP_NET_RAW in a container). Exit 0 pass, 77 skip (no privilege either way), 79 IPv6 part skipped, else the step */
static int icmp_linux_child(void) {
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0) {
        if (lo_up() != 0)
            return 77;
    } else {
        int probe = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (probe < 0)
            return 77;
        close(probe);
    }
    int r = unreach_cases();
    if (r)
        return r;
    r = ptb_cases(4);
    if (r)
        return r;
    r = ptb_cases(6);
    return r == 79 ? 79 : r;
}
#endif

void run_icmp(void) {
    SECTION("icmp");
    static const uint8_t t4[4] = {198, 51, 100, 7}, l4[4] = {192, 0, 2, 1};
    static const uint8_t t6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};
    static const uint8_t l6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t ta[KSL_UDP_ADDR_LEN], la[KSL_UDP_ADDR_LEN], t6a[KSL_UDP_ADDR_LEN], l6a[KSL_UDP_ADDR_LEN];
    addr(ta, 4, t4, 443);
    addr(la, 4, l4, 50000);
    addr(t6a, 6, t6, 443);
    addr(l6a, 6, l6, 50000);
    uint8_t payload[1400];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)(i * 7 + 1);
    uint8_t m[KSL_ICMP_PTB_MAX + 64];

    /* IPv4, a short datagram: type 3 code 4, the Next-Hop MTU, the whole datagram quoted */
    uint32_t n = ksl_icmp_ptb_build(m, sizeof m, ta, la, payload, 100, 100);
    CHECK(n == 8 + 20 + 8 + 100, "IPv4 length: header + whole datagram");
    CHECK(m[0] == 3 && m[1] == 4, "IPv4 type 3 code 4");
    CHECK(m[4] == 0 && m[5] == 0 && be16at(m + 6) == 100,
          "IPv4 unused field zero, Next-Hop MTU 100 (RFC 1191 section 4)");
    CHECK(verify(0, m, n) == 0, "ICMP checksum over the message (RFC 792)");
    const uint8_t *q = m + 8;
    CHECK(q[0] == 0x45 && be16at(q + 2) == 128 && q[6] == 0x40 && q[9] == 17,
          "quoted IPv4 header: v4, IHL 5, length, DF, UDP");
    CHECK(!memcmp(q + 12, t4, 4) && !memcmp(q + 16, l4, 4), "quoted addresses: from the target to the proxy");
    CHECK(verify(0, q, 20) == 0, "quoted IPv4 header checksum");
    CHECK(be16at(q + 20) == 443 && be16at(q + 22) == 50000 && be16at(q + 24) == 108, "quoted UDP ports and length");
    CHECK(verify(pseudo(t4, l4, 4, 17, 108), q + 20, 108) == 0,
          "quoted UDP checksum over pseudo-header, header, payload");
    CHECK(!memcmp(q + 28, payload, 100), "quoted payload");

    /* IPv4, a long datagram: the quote stops at a 576-byte IP datagram (RFC 1812 section 4.3.2.3) */
    n = ksl_icmp_ptb_build(m, sizeof m, ta, la, payload, 1400, 1280);
    CHECK(n == 576 - 20, "IPv4 message within 576 bytes of IP datagram");
    CHECK(verify(0, m, n) == 0, "ICMP checksum of a truncated quote");
    CHECK(be16at(m + 8 + 2) == 20 + 8 + 1400, "the quoted header keeps the original total length");
    CHECK(!memcmp(m + 8 + 28, payload, n - 8 - 28), "the quote is the start of the payload");

    /* IPv6: type 2 code 0, the 32-bit MTU, the quote within 1280 bytes (RFC 4443 sections 2.4 (c), 3.2) */
    n = ksl_icmp_ptb_build(m, sizeof m, t6a, l6a, payload, 1400, 1300);
    CHECK(n == 1280 - 40, "IPv6 message within the minimum MTU");
    CHECK(n == KSL_ICMP_PTB_MAX, "KSL_ICMP_PTB_MAX is the largest message");
    CHECK(m[0] == 2 && m[1] == 0 && m[4] == 0 && m[5] == 0 && be16at(m + 6) == 1300, "IPv6 type 2 code 0, MTU 1300");
    CHECK(verify(pseudo(l6, t6, 16, 58, n), m, n) == 0,
          "ICMPv6 checksum over the pseudo-header from the proxy to the target");
    q = m + 8;
    CHECK(q[0] == 0x60 && be16at(q + 4) == 8 + 1400 && q[6] == 17, "quoted IPv6 header: version, payload length, UDP");
    CHECK(!memcmp(q + 8, t6, 16) && !memcmp(q + 24, l6, 16), "quoted IPv6 addresses: from the target to the proxy");
    CHECK(be16at(q + 40) == 443 && be16at(q + 42) == 50000, "quoted UDP ports");
    n = ksl_icmp_ptb_build(m, sizeof m, t6a, l6a, payload, 1300, 1280);
    CHECK(n == 8 + 40 + 8 + 1184 && verify(pseudo(l6, t6, 16, 58, n), m, n) == 0, "IPv6 quote of exactly the limit");
    uint8_t whole[8 + 40 + 8 + 1300];
    CHECK(ksl_icmp_ptb_build(whole, sizeof whole, t6a, l6a, payload, 1300, 1280) == n, "an exact buffer suffices");
    CHECK(ksl_icmp_ptb_build(whole, n - 1, t6a, l6a, payload, 1300, 1280) == 0,
          "negative_icmpBufferTooSmall: one byte short");

    /* refusals */
    CHECK(ksl_icmp_ptb_build(m, sizeof m, ta, la, payload, 40, 68) == 0,
          "negative_icmpMtuNotBelowTheDatagram (68 = its size)");
    CHECK(ksl_icmp_ptb_build(m, sizeof m, ta, la, payload, 40, 67) == 0, "negative_icmpIpv4MtuBelow68");
    CHECK(ksl_icmp_ptb_build(m, sizeof m, t6a, l6a, payload, 1400, 1279) == 0,
          "negative_icmpIpv6MtuBelow1280 (RFC 8200 section 5)");
    CHECK(ksl_icmp_ptb_build(m, sizeof m, ta, l6a, payload, 40, 50) == 0, "negative_icmpFamiliesDiffer");
    CHECK(ksl_icmp_ptb_build(m, sizeof m, ta, la, NULL, 40, 50) == 0, "negative_icmpNoPayload");
    CHECK(ksl_icmp_ptb_build(m, sizeof m, ta, la, payload, 65508, 1280) == 0, "negative_icmpPayloadAboveUdpLimit");
    uint8_t bad[KSL_UDP_ADDR_LEN];
    memcpy(bad, ta, sizeof bad);
    bad[0] = 5;
    CHECK(ksl_icmp_ptb_build(m, sizeof m, bad, la, payload, 40, 50) == 0, "negative_icmpUnknownFamily");
    CHECK(ksl_icmp_ptb_build(NULL, sizeof m, ta, la, payload, 40, 50) == 0, "negative_icmpNoBuffer");

    /* the probe: a raw socket only with the privilege (Linux CAP_NET_RAW); never anywhere else */
    int err = 0;
    int fd = ksl_icmp_open(4, &err);
#if defined(__linux__)
    if (fd >= 0) {
        printf("icmp: raw ICMP socket available (privileged run)\n");
        /* sends nothing to anyone in a test */
        ksl_icmp_close(fd);
    } else {
        CHECK(err != 0, "an unprivileged probe reports why");
    }
#else
    CHECK(fd == -1 && err == (int)KSL_E_NOT_SUPPORTED, "no raw ICMP sender outside Linux and Android");
    CHECK(ksl_icmp_send(-1, m, 8, ta, la) == 0, "send without a socket does nothing");
#endif
    CHECK(ksl_icmp_open(5, &err) == -1 && (err == (int)KSL_E_BAD_ARG || err == (int)KSL_E_NOT_SUPPORTED),
          "probe of an unknown family");
#if defined(__linux__)
    {
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0)
            _exit(icmp_linux_child());
        int st = 0;
        waitpid(pid, &st, 0);
        int code = WIFEXITED(st) ? WEXITSTATUS(st) : 100;
        /* markers tools/interop/icmp-linux-check.sh requires */
        if (code == 77)
            printf("icmp_linux: SKIP (no user namespace and no raw-socket privilege)\n");
        else {
            CHECK(code == 0 || code == 79, "icmp_linux (child exit = failed step)");
            if (code == 0 || code == 79) {
                printf("icmp_linux_unreachable: OK\nicmp_linux_ptb_v4: OK\n");
                printf(code == 0 ? "icmp_linux_ptb_v6: OK\n" : "icmp_linux_ptb_v6: SKIP (no ::1)\n");
            } else
                printf("    icmp_linux child failed at step %d\n", code);
        }
    }
#endif
#if defined(__linux__) || defined(__APPLE__)
    /* ksl_udp_take_unreachable: each note once, oldest first, with its kind and quoted payload; a full ring of 8 keeps the older
       ones (RFC 9298 section 3.1, RFC 8085 section 5.2) */
    static const uint8_t lo[4] = {127, 0, 0, 1};
    uint8_t loa[KSL_UDP_ADDR_LEN], got[KSL_UDP_ADDR_LEN], uq[KSL_UDP_PTB_QUOTE + 8], big[100];
    uint32_t ql = 0, kind = 0;
    memset(big, 0x5a, sizeof big);
    addr(loa, 4, lo, 0);
    uint32_t uerr = 0;
    char msg[128];
    ksl_udp *u = ksl_udp_open(loa, 0, &uerr, msg, sizeof msg);
    CHECK(u != NULL, "a loopback UDP socket");
    if (u) {
        CHECK(ksl_udp_take_unreachable(u, got, uq, sizeof uq, &ql, &kind) == 0,
              "nothing reported before an unreachable");
        ksl_udp_note_unreachable(u, ta, (const uint8_t *)"abc", 3, KSL_UNREACH_PORT);
        ksl_udp_note_unreachable(u, t6a, big, sizeof big, KSL_UNREACH_HOST);
        CHECK(ksl_udp_take_unreachable(u, got, uq, sizeof uq, &ql, &kind) == 1 && !memcmp(got, ta, KSL_UDP_ADDR_LEN) &&
                  ql == 3 && !memcmp(uq, "abc", 3) && kind == KSL_UNREACH_PORT,
              "the oldest first, its quote and kind");
        CHECK(ksl_udp_take_unreachable(u, got, uq, sizeof uq, &ql, &kind) == 1 && !memcmp(got, t6a, KSL_UDP_ADDR_LEN) &&
                  ql == KSL_UDP_PTB_QUOTE && uq[KSL_UDP_PTB_QUOTE - 1] == 0x5a && kind == KSL_UNREACH_HOST,
              "a long quote kept to KSL_UDP_PTB_QUOTE bytes");
        CHECK(ksl_udp_take_unreachable(u, got, uq, sizeof uq, &ql, &kind) == 0, "reported once");
        ksl_udp_note_unreachable(u, ta, NULL, 0, KSL_UNREACH_PORT);
        CHECK(ksl_udp_take_unreachable(u, got, uq, 2, &ql, &kind) == 1 && ql == 0, "headers only: an empty quote");
        for (int i = 0; i < 10; i++)
            ksl_udp_note_unreachable(u, i < 8 ? ta : t6a, big, 4, KSL_UNREACH_PORT);
        int n = 0;
        while (ksl_udp_take_unreachable(u, got, uq, sizeof uq, &ql, &kind) == 1) {
            CHECK(!memcmp(got, ta, KSL_UDP_ADDR_LEN), "a full ring keeps the older entries");
            n++;
        }
        CHECK(n == 8, "a ring of 8");
        ksl_udp_note_unreachable(u, ta, big, 4, KSL_UNREACH_PORT);
        CHECK(ksl_udp_take_unreachable(u, got, uq, 2, &ql, &kind) == 1 && ql == 2, "the quote kept to cap");
        CHECK(ksl_udp_take_unreachable(NULL, got, uq, sizeof uq, &ql, &kind) == 0 &&
                  ksl_udp_take_unreachable(u, NULL, uq, sizeof uq, &ql, &kind) == 0 &&
                  ksl_udp_take_unreachable(u, got, NULL, 4, &ql, &kind) == 0 &&
                  ksl_udp_take_unreachable(u, got, uq, sizeof uq, NULL, &kind) == 0 &&
                  ksl_udp_take_unreachable(u, got, uq, sizeof uq, &ql, NULL) == 0,
              "bad arguments");
        ksl_udp_close(u);
    }
#endif
    END();
}
