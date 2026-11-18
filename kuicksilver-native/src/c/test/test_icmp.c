/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_icmp_*: the ICMP Packet Too Big of a CONNECT-UDP proxy (RFC 9298 section 6.1): the message's fields, checksums, quote
 * and length limits, its refusals, and the raw socket's probe (a privilege the tests usually lack). */
#include "test_common.h"

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
void ksl_udp_note_unreachable(ksl_udp *u, const uint8_t dst[KSL_UDP_ADDR_LEN]);

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
    CHECK(ksl_icmp_open(5, &err) == -1 && err == (int)KSL_E_BAD_ARG || (err == (int)KSL_E_NOT_SUPPORTED),
          "probe of an unknown family");
#if defined(__linux__) || defined(__APPLE__)
    /* ksl_udp_take_unreachable: each note is reported once, with the latest destination (RFC 9298 section 3.1) */
    static const uint8_t lo[4] = {127, 0, 0, 1};
    uint8_t loa[KSL_UDP_ADDR_LEN], got[KSL_UDP_ADDR_LEN];
    addr(loa, 4, lo, 0);
    uint32_t uerr = 0;
    char msg[128];
    ksl_udp *u = ksl_udp_open(loa, 0, &uerr, msg, sizeof msg);
    CHECK(u != NULL, "a loopback UDP socket");
    if (u) {
        CHECK(ksl_udp_take_unreachable(u, got) == 0, "nothing reported before an unreachable");
        ksl_udp_note_unreachable(u, ta);
        ksl_udp_note_unreachable(u, t6a);
        CHECK(ksl_udp_take_unreachable(u, got) == 1 && !memcmp(got, t6a, KSL_UDP_ADDR_LEN), "the latest destination");
        CHECK(ksl_udp_take_unreachable(u, got) == 0, "reported once");
        CHECK(ksl_udp_take_unreachable(NULL, got) == 0 && ksl_udp_take_unreachable(u, NULL) == 0, "bad arguments");
        ksl_udp_close(u);
    }
#endif
    END();
}
