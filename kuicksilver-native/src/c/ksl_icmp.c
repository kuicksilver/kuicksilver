/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ICMP Packet Too Big for a CONNECT-UDP proxy (RFC 9298 section 6.1): ksl_icmp_ptb_build writes the message (pure, every
 * platform, fuzzed by tools/fuzz/ksl mode 0xfc and tested), ksl_icmp_open / ksl_icmp_send / ksl_icmp_close send it through a raw socket, which needs
 * CAP_NET_RAW (or root) on Linux and Android; elsewhere ksl_icmp_open answers KSL_E_NOT_SUPPORTED. The raw socket only
 * sends: it never reads (a raw ICMP socket would see every ICMP message of the host), so nothing from the network is
 * parsed here. No allocation, no state beyond the descriptor. */
#if defined(__linux__) && !defined(__ANDROID__)
#define _GNU_SOURCE /* struct in6_pktinfo in glibc's netinet/in.h */
#endif
#include "ksl.h"
#include <string.h>

#if defined(__linux__)
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#define IPV4_HEADER 20
#define IPV6_HEADER 40
#define UDP_HEADER 8
#define ICMP_HEADER 8
/* RFC 1812 section 4.3.2.3: an ICMP error carries as much of the original datagram as fits a 576-byte IP datagram */
#define IPV4_ERROR_MAX 576
/* RFC 4443 section 2.4 (c): as much of the invoking packet as fits without exceeding the minimum IPv6 MTU */
#define IPV6_ERROR_MAX 1280

static void be16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* the one's-complement sum of RFC 1071 over [p, p + n), added to [sum] (not folded) */
static uint32_t sum16(uint32_t sum, const uint8_t *p, uint32_t n) {
    for (uint32_t i = 0; i + 1 < n; i += 2)
        sum += (uint32_t)p[i] << 8 | p[i + 1];
    if (n & 1)
        sum += (uint32_t)p[n - 1] << 8;
    return sum;
}

static uint32_t fold(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum & 0xffff;
}

/* the IPv4 or IPv6 pseudo-header sum for [proto] and [len] (RFC 768; RFC 8200 section 8.1) */
static uint32_t pseudo(int v6, const uint8_t *src, const uint8_t *dst, uint8_t proto, uint32_t len) {
    uint32_t s = sum16(0, src, v6 ? 16 : 4);
    s = sum16(s, dst, v6 ? 16 : 4);
    s += proto;
    s += len >> 16;
    s += len & 0xffff;
    return s;
}

uint32_t ksl_icmp_ptb_build(uint8_t *out, uint32_t cap, const uint8_t target[KSL_UDP_ADDR_LEN],
                            const uint8_t local[KSL_UDP_ADDR_LEN], const uint8_t *payload, uint32_t payload_len,
                            uint32_t mtu) {
    if (!out || !target || !local || (!payload && payload_len))
        return 0;
    int fam = target[0];
    if ((fam != 4 && fam != 6) || local[0] != fam)
        return 0;
    int v6 = fam == 6;
    /* the datagram that could not go on: UDP, the target to us, as the proxy received it (65507/65527 bytes of payload at most) */
    if (payload_len > (v6 ? 65527u : 65507u))
        return 0;
    /* IPv4: Next-Hop MTU, 68 at least (RFC 791, RFC 1191 section 4); IPv6: a Packet Too Big below 1280 is ignored by the
       receiver (RFC 8200 section 5), and above the datagram's own size it would say nothing */
    uint32_t ip = v6 ? IPV6_HEADER : IPV4_HEADER;
    uint32_t orig = ip + UDP_HEADER + payload_len;
    if (mtu < (v6 ? 1280u : 68u) || mtu >= orig || mtu > 0xffffu)
        return 0;
    uint32_t limit = v6 ? IPV6_ERROR_MAX - IPV6_HEADER : IPV4_ERROR_MAX - IPV4_HEADER; /* the ICMP message itself */
    uint32_t quote = orig < limit - ICMP_HEADER ? orig : limit - ICMP_HEADER;
    uint32_t total = ICMP_HEADER + quote;
    if (cap < total)
        return 0;
    const uint8_t *src = target + 3, *dst = local + 3; /* the original went from the target to us */
    memset(out, 0, total);
    uint8_t *q = out + ICMP_HEADER;
    uint8_t udp[UDP_HEADER];
    be16(udp, (uint32_t)target[1] << 8 | target[2]);
    be16(udp + 2, (uint32_t)local[1] << 8 | local[2]);
    be16(udp + 4, UDP_HEADER + payload_len);
    udp[6] = udp[7] = 0;
    uint32_t us = pseudo(v6, src, dst, 17, UDP_HEADER + payload_len);
    us = sum16(us, udp, UDP_HEADER);
    us = sum16(us, payload, payload_len);
    uint32_t uc = fold(us);
    be16(udp + 6, uc == 0 ? 0xffff : uc); /* RFC 768: a computed zero is sent as all ones */
    if (v6) {
        q[0] = 0x60; /* version 6, no traffic class or flow label: the original's are not known */
        be16(q + 4, UDP_HEADER + payload_len);
        q[6] = 17; /* next header: UDP */
        q[7] = 64; /* hop limit: not known either; the receiver matches on addresses and ports */
        memcpy(q + 8, src, 16);
        memcpy(q + 24, dst, 16);
    } else {
        q[0] = 0x45;
        be16(q + 2, orig);
        q[6] = 0x40; /* DF: the datagram was not to be fragmented (RFC 1191 section 4) */
        q[8] = 64;
        q[9] = 17;
        memcpy(q + 12, src, 4);
        memcpy(q + 16, dst, 4);
        be16(q + 10, fold(sum16(0, q, IPV4_HEADER)));
    }
    uint32_t rest = quote - ip; /* UDP header and payload bytes that fit */
    memcpy(q + ip, udp, rest < UDP_HEADER ? rest : UDP_HEADER);
    if (rest > UDP_HEADER)
        memcpy(q + ip + UDP_HEADER, payload, rest - UDP_HEADER);
    if (v6) {
        out[0] = 2; /* Packet Too Big (RFC 4443 section 3.2), code 0 */
        out[4] = (uint8_t)(mtu >> 24);
        out[5] = (uint8_t)(mtu >> 16);
        out[6] = (uint8_t)(mtu >> 8);
        out[7] = (uint8_t)mtu;
        /* from us to the target: the pseudo-header of the message we send (RFC 4443 section 2.3) */
        be16(out + 2, fold(sum16(pseudo(1, dst, src, 58, total), out, total)));
    } else {
        out[0] =
            3; /* Destination Unreachable, code 4: fragmentation needed and DF set (RFC 792), Next-Hop MTU (RFC 1191) */
        out[1] = 4;
        be16(out + 6, mtu);
        be16(out + 2, fold(sum16(0, out, total)));
    }
    return total;
}

#if defined(__linux__)
int ksl_icmp_open(int family, int *err) {
    if (err)
        *err = 0;
    if (family != 4 && family != 6) {
        if (err)
            *err = (int)KSL_E_BAD_ARG;
        return -1;
    }
    int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    family == 6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (fd < 0) {
        if (err)
            *err = errno; /* EPERM without CAP_NET_RAW */
        return -1;
    }
    /* sends only: a receive filter that admits nothing, so the socket never queues the host's ICMP traffic */
    int rc;
    if (family == 6) {
        struct icmp6_filter_ {
            uint32_t data[8];
        } f;
        memset(&f, 0xff, sizeof f); /* ICMP6_FILTER_SETBLOCKALL */
        rc = setsockopt(fd, IPPROTO_ICMPV6, 1 /* ICMP6_FILTER */, &f, sizeof f);
    } else {
        uint32_t mask = 0xffffffffu; /* ICMP_FILTER: every type blocked */
        rc = setsockopt(fd, IPPROTO_RAW /* SOL_RAW */, 1 /* ICMP_FILTER */, &mask, sizeof mask);
    }
    if (rc != 0) { /* a socket that would queue every ICMP message of the host is not handed out */
        if (err)
            *err = errno;
        close(fd);
        return -1;
    }
    return fd;
}

int ksl_icmp_send(int fd, const uint8_t *msg, uint32_t len, const uint8_t target[KSL_UDP_ADDR_LEN],
                  const uint8_t local[KSL_UDP_ADDR_LEN]) {
    if (fd < 0 || !msg || !len || len > IPV6_ERROR_MAX || !target || !local || local[0] != target[0])
        return 0;
    struct msghdr m;
    struct iovec iov = {(void *)msg, len};
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    union {
        char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        struct cmsghdr align;
    } c;
    memset(&c, 0, sizeof c);
    m.msg_control = c.buf;
    struct cmsghdr *h;
    if (target[0] == 6) {
        struct sockaddr_in6 to;
        memset(&to, 0, sizeof to);
        to.sin6_family = AF_INET6;
        memcpy(&to.sin6_addr, target + 3, 16);
        m.msg_name = &to;
        m.msg_namelen = sizeof to;
        /* the source: our address the target sent to, so the message comes from the proxy's end of that path */
        m.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
        h = CMSG_FIRSTHDR(&m);
        h->cmsg_level = IPPROTO_IPV6;
        h->cmsg_type = IPV6_PKTINFO;
        h->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        struct in6_pktinfo pi;
        memset(&pi, 0, sizeof pi);
        memcpy(&pi.ipi6_addr, local + 3, 16);
        memcpy(CMSG_DATA(h), &pi, sizeof pi);
        return sendmsg(fd, &m, 0) == (ssize_t)len;
    }
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    memcpy(&to.sin_addr, target + 3, 4);
    m.msg_name = &to;
    m.msg_namelen = sizeof to;
    m.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
    h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = IPPROTO_IP;
    h->cmsg_type = IP_PKTINFO;
    h->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    struct in_pktinfo pi;
    memset(&pi, 0, sizeof pi);
    memcpy(&pi.ipi_spec_dst, local + 3, 4);
    memcpy(CMSG_DATA(h), &pi, sizeof pi);
    return sendmsg(fd, &m, 0) == (ssize_t)len;
}

void ksl_icmp_close(int fd) {
    if (fd >= 0)
        close(fd);
}
#else
/* Apple platforms and Windows: raw ICMP sockets need root or administrator rights, and their source-address control differs;
   not offered (RFC 9298 section 6.1's message is not sent there) */
int ksl_icmp_open(int family, int *err) {
    (void)family;
    if (err)
        *err = (int)KSL_E_NOT_SUPPORTED;
    return -1;
}

int ksl_icmp_send(int fd, const uint8_t *msg, uint32_t len, const uint8_t target[KSL_UDP_ADDR_LEN],
                  const uint8_t local[KSL_UDP_ADDR_LEN]) {
    (void)fd;
    (void)msg;
    (void)len;
    (void)target;
    (void)local;
    return 0;
}

void ksl_icmp_close(int fd) {
    (void)fd;
}
#endif
