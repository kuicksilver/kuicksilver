/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_resolve: the addresses of one family of a name from getaddrinfo (Happy Eyeballs, RFC 8305 section 3: AAAA and A
 * as separate queries), for the JVM and Android, whose InetAddress asks for both families at once. ksl_addr_info: what the
 * system knows about one of its own addresses, for the destination address sort of RFC 6724 section 6 (Rule 3, deprecated
 * sources; Rule 7, tunnels; Rule 9, the source's prefix length). No state, no threads; ksl_resolve blocks its caller for as
 * long as the system resolver takes. */
#if defined(__linux__) && !defined(__ANDROID__)
#define _GNU_SOURCE /* EAI_NODATA and EAI_ADDRFAMILY in glibc's netdb.h */
#endif
#include "ksl.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

/* a name getaddrinfo may be given: 1..253 printable ASCII bytes without spaces, labels of 1..63 bytes */
static int net_name_ok(const char *name) {
    if (!name)
        return 0;
    size_t n = 0, label = 0;
    for (; n < 254 && name[n]; n++) {
        unsigned char c = (unsigned char)name[n];
        if (c <= 0x20 || c >= 0x7f)
            return 0;
        if (c == '.') {
            if (label == 0)
                return 0;
            label = 0;
        } else if (++label > 63)
            return 0;
    }
    return n > 0 && n <= 253 && !name[n];
}

/* getaddrinfo's "the name has no address of this family" (or no such name), as opposed to a failed lookup */
static int net_gai_not_found(int rc) {
#if defined(_WIN32)
    return rc == WSAHOST_NOT_FOUND || rc == WSANO_DATA;
#else
    if (rc == EAI_NONAME)
        return 1;
#ifdef EAI_NODATA
    if (rc == EAI_NODATA)
        return 1;
#endif
#ifdef EAI_ADDRFAMILY
    if (rc == EAI_ADDRFAMILY)
        return 1;
#endif
    return 0;
#endif
}

int ksl_resolve(const char *name, int family, uint8_t *out, size_t cap, size_t *len) {
    if (len)
        *len = 0;
    if (!net_name_ok(name) || !out || !len || cap < KSL_RESOLVE_ENTRY_LEN ||
        (family != KSL_ADDR_V4 && family != KSL_ADDR_V6))
        return KSL_ERROR;
#if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return KSL_ERROR;
#endif
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = family == KSL_ADDR_V6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM; /* one entry per address, not one per socket type */
    /* flags of our own: Apple applies its AI_DEFAULT (AI_V4MAPPED_CFG) to flags 0, so an IPv6 query would wait for the A
       answer and hand it back as IPv4-mapped addresses */
    hints.ai_flags = AI_NUMERICSERV;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(name, NULL, &hints, &res);
    int r = KSL_OK;
    if (rc != 0) {
        r = net_gai_not_found(rc) ? KSL_DNS_NOT_FOUND : KSL_ERROR;
    } else {
        size_t at = 0;
        for (struct addrinfo *a = res; a && r == KSL_OK; a = a->ai_next) {
            uint8_t e[KSL_RESOLVE_ENTRY_LEN];
            memset(e, 0, sizeof e);
            if (a->ai_family == AF_INET6 && family == KSL_ADDR_V6 && a->ai_addr &&
                (size_t)a->ai_addrlen >= sizeof(struct sockaddr_in6)) {
                const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)a->ai_addr;
                static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
                if (memcmp(&s->sin6_addr, mapped, 12) == 0)
                    continue; /* an IPv4 address in disguise (AI_V4MAPPED): the A query's, not this one's */
                uint32_t scope = (uint32_t)s->sin6_scope_id;
                e[0] = KSL_ADDR_V6;
                memcpy(e + 1, &s->sin6_addr, 16);
                e[17] = (uint8_t)(scope >> 24);
                e[18] = (uint8_t)(scope >> 16);
                e[19] = (uint8_t)(scope >> 8);
                e[20] = (uint8_t)scope;
            } else if (a->ai_family == AF_INET && family == KSL_ADDR_V4 && a->ai_addr &&
                       (size_t)a->ai_addrlen >= sizeof(struct sockaddr_in)) {
                const struct sockaddr_in *s = (const struct sockaddr_in *)a->ai_addr;
                e[0] = KSL_ADDR_V4;
                memcpy(e + 1, &s->sin_addr, 4);
            } else {
                continue; /* another family (an IPv4-mapped answer is never asked for): not this query's */
            }
            int dup = 0; /* getaddrinfo can list one address more than once (several hosts-file lines) */
            for (size_t p = 0; p < at && !dup; p += KSL_RESOLVE_ENTRY_LEN)
                dup = memcmp(out + p, e, KSL_RESOLVE_ENTRY_LEN) == 0;
            if (dup)
                continue;
            if (cap - at < KSL_RESOLVE_ENTRY_LEN)
                break; /* more addresses than fit: the first ones, in the resolver's order, are kept */
            memcpy(out + at, e, KSL_RESOLVE_ENTRY_LEN);
            at += KSL_RESOLVE_ENTRY_LEN;
        }
        if (r == KSL_OK)
            *len = at;
        if (r == KSL_OK && at == 0)
            r = KSL_DNS_NOT_FOUND;
        freeaddrinfo(res);
    }
#if defined(_WIN32)
    WSACleanup();
#endif
    if (r != KSL_OK)
        *len = 0;
    return r;
}

int ksl_nat64_synthesize(const uint8_t *v4, uint8_t *out, size_t cap, size_t *len) {
    if (len)
        *len = 0;
    if (!v4 || !out || !len || cap < 16)
        return KSL_ERROR;
#if defined(__APPLE__)
    /* Apple's documented way (getaddrinfo on an IPv4 literal with AI_DEFAULT): on a NAT64 network the system answers
       with the IPv6 addresses its own prefixes give, elsewhere with the IPv4 address (or its mapped form) */
    char text[16];
    snprintf(text, sizeof text, "%u.%u.%u.%u", v4[0], v4[1], v4[2], v4[3]);
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_DEFAULT;
    struct addrinfo *res = NULL;
    if (getaddrinfo(text, NULL, &hints, &res) != 0)
        return KSL_ERROR;
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    size_t at = 0;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        if (a->ai_family != AF_INET6 || !a->ai_addr || (size_t)a->ai_addrlen < sizeof(struct sockaddr_in6))
            continue;
        const uint8_t *b = (const uint8_t *)&((const struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
        if (memcmp(b, mapped, 12) == 0)
            continue;
        int dup = 0;
        for (size_t p = 0; p < at && !dup; p += 16)
            dup = memcmp(out + p, b, 16) == 0;
        if (dup)
            continue;
        if (cap - at < 16)
            break;
        memcpy(out + at, b, 16);
        at += 16;
    }
    freeaddrinfo(res);
    *len = at;
    return at ? KSL_OK : KSL_DNS_NOT_FOUND;
#else
    (void)cap;
    return KSL_DNS_NOT_SUPPORTED;
#endif
}

#if !defined(_WIN32)
/* the number of leading one bits of a netmask of n bytes (a contiguous mask; a gap ends the count) */
static int net_prefix_len(const uint8_t *mask, size_t n) {
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = mask[i];
        for (int k = 7; k >= 0; k--) {
            if (!(b >> k & 1))
                return bits;
            bits++;
        }
    }
    return bits;
}
#endif

#if defined(_WIN32)
typedef ULONG(WINAPI *net_gaa_fn)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);

int ksl_addr_info(const uint8_t *addr, size_t len, uint32_t scope, int *prefix_len, int *flags) {
    if (prefix_len)
        *prefix_len = -1;
    if (flags)
        *flags = 0;
    if (!addr || (len != 4 && len != 16) || !prefix_len || !flags)
        return KSL_ERROR;
    /* iphlpapi is loaded here, not linked: only this call needs it */
    HMODULE lib = LoadLibraryExW(L"iphlpapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!lib)
        return KSL_ERROR;
    net_gaa_fn gaa = (net_gaa_fn)(void *)GetProcAddress(lib, "GetAdaptersAddresses");
    if (!gaa) {
        FreeLibrary(lib);
        return KSL_ERROR;
    }
    ULONG size = 16384;
    IP_ADAPTER_ADDRESSES *list = NULL;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int tries = 0; tries < 4 && rc == ERROR_BUFFER_OVERFLOW; tries++) {
        free(list);
        list = malloc(size);
        if (!list) {
            FreeLibrary(lib);
            return KSL_ERROR;
        }
        rc = gaa(len == 16 ? AF_INET6 : AF_INET,
                 GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
                     GAA_FLAG_SKIP_FRIENDLY_NAME,
                 NULL, list, &size);
    }
    int r = KSL_DNS_NOT_FOUND;
    if (rc != NO_ERROR) {
        r = rc == ERROR_NO_DATA ? KSL_DNS_NOT_FOUND : KSL_ERROR;
    } else {
        for (IP_ADAPTER_ADDRESSES *a = list; a && r == KSL_DNS_NOT_FOUND; a = a->Next) {
            for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
                const struct sockaddr *sa = u->Address.lpSockaddr;
                int match = 0;
                if (len == 16 && sa && sa->sa_family == AF_INET6) {
                    const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
                    match = memcmp(&s->sin6_addr, addr, 16) == 0 && (scope == 0 || s->sin6_scope_id == scope);
                } else if (len == 4 && sa && sa->sa_family == AF_INET) {
                    match = memcmp(&((const struct sockaddr_in *)sa)->sin_addr, addr, 4) == 0;
                }
                if (!match)
                    continue;
                *prefix_len = u->OnLinkPrefixLength;
                if (u->DadState == IpDadStateDeprecated)
                    *flags |= KSL_ADDR_DEPRECATED;
                if (a->IfType == IF_TYPE_TUNNEL)
                    *flags |= KSL_ADDR_TUNNEL;
                r = KSL_OK;
                break;
            }
        }
    }
    free(list);
    FreeLibrary(lib);
    return r;
}

#else
#if defined(__linux__)
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#ifndef ARPHRD_IP6GRE
#define ARPHRD_IP6GRE 823
#endif

/* an interface of an encapsulating transition mechanism: IPv6 in IPv4 (sit: 6in4, 6rd, ISATAP), IP in IP and IP in IPv6
   (ipip, ip6tnl: DS-Lite), GRE over either family */
static int net_tunnel_type(unsigned short t) {
    return t == ARPHRD_TUNNEL || t == ARPHRD_TUNNEL6 || t == ARPHRD_SIT || t == ARPHRD_IPGRE || t == ARPHRD_IP6GRE;
}

/* whether the IPv6 address addr (of interface scope, 0 for any) is deprecated, from an RTM_GETADDR dump (netlink, no
   file: /proc/net is closed to Android apps): 1 or 0, -1 when the dump cannot be read or has no such address */
static int net_nl_deprecated(const uint8_t *addr, uint32_t scope) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return -1;
    struct {
        struct nlmsghdr nh;
        struct ifaddrmsg ifa;
    } req;
    memset(&req, 0, sizeof req);
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nh.nlmsg_type = RTM_GETADDR;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1;
    req.ifa.ifa_family = AF_INET6;
    struct sockaddr_nl to;
    memset(&to, 0, sizeof to);
    to.nl_family = AF_NETLINK;
    int found = -1;
    struct timeval tv = {1, 0}; /* a dump that never ends must not hold the caller: one second per read at most */
    struct sockaddr_nl me;
    socklen_t mel = sizeof me;
    memset(&me, 0, sizeof me);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0 ||
        sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&to, sizeof to) < 0 ||
        getsockname(fd, (struct sockaddr *)&me, &mel) != 0) {
        close(fd);
        return -1;
    }
    uint32_t buf[4096]; /* 16 KiB, aligned for nlmsghdr */
    int done = 0;
    for (int rounds = 0; !done && rounds < 1024; rounds++) {
        ssize_t got = recv(fd, buf, sizeof buf, 0);
        if (got <= 0)
            break;
        unsigned int left = (unsigned int)got;
        for (struct nlmsghdr *h = (struct nlmsghdr *)(void *)buf; NLMSG_OK(h, left); h = NLMSG_NEXT(h, left)) {
            if (h->nlmsg_seq != req.nh.nlmsg_seq || h->nlmsg_pid != me.nl_pid)
                continue; /* not the answer to this dump */
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) {
                done = 1;
                break;
            }
            if (h->nlmsg_type != RTM_NEWADDR || h->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifaddrmsg)))
                continue;
            const struct ifaddrmsg *ifa = (const struct ifaddrmsg *)NLMSG_DATA(h);
            if (ifa->ifa_family != AF_INET6 || (scope != 0 && ifa->ifa_index != scope))
                continue;
            uint32_t flags = ifa->ifa_flags;
            int match = 0;
            unsigned int rl = (unsigned int)IFA_PAYLOAD(h);
            for (struct rtattr *at = IFA_RTA(ifa); RTA_OK(at, rl); at = RTA_NEXT(at, rl)) {
                if ((at->rta_type == IFA_ADDRESS || at->rta_type == IFA_LOCAL) && RTA_PAYLOAD(at) == 16 &&
                    memcmp(RTA_DATA(at), addr, 16) == 0)
                    match = 1;
                else if (at->rta_type == IFA_FLAGS && RTA_PAYLOAD(at) >= 4)
                    memcpy(&flags, RTA_DATA(at), 4); /* the full flags; ifa_flags holds the low 8 bits */
            }
            if (match && found < 0)
                found = (flags & IFA_F_DEPRECATED) ? 1 : 0;
        }
    }
    close(fd);
    return found;
}

#elif defined(__APPLE__)
#include <net/if_dl.h>
#include <net/if_types.h>
#include <TargetConditionals.h>
#if TARGET_OS_OSX
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet6/in6_var.h>
#endif
#endif

int ksl_addr_info(const uint8_t *addr, size_t len, uint32_t scope, int *prefix_len, int *flags) {
    if (prefix_len)
        *prefix_len = -1;
    if (flags)
        *flags = 0;
    if (!addr || (len != 4 && len != 16) || !prefix_len || !flags)
        return KSL_ERROR;
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return KSL_ERROR;
    const struct ifaddrs *hit = NULL;
    for (const struct ifaddrs *i = list; i && !hit; i = i->ifa_next) {
        const struct sockaddr *sa = i->ifa_addr;
        if (!sa)
            continue;
        if (len == 16 && sa->sa_family == AF_INET6) {
            const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
            if (memcmp(&s->sin6_addr, addr, 16) == 0 && (scope == 0 || s->sin6_scope_id == scope))
                hit = i;
        } else if (len == 4 && sa->sa_family == AF_INET) {
            if (memcmp(&((const struct sockaddr_in *)sa)->sin_addr, addr, 4) == 0)
                hit = i;
        }
    }
    if (!hit) {
        freeifaddrs(list);
        return KSL_DNS_NOT_FOUND;
    }
    if (hit->ifa_netmask) {
        if (len == 16)
            *prefix_len =
                net_prefix_len((const uint8_t *)&((const struct sockaddr_in6 *)hit->ifa_netmask)->sin6_addr, 16);
        else
            *prefix_len = net_prefix_len((const uint8_t *)&((const struct sockaddr_in *)hit->ifa_netmask)->sin_addr, 4);
    }
    /* the link-layer entry of the same interface names its type */
    for (const struct ifaddrs *i = list; i; i = i->ifa_next) {
        if (!i->ifa_addr || !i->ifa_name || strcmp(i->ifa_name, hit->ifa_name) != 0)
            continue;
#if defined(__linux__)
        if (i->ifa_addr->sa_family == AF_PACKET &&
            net_tunnel_type(((const struct sockaddr_ll *)(const void *)i->ifa_addr)->sll_hatype))
            *flags |= KSL_ADDR_TUNNEL;
#elif defined(__APPLE__)
        if (i->ifa_addr->sa_family == AF_LINK) {
            unsigned char t = ((const struct sockaddr_dl *)(const void *)i->ifa_addr)->sdl_type;
            if (t == IFT_GIF || t == IFT_STF) /* gif: configured tunnels; stf: 6to4 */
                *flags |= KSL_ADDR_TUNNEL;
        }
#endif
    }
    if (len == 16) {
#if defined(__linux__)
        if (net_nl_deprecated(addr, scope) == 1)
            *flags |= KSL_ADDR_DEPRECATED;
#elif defined(__APPLE__) && TARGET_OS_OSX
        int fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct in6_ifreq q;
            memset(&q, 0, sizeof q);
            strncpy(q.ifr_name, hit->ifa_name, sizeof q.ifr_name - 1);
            memcpy(&q.ifr_addr, hit->ifa_addr, sizeof(struct sockaddr_in6));
            if (ioctl(fd, SIOCGIFAFLAG_IN6, &q) == 0 && (q.ifr_ifru.ifru_flags6 & IN6_IFF_DEPRECATED))
                *flags |= KSL_ADDR_DEPRECATED;
            close(fd);
        }
#endif
    }
    freeifaddrs(list);
    return KSL_OK;
}
#endif
