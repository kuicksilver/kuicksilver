/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_dns_query: one record type of one name from the operating system's resolver (HTTPS records, RFC 9460). Linux asks
 * res_nquery (libresolv) and returns the whole DNS message; Apple asks DNSServiceQueryRecord (libSystem) and Windows
 * DnsQuery_W (dnsapi), which hand out records, not messages, so those come back as a list. Android has no public call for
 * it below API 29 and Kotlin asks DnsResolver there: KSL_DNS_NOT_SUPPORTED. No state, no threads: the call blocks its caller
 * for at most about timeout_ms (Linux and Apple; Windows takes no timeout, the caller stops waiting instead). */
#if defined(__linux__) && !defined(__ANDROID__)
#define _GNU_SOURCE   /* res_ninit and struct __res_state in glibc's resolv.h */
#endif
#include "ksl.h"
#include <string.h>
#include <limits.h>

/* a name the resolvers may be given: 1..253 printable ASCII bytes without spaces, labels of 1..63 bytes; checked before any call */
static int dns_name_ok(const char *name, size_t *out_len) {
    if (!name) return 0;
    size_t n = 0, label = 0;
    for (; n < 254 && name[n]; n++) {
        unsigned char c = (unsigned char)name[n];
        if (c <= 0x20 || c >= 0x7f) return 0;
        if (c == '.') { if (label == 0) return 0; label = 0; } else if (++label > 63) return 0;
    }
    if (n == 0 || n > 253 || name[n]) return 0;
    if (out_len) *out_len = n;
    return 1;
}

#if defined(__APPLE__) || defined(_WIN32)
/* the list form: ttl:4 BE | owner length:1 | owner (presentation form, no final dot) | rdata length:2 BE | rdata */
static int dns_append(uint8_t *out, size_t cap, size_t *at, uint32_t ttl, const char *owner, size_t owner_len, const uint8_t *rd, size_t rdlen) {
    if (owner_len > 255 || rdlen > 65535) return KSL_ERROR;
    size_t need = 4 + 1 + owner_len + 2 + rdlen;
    if (*at > cap || need > cap - *at) return KSL_ERROR;
    uint8_t *p = out + *at;
    p[0] = (uint8_t)(ttl >> 24); p[1] = (uint8_t)(ttl >> 16); p[2] = (uint8_t)(ttl >> 8); p[3] = (uint8_t)ttl;
    p[4] = (uint8_t)owner_len; if (owner_len) memcpy(p + 5, owner, owner_len);
    p[5 + owner_len] = (uint8_t)(rdlen >> 8); p[6 + owner_len] = (uint8_t)rdlen;
    if (rdlen) memcpy(p + 7 + owner_len, rd, rdlen);
    *at += need;
    return KSL_OK;
}
#endif

#if defined(__linux__) && !defined(__ANDROID__)
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

int ksl_dns_query(const char *name, uint16_t type, const uint8_t *server, int timeout_ms, uint8_t *out, size_t cap, size_t *len) {
    if (len) *len = 0;
    if (!dns_name_ok(name, NULL) || !out || !len || cap < 1 + 12 || timeout_ms <= 0) return KSL_ERROR;
    if (server && server[0] != 4) return KSL_DNS_NOT_SUPPORTED;   /* an IPv6 server would need the glibc-private _u._ext */
    struct __res_state st; memset(&st, 0, sizeof st);
    if (res_ninit(&st) != 0) { res_nclose(&st); return KSL_ERROR; }
    int secs = timeout_ms / 1000 / 2;
    st.retrans = secs < 1 ? 1 : secs;   /* per try, in seconds; two tries */
    st.retry = 2;
    if (server) {
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; memcpy(&a.sin_port, server + 2, 2); memcpy(&a.sin_addr, server + 4, 4);   /* KSL_UDP_ADDR_LEN: family, port BE, address */
        st.nsaddr_list[0] = a; st.nscount = 1;
    }
    size_t room = cap - 1; if (room > INT_MAX) room = INT_MAX;
    int n = res_nquery(&st, name, C_IN, type, out + 1, (int)room);
    int herr = st.res_h_errno;
    res_nclose(&st);
    if (n < 0) return herr == HOST_NOT_FOUND || herr == NO_DATA ? KSL_DNS_NOT_FOUND : KSL_ERROR;
    if ((size_t)n > room) return KSL_ERROR;   /* res_nquery reports the full length of an answer it cut */
    out[0] = KSL_DNS_MESSAGE; *len = (size_t)n + 1;
    return KSL_OK;
}

#elif defined(__APPLE__)
#include <dns_sd.h>
#include <poll.h>
#include <errno.h>
#include <time.h>

typedef struct { uint16_t type; uint8_t *out; size_t cap, at; int result, done, records; } dns_acc;

static void DNSSD_API dns_on_record(DNSServiceRef ref, DNSServiceFlags flags, uint32_t ifi, DNSServiceErrorType err, const char *fullname,
                                    uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *ctx) {
    (void)ref; (void)ifi; (void)rrclass;
    dns_acc *a = ctx;
    if (err == kDNSServiceErr_NoSuchRecord || err == kDNSServiceErr_NoSuchName) {
        if (a->result == KSL_OK && !a->records) a->result = KSL_DNS_NOT_FOUND;   /* a negative answer, delivered with ReturnIntermediates */
    } else if (err != kDNSServiceErr_NoError) {
        a->result = KSL_ERROR;
    } else if ((flags & kDNSServiceFlagsAdd) && rrtype == a->type && a->result != KSL_ERROR) {
        size_t olen = 0; while (fullname && olen < 256 && fullname[olen]) olen++;
        if (olen > 1 && fullname[olen - 1] == '.') olen--;   /* mDNSResponder names end in a dot */
        if (dns_append(a->out, a->cap, &a->at, ttl, fullname, olen, rdata, rdlen) != KSL_OK) a->result = KSL_ERROR;
        else { a->records++; a->result = KSL_OK; }
    }
    if (!(flags & kDNSServiceFlagsMoreComing)) a->done = 1;
}

static int64_t dns_now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000; }

int ksl_dns_query(const char *name, uint16_t type, const uint8_t *server, int timeout_ms, uint8_t *out, size_t cap, size_t *len) {
    if (len) *len = 0;
    if (!dns_name_ok(name, NULL) || !out || !len || cap < 1 || timeout_ms <= 0) return KSL_ERROR;
    if (server) return KSL_DNS_NOT_SUPPORTED;   /* mDNSResponder asks the system's resolvers only */
    dns_acc a = { type, out, cap, 1, KSL_OK, 0, 0 };   /* out[0] holds the kind */
    DNSServiceRef ref = NULL;
    if (DNSServiceQueryRecord(&ref, kDNSServiceFlagsReturnIntermediates, 0, name, type, kDNSServiceClass_IN, dns_on_record, &a) != kDNSServiceErr_NoError)
        return KSL_ERROR;
    int fd = DNSServiceRefSockFD(ref);
    int64_t deadline = dns_now_ms() + timeout_ms;
    int r = KSL_OK;
    while (!a.done) {
        int64_t left = deadline - dns_now_ms();
        if (left <= 0 || fd < 0) { r = KSL_ERROR; break; }
        struct pollfd p = { fd, POLLIN, 0 };
        int n = poll(&p, 1, (int)left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { r = KSL_ERROR; break; }   /* the deadline passed (or poll failed) */
        if (DNSServiceProcessResult(ref) != kDNSServiceErr_NoError) { r = KSL_ERROR; break; }
    }
    DNSServiceRefDeallocate(ref);
    if (r != KSL_OK) return r;
    if (a.result != KSL_OK) return a.result;
    out[0] = KSL_DNS_RECORDS; *len = a.at;
    return KSL_OK;
}

#elif defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <windns.h>

int ksl_dns_query(const char *name, uint16_t type, const uint8_t *server, int timeout_ms, uint8_t *out, size_t cap, size_t *len) {
    if (len) *len = 0;
    size_t nlen = 0;
    if (!dns_name_ok(name, &nlen) || !out || !len || cap < 1 || timeout_ms <= 0) return KSL_ERROR;
    /* DnsQuery_W takes IPv4 servers on port 53 only */
    if (server && (server[0] != 4 || server[2] != 0 || server[3] != 53)) return KSL_DNS_NOT_SUPPORTED;
    WCHAR wname[256];
    for (size_t i = 0; i <= nlen; i++) wname[i] = (WCHAR)(unsigned char)name[i];   /* ASCII, checked above; the loop copies the NUL */
    IP4_ARRAY servers; memset(&servers, 0, sizeof servers);
    if (server) { servers.AddrCount = 1; memcpy(&servers.AddrArray[0], server + 4, 4); }
    PDNS_RECORD rec = NULL;   /* DnsQuery_W fills it with DNS_RECORDW entries whatever UNICODE says */
    /* without DNS_QUERY_PARSE_ALL_RECORDS an HTTPS record comes as its raw RDATA on Windows 10 and 11 alike */
    DNS_STATUS s = DnsQuery_W(wname, type, DNS_QUERY_STANDARD, server ? &servers : NULL, &rec, NULL);
    if (s == DNS_ERROR_RCODE_NAME_ERROR || s == DNS_INFO_NO_RECORDS) { if (rec) DnsRecordListFree(rec, DnsFreeRecordList); return KSL_DNS_NOT_FOUND; }
    if (s != 0) { if (rec) DnsRecordListFree(rec, DnsFreeRecordList); return KSL_ERROR; }
    size_t at = 1; int r = KSL_OK, records = 0;
    for (PDNS_RECORDW p = (PDNS_RECORDW)rec; p && r == KSL_OK; p = p->pNext) {
        if (p->wType != type || p->Flags.S.Section != DnsSectionAnswer) continue;
        char owner[256]; size_t olen = 0;
        for (const WCHAR *w = p->pName; w && *w && olen < sizeof owner; w++) owner[olen++] = *w < 0x80 ? (char)*w : '?';
        if (olen > 1 && owner[olen - 1] == '.') olen--;
        r = dns_append(out, cap, &at, p->dwTtl, owner, olen, (const uint8_t *)&p->Data, p->wDataLength);
        records++;
    }
    DnsRecordListFree(rec, DnsFreeRecordList);
    if (r != KSL_OK) return r;
    if (!records) return KSL_DNS_NOT_FOUND;
    out[0] = KSL_DNS_RECORDS; *len = at;
    (void)timeout_ms;
    return KSL_OK;
}

#else   /* Android (DnsResolver from Kotlin), and anything else */
int ksl_dns_query(const char *name, uint16_t type, const uint8_t *server, int timeout_ms, uint8_t *out, size_t cap, size_t *len) {
    (void)name; (void)type; (void)server; (void)timeout_ms; (void)out; (void)cap; (void)dns_name_ok;
    if (len) *len = 0;
    return KSL_DNS_NOT_SUPPORTED;
}
#endif
