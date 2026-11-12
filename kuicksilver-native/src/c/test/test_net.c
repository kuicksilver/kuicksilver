/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_resolve and ksl_addr_info: one family per query, arguments checked before any lookup, answers bounded by cap, and the
 * loopback addresses every host has (no network needed). */
#include "test_common.h"

/* whether out (len bytes of entries) holds the address a of the family */
static int net_has(const uint8_t *out, size_t len, int family, const uint8_t *a, size_t alen) {
    for (size_t p = 0; p + KSL_RESOLVE_ENTRY_LEN <= len; p += KSL_RESOLVE_ENTRY_LEN)
        if (out[p] == family && memcmp(out + p + 1, a, alen) == 0)
            return 1;
    return 0;
}

static void resolve_one_family(void) {
    uint8_t out[KSL_RESOLVE_ENTRY_LEN * 32];
    size_t len = 0;
    static const uint8_t lo4[4] = {127, 0, 0, 1};
    int r = ksl_resolve("127.0.0.1", KSL_ADDR_V4, out, sizeof out, &len);
    CHECK(r == KSL_OK && len == KSL_RESOLVE_ENTRY_LEN && net_has(out, len, KSL_ADDR_V4, lo4, 4), "an IPv4 literal, as IPv4");
    r = ksl_resolve("localhost", KSL_ADDR_V4, out, sizeof out, &len);
    CHECK(r == KSL_OK && len >= KSL_RESOLVE_ENTRY_LEN && len % KSL_RESOLVE_ENTRY_LEN == 0, "localhost has IPv4");
    int only_v4 = 1;
    for (size_t p = 0; p < len; p += KSL_RESOLVE_ENTRY_LEN)
        only_v4 &= out[p] == KSL_ADDR_V4;
    CHECK(only_v4, "an A query answers IPv4 only");
    len = 7;
    r = ksl_resolve("127.0.0.1", KSL_ADDR_V6, out, sizeof out, &len);
    CHECK((r == KSL_DNS_NOT_FOUND || r == KSL_ERROR) && len == 0, "an IPv4 literal has no IPv6 address");
    static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    r = ksl_resolve("::1", KSL_ADDR_V6, out, sizeof out, &len);
    CHECK(r == KSL_OK && len == KSL_RESOLVE_ENTRY_LEN && net_has(out, len, KSL_ADDR_V6, lo6, 16), "an IPv6 literal, as IPv6");
}

static void resolve_bad_arguments(void) {
    uint8_t out[KSL_RESOLVE_ENTRY_LEN * 4];
    size_t len = 9;
    CHECK(ksl_resolve(NULL, KSL_ADDR_V4, out, sizeof out, &len) == KSL_ERROR && len == 0, "no name");
    CHECK(ksl_resolve("a b.example", KSL_ADDR_V4, out, sizeof out, &len) == KSL_ERROR, "a bad name is refused");
    CHECK(ksl_resolve("a..example", KSL_ADDR_V6, out, sizeof out, &len) == KSL_ERROR, "an empty label is refused");
    CHECK(ksl_resolve("localhost", 5, out, sizeof out, &len) == KSL_ERROR, "an unknown family");
    CHECK(ksl_resolve("localhost", KSL_ADDR_V4, NULL, 64, &len) == KSL_ERROR, "no buffer");
    CHECK(ksl_resolve("localhost", KSL_ADDR_V4, out, sizeof out, NULL) == KSL_ERROR, "no length");
    len = 9;
    CHECK(ksl_resolve("127.0.0.1", KSL_ADDR_V4, out, KSL_RESOLVE_ENTRY_LEN - 1, &len) == KSL_ERROR && len == 0,
          "an answer over cap fails, nothing written past it");
}

static void addr_info_loopback(void) {
    static const uint8_t lo4[4] = {127, 0, 0, 1};
    int plen = 0, flags = -1;
    int r = ksl_addr_info(lo4, 4, 0, &plen, &flags);
    CHECK(r == KSL_OK && plen == 8 && !(flags & KSL_ADDR_TUNNEL) && !(flags & KSL_ADDR_DEPRECATED), "127.0.0.1 is 127/8");
    static const uint8_t doc4[4] = {192, 0, 2, 1};
    plen = 0;
    CHECK(ksl_addr_info(doc4, 4, 0, &plen, &flags) == KSL_DNS_NOT_FOUND && plen == -1 && flags == 0,
          "an address of no interface is not found");
    static const uint8_t doc6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    CHECK(ksl_addr_info(doc6, 16, 0, &plen, &flags) == KSL_DNS_NOT_FOUND, "an IPv6 address of no interface");
    CHECK(ksl_addr_info(lo4, 5, 0, &plen, &flags) == KSL_ERROR, "an address of 5 bytes");
    CHECK(ksl_addr_info(NULL, 4, 0, &plen, &flags) == KSL_ERROR, "no address");
    CHECK(ksl_addr_info(lo4, 4, 0, NULL, &flags) == KSL_ERROR, "no prefix length");
}

void run_net(void) {
    SECTION("net");
    resolve_one_family();
    resolve_bad_arguments();
    addr_info_loopback();
    END();
}
