#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# ksl_resolve and ksl_nat64_synthesize on Apple's fallback lookup path: under a sandbox profile that keeps mDNSResponder out of
# reach, Libinfo answers from the hosts file through _gai_simple, which fails any lookup with AI_NUMERICSERV and no service
# (what a process without a bootstrap port, such as a simctl spawn --standalone test run, gets). localhost must still give
# 127.0.0.1 (A) and ::1 (AAAA). A control lookup with AI_NUMERICSERV and no service must fail there, or the profile no longer
# reaches the fallback path and the check would prove nothing. macOS only. Usage: tools/check/ksl-resolve-fallback.sh
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$(uname)" = Darwin ] || { echo "SKIP: ksl-resolve-fallback is macOS only"; exit 0; }
command -v sandbox-exec >/dev/null 2>&1 || { echo "SKIP: sandbox-exec not found"; exit 0; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
cat >"$tmp/main.c" <<'C'
#include "ksl.h"
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
static int fails;
static void check(int ok, const char *what) {
    printf("%s: %s\n", what, ok ? "OK" : "FAIL");
    fails += !ok;
}
int main(void) {
    struct addrinfo h, *res = NULL;
    memset(&h, 0, sizeof h);
    h.ai_family = AF_INET;
    h.ai_socktype = SOCK_STREAM;
    h.ai_flags = AI_NUMERICSERV;
    int rc = getaddrinfo("localhost", NULL, &h, &res);
    if (res)
        freeaddrinfo(res);
    check(rc != 0, "control: the fallback path is in use (AI_NUMERICSERV, no service fails)");
    uint8_t out[KSL_RESOLVE_ENTRY_LEN * 8];
    size_t len = 0;
    static const uint8_t lo4[4] = {127, 0, 0, 1}, lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    rc = ksl_resolve("localhost", KSL_ADDR_V4, out, sizeof out, &len);
    check(rc == KSL_OK && len >= KSL_RESOLVE_ENTRY_LEN && out[0] == KSL_ADDR_V4 && memcmp(out + 1, lo4, 4) == 0,
          "ksl_resolve localhost V4 is 127.0.0.1");
    rc = ksl_resolve("localhost", KSL_ADDR_V6, out, sizeof out, &len);
    check(rc == KSL_OK && len >= KSL_RESOLVE_ENTRY_LEN && out[0] == KSL_ADDR_V6 && memcmp(out + 1, lo6, 16) == 0,
          "ksl_resolve localhost V6 is ::1");
    static const uint8_t v4[4] = {192, 0, 2, 33};
    uint8_t s[64];
    len = 7;
    rc = ksl_nat64_synthesize(v4, s, sizeof s, &len);
    check(rc == KSL_DNS_NOT_FOUND && len == 0, "ksl_nat64_synthesize answers (nothing synthesized, no failed lookup)");
    return fails ? 1 : 0;
}
C
${CC:-clang} -std=c11 -Wall -Wextra -Werror -I"$root/kuicksilver-native/src/c" "$tmp/main.c" "$root/kuicksilver-native/src/c/ksl_net.c" -o "$tmp/fallback"
profile='(version 1)(allow default)(deny mach-lookup (global-name "com.apple.mDNSResponder"))(deny network-outbound (literal "/private/var/run/mDNSResponder"))'
sandbox-exec -p "$profile" "$tmp/fallback"
