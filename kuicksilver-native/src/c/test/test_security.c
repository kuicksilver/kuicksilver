/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Findings of the 0.2.0 security review: framing bounds, keylog buffer growth, native session ticket keys. */
#include "test_common.h"
#include "ksl_internal.h"
#include <limits.h>
void ksl_secret_move(void *dst, void *old, size_t used, size_t old_cap);   /* ksl_ctx.c */

/* review finding 10: a 32-bit length field near 2^32 must not wrap the bounds check (32-bit size_t, armeabi-v7a). The same
   arithmetic is checked here with SIZE_MAX-sized values, which wrap on any size_t. */
static void test_span_fits_never_wraps(void) {
    SECTION("negative_frameLengthDoesNotWrap");
    CHECK(ksl_span_fits(4, 12, 16), "a span that fits");
    CHECK(ksl_span_fits(16, 0, 16), "an empty span at the end fits");
    CHECK(!ksl_span_fits(4, 13, 16), "one byte too long");
    CHECK(!ksl_span_fits(8, SIZE_MAX - 3, 16), "negative: off + n wraps to a small value");
    CHECK(!ksl_span_fits(4, SIZE_MAX, 16), "negative: n = SIZE_MAX");
    CHECK(!ksl_span_fits(17, 0, 16), "negative: off past the end");
    /* a framed chain whose length field claims 0xffffffff bytes is refused, not parsed */
    uint8_t framed[8] = {0xff, 0xff, 0xff, 0xff, 0x30, 0x03, 0x02, 0x01};
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT);
    CHECK(ksl_ctx_set_roots(c, framed, sizeof framed) == KSL_ERROR, "negative: a huge frame length is refused");
    ksl_ctx_free(c);
    END();
}

/* review finding 11: the keylog buffer holds TLS secrets; growing it must leave no copy behind in the freed block (realloc did) */
static void test_secret_buffer_growth_wipes_old_block(void) {
    SECTION("negative_keylogGrowthLeavesNoCopy");
    char old[64]; memset(old, 'S', sizeof old);
    char *grown = malloc(128); CHECK(grown != NULL, "allocated");
    ksl_secret_move(grown, old, 40, sizeof old);
    CHECK(!memcmp(grown, "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS", 40), "the used bytes are copied");
    int clean = 1; for (size_t i = 0; i < sizeof old; i++) clean &= old[i] == 0;
    CHECK(clean, "negative: the old block (all of its capacity) is zeroed before it is freed");
    free(grown);
    /* a real handshake: every keylog line survives several growth steps */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
    ksl_ctx_set_option(sc, KSL_OPT_KEYLOG, 1);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", 11); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", 11);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP);
    side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 50, NULL, NULL); CHECK(cs.done && ss.done, "handshake completes");
    char log[4096]; size_t n = 0; CHECK(ksl_ssl_get(s, KSL_GET_KEYLOG, (uint8_t *)log, sizeof log - 1, &n) == KSL_OK, "keylog read"); log[n] = 0;
    int lines = 0; for (size_t i = 0; i < n; i++) lines += log[i] == '\n';
    CHECK(lines >= 4 && strstr(log, "SERVER_TRAFFIC_SECRET_0 ") && strstr(log, "CLIENT_HANDSHAKE_TRAFFIC_SECRET "), "every secret line is kept across growth");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    END();
}

void run_security(void) { test_span_fits_never_wraps(); test_secret_buffer_growth_wipes_old_block(); }
