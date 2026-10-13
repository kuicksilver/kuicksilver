/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Findings of the 0.2.0 security review: framing bounds, keylog buffer growth, native session ticket keys. */
#include "test_common.h"
#include "ksl_internal.h"
#include <limits.h>

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

void run_security(void) { test_span_fits_never_wraps(); }
