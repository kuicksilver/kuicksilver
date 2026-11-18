/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Replaces brotli's enc/static_init.c (tools/openssl/compression.mk, ADR-0025). The encoder is built with
   BROTLI_STATIC_INIT_LAZY: its static dictionary lookup tables (about 290 KB) are computed when they are first needed instead of
   being shipped. Upstream leaves the call of that computation to the embedder (a C++11 function-local static in
   static_init_lazy.cc), and OpenSSL makes no such call, so here the check every encoder instance makes on creation
   (BrotliEncoderEnsureStaticInit, encode.c) runs the computation once, under CRYPTO_THREAD_run_once: concurrent first encoders
   wait for it and then see the tables (the once primitive orders the writes before every return). */
#include <openssl/crypto.h>
#include "../common/dictionary.h"
#include "../common/platform.h"
#include "../common/static_init.h"
#include "dictionary_hash.h"
#include "static_dict_lut.h"
#include "static_init.h"

#if BROTLI_STATIC_INIT != BROTLI_STATIC_INIT_LAZY
#error "ksl_static_init.c is built with BROTLI_STATIC_INIT_LAZY only"
#endif

static CRYPTO_ONCE ksl_brotli_once = CRYPTO_ONCE_STATIC_INIT;
static BROTLI_BOOL ksl_brotli_ok;

static void ksl_brotli_init(void) {
    const BrotliDictionary *dict = BrotliGetDictionary();
    ksl_brotli_ok = BrotliEncoderInitStaticDictionaryLut(dict, kStaticDictionaryBuckets, kStaticDictionaryWords) &&
                    BrotliEncoderInitDictionaryHash(dict, kStaticDictionaryHashWords, kStaticDictionaryHashLengths);
}

void BrotliEncoderLazyStaticInitInner(void) {
    ksl_brotli_init();
}
void BrotliEncoderLazyStaticInit(void) {
    CRYPTO_THREAD_run_once(&ksl_brotli_once, ksl_brotli_init);
}
BROTLI_BOOL BrotliEncoderEnsureStaticInit(void) {
    return CRYPTO_THREAD_run_once(&ksl_brotli_once, ksl_brotli_init) && ksl_brotli_ok ? BROTLI_TRUE : BROTLI_FALSE;
}
