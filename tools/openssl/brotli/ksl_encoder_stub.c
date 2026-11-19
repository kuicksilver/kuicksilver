/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_encoder_stub.c: the brotli encoder's entry points that OpenSSL's crypto/comp/c_brotli.c calls, for the builds that ship brotli's decoder only
   (Android and iOS; tools/openssl/compression.mk, ADR-0025). Each one fails: OpenSSL then compresses nothing with brotli, while it
   still decompresses it. ksl compresses a server's chain with zlib there and never compresses a client certificate
   (KSL_OPT_CERT_COMPRESSION). */
#include <brotli/encode.h>

BrotliEncoderState *BrotliEncoderCreateInstance(brotli_alloc_func alloc_func, brotli_free_func free_func, void *opaque) {
    (void)alloc_func;
    (void)free_func;
    (void)opaque;
    return NULL;
}
void BrotliEncoderDestroyInstance(BrotliEncoderState *state) {
    (void)state;
}
BROTLI_BOOL BrotliEncoderCompressStream(BrotliEncoderState *state, BrotliEncoderOperation op, size_t *available_in,
                                        const uint8_t **next_in, size_t *available_out, uint8_t **next_out,
                                        size_t *total_out) {
    (void)state;
    (void)op;
    (void)available_in;
    (void)next_in;
    (void)available_out;
    (void)next_out;
    (void)total_out;
    return BROTLI_FALSE;
}
BROTLI_BOOL BrotliEncoderHasMoreOutput(BrotliEncoderState *state) {
    (void)state;
    return BROTLI_FALSE;
}
BROTLI_BOOL BrotliEncoderCompress(int quality, int lgwin, BrotliEncoderMode mode, size_t input_size,
                                  const uint8_t input_buffer[], size_t *encoded_size, uint8_t encoded_buffer[]) {
    (void)quality;
    (void)lgwin;
    (void)mode;
    (void)input_size;
    (void)input_buffer;
    (void)encoded_size;
    (void)encoded_buffer;
    return BROTLI_FALSE;
}
