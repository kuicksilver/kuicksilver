/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_decompress.c: brotli's one-shot decoder with a bounded allocator (tools/openssl/compression.mk, ADR-0025). OpenSSL decodes a
   peer's brotli CompressedCertificate (RFC 8879) with BrotliDecoderDecompress into a buffer of the announced uncompressed_length.
   brotli 1.2.1 sizes its ring buffer by the meta-block length the stream declares, so 68 bytes can make it allocate about 16.8 MiB
   whatever that length is; RFC 8879 section 5: implementations "SHOULD bound the memory usage when decompressing". This
   BrotliDecoderDecompress (upstream's is renamed ksl_brotli_decompress_upstream when dec/decode.c is compiled) runs the same
   streaming decoder with allocations capped at 3 x the output size + 256 KiB: an honest stream's ring buffer is at most the next
   power of two above what it writes (2 x), 1.5 x that for the moment it grows, and its tables are a few dozen KiB. A stream
   that asks for more fails, as one that does not fit the output does. */
#include <stdlib.h>
#include <brotli/decode.h>

#define KSL_BROTLI_SLACK (256u * 1024u)

typedef struct {
    size_t cap, used, peak;
} ksl_brotli_budget;

/* the largest total of live allocations of the last call (read by the C tests) */
size_t ksl_brotli_decode_peak;

static void *ksl_brotli_alloc(void *opaque, size_t n) {
    ksl_brotli_budget *b = opaque;
    if (n > b->cap - b->used || n > SIZE_MAX - 16)
        return NULL;
    size_t *p = malloc(n + 16);
    if (p == NULL)
        return NULL;
    p[0] = n;
    b->used += n;
    if (b->used > b->peak)
        b->peak = b->used;
    return (unsigned char *)p + 16;
}

static void ksl_brotli_free(void *opaque, void *address) {
    ksl_brotli_budget *b = opaque;
    if (address == NULL)
        return;
    size_t *p = (size_t *)(void *)((unsigned char *)address - 16);
    b->used -= p[0];
    free(p);
}

/* the budget for an output of `decoded` bytes; SIZE_MAX / 4 and above saturate */
size_t ksl_brotli_decode_budget(size_t decoded) {
    if (decoded > (SIZE_MAX - KSL_BROTLI_SLACK) / 3)
        return SIZE_MAX;
    return decoded * 3 + KSL_BROTLI_SLACK;
}

BrotliDecoderResult BrotliDecoderDecompress(size_t encoded_size, const uint8_t encoded_buffer[], size_t *decoded_size,
                                            uint8_t decoded_buffer[]) {
    ksl_brotli_budget b = {ksl_brotli_decode_budget(*decoded_size), 0, 0};
    BrotliDecoderState *s = BrotliDecoderCreateInstance(ksl_brotli_alloc, ksl_brotli_free, &b);
    if (s == NULL)
        return BROTLI_DECODER_RESULT_ERROR;
    size_t total_out = 0, available_in = encoded_size, available_out = *decoded_size;
    const uint8_t *next_in = encoded_buffer;
    uint8_t *next_out = decoded_buffer;
    BrotliDecoderResult result =
        BrotliDecoderDecompressStream(s, &available_in, &next_in, &available_out, &next_out, &total_out);
    *decoded_size = total_out;
    BrotliDecoderDestroyInstance(s);
    ksl_brotli_decode_peak = b.peak;
    return result == BROTLI_DECODER_RESULT_SUCCESS ? result : BROTLI_DECODER_RESULT_ERROR;
}
