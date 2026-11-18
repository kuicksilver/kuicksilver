/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_compress.c: brotli's one-shot encoder at quality 9 at most (tools/openssl/compression.mk, ADR-0025). OpenSSL compresses a
   certificate chain (RFC 8879, SSL_CTX_compress_certs; a client certificate per handshake) with BrotliEncoderCompress at
   BROTLI_DEFAULT_QUALITY, 11: about 8.6 ms for the 13.7 KB test chain, against 1.4 ms at 9 for 6 % more bytes (1.7 % for an
   RSA-2048 leaf and intermediate). A server builds a context per identity, and per sniSelector answer, so a peer cycling
   server names could make it pay that per handshake (threat model 3.30). Upstream's function is renamed
   ksl_brotli_compress_upstream when enc/encode.c is compiled; nothing else calls the one-shot encoder. */
#include <brotli/encode.h>

#define KSL_BROTLI_CERT_QUALITY 9

BROTLI_BOOL ksl_brotli_compress_upstream(int quality, int lgwin, BrotliEncoderMode mode, size_t input_size,
                                         const uint8_t input_buffer[], size_t *encoded_size, uint8_t encoded_buffer[]);

BROTLI_BOOL BrotliEncoderCompress(int quality, int lgwin, BrotliEncoderMode mode, size_t input_size,
                                  const uint8_t input_buffer[], size_t *encoded_size, uint8_t encoded_buffer[]) {
    return ksl_brotli_compress_upstream(quality > KSL_BROTLI_CERT_QUALITY ? KSL_BROTLI_CERT_QUALITY : quality, lgwin, mode,
                                        input_size, input_buffer, encoded_size, encoded_buffer);
}
