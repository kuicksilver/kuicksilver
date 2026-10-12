/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Entry point for the ksl C tests. Run from the repository root: tools/c-test.sh. Exit 0 only if every check passed. */
#include "test_common.h"
int failures = 0;

/* test-only helpers implemented in test_main.c */
size_t ksl_spki_der_for_test(const uint8_t *cert_der, size_t len, uint8_t *out, size_t cap);
int ksl_base64_equals_for_test(const uint8_t *bytes, size_t n, const char *b64, size_t b64len);

#include <openssl/x509.h>
#include <openssl/evp.h>
size_t ksl_spki_der_for_test(const uint8_t *cert_der, size_t len, uint8_t *out, size_t cap) {
    const unsigned char *p = cert_der; X509 *x = d2i_X509(NULL, &p, (long)len); if (!x) return 0;
    unsigned char *buf = NULL; int l = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &buf); X509_free(x);
    if (l <= 0 || (size_t)l > cap) { OPENSSL_free(buf); return 0; }
    memcpy(out, buf, (size_t)l); OPENSSL_free(buf); return (size_t)l;
}
int ksl_base64_equals_for_test(const uint8_t *bytes, size_t n, const char *b64, size_t b64len) {
    uint8_t dec[64]; int l = EVP_DecodeBlock(dec, (const unsigned char *)b64, (int)b64len - 1 /* trailing newline */);
    return l >= (int)n && !memcmp(dec, bytes, n);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    if (ksl_init() != KSL_OK) { printf("ksl_init failed\n"); return 2; }
    printf("%s (abi %u)\n", ksl_version(), ksl_abi_version());
    run_quic(); run_early(); run_key(); run_crypto(); run_udp();
#ifdef KSL_TEST_TCP
    run_tcp(); run_verify();
#endif
    if (failures) { printf("%d FAILURES\n", failures); return 1; }
    printf("ALL OK (0 failures)\n"); return 0;
}
