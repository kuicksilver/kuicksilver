/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* KslCrypto helpers: rand, SHA-2, HKDF-Expand-Label (RFC 8446), ECDSA P-256, Ed25519, SPKI SHA-256. */
#include "test_common.h"
size_t ksl_spki_der_for_test(const uint8_t *cert_der, size_t len, uint8_t *out, size_t cap);
int ksl_base64_equals_for_test(const uint8_t *bytes, size_t n, const char *b64, size_t b64len);

static const uint8_t SHA256_ABC[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
static const uint8_t SHA384_ABC[48] = {0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7};
/* RFC 8448 section 3: client_handshake_traffic_secret -> "key" and "iv" (AES-128-GCM) */
static const uint8_t RFC8448_CHTS[32] = {0xb3,0xed,0xdb,0x12,0x6e,0x06,0x7f,0x35,0xa7,0x80,0xb3,0xab,0xf4,0x5e,0x2d,0x8f,0x3b,0x1a,0x95,0x07,0x38,0xf5,0x2e,0x96,0x00,0x74,0x6a,0x0e,0x27,0xa5,0x5a,0x21};
static const uint8_t RFC8448_KEY[16] = {0xdb,0xfa,0xa6,0x93,0xd1,0x76,0x2c,0x5b,0x66,0x6a,0xf5,0xd9,0x50,0x25,0x8d,0x01};
static const uint8_t RFC8448_IV[12] = {0x5b,0xd3,0xc7,0x1b,0x83,0x6e,0x0b,0x76,0xbb,0x73,0x26,0x5f};

void run_crypto(void) {
    SECTION("crypto_helpers");
    uint8_t a[64], b[64]; CHECK(ksl_rand(a, 32) == KSL_OK && ksl_rand(b, 32) == KSL_OK && memcmp(a, b, 32) != 0, "rand not repeating");
    uint8_t h[48]; CHECK(ksl_sha2(256, (const uint8_t *)"abc", 3, h) == KSL_OK && !memcmp(h, SHA256_ABC, 32), "sha256(abc)");
    CHECK(ksl_sha2(384, (const uint8_t *)"abc", 3, h) == KSL_OK && !memcmp(h, SHA384_ABC, 48), "sha384(abc)");
    CHECK(ksl_sha2(512, (const uint8_t *)"abc", 3, h) == KSL_ERROR, "negative: unsupported hash size");
    uint8_t k[16], iv[12];
    CHECK(ksl_hkdf_expand_label(KSL_HASH_SHA256, RFC8448_CHTS, 32, "key", NULL, 0, k, 16) == KSL_OK && !memcmp(k, RFC8448_KEY, 16), "RFC 8448 key");
    CHECK(ksl_hkdf_expand_label(KSL_HASH_SHA256, RFC8448_CHTS, 32, "iv", NULL, 0, iv, 12) == KSL_OK && !memcmp(iv, RFC8448_IV, 12), "RFC 8448 iv");
    /* ECDSA P-256 with the server test key; verify with its SPKI from the certificate */
    size_t kl; uint8_t *key = key_of("server", &kl); size_t cl; uint8_t *cert = read_file(TESTDATA "server.der", &cl);
    uint8_t sig[128]; size_t sl = sizeof sig; const uint8_t msg[] = "kuicksilver";
    CHECK(ksl_sign(KSL_SIG_ECDSA_P256, key, kl, msg, sizeof msg, sig, &sl) == KSL_OK && sl >= 64, "ecdsa sign");
    uint8_t spki[600]; size_t spl = ksl_spki_der_for_test(cert, cl, spki, sizeof spki);
    CHECK(spl > 0 && ksl_verify(KSL_SIG_ECDSA_P256, spki, spl, msg, sizeof msg, sig, sl) == 1, "ecdsa verify with the certificate's SPKI");
    sig[10] ^= 1; CHECK(ksl_verify(KSL_SIG_ECDSA_P256, spki, spl, msg, sizeof msg, sig, sl) == 0, "negative: tampered signature");
    uint8_t spki_hash[32]; size_t bl; uint8_t *b64 = read_file(TESTDATA "server.spki.sha256.b64", &bl);
    CHECK(ksl_spki_sha256(cert, cl, spki_hash) == KSL_OK && ksl_base64_equals_for_test(spki_hash, 32, (const char *)b64, bl), "spki sha256 matches openssl CLI");
    free(key); free(cert); free(b64);
    END();
}
