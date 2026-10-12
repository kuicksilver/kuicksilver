/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* RFC 9001 and RFC 9369 Appendix A vectors through ksl_key_*, ksl_seal/open, ksl_header_mask, ksl_retry_tag. */
#include "test_common.h"
#include "vectors_rfc9001.h"
#include "vectors_rfc9369.h"

#define VEC(T, name) T##_##name
#define RUN_VECTORS(T) do { \
    SECTION(#T "_appendix_a"); \
    ksl_key *cw = ksl_key_initial(VEC(T, DCID), sizeof VEC(T, DCID), 0, KSL_DIR_WRITE, T##_VERSION); \
    ksl_key *sr = ksl_key_initial(VEC(T, DCID), sizeof VEC(T, DCID), 1, KSL_DIR_READ, T##_VERSION); \
    ksl_key *sw = ksl_key_initial(VEC(T, DCID), sizeof VEC(T, DCID), 1, KSL_DIR_WRITE, T##_VERSION); \
    ksl_key *cr = ksl_key_initial(VEC(T, DCID), sizeof VEC(T, DCID), 0, KSL_DIR_READ, T##_VERSION); \
    CHECK(cw && sr && sw && cr, "initial keys derived"); \
    /* A.2: client Initial, payload = CRYPTO + PADDING to 1162, pn 2 */ \
    uint8_t pl[1200]; memset(pl, 0, sizeof pl); memcpy(pl, VEC(T, A2_CRYPTO), sizeof VEC(T, A2_CRYPTO)); \
    int n = ksl_seal(cw, T##_A2_PN, VEC(T, A2_HEADER), sizeof VEC(T, A2_HEADER), pl, 1162, sizeof pl); \
    CHECK(n == 1178, "A.2 sealed length 1178"); \
    CHECK(!memcmp(pl, VEC(T, A2_PROTECTED) + sizeof VEC(T, A2_HEADER), 1178), "A.2 ciphertext + tag byte-exact"); \
    uint8_t mask[5]; CHECK(ksl_header_mask(cw, VEC(T, A2_SAMPLE), mask) == KSL_OK && !memcmp(mask, VEC(T, A2_MASK), 5), "A.2 header protection mask"); \
    uint8_t hdr[22]; memcpy(hdr, VEC(T, A2_HEADER), 22); hdr[0] ^= mask[0] & 0x0f; for (int i = 0; i < 4; i++) hdr[18 + i] ^= mask[1 + i]; \
    CHECK(!memcmp(hdr, VEC(T, A2_PROTECTED_HEADER), 22), "A.2 protected header"); \
    int m = ksl_open(sr, T##_A2_PN, VEC(T, A2_HEADER), sizeof VEC(T, A2_HEADER), pl, 1178); \
    CHECK(m == 1162 && !memcmp(pl, VEC(T, A2_CRYPTO), sizeof VEC(T, A2_CRYPTO)), "A.2 opened by the server read key"); \
    pl[100] ^= 1; CHECK(ksl_open(sr, T##_A2_PN, VEC(T, A2_HEADER), sizeof VEC(T, A2_HEADER), pl, 1178) == KSL_ERROR, "negative: corrupted ciphertext rejected"); \
    /* A.3: server Initial, pn 1 */ \
    uint8_t s3[200]; memcpy(s3, VEC(T, A3_PAYLOAD), sizeof VEC(T, A3_PAYLOAD)); \
    n = ksl_seal(sw, T##_A3_PN, VEC(T, A3_HEADER), sizeof VEC(T, A3_HEADER), s3, sizeof VEC(T, A3_PAYLOAD), sizeof s3); \
    CHECK(n == (int)sizeof VEC(T, A3_PAYLOAD) + 16 && !memcmp(s3, VEC(T, A3_PROTECTED) + sizeof VEC(T, A3_HEADER), (size_t)n), "A.3 server Initial byte-exact"); \
    CHECK(ksl_header_mask(sw, VEC(T, A3_SAMPLE), mask) == KSL_OK && !memcmp(mask, VEC(T, A3_MASK), 5), "A.3 mask"); \
    CHECK(ksl_open(cr, T##_A3_PN, VEC(T, A3_HEADER), sizeof VEC(T, A3_HEADER), s3, (size_t)n) == (int)sizeof VEC(T, A3_PAYLOAD), "A.3 opened by the client"); \
    /* A.4: Retry integrity tag over (odcid_len || odcid || retry packet without tag) */ \
    uint8_t pseudo[64]; pseudo[0] = 8; memcpy(pseudo + 1, VEC(T, DCID), 8); memcpy(pseudo + 9, VEC(T, A4_RETRY), sizeof VEC(T, A4_RETRY) - 16); \
    uint8_t tag[16]; CHECK(ksl_retry_tag(T##_VERSION, VEC(T, DCID), 8, pseudo, 9 + sizeof VEC(T, A4_RETRY) - 16, tag) == KSL_OK && !memcmp(tag, VEC(T, A4_RETRY) + sizeof VEC(T, A4_RETRY) - 16, 16), "A.4 retry tag"); \
    ksl_key_free(cw); ksl_key_free(sr); ksl_key_free(sw); ksl_key_free(cr); \
    END(); \
} while (0)

/* A.5: ChaCha20-Poly1305 short header from an application secret; A.6-style key update via ksl_key_next. */
#define RUN_CHACHA(T) do { \
    SECTION(#T "_a5_chacha20_and_key_update"); \
    uint8_t key[32], iv[12], hp[32], ku[32]; \
    CHECK(ksl_hkdf_expand_label(KSL_HASH_SHA256, VEC(T, A5_SECRET), 32, T##_VERSION == 1u ? "quic key" : "quicv2 key", NULL, 0, key, 32) == KSL_OK && !memcmp(key, VEC(T, A5_KEY), 32), "A.5 key"); \
    CHECK(ksl_hkdf_expand_label(KSL_HASH_SHA256, VEC(T, A5_SECRET), 32, T##_VERSION == 1u ? "quic iv" : "quicv2 iv", NULL, 0, iv, 12) == KSL_OK && !memcmp(iv, VEC(T, A5_IV), 12), "A.5 iv"); \
    CHECK(ksl_hkdf_expand_label(KSL_HASH_SHA256, VEC(T, A5_SECRET), 32, T##_VERSION == 1u ? "quic hp" : "quicv2 hp", NULL, 0, hp, 32) == KSL_OK && !memcmp(hp, VEC(T, A5_HP), 32), "A.5 hp"); \
    CHECK(ksl_hkdf_expand_label(KSL_HASH_SHA256, VEC(T, A5_SECRET), 32, T##_VERSION == 1u ? "quic ku" : "quicv2 ku", NULL, 0, ku, 32) == KSL_OK && !memcmp(ku, VEC(T, A5_KU), 32), "A.5 ku"); \
    ksl_key *k = ksl_key_from_secret_for_test(KSL_AEAD_CHACHA20_POLY1305, VEC(T, A5_SECRET), 32, T##_VERSION); \
    uint8_t p[32] = {0x01}; int n = ksl_seal(k, T##_A5_PN, VEC(T, A5_HEADER), 4, p, 1, sizeof p); \
    CHECK(n == 17 && !memcmp(p, VEC(T, A5_CIPHERTEXT), 17), "A.5 ChaCha20 ciphertext"); \
    uint8_t mask[5]; CHECK(ksl_header_mask(k, VEC(T, A5_SAMPLE), mask) == KSL_OK && !memcmp(mask, VEC(T, A5_MASK), 5), "A.5 ChaCha20 mask"); \
    ksl_key *k2 = ksl_key_next(k); uint8_t q[32] = {0x01}; \
    CHECK(k2 && ksl_seal(k2, T##_A5_PN, VEC(T, A5_HEADER), 4, q, 1, sizeof q) == 17 && memcmp(q, VEC(T, A5_CIPHERTEXT), 17) != 0, "next generation encrypts differently"); \
    uint8_t mask2[5]; CHECK(ksl_header_mask(k2, VEC(T, A5_SAMPLE), mask2) == KSL_OK && !memcmp(mask2, mask, 5), "header protection key unchanged after key update"); \
    ksl_key_free(k); ksl_key_free(k2); \
    END(); \
} while (0)

/* test-only hook exported by ksl_key.c: builds a key from a TLS secret (what the KEY event does internally) */
ksl_key *ksl_key_from_secret_for_test(int aead, const uint8_t *secret, size_t slen, uint32_t version);

void run_key(void) {
    RUN_VECTORS(RFC9001); RUN_VECTORS(RFC9369);
    RUN_CHACHA(RFC9001); RUN_CHACHA(RFC9369);
    SECTION("key_negative_controls");
    ksl_key *k = ksl_key_initial(RFC9001_DCID, 8, 0, KSL_DIR_WRITE, 0x00000001u); uint8_t buf[64] = {0};
    CHECK(ksl_seal(k, 1, buf, 4, buf + 8, 50, 60) == KSL_ERROR, "negative: no room for the tag");
    CHECK(ksl_open(k, 1, buf, 4, buf, 15) == KSL_ERROR, "negative: shorter than a tag");
    CHECK(ksl_key_initial(RFC9001_DCID, 8, 0, KSL_DIR_WRITE, 0xdeadbeefu) == NULL, "negative: unknown version");
    ksl_key_free(k); END();

    /* K3: endpoint keys (Retry tokens, stateless reset) generated and kept inside ksl */
    { SECTION("endpoint_keys");
    ksl_key *t1 = ksl_key_random(KSL_EKEY_TOKEN), *t2 = ksl_key_random(KSL_EKEY_TOKEN), *r1 = ksl_key_random(KSL_EKEY_RESET), *r2 = ksl_key_random(KSL_EKEY_RESET);
    CHECK(t1 && t2 && r1 && r2, "random endpoint keys created");
    const uint8_t aad[7] = {1, 10, 0, 0, 1, 0x1f, 0x90}; uint8_t tok[48] = {0}; memcpy(tok, "token-plaintext", 15);
    int sealed = ksl_seal(t1, 0x0102030405060708ull, aad, sizeof aad, tok, 15, sizeof tok);
    CHECK(sealed == 31, "ekey_token_seal_open_roundtrip: sealed = plaintext + 16");
    uint8_t copy[48]; memcpy(copy, tok, sizeof tok);
    CHECK(ksl_open(t1, 0x0102030405060708ull, aad, sizeof aad, copy, 31) == 15 && !memcmp(copy, "token-plaintext", 15), "ekey_token_seal_open_roundtrip: opened");
    uint8_t aad2[7]; memcpy(aad2, aad, 7); aad2[6] ^= 1; memcpy(copy, tok, sizeof tok);
    CHECK(ksl_open(t1, 0x0102030405060708ull, aad2, sizeof aad2, copy, 31) == KSL_ERROR, "ekey_token_wrong_aad_fails");
    uint8_t tok2[48] = {0}; memcpy(tok2, "token-plaintext", 15); CHECK(ksl_seal(t2, 0x0102030405060708ull, aad, sizeof aad, tok2, 15, sizeof tok2) == 31 && memcmp(tok, tok2, 31) != 0, "ekey_token_two_keys_differ");
    const uint8_t cid[8] = {1, 2, 3, 4, 5, 6, 7, 8}; uint8_t m1[16], m1b[16], m2[16];
    CHECK(ksl_key_mac16(r1, cid, 8, m1) == KSL_OK && ksl_key_mac16(r1, cid, 8, m1b) == KSL_OK && !memcmp(m1, m1b, 16), "ekey_reset_mac16_is_stable");
    CHECK(ksl_key_mac16(r2, cid, 8, m2) == KSL_OK && memcmp(m1, m2, 16) != 0, "ekey_reset_mac16_differs_across_keys");
    uint8_t junk[32] = {0}; CHECK(ksl_seal(r1, 1, aad, sizeof aad, junk, 8, sizeof junk) == KSL_ERROR, "ekey_reset_rejects_seal");
    CHECK(ksl_key_mac16(t1, cid, 8, m2) == KSL_ERROR, "ekey_token_rejects_mac16");
    CHECK(ksl_key_random(7) == NULL, "ekey_unknown_kind_null");
    ksl_key_free(t1); ksl_key_free(t2); ksl_key_free(r1); ksl_key_free(r2); END(); }

    /* ABI 5: an identity private key is parsed once into a ksl_pkey; a context takes its own reference, so the caller's
       handle (and its DER copy) can go away while the context keeps serving the key. */
    { SECTION("pkey_roundtrip_identity");
    size_t kl; uint8_t *kd = key_of("server", &kl), *other = NULL; size_t ol; other = key_of("client", &ol);
    ksl_pkey *pk = ksl_pkey_new(kd, kl), *wrong = ksl_pkey_new(other, ol);
    CHECK(pk && wrong, "PKCS#8 DER parsed into a pkey handle");
    uint8_t junk[16] = {0x30, 0x03, 0x02, 0x01, 0x00}; CHECK(ksl_pkey_new(junk, sizeof junk) == NULL, "negative: garbage is not a key");
    CHECK(ksl_pkey_new(NULL, 0) == NULL, "negative: empty input");
    blob ch = chain_of(1, "server");
    ksl_ctx *bad = ksl_ctx_new(KSL_SERVER);
    CHECK(ksl_ctx_set_identity_pkey(bad, ch.buf, ch.len, wrong) == KSL_ERROR, "negative: a key of another certificate is rejected");
    CHECK(ksl_ctx_set_identity_pkey(bad, ch.buf, ch.len, NULL) == KSL_ERROR, "negative: no key");
    ksl_ctx_free(bad);
    ksl_ctx *sc = ksl_ctx_new(KSL_SERVER); ksl_ctx_set_alpn(sc, ALPN_H3, sizeof ALPN_H3);
    CHECK(ksl_ctx_set_identity_pkey(sc, ch.buf, ch.len, pk) == KSL_OK, "identity from the pkey handle");
    ksl_pkey_free(pk); ksl_pkey_free(wrong); ksl_pkey_free(NULL); free(ch.buf); free(kd); free(other);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", 11); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", 11);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP);
    side cs = {0}, ss = {0}; int rc = pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done && ss.done, "handshake signed with the key after the caller freed its handle");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END(); }
}
