/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Packet protection keys (RFC 9001 section 5, RFC 9369): material stays in native memory behind a handle. */
#include "ksl_internal.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define V1 0x00000001u
#define V2 0x6b3343cfu
static const uint8_t SALT_V1[20] = {0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
static const uint8_t SALT_V2[20] = {0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9};
static const uint8_t RETRY_KEY_V1[16] = {0xbe,0x0c,0x69,0x0b,0x9f,0x66,0x57,0x5a,0x1d,0x76,0x6b,0x54,0xe3,0x68,0xc8,0x4e};
static const uint8_t RETRY_NONCE_V1[12] = {0x46,0x15,0x99,0xd3,0x5d,0x63,0x2b,0xf2,0x23,0x98,0x25,0xbb};
static const uint8_t RETRY_KEY_V2[16] = {0x8f,0xb4,0xb0,0x1b,0x56,0xac,0x48,0xe2,0x60,0xfb,0xcb,0xce,0xad,0x7c,0xcc,0x92};
static const uint8_t RETRY_NONCE_V2[12] = {0xd8,0x69,0x69,0xbc,0x2d,0x7c,0x6d,0x99,0x90,0xef,0xb0,0x4a};

static const char *label(uint32_t v, const char *what) {
    static const char *v1[] = {"quic key", "quic iv", "quic hp", "quic ku"}, *v2[] = {"quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku"};
    int i = what[0] == 'k' && what[1] == 'e' ? 0 : what[0] == 'i' ? 1 : what[0] == 'h' ? 2 : 3;
    return v == V2 ? v2[i] : v1[i];
}
int ksl_aead_of_cipher(const SSL_CIPHER *c) {
    if (!c) return 0;
    switch (SSL_CIPHER_get_id(c) & 0xffff) {
    case 0x1301: return KSL_AEAD_AES_128_GCM;
    case 0x1302: return KSL_AEAD_AES_256_GCM;
    case 0x1303: return KSL_AEAD_CHACHA20_POLY1305;
    default: return 0;
    }
}
static const EVP_CIPHER *cipher_of(int aead) { return aead == KSL_AEAD_AES_128_GCM ? EVP_aes_128_gcm() : aead == KSL_AEAD_AES_256_GCM ? EVP_aes_256_gcm() : EVP_chacha20_poly1305(); }
static const EVP_CIPHER *hp_cipher_of(int aead) { return aead == KSL_AEAD_AES_128_GCM ? EVP_aes_128_ecb() : aead == KSL_AEAD_AES_256_GCM ? EVP_aes_256_ecb() : EVP_chacha20(); }

static ksl_key *key_build(int aead, uint32_t version, const uint8_t *secret, size_t slen) {
    ksl_key *k = calloc(1, sizeof *k); if (!k) return NULL;
    ksl_live_add(KSL_LIVE_KEY, 1);   /* a failed build frees through ksl_key_free, which takes it back */
    k->aead = aead; k->version = version; k->hash = aead == KSL_AEAD_AES_256_GCM ? KSL_HASH_SHA384 : KSL_HASH_SHA256;
    k->key_len = aead == KSL_AEAD_AES_128_GCM ? 16 : 32; k->secret_len = slen; memcpy(k->secret, secret, slen);
    int ok = ksl_hkdf_expand_label(k->hash, secret, slen, label(version, "key"), NULL, 0, k->key, k->key_len) == KSL_OK
          && ksl_hkdf_expand_label(k->hash, secret, slen, label(version, "iv"), NULL, 0, k->iv, 12) == KSL_OK
          && ksl_hkdf_expand_label(k->hash, secret, slen, label(version, "hp"), NULL, 0, k->hp, k->key_len) == KSL_OK;
    k->enc = EVP_CIPHER_CTX_new(); k->dec = EVP_CIPHER_CTX_new(); k->hp_ctx = EVP_CIPHER_CTX_new();
    ok = ok && k->enc && k->dec && k->hp_ctx
      && EVP_EncryptInit_ex(k->enc, cipher_of(aead), NULL, k->key, NULL) == 1 && EVP_DecryptInit_ex(k->dec, cipher_of(aead), NULL, k->key, NULL) == 1;
    if (ok && aead != KSL_AEAD_CHACHA20_POLY1305) ok = EVP_EncryptInit_ex(k->hp_ctx, hp_cipher_of(aead), NULL, k->hp, NULL) == 1 && EVP_CIPHER_CTX_set_padding(k->hp_ctx, 0) == 1;
    if (!ok) { ksl_key_free(k); return NULL; }
    return k;
}
ksl_key *ksl_key_from_secret(int aead, const uint8_t *secret, size_t slen, uint32_t version) {
    if (slen != 32 && slen != 48) return NULL; return key_build(aead, version, secret, slen);
}
#ifdef KSL_TEST   /* a key from a raw secret would let a caller import key material: test builds only */
ksl_key *ksl_key_from_secret_for_test(int aead, const uint8_t *secret, size_t slen, uint32_t version) { return ksl_key_from_secret(aead, secret, slen, version); }
#endif

ksl_key *ksl_key_initial(const uint8_t *dcid, size_t len, int is_server, int direction, uint32_t version) {
    const uint8_t *salt = version == V1 ? SALT_V1 : version == V2 ? SALT_V2 : NULL; if (!salt) return NULL;
    uint8_t initial[32], sec[32];
    if (ksl_hkdf_extract(KSL_HASH_SHA256, salt, 20, dcid, len, initial, 32) != KSL_OK) return NULL;
    int use_server = (is_server != 0) ^ (direction == KSL_DIR_READ);   /* a client's read key is the server's write key */
    if (ksl_hkdf_expand_label(KSL_HASH_SHA256, initial, 32, use_server ? "server in" : "client in", NULL, 0, sec, 32) != KSL_OK) return NULL;
    ksl_key *k = key_build(KSL_AEAD_AES_128_GCM, version, sec, 32); OPENSSL_cleanse(initial, 32); OPENSSL_cleanse(sec, 32); return k;
}
ksl_key *ksl_key_random(int kind) {
    uint8_t secret[32];
    if (kind != KSL_EKEY_TOKEN && kind != KSL_EKEY_RESET) return NULL;
    if (RAND_bytes(secret, 32) != 1) return NULL;
    ksl_key *k;
    if (kind == KSL_EKEY_TOKEN) k = key_build(KSL_AEAD_AES_256_GCM, V1, secret, 32);
    else { k = calloc(1, sizeof *k); if (k) { ksl_live_add(KSL_LIVE_KEY, 1); k->secret_len = 32; memcpy(k->secret, secret, 32); } }
    OPENSSL_cleanse(secret, 32);
    if (k) k->kind = kind;
    return k;
}
int ksl_key_mac16(ksl_key *k, const uint8_t *in, size_t len, uint8_t out[16]) {
    if (!k || k->kind != KSL_EKEY_RESET || !out) return KSL_ERROR;
    uint8_t mac[EVP_MAX_MD_SIZE]; unsigned int mlen = 0;
    if (!HMAC(EVP_sha256(), k->secret, (int)k->secret_len, in, len, mac, &mlen) || mlen < 16) return KSL_ERROR;   /* a fresh context per call: the key object stays immutable */
    memcpy(out, mac, 16); OPENSSL_cleanse(mac, sizeof mac); return KSL_OK;
}
ksl_key *ksl_key_next(ksl_key *k) {
    if (!k || k->kind != 0) return NULL;
    uint8_t next[48]; if (ksl_hkdf_expand_label(k->hash, k->secret, k->secret_len, label(k->version, "ku"), NULL, 0, next, k->secret_len) != KSL_OK) return NULL;
    ksl_key *n = key_build(k->aead, k->version, next, k->secret_len); OPENSSL_cleanse(next, sizeof next);
    if (n) { memcpy(n->hp, k->hp, sizeof n->hp); if (k->aead != KSL_AEAD_CHACHA20_POLY1305) EVP_EncryptInit_ex(n->hp_ctx, hp_cipher_of(k->aead), NULL, n->hp, NULL); }   /* RFC 9001 5.4: hp key is not updated */
    return n;
}
void ksl_key_free(ksl_key *k) {
    if (!k) return; ksl_live_add(KSL_LIVE_KEY, -1); EVP_CIPHER_CTX_free(k->enc); EVP_CIPHER_CTX_free(k->dec); EVP_CIPHER_CTX_free(k->hp_ctx);
    OPENSSL_cleanse(k, sizeof *k); free(k);
}
static void nonce_for(const ksl_key *k, uint64_t pn, uint8_t out[12]) { memcpy(out, k->iv, 12); for (int i = 0; i < 8; i++) out[11 - i] ^= (uint8_t)(pn >> (8 * i)); }

int ksl_seal(ksl_key *k, uint64_t pn, const uint8_t *hdr, size_t hdr_len, uint8_t *payload, size_t len, size_t cap) {
    if (!k || !k->enc || len + 16 > cap || len > INT32_MAX) return KSL_ERROR;   /* a reset key has no cipher: KSL_ERROR, never a crash */
    uint8_t nonce[12]; nonce_for(k, pn, nonce); int n = 0, fin = 0;
    if (EVP_EncryptInit_ex(k->enc, NULL, NULL, NULL, nonce) != 1) return KSL_ERROR;
    if (EVP_EncryptUpdate(k->enc, NULL, &n, hdr, (int)hdr_len) != 1) return KSL_ERROR;
    if (EVP_EncryptUpdate(k->enc, payload, &n, payload, (int)len) != 1 || (size_t)n != len) return KSL_ERROR;
    if (EVP_EncryptFinal_ex(k->enc, payload + n, &fin) != 1) return KSL_ERROR;
    if (EVP_CIPHER_CTX_ctrl(k->enc, EVP_CTRL_AEAD_GET_TAG, 16, payload + len) != 1) return KSL_ERROR;
    return (int)(len + 16);
}
int ksl_open(ksl_key *k, uint64_t pn, const uint8_t *hdr, size_t hdr_len, uint8_t *payload, size_t len) {
    if (!k || !k->dec || len < 16 || len > INT32_MAX) return KSL_ERROR;
    uint8_t nonce[12]; nonce_for(k, pn, nonce); int n = 0, fin = 0; size_t clen = len - 16;
    if (EVP_DecryptInit_ex(k->dec, NULL, NULL, NULL, nonce) != 1) return KSL_ERROR;
    if (EVP_DecryptUpdate(k->dec, NULL, &n, hdr, (int)hdr_len) != 1) return KSL_ERROR;
    if (EVP_CIPHER_CTX_ctrl(k->dec, EVP_CTRL_AEAD_SET_TAG, 16, payload + clen) != 1) return KSL_ERROR;
    uint8_t *tmp = malloc(clen ? clen : 1); if (!tmp) return KSL_ERROR;   /* a failed tag never leaves plaintext in the caller's buffer */
    int ok = EVP_DecryptUpdate(k->dec, tmp, &n, payload, (int)clen) == 1 && (size_t)n == clen && EVP_DecryptFinal_ex(k->dec, tmp + n, &fin) == 1;
    if (ok) memcpy(payload, tmp, clen);
    OPENSSL_cleanse(tmp, clen ? clen : 1); free(tmp); ERR_clear_error();
    return ok ? (int)clen : KSL_ERROR;
}
int ksl_header_mask(ksl_key *k, const uint8_t sample[16], uint8_t mask[5]) {
    if (!k || !k->hp_ctx) return KSL_ERROR; uint8_t out[16]; int n = 0;
    if (k->aead == KSL_AEAD_CHACHA20_POLY1305) {
        /* RFC 9001 5.4.4: counter = sample[0..4], nonce = sample[4..16], mask = ChaCha20 keystream over 5 zero bytes */
        static const uint8_t zero[5] = {0};
        if (EVP_EncryptInit_ex(k->hp_ctx, EVP_chacha20(), NULL, k->hp, sample) != 1 || EVP_EncryptUpdate(k->hp_ctx, out, &n, zero, 5) != 1 || n != 5) return KSL_ERROR;
    } else {
        if (EVP_EncryptUpdate(k->hp_ctx, out, &n, sample, 16) != 1 || n != 16) return KSL_ERROR;
    }
    memcpy(mask, out, 5); return KSL_OK;
}
int ksl_retry_tag(uint32_t version, const uint8_t *odcid, size_t odcid_len, const uint8_t *retry_pseudo, size_t plen, uint8_t tag[16]) {
    (void)odcid; (void)odcid_len;   /* the pseudo-packet already starts with the ODCID */
    const uint8_t *key = version == V2 ? RETRY_KEY_V2 : RETRY_KEY_V1, *nonce = version == V2 ? RETRY_NONCE_V2 : RETRY_NONCE_V1;
    if (version != V1 && version != V2) return KSL_ERROR;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int n = 0, ok = c != NULL;
    ok = ok && EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, key, nonce) == 1 && EVP_EncryptUpdate(c, NULL, &n, retry_pseudo, (int)plen) == 1
       && EVP_EncryptFinal_ex(c, tag, &n) == 1 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(c); return ok ? KSL_OK : KSL_ERROR;
}
