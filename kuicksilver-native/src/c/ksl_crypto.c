/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* KslCrypto helpers over the OpenSSL EVP API: random bytes, SHA-2, HKDF, ECDSA P-256, Ed25519, SPKI hashing. */
#include "ksl_internal.h"
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

static const char *digest_name(int hash) { return hash == KSL_HASH_SHA384 ? "SHA384" : "SHA256"; }

static int hkdf(int mode, int hash, const uint8_t *key, size_t klen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t ilen, uint8_t *out, size_t olen) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL); if (!kdf) return 0;
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf); EVP_KDF_free(kdf); if (!kctx) return 0;
    OSSL_PARAM p[6]; int i = 0;
    p[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)digest_name(hash), 0);
    p[i++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, klen);
    if (salt) p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, slen);
    if (info) p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, ilen);
    p[i] = OSSL_PARAM_construct_end();
    int ok = EVP_KDF_derive(kctx, out, olen, p) == 1; EVP_KDF_CTX_free(kctx); return ok;
}
int ksl_hkdf_extract(int hash, const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il, uint8_t *out, size_t olen) {
    return hkdf(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, hash, ikm, il, salt, sl, NULL, 0, out, olen) ? KSL_OK : KSL_ERROR;
}
/* RFC 8446 section 7.1: HkdfLabel = length(2) || "tls13 " + label || context */
int ksl_hkdf_expand_label(int hash, const uint8_t *secret, size_t slen, const char *label, const uint8_t *ctx, size_t clen, uint8_t *out, size_t olen) {
    size_t ll = strlen(label); if (ll > 249 || clen > 255 || olen > 0xffff) return KSL_ERROR;
    uint8_t info[2 + 1 + 255 + 1 + 255]; size_t n = 0;
    info[n++] = (uint8_t)(olen >> 8); info[n++] = (uint8_t)olen;
    info[n++] = (uint8_t)(6 + ll); memcpy(info + n, "tls13 ", 6); n += 6; memcpy(info + n, label, ll); n += ll;
    info[n++] = (uint8_t)clen; if (clen) { memcpy(info + n, ctx, clen); n += clen; }
    return hkdf(EVP_KDF_HKDF_MODE_EXPAND_ONLY, hash, secret, slen, NULL, 0, info, n, out, olen) ? KSL_OK : KSL_ERROR;
}
int ksl_rand(uint8_t *out, size_t len) { return RAND_bytes(out, (int)len) == 1 ? KSL_OK : KSL_ERROR; }
int ksl_sha2(int bits, const uint8_t *in, size_t len, uint8_t *out) {
    const EVP_MD *md = bits == 256 ? EVP_sha256() : bits == 384 ? EVP_sha384() : NULL; if (!md) return KSL_ERROR;
    unsigned l; return EVP_Digest(in, len, out, &l, md, NULL) == 1 ? KSL_OK : KSL_ERROR;
}
static int alg_ok(int alg, EVP_PKEY *k) {
    int id = EVP_PKEY_get_id(k);
    if (alg == KSL_SIG_ED25519) return id == EVP_PKEY_ED25519;
    if (alg == KSL_SIG_ECDSA_P256) { if (id != EVP_PKEY_EC) return 0; char g[32]; size_t gl; return EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_GROUP_NAME, g, sizeof g, &gl) == 1 && !strcmp(g, "prime256v1"); }
    return 0;
}
int ksl_sign(int alg, const uint8_t *key_der, size_t klen, const uint8_t *msg, size_t mlen, uint8_t *sig, size_t *slen) {
    const unsigned char *p = key_der; EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &p, (long)klen); if (!k || !alg_ok(alg, k)) { EVP_PKEY_free(k); return KSL_ERROR; }
    EVP_MD_CTX *m = EVP_MD_CTX_new(); int ok = m && EVP_DigestSignInit(m, NULL, alg == KSL_SIG_ECDSA_P256 ? EVP_sha256() : NULL, NULL, k) == 1 && EVP_DigestSign(m, sig, slen, msg, mlen) == 1;
    EVP_MD_CTX_free(m); EVP_PKEY_free(k); ERR_clear_error(); return ok ? KSL_OK : KSL_ERROR;
}
int ksl_verify(int alg, const uint8_t *pub_der, size_t plen, const uint8_t *msg, size_t mlen, const uint8_t *sig, size_t slen) {
    const unsigned char *p = pub_der; EVP_PKEY *k = d2i_PUBKEY(NULL, &p, (long)plen); if (!k || !alg_ok(alg, k)) { EVP_PKEY_free(k); return KSL_ERROR; }
    /* once the key parsed and the context is set up, every answer but 1 is a bad signature: EVP_DigestVerify answers -1 (not 0)
       for an ECDSA signature that is not a DER ECDSA-Sig-Value (RFC 8446 section 4.2.3), which comes from the peer, not from us */
    EVP_MD_CTX *m = EVP_MD_CTX_new(); int r = m && EVP_DigestVerifyInit(m, NULL, alg == KSL_SIG_ECDSA_P256 ? EVP_sha256() : NULL, NULL, k) == 1 ? (EVP_DigestVerify(m, sig, slen, msg, mlen) == 1 ? 1 : 0) : KSL_ERROR;
    EVP_MD_CTX_free(m); EVP_PKEY_free(k); ERR_clear_error(); return r;
}
int ksl_spki_sha256(const uint8_t *cert_der, size_t len, uint8_t out[32]) {
    const unsigned char *p = cert_der; X509 *x = d2i_X509(NULL, &p, (long)len); if (!x) return KSL_ERROR;
    unsigned char *spki = NULL; int l = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &spki); X509_free(x); if (l <= 0) return KSL_ERROR;
    int rc = ksl_sha2(256, spki, (size_t)l, out); OPENSSL_free(spki); return rc;
}
