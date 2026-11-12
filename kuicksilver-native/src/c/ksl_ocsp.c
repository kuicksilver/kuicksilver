/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Certificate revocation (RFC 9325 section 7.5): stapled OCSP responses (RFC 6066 section 8, RFC 9846 section 4.4.2.1, RFC 6960)
 * checked by a client and stapled by a server, and application-supplied CRLs (RFC 5280) in a context's own trust store. */
#include "ksl_internal.h"
#include <limits.h>
#include <time.h>
#include <openssl/ocsp.h>

/* OCSP needs OpenSSL's ocsp module (no "no-http" in tools/openssl/configure-flags.txt: Configure turns ocsp off with http); a
   build without it has no status_request at all, and the OCSP entry points answer KSL_E_NOT_SUPPORTED. CRLs need nothing more. */
#ifndef OPENSSL_NO_OCSP

/* Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's days_from_civil): no timegm, which Windows lacks. */
static int64_t days_from_civil(int64_t y, int m, int d) {
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}
static int asn1_epoch(const ASN1_TIME *t, int64_t *out) {
    struct tm tm;
    if (t == NULL || ASN1_TIME_to_tm(t, &tm) != 1)
        return 0;
    *out = days_from_civil((int64_t)tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday) * 86400 + tm.tm_hour * 3600 +
           tm.tm_min * 60 + tm.tm_sec;
    return 1;
}

/* RFC 6960 section 4.2.2.2: the response is signed by the CA that issued the certificate (its key), or by a delegated responder
   that carries id-kp-OCSPSigning and that CA issued: "Systems relying on OCSP responses MUST recognize a delegation certificate
   as being issued by the CA that issued the certificate in question only if the delegation certificate and the certificate
   being checked for revocation were signed by the same key" - so the responder's certificate must verify under the issuer's
   key, and be valid at `at`. No locally configured responders (the MAY of that section). The responder's own revocation status
   is not checked (section 4.2.2.2.1 leaves it to local policy). */
static int responder_authorized(X509 *signer, X509 *issuer, int64_t at) {
    EVP_PKEY *ik = X509_get0_pubkey(issuer);
    if (ik == NULL)
        return 0;
    if (X509_cmp(signer, issuer) == 0 || EVP_PKEY_eq(X509_get0_pubkey(signer), ik) == 1)
        return 1;
    uint32_t xku = X509_get_extended_key_usage(signer); /* caches the extensions; UINT32_MAX when the certificate has none */
    if ((X509_get_extension_flags(signer) & EXFLAG_XKUSAGE) == 0 || (xku & XKU_OCSP_SIGN) == 0)
        return 0;
    if (X509_check_issued(issuer, signer) != X509_V_OK || X509_verify(signer, ik) != 1)
        return 0;
    time_t when = (time_t)at;
    return X509_cmp_time(X509_get0_notBefore(signer), &when) <= 0 && X509_cmp_time(X509_get0_notAfter(signer), &when) >= 0;
}

/* Clock skew allowed on thisUpdate and nextUpdate, and how long a response without nextUpdate counts as fresh (RFC 6960 section
   4.2.2.1: "If nextUpdate is not set, the responder is indicating that newer revocation information is available all the time"). */
#define OCSP_SKEW 300
#define OCSP_NO_NEXT_UPDATE_TTL 86400

static int ksl_ocsp_check_x509(const uint8_t *der, size_t len, X509 *leaf, X509 *issuer, int64_t at, int64_t *valid_until) {
    if (valid_until)
        *valid_until = 0;
    if (der == NULL || len == 0 || len > LONG_MAX || leaf == NULL || issuer == NULL)
        return KSL_OCSP_INVALID;
    const unsigned char *p = der;
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &p, (long)len);
    OCSP_BASICRESP *bs = NULL;
    STACK_OF(X509) *extra = NULL;
    X509_STORE *unused = NULL;
    int r = KSL_OCSP_INVALID;
    if (resp == NULL || p != der + len || OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL ||
        (bs = OCSP_response_get1_basic(resp)) == NULL)
        goto done;
    /* RFC 6960 section 3.2, 1: the response names this certificate (certID under the hash the responder chose, and the issuer we
       trust: its name and key hashes) */
    OCSP_SINGLERESP *single = NULL;
    for (int i = 0; i < OCSP_resp_count(bs) && single == NULL; i++) {
        OCSP_SINGLERESP *sr = OCSP_resp_get0(bs, i);
        ASN1_OBJECT *md_oid = NULL;
        if (OCSP_id_get0_info(NULL, &md_oid, NULL, NULL, (OCSP_CERTID *)OCSP_SINGLERESP_get0_id(sr)) != 1)
            continue;
        EVP_MD *md = EVP_MD_fetch(NULL, OBJ_nid2sn(OBJ_obj2nid(md_oid)), NULL);
        OCSP_CERTID *mine = md ? OCSP_cert_to_id(md, leaf, issuer) : NULL;
        if (mine && OCSP_id_cmp(mine, OCSP_SINGLERESP_get0_id(sr)) == 0)
            single = sr;
        OCSP_CERTID_free(mine);
        EVP_MD_free(md);
    }
    if (single == NULL) {
        r = KSL_OCSP_MISMATCH;
        goto done;
    }
    /* 2-4: the signature verifies under the signer's key, and the signer may speak for this issuer */
    X509 *signer = NULL;
    extra = sk_X509_new_null();
    unused = X509_STORE_new();
    if (extra == NULL || unused == NULL || !sk_X509_push(extra, issuer) || OCSP_resp_get0_signer(bs, &signer, extra) != 1 ||
        signer == NULL)
        goto done;
    /* OCSP_NOVERIFY: only the signature (the signer's chain and authority are checked by responder_authorized, against the issuer
       the handshake verified, instead of OpenSSL's own trust lookup); OCSP_NOEXPLICIT is implied by NOVERIFY */
    if (OCSP_basic_verify(bs, extra, unused, OCSP_NOVERIFY) != 1 || !responder_authorized(signer, issuer, at))
        goto done;
    /* 5, 6: thisUpdate recent, nextUpdate not passed (section 4.2.2.1: either otherwise "SHOULD be considered unreliable") */
    int status = -1, reason = 0;
    ASN1_GENERALIZEDTIME *rev = NULL, *thisupd = NULL, *nextupd = NULL;
    status = OCSP_single_get0_status(single, &reason, &rev, &thisupd, &nextupd);
    int64_t t_this = 0, t_next = 0;
    if (!asn1_epoch(thisupd, &t_this) || (nextupd != NULL && !asn1_epoch(nextupd, &t_next)))
        goto done;
    if (nextupd == NULL)
        t_next = t_this + OCSP_NO_NEXT_UPDATE_TTL;
    if (t_this > at + OCSP_SKEW || t_next + OCSP_SKEW < at || t_next < t_this) {
        r = KSL_OCSP_STALE;
        goto done;
    }
    if (valid_until)
        *valid_until = t_next + OCSP_SKEW;
    r = status == V_OCSP_CERTSTATUS_GOOD      ? KSL_OCSP_GOOD
        : status == V_OCSP_CERTSTATUS_REVOKED ? KSL_OCSP_REVOKED
        : status == V_OCSP_CERTSTATUS_UNKNOWN ? KSL_OCSP_UNKNOWN
                                              : KSL_OCSP_INVALID;
done:
    if (r != KSL_OCSP_GOOD && r != KSL_OCSP_REVOKED && r != KSL_OCSP_UNKNOWN && valid_until)
        *valid_until = 0;
    sk_X509_free(extra);
    X509_STORE_free(unused);
    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(resp);
    ERR_clear_error();
    return r;
}

int ksl_ocsp_check(const uint8_t *resp, size_t resp_len, const uint8_t *chain, size_t chain_len, int64_t at,
                   int64_t *valid_until) {
    ERR_clear_error();
    if (valid_until)
        *valid_until = 0;
    STACK_OF(X509) *sk = NULL;
    if (chain == NULL || !ksl_parse_chain(chain, chain_len, &sk) || sk_X509_num(sk) < 2) {
        sk_X509_pop_free(sk, X509_free);
        ERR_clear_error();
        return KSL_ERROR;
    }
    int r = ksl_ocsp_check_x509(resp, resp_len, sk_X509_value(sk, 0), sk_X509_value(sk, 1),
                                at > 0 ? at : (int64_t)time(NULL), valid_until);
    sk_X509_pop_free(sk, X509_free);
    return r;
}

/* RFC 7633: the leaf requires a stapled response (a TLS feature extension listing status_request, 5) */
static int must_staple(X509 *leaf) {
    int crit = 0;
    STACK_OF(ASN1_INTEGER) *features = X509_get_ext_d2i(leaf, NID_tlsfeature, &crit, NULL);
    int found = 0;
    for (int i = 0; features && i < sk_ASN1_INTEGER_num(features) && !found; i++)
        found = ASN1_INTEGER_get(sk_ASN1_INTEGER_value(features, i)) == TLSEXT_TYPE_status_request;
    sk_ASN1_INTEGER_pop_free(features, ASN1_INTEGER_free);
    ERR_clear_error();
    return found;
}

/* A client's status callback (OpenSSL tls_process_initial_server_flight: after the server's Finished in TLS 1.3, after
   ServerHelloDone in TLS 1.2, so after ksl_cert_verify_cb built the validated chain). RFC 6066 section 8: "Clients requesting an
   OCSP response and receiving an OCSP response in a "CertificateStatus" message MUST check the OCSP response and abort the
   handshake if the response is not satisfactory with bad_certificate_status_response(113) alert" - returning 0 does that (OpenSSL
   sends 113; generic alerts do not apply to it). Only where ksl's own verifier ran (KSL_VERIFY_OPENSSL): the issuer is the one
   that verifier trusted. A leaf that is itself a trust anchor has no issuer here, and its trust is configuration: nothing is
   checked. The verdict: revoked fails (CERT_REVOKED); a response that does not verify, names another certificate or is outside
   its validity interval fails (OCSP_VERIFY_FAILED); no response, or "unknown", fails only under KSL_REVOCATION_REQUIRE_STAPLED or
   for a must-staple leaf (OCSP_VERIFY_NEEDED, OCSP_CERT_UNKNOWN) and passes otherwise. */
static int client_status(SSL *ssl, ksl_ssl *s) {
    s->ocsp_status = -1;
    s->ocsp_until = 0;
    if (s->owner->revocation == KSL_REVOCATION_OFF || s->verify_mode != KSL_VERIFY_OPENSSL || s->validated_chain == NULL ||
        sk_X509_num(s->validated_chain) < 2)
        return 1;
    X509 *leaf = sk_X509_value(s->validated_chain, 0), *issuer = sk_X509_value(s->validated_chain, 1);
    int required = s->owner->revocation == KSL_REVOCATION_REQUIRE_STAPLED || must_staple(leaf);
    const unsigned char *resp = NULL;
    long len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);
    if (resp == NULL || len <= 0) {
        if (!required)
            return 1;
        s->verify_err = X509_V_ERR_OCSP_VERIFY_NEEDED;
        return 0;
    }
    int64_t until = 0;
    int r = ksl_ocsp_check_x509(resp, (size_t)len, leaf, issuer, (int64_t)time(NULL), &until);
    switch (r) {
    case KSL_OCSP_GOOD:
        s->ocsp_status = r;
        s->ocsp_until = until;
        return 1;
    case KSL_OCSP_UNKNOWN:
        if (required) {
            s->verify_err = X509_V_ERR_OCSP_CERT_UNKNOWN;
            return 0;
        }
        s->ocsp_status = r;
        s->ocsp_until = until;
        return 1;
    case KSL_OCSP_REVOKED:
        s->verify_err = X509_V_ERR_CERT_REVOKED;
        return 0;
    default:
        s->verify_err = X509_V_ERR_OCSP_VERIFY_FAILED;
        return 0;
    }
}

/* A server's status callback (OpenSSL tls_handle_status_request: the client sent status_request and the certificate is chosen,
   an SNI override's included). The response KSL_SET_OCSP_RESPONSE gave is stapled only when it is for the leaf being sent (its
   issuer the next certificate of the configured chain that issued it), verifies, and is inside its validity interval now: a
   stale or foreign response is never sent (RFC 6066 section 8: a server "MAY return a suitable certificate status response").
   RFC 9846 section 4.4.2.1 puts it into the leaf's CertificateEntry in TLS 1.3; OpenSSL does that. */
static int server_status(SSL *ssl, ksl_ssl *s) {
    if (s->ocsp_staple == NULL)
        return SSL_TLSEXT_ERR_NOACK;
    X509 *leaf = SSL_get_certificate(ssl), *issuer = NULL;
    STACK_OF(X509) *chain = NULL;
    if (leaf == NULL || SSL_get0_chain_certs(ssl, &chain) != 1)
        return SSL_TLSEXT_ERR_NOACK;
    for (int i = 0; chain && i < sk_X509_num(chain) && issuer == NULL; i++)
        if (X509_check_issued(sk_X509_value(chain, i), leaf) == X509_V_OK)
            issuer = sk_X509_value(chain, i);
    ERR_clear_error();
    if (issuer == NULL)
        return SSL_TLSEXT_ERR_NOACK;
    int r = ksl_ocsp_check_x509(s->ocsp_staple, s->ocsp_staple_len, leaf, issuer, (int64_t)time(NULL), NULL);
    if (r != KSL_OCSP_GOOD && r != KSL_OCSP_REVOKED && r != KSL_OCSP_UNKNOWN)
        return SSL_TLSEXT_ERR_NOACK;
    unsigned char *copy = OPENSSL_memdup(s->ocsp_staple, s->ocsp_staple_len);
    if (copy == NULL || SSL_set_tlsext_status_ocsp_resp(ssl, copy, (long)s->ocsp_staple_len) != 1) {
        OPENSSL_free(copy);
        ERR_clear_error();
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

int ksl_ocsp_status_cb(SSL *ssl, void *arg) {
    (void)arg;
    ksl_ssl *s = SSL_get_ex_data(ssl, 1);
    if (s == NULL)
        return SSL_is_server(ssl) ? SSL_TLSEXT_ERR_NOACK : 1;
    return SSL_is_server(ssl) ? server_status(ssl, s) : client_status(ssl, s);
}

#else
int ksl_ocsp_check(const uint8_t *resp, size_t resp_len, const uint8_t *chain, size_t chain_len, int64_t at,
                   int64_t *valid_until) {
    (void)resp;
    (void)resp_len;
    (void)chain;
    (void)chain_len;
    (void)at;
    if (valid_until)
        *valid_until = 0;
    return KSL_ERROR;
}
#endif

/* With CRLs configured every certificate on the path is checked against the CRL of its issuer (X509_V_FLAG_CRL_CHECK_ALL); a
   certificate whose issuer has no CRL among the configured ones is not checked (a CRL the application configured is the
   strategy for that CA, RFC 9325 section 7.5), so OpenSSL's "unable to get certificate CRL" is passed. A revoked certificate,
   and a CRL that is expired, not yet valid or does not verify, still fail. */
static int crl_verify_cb(int ok, X509_STORE_CTX *x) {
    if (!ok && X509_STORE_CTX_get_error(x) == X509_V_ERR_UNABLE_TO_GET_CRL) {
        X509_STORE_CTX_set_error(x, X509_V_OK);
        return 1;
    }
    return ok;
}

int ksl_ctx_set_crls(ksl_ctx *c, const uint8_t *crls, size_t crls_len) {
    if (c->frozen) {
        ksl_ctx_set_error(c, KSL_E_CTX_FROZEN, "ksl: context is frozen");
        return KSL_ERROR;
    }
    ERR_clear_error();
    if (!c->own_roots || c->shared_roots) {
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: CRLs need the context's own roots (ksl_ctx_set_roots with certificates)");
        return KSL_ERROR;
    }
    if (crls == NULL || crls_len == 0) {
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: no CRLs");
        return KSL_ERROR;
    }
    /* every CRL is parsed before any is installed: a list that does not parse changes nothing */
    STACK_OF(X509_CRL) *sk = sk_X509_CRL_new_null();
    size_t off = 0;
    int ok = sk != NULL;
    while (ok && off < crls_len) {
        ok = ksl_span_fits(off, 4, crls_len);
        if (!ok)
            break;
        size_t l = ((size_t)crls[off] << 24) | ((size_t)crls[off + 1] << 16) | ((size_t)crls[off + 2] << 8) | crls[off + 3];
        off += 4;
        ok = l > 0 && l <= LONG_MAX && ksl_span_fits(off, l, crls_len);
        if (!ok)
            break;
        const unsigned char *p = crls + off;
        X509_CRL *crl = d2i_X509_CRL(NULL, &p, (long)l);
        ok = crl != NULL && p == crls + off + l && sk_X509_CRL_push(sk, crl) > 0;
        if (!ok)
            X509_CRL_free(crl);
        off += l;
    }
    X509_STORE *st = ok ? ksl_ctx_private_store(c) : NULL;
    for (int i = 0; st && i < sk_X509_CRL_num(sk); i++)
        if (X509_STORE_add_crl(st, sk_X509_CRL_value(sk, i)) != 1)
            st = NULL;
    sk_X509_CRL_pop_free(sk, X509_CRL_free);
    if (st == NULL) {
        ERR_clear_error();
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, ok ? "ksl: CRL rejected by the store" : "ksl: bad CRL framing or DER");
        return KSL_ERROR;
    }
    X509_STORE_set_verify_cb(st, crl_verify_cb);
    if (X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(c->ctx), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) != 1) {
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: CRL flags rejected");
        return KSL_ERROR;
    }
    return KSL_OK;
}
