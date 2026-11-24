/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Certificate revocation (RFC 9325 section 7.5): stapled OCSP responses (RFC 6066 section 8, RFC 9846 section 4.5.1.1, RFC 6960)
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

/* Whether one of the CRLs configured in `crls` (the client context's store, NULL for none) from `issuer` - same name, signature
   verifying under its key - lists `cert`. No time check: the CRL is the application's word on that certificate. */
static int crl_lists(X509_STORE *crls, X509 *issuer, X509 *cert) {
    if (crls == NULL)
        return 0;
    int listed = 0;
    /* a snapshot taken under the store's own lock (X509_STORE_get1_objects locks it: holding X509_STORE_lock around the
       call would deadlock); NULL when out of memory, then counted as listed so the responder is refused (fail closed) */
    STACK_OF(X509_OBJECT) *objs = X509_STORE_get1_objects(crls);
    if (objs == NULL) {
        ERR_clear_error();
        return 1;
    }
    for (int i = 0; i < sk_X509_OBJECT_num(objs) && !listed; i++) {
        X509_CRL *crl = X509_OBJECT_get0_X509_CRL(sk_X509_OBJECT_value(objs, i));
        X509_REVOKED *rev = NULL;
        if (crl && X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(issuer)) == 0 &&
            X509_CRL_verify(crl, X509_get0_pubkey(issuer)) == 1 && X509_CRL_get0_by_cert(crl, &rev, cert) == 1)
            listed = 1;
    }
    sk_X509_OBJECT_pop_free(objs, X509_OBJECT_free);
    ERR_clear_error();
    return listed;
}

/* RFC 6960 section 4.2.2.2: the response is signed by the CA that issued the certificate (its key), or by a delegated responder
   that carries id-kp-OCSPSigning and that CA issued: "Systems relying on OCSP responses MUST recognize a delegation certificate
   as being issued by the CA that issued the certificate in question only if the delegation certificate and the certificate
   being checked for revocation were signed by the same key" - so the responder's certificate must verify under the issuer's
   key, and be valid at `at`. No locally configured responders (the MAY of that section). A delegated responder's certificate is
   held to what a certificate on a verified path is: no unknown critical extension and nothing OpenSSL found invalid
   (EXFLAG_CRITICAL, EXFLAG_INVALID), OpenSSL's security level on its key and signature (ksl_chain_security over [responder,
   issuer]), and not listed on a configured CRL of the issuer (section 4.2.2.2.1 leaves the responder's revocation to local
   policy: the CRLs the application gave are that policy; no other check is made). */
static int responder_authorized(X509 *signer, X509 *issuer, int64_t at, X509_STORE *crls) {
    EVP_PKEY *ik = X509_get0_pubkey(issuer);
    if (ik == NULL)
        return 0;
    if (X509_cmp(signer, issuer) == 0 || EVP_PKEY_eq(X509_get0_pubkey(signer), ik) == 1)
        return 1;
    uint32_t xku =
        X509_get_extended_key_usage(signer); /* caches the extensions; UINT32_MAX when the certificate has none */
    uint32_t flags = X509_get_extension_flags(signer);
    if ((flags & (EXFLAG_CRITICAL | EXFLAG_INVALID)) != 0 || (flags & EXFLAG_XKUSAGE) == 0 ||
        (xku & XKU_OCSP_SIGN) == 0)
        return 0;
    if (X509_check_issued(issuer, signer) != X509_V_OK || X509_verify(signer, ik) != 1)
        return 0;
    time_t when = (time_t)at;
    /* -2: a time that does not parse, refused like one outside the validity period */
    int nb = ASN1_TIME_cmp_time_t(X509_get0_notBefore(signer), when),
        na = ASN1_TIME_cmp_time_t(X509_get0_notAfter(signer), when);
    if (nb == -2 || na == -2 || nb > 0 || na < 0)
        return 0;
    STACK_OF(X509) *path = sk_X509_new_null();
    int weak = path == NULL || !sk_X509_push(path, signer) || !sk_X509_push(path, issuer) ||
               ksl_chain_security(OPENSSL_TLS_SECURITY_LEVEL, path) != X509_V_OK;
    sk_X509_free(path);
    ERR_clear_error();
    return !weak && !crl_lists(crls, issuer, signer);
}

/* Clock skew allowed on thisUpdate and nextUpdate, and how long a response without nextUpdate counts as fresh (RFC 6960 section
   4.2.2.1: "If nextUpdate is not set, the responder is indicating that newer revocation information is available all the time"). */
#define OCSP_SKEW 300
/* The clock of the status checks during handshakes; test builds can move it (ksl_test_ocsp_clock_skew) to age a cached verdict. */
#ifdef KSL_TEST
int64_t ksl_test_ocsp_clock_skew = 0;
int ksl_test_ocsp_server_checks = 0; /* responses server_status parsed and verified (not taken from the cache) */
static int64_t ocsp_now(void) {
    return (int64_t)time(NULL) + ksl_test_ocsp_clock_skew;
}
#else
static int64_t ocsp_now(void) {
    return (int64_t)time(NULL);
}
#endif
#define OCSP_NO_NEXT_UPDATE_TTL 86400

/* The RFC 6960 section 3.2 checks of one DER response for `leaf` issued by `issuer` at `at` (ksl_ocsp_check); `crls`: the store
   whose configured CRLs a delegated responder must not be listed on, or NULL. On a status, *valid_from and *valid_until bound
   the time the response passes in (thisUpdate - 5 min, nextUpdate + 5 min). */
static int ksl_ocsp_check_x509(const uint8_t *der, size_t len, X509 *leaf, X509 *issuer, int64_t at, X509_STORE *crls,
                               int64_t *valid_from, int64_t *valid_until) {
    if (valid_until)
        *valid_until = 0;
    if (valid_from)
        *valid_from = 0;
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
    if (extra == NULL || unused == NULL || !sk_X509_push(extra, issuer) ||
        OCSP_resp_get0_signer(bs, &signer, extra) != 1 || signer == NULL)
        goto done;
    /* OCSP_NOVERIFY: only the signature (the signer's chain and authority are checked by responder_authorized, against the issuer
       the handshake verified, instead of OpenSSL's own trust lookup); OCSP_NOEXPLICIT is implied by NOVERIFY */
    if (OCSP_basic_verify(bs, extra, unused, OCSP_NOVERIFY) != 1 || !responder_authorized(signer, issuer, at, crls))
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
    /* the interval the response passes in; a delegated responder's certificate bounds it too (responder_authorized checks it at
       `at`, so a verdict kept for later - the server's cache, a client's resumption bound - must not outlive it) */
    int64_t from = t_this - OCSP_SKEW, until = t_next + OCSP_SKEW;
    if (EVP_PKEY_eq(X509_get0_pubkey(signer), X509_get0_pubkey(issuer)) != 1) {
        int64_t nb = 0, na = 0;
        if (!asn1_epoch(X509_get0_notBefore(signer), &nb) || !asn1_epoch(X509_get0_notAfter(signer), &na))
            goto done;
        if (nb > from)
            from = nb;
        if (na < until)
            until = na;
    }
    if (valid_until)
        *valid_until = until;
    if (valid_from)
        *valid_from = from;
    r = status == V_OCSP_CERTSTATUS_GOOD      ? KSL_OCSP_GOOD
        : status == V_OCSP_CERTSTATUS_REVOKED ? KSL_OCSP_REVOKED
        : status == V_OCSP_CERTSTATUS_UNKNOWN ? KSL_OCSP_UNKNOWN
                                              : KSL_OCSP_INVALID;
done:
    if (r != KSL_OCSP_GOOD && r != KSL_OCSP_REVOKED && r != KSL_OCSP_UNKNOWN) {
        if (valid_until)
            *valid_until = 0;
        if (valid_from)
            *valid_from = 0;
    }
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
                                at > 0 ? at : (int64_t)time(NULL), NULL, NULL, valid_until);
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

/* Whether [c] issued [leaf]: it names the leaf's issuer (X509_check_issued: name, AKID, keyUsage), its key verifies the leaf's
   signature, and that key is not the leaf's own (a self-signed leaf, or another certificate of the same key, would sign its own
   "good" response). A certificate that only takes the issuer's name and key identifier fails the signature. */
static int issued_by(X509 *c, X509 *leaf) {
    EVP_PKEY *key = X509_get0_pubkey(c), *own = X509_get0_pubkey(leaf);
    int r = c != leaf && key != NULL && own != NULL && EVP_PKEY_eq(key, own) != 1 &&
            X509_check_issued(c, leaf) == X509_V_OK && X509_verify(leaf, key) == 1;
    ERR_clear_error();
    return r;
}

/* The issuer of [leaf] a staple is checked against on the pause path: [candidate] (the certificate above the leaf in the path
   the caller's verifier built, KSL_SET_ISSUER_CANDIDATE) when it issued the leaf, else the first certificate of the presented
   [chain] that did (issued_by). NULL when none did (the leaf sent alone and no candidate, its issuer left out, a self-signed
   leaf). */
static X509 *issuer_among(X509 *candidate, STACK_OF(X509) * chain, X509 *leaf) {
    if (candidate != NULL && issued_by(candidate, leaf))
        return candidate;
    for (int i = 0; chain && i < sk_X509_num(chain); i++) {
        X509 *c = sk_X509_value(chain, i);
        if (issued_by(c, leaf))
            return c;
    }
    return NULL;
}

/* Whether the stapled [der] is a whole DER OCSPResponse whose responseStatus is not successful (tryLater, internalError,
   malformedRequest, sigRequired, unauthorized): such a response has no responseBytes (RFC 6960 section 4.2.1) and so carries
   no status of the certificate (section 2.3), and the client takes it for no staple, as Firefox does; Apache's mod_ssl, for
   one, staples a tryLater it made up while its CA's responder is down. One that does not decode, has bytes after it or says
   successful is an answer, and the checks decide it (an undecodable one fails them). */
static int no_answer(const uint8_t *der, size_t len) {
    if (der == NULL || len == 0 || len > LONG_MAX)
        return 0;
    const unsigned char *p = der;
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &p, (long)len);
    int r = resp != NULL && p == der + len && OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL;
    OCSP_RESPONSE_free(resp);
    ERR_clear_error();
    return r;
}

#ifdef KSL_TEST
int ksl_test_ocsp_no_answer(const uint8_t *der, size_t len) {
    return no_answer(der, len);
}

int ksl_test_presented_issuer(const uint8_t *chain, size_t chain_len, const uint8_t *candidate, size_t candidate_len) {
    STACK_OF(X509) *sk = NULL, *cand = NULL;
    int r = -1;
    if (ksl_parse_chain(chain, chain_len, &sk) && sk_X509_num(sk) >= 1 &&
        (candidate == NULL || (ksl_parse_chain(candidate, candidate_len, &cand) && sk_X509_num(cand) == 1))) {
        X509 *leaf = sk_X509_value(sk, 0), *c = cand ? sk_X509_value(cand, 0) : NULL;
        X509 *got = issuer_among(c, sk, leaf);
        if (got != NULL && got == c)
            r = 0;
        for (int i = 1; got != NULL && r < 0 && i < sk_X509_num(sk); i++)
            if (sk_X509_value(sk, i) == got)
                r = i;
    }
    sk_X509_pop_free(sk, X509_free);
    sk_X509_pop_free(cand, X509_free);
    ERR_clear_error();
    return r;
}
#endif

/* A client's status callback (OpenSSL tls_process_initial_server_flight: after the server's Finished in TLS 1.3, after
   ServerHelloDone in TLS 1.2, so after the chain was verified, by ksl_cert_verify_cb or, on the pause path, by the caller's
   verifier). RFC 6066 section 8: "Clients requesting an OCSP response and receiving an OCSP response in a "CertificateStatus"
   message MUST check the OCSP response and abort the handshake if the response is not satisfactory with
   bad_certificate_status_response(113) alert" - returning 0 does that (OpenSSL sends 113; generic alerts do not apply to it).
   The issuer the response is checked against: where ksl's own verifier ran (KSL_VERIFY_OPENSSL), the one it trusted; on the
   pause path (KSL_VERIFY_PAUSE: the platform's verifier, an application's, TOFU), the certificate above the leaf in the path that
   verifier built (KSL_SET_ISSUER_CANDIDATE) or else the presented certificate that issued the leaf (issuer_among), since the caller's verifier said yes to that chain and only the leaf's real issuer, or a responder it
   delegated, can sign a response for it. A leaf with no such issuer (a trust anchor itself, or sent without its issuer) is not
   checked, unless a stapled response is required (KSL_REVOCATION_REQUIRE_STAPLED, a must-staple leaf), which then fails
   (OCSP_VERIFY_NEEDED: no response can be checked without an issuer). RFC 7633 section 4.3.3: a client "MUST treat a
   certificate with a TLS feature extension as an invalid certificate if the features offered by the server do not contain all
   features present in both the client's ClientHello message and the TLS feature extension", and section 4.2.3.1 has it reject
   a server inconsistent with status_request (SHOULD): every client but KSL_REVOCATION_OFF sends status_request, on both paths,
   so a must-staple leaf needs a good staple everywhere. A delegated responder listed on a configured CRL of the issuer is not
   authorized (responder_authorized; CRLs exist on the ksl verifier's path only). The verdict: revoked fails (CERT_REVOKED); a
   response that does not verify, names another certificate or is outside its validity interval fails (OCSP_VERIFY_FAILED); no
   response, or "unknown", fails only under KSL_REVOCATION_REQUIRE_STAPLED or for a must-staple leaf (OCSP_VERIFY_NEEDED,
   OCSP_CERT_UNKNOWN) and passes otherwise. A resumed session presents no certificate: nothing is checked (the full handshake
   that made the ticket was). */
static int client_status(SSL *ssl, ksl_ssl *s) {
    s->ocsp_status = -1;
    s->ocsp_until = 0;
    if (s->owner->revocation == KSL_REVOCATION_OFF || SSL_session_reused(ssl))
        return 1;
    X509 *leaf = NULL, *issuer = NULL;
    if (s->verify_mode == KSL_VERIFY_OPENSSL) {
        if (s->validated_chain == NULL || sk_X509_num(s->validated_chain) < 1)
            return 1;
        leaf = sk_X509_value(s->validated_chain, 0);
        if (sk_X509_num(s->validated_chain) >= 2)
            issuer = sk_X509_value(s->validated_chain, 1);
    } else if (s->verify_mode == KSL_VERIFY_PAUSE) {
        leaf = SSL_get0_peer_certificate(ssl);
        if (leaf == NULL)
            return 1;
        issuer = issuer_among(s->issuer_candidate, SSL_get_peer_cert_chain(ssl), leaf);
    } else {
        return 1; /* KSL_VERIFY_NONE: nothing is verified, tests only */
    }
    int required = s->owner->revocation == KSL_REVOCATION_REQUIRE_STAPLED || must_staple(leaf);
    if (issuer == NULL) {
        if (!required)
            return 1;
        s->verify_err = X509_V_ERR_OCSP_VERIFY_NEEDED;
        return 0;
    }
    const unsigned char *resp = NULL;
    long len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);
    /* a non-successful OCSPResponse carries no status of the certificate: no staple (no_answer) */
    if (resp != NULL && len > 0 && no_answer(resp, (size_t)len))
        resp = NULL;
    if (resp == NULL || len <= 0) {
        if (!required)
            return 1;
        s->verify_err = X509_V_ERR_OCSP_VERIFY_NEEDED;
        return 0;
    }
    int64_t until = 0;
    X509_STORE *crls =
        s->verify_mode == KSL_VERIFY_OPENSSL && s->owner->has_crls ? SSL_CTX_get_cert_store(s->owner->ctx) : NULL;
    int r = ksl_ocsp_check_x509(resp, (size_t)len, leaf, issuer, ocsp_now(), crls, NULL, &until);
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
   RFC 9846 section 4.5.1.1 puts it into the leaf's CertificateEntry in TLS 1.3; OpenSSL does that. The verdict is kept in the
   context (shared by its sessions, under its lock) for the last response and leaf it was asked about: the SHA-256 of the
   response, the leaf, and the interval it passes in; a hit within that interval staples without parsing the response again. An
   SNI override's identity is another context with its own leaf: a response for the default leaf is not stapled for it. */
static int staple_cached(ksl_ctx *c, const uint8_t hash[32], X509 *leaf, int64_t now) {
    int hit = 0;
    if (c->ocsp_lock && CRYPTO_THREAD_read_lock(c->ocsp_lock)) {
        hit =
            c->ocsp_leaf == leaf && memcmp(c->ocsp_hash, hash, 32) == 0 && now >= c->ocsp_from && now <= c->ocsp_until;
        CRYPTO_THREAD_unlock(c->ocsp_lock);
    }
    return hit;
}
static void staple_remember(ksl_ctx *c, const uint8_t hash[32], X509 *leaf, int64_t from, int64_t until) {
    if (c->ocsp_lock && CRYPTO_THREAD_write_lock(c->ocsp_lock)) {
        memcpy(c->ocsp_hash, hash, 32);
        c->ocsp_leaf = leaf;
        c->ocsp_from = from;
        c->ocsp_until = until;
        CRYPTO_THREAD_unlock(c->ocsp_lock);
    }
}
/* RFC 6066 section 8: a server "SHOULD use the information contained in the extension when selecting an OCSP responder". The
   response is fetched before the handshake, so no responder is selected per client; when the client named responders
   (responder_id_list), the response is stapled only if one of them signed it. An empty list leaves the responder to the server. */
static int responder_wanted(SSL *ssl, const uint8_t *der, size_t len, X509 *issuer) {
    STACK_OF(OCSP_RESPID) *ids = NULL;
    SSL_get_tlsext_status_ids(ssl, &ids);
    if (ids == NULL || sk_OCSP_RESPID_num(ids) == 0)
        return 1;
    const unsigned char *p = der;
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &p, (long)len);
    OCSP_BASICRESP *bs = resp ? OCSP_response_get1_basic(resp) : NULL;
    STACK_OF(X509) *extra = sk_X509_new_null();
    X509 *signer = NULL;
    int wanted = 0;
    if (bs && extra && sk_X509_push(extra, issuer) && OCSP_resp_get0_signer(bs, &signer, extra) == 1 && signer)
        for (int i = 0; i < sk_OCSP_RESPID_num(ids) && !wanted; i++)
            wanted = OCSP_RESPID_match(sk_OCSP_RESPID_value(ids, i), signer) == 1;
    sk_X509_free(extra);
    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(resp);
    ERR_clear_error();
    return wanted;
}
/* The largest response TLS 1.3 (and QUIC) can carry: it goes in the leaf's CertificateEntry, whose extensions<0..2^16-1>
   (RFC 8446 section 4.4.2) hold the extension's type and length (4 bytes) and the CertificateStatus (status_type and a
   3-byte length, RFC 8446 section 4.4.2.1): 65535 - 8. A larger one would make OpenSSL fail the handshake with
   internal_error; RFC 6066 section 8 lets a server send none, so it is not stapled. TLS 1.2 carries it in a
   CertificateStatus message of its own (up to 2^24-5 bytes, the setter's limit). */
#define KSL_OCSP_MAX_TLS13 65527u
static int server_status(SSL *ssl, ksl_ssl *s) {
    if (s->ocsp_staple == NULL)
        return SSL_TLSEXT_ERR_NOACK;
    if (SSL_version(ssl) >= TLS1_3_VERSION && s->ocsp_staple_len > KSL_OCSP_MAX_TLS13)
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
    uint8_t hash[32];
    int64_t now = ocsp_now(), from = 0, until = 0;
    int hashed = ksl_sha2(256, s->ocsp_staple, s->ocsp_staple_len, hash) == KSL_OK;
    if (!hashed || !staple_cached(s->owner, hash, leaf, now)) {
#ifdef KSL_TEST
        __atomic_add_fetch(&ksl_test_ocsp_server_checks, 1, __ATOMIC_RELAXED);
#endif
        int r = ksl_ocsp_check_x509(s->ocsp_staple, s->ocsp_staple_len, leaf, issuer, now, NULL, &from, &until);
        if (r != KSL_OCSP_GOOD && r != KSL_OCSP_REVOKED && r != KSL_OCSP_UNKNOWN)
            return SSL_TLSEXT_ERR_NOACK;
        if (hashed)
            staple_remember(s->owner, hash, leaf, from, until);
    }
    if (!responder_wanted(ssl, s->ocsp_staple, s->ocsp_staple_len, issuer))
        return SSL_TLSEXT_ERR_NOACK;
    unsigned char *copy = OPENSSL_memdup(s->ocsp_staple, s->ocsp_staple_len);
    if (copy == NULL || SSL_set_tlsext_status_ocsp_resp(ssl, copy, (long)s->ocsp_staple_len) != 1) {
        OPENSSL_free(copy);
        ERR_clear_error();
        return SSL_TLSEXT_ERR_NOACK;
    }
    /* RFC 8879 section 4: a CompressedCertificate holds "the encoded Certificate message that would have been sent", which over TLS
       1.3 carries this response in the leaf's CertificateEntry (RFC 9846 section 4.4.2.1). An OpenSSL server sends only a chain
       compressed beforehand (ksl_ctx_freeze), which has no session's response in it: sent to a client that offered compression,
       the response would be gone, a revoked status included. A session that staples sends its Certificate uncompressed (this
       callback runs while the ClientHello is processed, before OpenSSL chooses at EncryptedExtensions). */
    SSL_set_options(ssl, SSL_OP_NO_TX_CERTIFICATE_COMPRESSION);
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

/* With CRLs configured every certificate on the path is checked against the CRL of its issuer (X509_V_FLAG_CRL_CHECK_ALL). OpenSSL's
   "unable to get certificate CRL" passes only when no configured CRL names the certificate's issuer: then the application gave
   no CRL for that CA, and that CA is not checked. When one does (a CRL OpenSSL does not take for this certificate: a distribution
   point the certificate does not name, a scope it is outside of) the error stands: the status is unknown, and the handshake
   fails (fail closed). A revoked certificate, and a CRL that is expired, not yet valid or does not verify, fail as well. */
static int crl_verify_cb(int ok, X509_STORE_CTX *x);
static int crl_error(int e) {
    switch (e) {
    case X509_V_ERR_CERT_REVOKED:
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
    case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
    case X509_V_ERR_DIFFERENT_CRL_SCOPE:
    case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
        return 1;
    default:
        return 0;
    }
}
/* marks the nested verification of anchor_status, so that its own callbacks never start another one */
static const char anchor_check_mark = 0;
/* The status of a trust anchor that is not self-signed (AnchoredCa roots = [an intermediate], X509_V_FLAG_PARTIAL_CHAIN) when a
   configured CRL names its issuer. OpenSSL 3.5 checked it with X509_V_FLAG_CRL_CHECK_ALL; OpenSSL 4 stops the CRL checks of a
   partial chain below the anchor (x509_vfy.c revocation_check_end: num_untrusted - 1), so ksl checks it here as before: the
   anchor is verified on its own, as the target of a path without PARTIAL_CHAIN, against the same store, time and level, with
   X509_V_FLAG_CRL_CHECK for it alone. A CRL error of that check is the anchor's (revoked: 44; expired: 45; ...); a path that does
   not build (the CRL's issuer is not among the roots) or fails otherwise leaves the CRL unverifiable: CRL_SIGNATURE_FAILURE when
   no issuer was found (51), UNABLE_TO_GET_CRL otherwise (48), fail closed either way (docs/guide/tls.md, Certificate
   revocation). X509_V_OK when the anchor passes or no configured CRL names its issuer. */
static int anchor_status(X509_STORE_CTX *x, X509 *anchor) {
    STACK_OF(X509_CRL) *named = X509_STORE_CTX_get1_crls(x, X509_get_issuer_name(anchor));
    int any = named != NULL && sk_X509_CRL_num(named) > 0;
    sk_X509_CRL_pop_free(named, X509_CRL_free);
    if (!any)
        return X509_V_OK;
    X509_STORE_CTX *n = X509_STORE_CTX_new();
    int e = X509_V_ERR_UNABLE_TO_GET_CRL;
    if (n != NULL && X509_STORE_CTX_init(n, X509_STORE_CTX_get0_store(x), anchor, NULL) == 1) {
        X509_VERIFY_PARAM *p = X509_STORE_CTX_get0_param(n);
        /* the outer path's time, depth and security level; no name, any purpose (a CA certificate), no partial chain */
        if (X509_VERIFY_PARAM_set1(p, X509_STORE_CTX_get0_param(x)) == 1 &&
            X509_VERIFY_PARAM_clear_flags(p, X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_CRL_CHECK_ALL) == 1 &&
            X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_CRL_CHECK) == 1 &&
            X509_VERIFY_PARAM_set1_host(p, NULL, 0) == 1 && X509_VERIFY_PARAM_set1_ip(p, NULL, 0) == 1 &&
            X509_VERIFY_PARAM_set_purpose(p, X509_PURPOSE_ANY) == 1 &&
            X509_STORE_CTX_set_app_data(n, (void *)&anchor_check_mark) == 1) {
            X509_STORE_CTX_set_verify_cb(n, crl_verify_cb);
            if (X509_verify_cert(n) == 1)
                e = X509_V_OK;
            else {
                int ne = X509_STORE_CTX_get_error(n);
                e = crl_error(ne) ? ne
                    : ne == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY || ne == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
                        ? X509_V_ERR_CRL_SIGNATURE_FAILURE
                        : X509_V_ERR_UNABLE_TO_GET_CRL;
            }
        }
    }
    X509_STORE_CTX_free(n);
    ERR_clear_error();
    return e;
}
static int crl_verify_cb(int ok, X509_STORE_CTX *x) {
    if (ok) {
        /* the success signal at the top of a path that ends in a trust anchor which is not self-signed */
        STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(x);
        X509 *cur = X509_STORE_CTX_get_current_cert(x);
        int top = chain != NULL ? sk_X509_num(chain) - 1 : -1;
        if (X509_STORE_CTX_get_app_data(x) == &anchor_check_mark || top < 0 ||
            X509_STORE_CTX_get_error_depth(x) != top || cur != sk_X509_value(chain, top) ||
            X509_STORE_CTX_get_num_untrusted(x) > top || X509_self_signed(cur, 0) == 1)
            return ok;
        int e = anchor_status(x, cur);
        if (e == X509_V_OK)
            return ok;
        X509_STORE_CTX_set_error(x, e);
        return 0;
    }
    if (X509_STORE_CTX_get_error(x) != X509_V_ERR_UNABLE_TO_GET_CRL)
        return ok;
    X509 *cur = X509_STORE_CTX_get_current_cert(x);
    STACK_OF(X509_CRL) *named = cur ? X509_STORE_CTX_get1_crls(x, X509_get_issuer_name(cur)) : NULL;
    int any = named != NULL && sk_X509_CRL_num(named) > 0;
    sk_X509_CRL_pop_free(named, X509_CRL_free);
    ERR_clear_error();
    if (any || cur == NULL)
        return 0;
    X509_STORE_CTX_set_error(x, X509_V_OK);
    return 1;
}

/* RFC 5280 section 5: only complete, direct CRLs that cover every reason are taken. A delta CRL (section 5.2.4), an indirect CRL,
   one limited to some reasons or to attribute certificates (section 5.2.5, issuingDistributionPoint), and an
   issuingDistributionPoint that does not decode or claims both user and CA certificates only, are refused: OpenSSL would score
   them as covering no certificate (x509_vfy.c get_crl_score), which the callback above would then report as unknown. */
static int crl_supported(X509_CRL *crl) {
    int crit = 0;
    if (X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0)
        return 0;
    ISSUING_DIST_POINT *idp = X509_CRL_get_ext_d2i(crl, NID_issuing_distribution_point, &crit, NULL);
    int ok = 1;
    if (idp == NULL)
        ok = crit == -1; /* -1: no such extension; -2: more than one; else it did not decode */
    else
        ok = !idp->indirectCRL && idp->onlysomereasons == NULL && !idp->onlyattr && !(idp->onlyuser && idp->onlyCA);
    ISSUING_DIST_POINT_free(idp);
    ERR_clear_error();
    return ok;
}

int ksl_ctx_set_crls(ksl_ctx *c, const uint8_t *crls, size_t crls_len) {
    if (c->frozen) {
        ksl_ctx_set_error(c, KSL_E_CTX_FROZEN, "ksl: context is frozen");
        return KSL_ERROR;
    }
    ERR_clear_error();
    if (!c->own_roots || c->shared_roots) {
        ksl_ctx_set_error(c, KSL_E_BAD_ARG,
                          "ksl: CRLs need the context's own roots (ksl_ctx_set_roots with certificates)");
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
        size_t l =
            ((size_t)crls[off] << 24) | ((size_t)crls[off + 1] << 16) | ((size_t)crls[off + 2] << 8) | crls[off + 3];
        off += 4;
        ok = l > 0 && l <= LONG_MAX && ksl_span_fits(off, l, crls_len);
        if (!ok)
            break;
        const unsigned char *p = crls + off;
        X509_CRL *crl = d2i_X509_CRL(NULL, &p, (long)l);
        ok = crl != NULL && p == crls + off + l && crl_supported(crl) && sk_X509_CRL_push(sk, crl) > 0;
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
        ksl_ctx_set_error(
            c, KSL_E_BAD_ARG,
            ok ? "ksl: CRL rejected by the store"
               : "ksl: bad CRL framing or DER, or a delta, indirect or reason-partitioned CRL (not supported)");
        return KSL_ERROR;
    }
    X509_STORE_set_verify_cb(st, crl_verify_cb);
    c->has_crls = 1;
    if (X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(c->ctx), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) !=
        1) {
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: CRL flags rejected");
        return KSL_ERROR;
    }
    return KSL_OK;
}
