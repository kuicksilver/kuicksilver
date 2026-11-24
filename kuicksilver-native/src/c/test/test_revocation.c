/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Certificate revocation (RFC 9325 section 7.5): ksl_ocsp_check on real responses (tools/certs/gen-revocation-certs.sh), a
 * client checking stapled responses and a server stapling its own over QUIC, TLS 1.3 and TLS 1.2, and CRLs in the store. */
#include "test_common.h"
#include "ksl_internal.h" /* the test server that staples whatever it is given, past ksl's own checks */
#include <time.h>
#include <openssl/ocsp.h>
#ifndef _WIN32
#include <pthread.h>
#else
#include <windows.h>
#endif

#define RV "revocation/"
/* 2029-01-01: a time inside rv-responder-short's validity (it ends 2030-01-01), so its tests do not depend on today's date */
#define SHORT_RESPONDER_AT 1861920000LL

static blob file_of(const char *name) {
    char path[256];
    snprintf(path, sizeof path, TESTDATA RV "%s.der", name);
    blob b;
    b.buf = read_file(path, &b.len);
    return b;
}
static blob framed(int n, ...) { /* (uint32 BE length || DER)* of files under revocation/ */
    blob b = {0};
    va_list ap;
    va_start(ap, n);
    for (int i = 0; i < n; i++) {
        blob f = file_of(va_arg(ap, const char *));
        b.buf = realloc(b.buf, b.len + 4 + f.len);
        b.buf[b.len] = (uint8_t)(f.len >> 24);
        b.buf[b.len + 1] = (uint8_t)(f.len >> 16);
        b.buf[b.len + 2] = (uint8_t)(f.len >> 8);
        b.buf[b.len + 3] = (uint8_t)f.len;
        memcpy(b.buf + b.len + 4, f.buf, f.len);
        b.len += 4 + f.len;
        free(f.buf);
    }
    va_end(ap);
    return b;
}
#ifndef OPENSSL_NO_OCSP
static int check_file(const char *resp, const char *leaf, const char *issuer, int64_t at, int64_t *until) {
    blob r = file_of(resp), ch = framed(2, leaf, issuer);
    int v = ksl_ocsp_check(r.buf, r.len, ch.buf, ch.len, at, until);
    free(r.buf);
    free(ch.buf);
    return v;
}
static int64_t this_update_of(const char *resp) {
    blob r = file_of(resp);
    const unsigned char *p = r.buf;
    OCSP_RESPONSE *o = d2i_OCSP_RESPONSE(NULL, &p, (long)r.len);
    OCSP_BASICRESP *bs = o ? OCSP_response_get1_basic(o) : NULL;
    ASN1_GENERALIZEDTIME *t = NULL;
    int64_t out = 0;
    if (bs && OCSP_single_get0_status(OCSP_resp_get0(bs, 0), NULL, NULL, &t, NULL) >= 0 && t) {
        int days = 0, secs = 0;
        if (ASN1_TIME_diff(&days, &secs, NULL, t) == 1)
            out = (int64_t)time(NULL) + (int64_t)days * 86400 + secs;
    }
    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(o);
    free(r.buf);
    return out;
}

/* The offset of the last byte of the response's signature value in its DER (the signer's certificate follows it) */
static size_t signature_end(blob r) {
    const unsigned char *p = r.buf;
    OCSP_RESPONSE *o = d2i_OCSP_RESPONSE(NULL, &p, (long)r.len);
    OCSP_BASICRESP *bs = o ? OCSP_response_get1_basic(o) : NULL;
    const ASN1_OCTET_STRING *sig = bs ? OCSP_resp_get0_signature(bs) : NULL;
    size_t at = 0;
    if (sig) {
        const unsigned char *d = ASN1_STRING_get0_data(sig);
        size_t n = ASN1_STRING_get_length(sig);
        for (size_t i = 0; n && i + n <= r.len && !at; i++)
            if (!memcmp(r.buf + i, d, n))
                at = i + n - 1;
    }
    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(o);
    return at;
}
static void test_ocsp_check(void) {
    SECTION("revocation_ocsp_check");
    int64_t until = 0, now = (int64_t)time(NULL);
    CHECK(check_file("ocsp-good", "rv-leaf", "rv-mid", 0, &until) == KSL_OCSP_GOOD && until > now,
          "good, signed by the issuing CA; fresh until its nextUpdate (+5 min)");
    CHECK(check_file("ocsp-good-delegated", "rv-leaf", "rv-mid", 0, NULL) == KSL_OCSP_GOOD,
          "good, signed by a delegated responder (id-kp-OCSPSigning, issued by the CA, RFC 6960 4.2.2.2)");
    CHECK(check_file("ocsp-revoked", "rv-leaf-revoked", "rv-mid", 0, &until) == KSL_OCSP_REVOKED && until > 0,
          "revoked");
    CHECK(check_file("ocsp-unknown", "rv-leaf-unlisted", "rv-mid", 0, NULL) == KSL_OCSP_UNKNOWN, "unknown");
    CHECK(check_file("ocsp-stale", "rv-leaf", "rv-mid", now + 3600, &until) == KSL_OCSP_STALE && until == 0,
          "negative_stale: nextUpdate passed (RFC 6960 3.2, 6)");
    CHECK(check_file("ocsp-good", "rv-leaf", "rv-mid", 1700000000, NULL) == KSL_OCSP_STALE,
          "negative_future: thisUpdate after the time of the check (RFC 6960 4.2.2.1)");
    int64_t tu = this_update_of("ocsp-nonext");
    CHECK(tu > 0 && check_file("ocsp-nonext", "rv-leaf", "rv-mid", tu + 3600, &until) == KSL_OCSP_GOOD &&
              until == tu + 86400 + 300,
          "no nextUpdate: fresh for a day after thisUpdate");
    CHECK(check_file("ocsp-nonext", "rv-leaf", "rv-mid", tu + 2 * 86400, NULL) == KSL_OCSP_STALE,
          "negative_no_next_update_old: stale a day after thisUpdate (RFC 6960 3.2, 5)");
    CHECK(check_file("ocsp-good", "rv-leaf-revoked", "rv-mid", 0, NULL) == KSL_OCSP_MISMATCH,
          "negative_mismatch: a response for another certificate (RFC 6960 3.2, 1)");
    CHECK(check_file("ocsp-good", "rv-leaf", "rv-root", 0, NULL) == KSL_OCSP_MISMATCH,
          "negative_wrong_issuer: the certID names another issuer");
    CHECK(check_file("ocsp-unauthorized", "rv-leaf", "rv-mid", 0, NULL) == KSL_OCSP_INVALID,
          "negative_unauthorized: a responder another CA issued (RFC 6960 4.2.2.2)");
    CHECK(check_file("ocsp-noeku", "rv-leaf", "rv-mid", 0, NULL) == KSL_OCSP_INVALID,
          "negative_no_ocsp_signing: a responder without id-kp-OCSPSigning");
    CHECK(check_file("ocsp-weak-responder", "rv-leaf", "rv-mid", 0, NULL) == KSL_OCSP_INVALID,
          "negative_weak_responder: an RSA-1024 responder key, below security level 2");
    CHECK(check_file("ocsp-critical-responder", "rv-leaf", "rv-mid", 0, NULL) == KSL_OCSP_INVALID,
          "negative_critical_responder: a responder certificate with an unknown critical extension");
    {
        int64_t u = 0;
        CHECK(check_file("ocsp-short-responder", "rv-leaf", "rv-mid", SHORT_RESPONDER_AT, &u) == KSL_OCSP_GOOD &&
                  u == 1893456000LL,
              "negative_responder_bounds_until: valid_until is the delegated responder's notAfter (2030-01-01)");
        CHECK(check_file("ocsp-short-responder", "rv-leaf", "rv-mid", 1924992000LL, NULL) == KSL_OCSP_INVALID,
              "negative_responder_expired: after the responder's notAfter");
    }
    CHECK(check_file("ocsp-revoked-responder", "rv-leaf", "rv-mid", 0, NULL) == KSL_OCSP_GOOD,
          "a delegated responder is not checked for revocation without configured CRLs");
    blob g = file_of("ocsp-good"), ch = framed(2, "rv-leaf", "rv-mid");
    size_t sig_at = signature_end(g);
    CHECK(sig_at > 0, "the signature located");
    g.buf[sig_at] ^= 0x01;
    CHECK(sig_at > 0 && ksl_ocsp_check(g.buf, g.len, ch.buf, ch.len, 0, NULL) == KSL_OCSP_INVALID,
          "negative_bad_signature: a flipped signature byte (RFC 6960 3.2, 2)");
    g.buf[sig_at] ^= 0x01;
    uint8_t *longer = malloc(g.len + 1);
    memcpy(longer, g.buf, g.len);
    longer[g.len] = 0;
    CHECK(ksl_ocsp_check(longer, g.len + 1, ch.buf, ch.len, 0, NULL) == KSL_OCSP_INVALID,
          "negative_trailing: bytes after the response");
    free(longer);
    static const uint8_t try_later[] = {0x30, 0x03, 0x0a, 0x01, 0x03};
    CHECK(ksl_ocsp_check(try_later, sizeof try_later, ch.buf, ch.len, 0, NULL) == KSL_OCSP_INVALID,
          "negative_try_later: an unsuccessful response status");
    CHECK(ksl_ocsp_check(g.buf, 10, ch.buf, ch.len, 0, NULL) == KSL_OCSP_INVALID, "negative_truncated");
    blob one = framed(1, "rv-leaf");
    CHECK(ksl_ocsp_check(g.buf, g.len, one.buf, one.len, 0, NULL) == KSL_ERROR, "negative: no issuer in the chain");
    free(one.buf);
    free(g.buf);
    free(ch.buf);
    END();
}

#endif

/* ---- handshakes ---- */
typedef struct {
    const char *leaf;   /* the server's leaf under revocation/ (chain: leaf, rv-mid) */
    const char *staple; /* KSL_SET_OCSP_RESPONSE, or NULL */
    const char *forced; /* the test server staples this past ksl's checks (forced_status_cb), or NULL */
    int revocation;     /* client KSL_OPT_REVOCATION */
    int mode;           /* KSL_MODE_QUIC, KSL_MODE_TCP */
    int tls12;
    int verify_mode; /* client; 0 means KSL_VERIFY_OPENSSL */
} hs;
typedef struct {
    int rc, done, alert, x509;
    uint8_t status[9];
} hs_out;

static blob forced_blob;
#ifndef OPENSSL_NO_OCSP
static int forced_status_cb(SSL *ssl, void *arg) {
    (void)arg;
    unsigned char *copy = OPENSSL_memdup(forced_blob.buf, forced_blob.len);
    SSL_set_tlsext_status_ocsp_resp(ssl, copy, (long)forced_blob.len);
    return SSL_TLSEXT_ERR_OK;
}
#endif
static size_t shuttle(ksl_ssl *a, ksl_ssl *b) {
    uint8_t buf[4096];
    size_t total = 0, n, used;
    while (ksl_tcp_drain(a, buf, sizeof buf, &n) == KSL_OK && n) {
        size_t off = 0;
        while (off < n) {
            if (ksl_tcp_feed(b, buf + off, n - off, &used) != KSL_OK || !used)
                break;
            off += used;
        }
        total += n;
    }
    return total;
}
static int accept_all(ksl_ssl *s, int rc, void *a) {
    (void)a;
    return rc != KSL_WANT_VERIFY || ksl_ssl_verify_resume(s, 1, 0) == KSL_OK;
}
static int tcp_pump(ksl_ssl *c, ksl_ssl *s) {
    for (int i = 0; i < 60; i++) {
        int r = ksl_drive(c);
        if (r == KSL_WANT_VERIFY)
            ksl_ssl_verify_resume(c, 1, 0), r = ksl_drive(c);
        shuttle(c, s);
        int r2 = ksl_drive(s);
        shuttle(s, c);
        if (r == KSL_ERROR || r2 == KSL_ERROR) {
            if (r2 == KSL_ERROR)
                ksl_drive(c);
            return KSL_ERROR;
        }
        if (c->done && s->done)
            return KSL_OK;
    }
    return KSL_WANT_READ;
}
static int server_leaf_only; /* the server sends its leaf without rv-mid */
static ksl_ctx *rv_server(const char *leaf, int tls12) {
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER);
    ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    char name[128];
    snprintf(name, sizeof name, "%s", leaf);
    blob ch = server_leaf_only ? framed(1, name) : framed(2, name, "rv-mid");
    char kp[128];
    snprintf(kp, sizeof kp, RV "%s", leaf);
    size_t kl;
    uint8_t *k = key_of(kp, &kl);
    if (ksl_ctx_set_identity(c, ch.buf, ch.len, k, kl) != KSL_OK)
        printf("identity %s refused\n", leaf);
    free(ch.buf);
    free(k);
    if (tls12)
        ksl_ctx_set_option(c, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    return c;
}
static const char *client_root = "rv-root"; /* the client's AnchoredCa */
static const char *client_root2 = NULL;     /* a second root, or NULL */
static ksl_ctx *rv_client(int revocation, int verify_mode, int tls12, const char *crl) {
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT);
    ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    blob r = client_root2 ? framed(2, client_root, client_root2) : framed(1, client_root);
    ksl_ctx_set_roots(c, r.buf, r.len);
    free(r.buf);
    if (crl) {
        blob l = framed(1, crl);
        CHECK(ksl_ctx_set_crls(c, l.buf, l.len) == KSL_OK, "CRL accepted");
        free(l.buf);
    }
    ksl_ctx_set_option(c, KSL_OPT_VERIFY_MODE, verify_mode ? verify_mode : KSL_VERIFY_OPENSSL);
    CHECK(ksl_ctx_set_option(c, KSL_OPT_REVOCATION, revocation) == KSL_OK, "revocation option");
    if (tls12) {
        ksl_ctx_set_option(c, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
        ksl_ctx_set_option(c, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    }
    return c;
}
static hs_out handshake_with(hs *x, const char *crl) {
    hs_out o;
    memset(&o, 0, sizeof o);
    ksl_ctx *cc = rv_client(x->revocation, x->verify_mode, x->tls12, crl), *sc = rv_server(x->leaf, x->tls12);
#ifndef OPENSSL_NO_OCSP
    if (x->forced) {
        forced_blob = file_of(x->forced);
        SSL_CTX_set_tlsext_status_cb(sc->ctx, forced_status_cb);
    }
#endif
    ksl_ssl *c = ksl_ssl_new(cc, x->mode), *s = ksl_ssl_new(sc, x->mode);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    if (x->staple) {
        blob b = file_of(x->staple);
        CHECK(ksl_ssl_set(s, KSL_SET_OCSP_RESPONSE, b.buf, b.len) == KSL_OK, "server takes the response");
        free(b.buf);
    }
    if (x->mode == KSL_MODE_QUIC) {
        ksl_quic_set_transport_params(c, TP, sizeof TP);
        ksl_quic_set_transport_params(s, TP, sizeof TP);
        side cs = {0}, ss = {0};
        o.rc = pump(c, s, &cs, &ss, 40, accept_all, NULL);
        o.done = cs.done && ss.done;
    } else {
        o.rc = tcp_pump(c, s);
        o.done = o.rc == KSL_OK;
    }
    int a = 0;
    char m[256];
    uint32_t code;
    ksl_ssl_last_error(c, &code, &a, m, sizeof m);
    o.alert = a & 0x1ff;
    o.x509 = a >> 16;
    size_t n;
    if (ksl_ssl_get(c, KSL_GET_OCSP_STATUS, o.status, sizeof o.status, &n) != KSL_OK)
        memset(o.status, 0xee, sizeof o.status);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    if (x->forced) {
        free(forced_blob.buf);
        forced_blob.buf = NULL;
    }
    return o;
}
#ifndef OPENSSL_NO_OCSP
static hs_out handshake(hs *x) {
    return handshake_with(x, NULL);
}
#define EXPECT_PASS(x, st, msg)                                                                                        \
    do {                                                                                                               \
        hs_out o_ = handshake(&(x));                                                                                   \
        CHECK(o_.done &&o_.rc != KSL_ERROR && o_.status[0] == (st), msg);                                              \
        if (!(o_.done && o_.rc != KSL_ERROR && o_.status[0] == (st)))                                                  \
            printf("  got rc=%d done=%d alert=%d x509=%d status=%d\n", o_.rc, o_.done, o_.alert, o_.x509,              \
                   o_.status[0]);                                                                                      \
    } while (0)
#define EXPECT_FAIL(x, err, msg)                                                                                       \
    do {                                                                                                               \
        hs_out o_ = handshake(&(x));                                                                                   \
        CHECK(o_.rc == KSL_ERROR && !o_.done && o_.alert == 113 && o_.x509 == (err), msg);                             \
        if (!(o_.rc == KSL_ERROR && !o_.done && o_.alert == 113 && o_.x509 == (err)))                                  \
            printf("  got rc=%d done=%d alert=%d x509=%d\n", o_.rc, o_.done, o_.alert, o_.x509);                       \
    } while (0)

static void stapling_over(int mode, int tls12, const char *what) {
    printf("  over %s\n", what);
    hs good = {"rv-leaf", "ocsp-good", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_PASS(good, KSL_OCSP_GOOD, "server staples, client checks: good");
    hs delegated = {"rv-leaf", "ocsp-good-delegated", NULL, KSL_REVOCATION_REQUIRE_STAPLED, mode, tls12, 0};
    EXPECT_PASS(delegated, KSL_OCSP_GOOD, "delegated responder, required");
    hs revoked = {"rv-leaf-revoked", "ocsp-revoked", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_FAIL(revoked, X509_V_ERR_CERT_REVOKED, "negative_revoked: bad_certificate_status_response, CERT_REVOKED");
    hs none = {"rv-leaf", NULL, NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_PASS(none, 0xff, "no staple: passes under stapled-if-present");
    hs none_req = {"rv-leaf", NULL, NULL, KSL_REVOCATION_REQUIRE_STAPLED, mode, tls12, 0};
    EXPECT_FAIL(none_req, X509_V_ERR_OCSP_VERIFY_NEEDED, "negative_required_missing: none stapled");
    hs unknown = {"rv-leaf-unlisted", "ocsp-unknown", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_PASS(unknown, KSL_OCSP_UNKNOWN, "unknown: passes under stapled-if-present");
    hs unknown_req = {"rv-leaf-unlisted", "ocsp-unknown", NULL, KSL_REVOCATION_REQUIRE_STAPLED, mode, tls12, 0};
    EXPECT_FAIL(unknown_req, X509_V_ERR_OCSP_CERT_UNKNOWN, "negative_required_unknown");
    hs must = {"rv-leaf-must-staple", NULL, NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_FAIL(must, X509_V_ERR_OCSP_VERIFY_NEEDED, "negative_must_staple: RFC 7633 leaf without a staple");
    hs must_ok = {"rv-leaf-must-staple", "ocsp-must-staple", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_PASS(must_ok, KSL_OCSP_GOOD, "must-staple leaf with its staple");
    /* the server checks before it staples: a stale or foreign response is not sent */
    hs stale_srv = {"rv-leaf", "ocsp-stale", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_PASS(stale_srv, 0xff, "negative_server_stale: a stale response is not stapled");
    hs foreign_srv = {"rv-leaf", "ocsp-revoked", NULL, KSL_REVOCATION_REQUIRE_STAPLED, mode, tls12, 0};
    EXPECT_FAIL(foreign_srv, X509_V_ERR_OCSP_VERIFY_NEEDED,
                "negative_server_foreign: a response for another certificate is not stapled");
    /* a server that staples anyway: the client refuses */
    hs stale = {"rv-leaf", NULL, "ocsp-stale", KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_FAIL(stale, X509_V_ERR_OCSP_VERIFY_FAILED, "negative_client_stale (RFC 6066 section 8: not satisfactory)");
    /* OpenSSL 3.6 and later staple a response only when it names the certificate by serial and issuer name hash (statem_srvr.c
       ossl_get_ocsp_response): one for another serial never reaches the client, and one for the same serial under another issuer
       key does, which the client refuses (RFC 6960 section 3.2, 1: the whole certID, issuer key hash included) */
    hs foreign_forced = {"rv-leaf", NULL, "ocsp-revoked", KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_PASS(foreign_forced, 0xff, "an OpenSSL server does not staple another serial's response");
    hs mismatch = {"rv-leaf", NULL, "ocsp-other-issuer-key", KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_FAIL(mismatch, X509_V_ERR_OCSP_VERIFY_FAILED,
                "negative_client_mismatch: a response for the same serial under another issuer key");
    hs unauth = {"rv-leaf", NULL, "ocsp-unauthorized", KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_FAIL(unauth, X509_V_ERR_OCSP_VERIFY_FAILED, "negative_client_unauthorized_responder");
    hs off = {"rv-leaf-revoked", "ocsp-revoked", NULL, KSL_REVOCATION_OFF, mode, tls12, 0};
    EXPECT_PASS(off, 0xff, "off: nothing requested, nothing checked");
    hs paused = {"rv-leaf-revoked", "ocsp-revoked", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12,
                 KSL_VERIFY_PAUSE};
    EXPECT_PASS(paused, 0xff, "the pause path (an application verifier) is not checked by ksl");
    /* a leaf that is itself the trust anchor, sent alone: nothing to check against, so a required staple fails */
    client_root = "rv-leaf";
    server_leaf_only = 1;
    hs anchor = {"rv-leaf", "ocsp-good", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_PASS(anchor, 0xff, "an anchored leaf: not checked when no staple is required");
    hs anchor_req = {"rv-leaf", "ocsp-good", NULL, KSL_REVOCATION_REQUIRE_STAPLED, mode, tls12, 0};
    EXPECT_FAIL(anchor_req, X509_V_ERR_OCSP_VERIFY_NEEDED, "negative_required_without_issuer: an anchored leaf");
    client_root = "rv-leaf-must-staple";
    hs anchor_must = {
        "rv-leaf-must-staple", "ocsp-must-staple", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_FAIL(anchor_must, X509_V_ERR_OCSP_VERIFY_NEEDED, "negative_must_staple_without_issuer");
    client_root = "rv-root";
    server_leaf_only = 0;
    /* a delegated responder the configured CRL lists is not authorized */
    hs rresp = {"rv-leaf", "ocsp-revoked-responder", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    hs_out o = handshake_with(&rresp, "crl-mid");
    CHECK(o.rc == KSL_ERROR && o.alert == 113 && o.x509 == X509_V_ERR_OCSP_VERIFY_FAILED,
          "negative_revoked_responder: a responder on the configured CRL");
    EXPECT_PASS(rresp, KSL_OCSP_GOOD, "the same responder without CRLs");
}

/* RFC 6066 section 8: a client's responder_id_list; the server staples only a response one of the named responders signed */
static int staple_with_responder_ids(const char *named) {
    ksl_ctx *cc = rv_client(KSL_REVOCATION_REQUIRE_STAPLED, 0, 0, NULL), *sc = rv_server("rv-leaf", 0);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_TCP), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    blob cert = file_of(named), b = file_of("ocsp-good");
    const unsigned char *p = cert.buf;
    X509 *x = d2i_X509(NULL, &p, (long)cert.len);
    OCSP_RESPID *id = OCSP_RESPID_new();
    STACK_OF(OCSP_RESPID) *ids = sk_OCSP_RESPID_new_null();
    OCSP_RESPID_set_by_name(id, x);
    sk_OCSP_RESPID_push(ids, id);
    SSL_set_tlsext_status_ids(c->ssl, ids); /* the SSL takes the list */
    ksl_ssl_set(s, KSL_SET_OCSP_RESPONSE, b.buf, b.len);
    int rc = tcp_pump(c, s);
    X509_free(x);
    free(cert.buf);
    free(b.buf);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    return rc;
}

static void test_stapling(void) {
    SECTION("revocation_stapling");
    stapling_over(KSL_MODE_QUIC, 0, "QUIC");
    stapling_over(KSL_MODE_TCP, 0, "TLS 1.3 over TCP");
    stapling_over(KSL_MODE_TCP, 1, "TLS 1.2 over TCP");
    CHECK(staple_with_responder_ids("rv-mid") == KSL_OK, "the client named the responder that signed the response");
    CHECK(staple_with_responder_ids("rv-responder-root") == KSL_ERROR,
          "negative_responder_not_named: the client named another responder, nothing is stapled");
    /* the setter's rules */
    ksl_ctx *cc = rv_client(0, 0, 0, NULL), *sc = rv_server("rv-leaf", 0);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_TCP), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    blob b = file_of("ocsp-good");
    CHECK(ksl_ssl_set(c, KSL_SET_OCSP_RESPONSE, b.buf, b.len) == KSL_ERROR, "negative: a client staples nothing");
    CHECK(ksl_ssl_set(s, KSL_SET_OCSP_RESPONSE, b.buf, 0) == KSL_OK && s->ocsp_staple == NULL,
          "an empty response clears");
    CHECK(ksl_ctx_set_option(sc, KSL_OPT_REVOCATION, 1) == KSL_ERROR, "negative: revocation is client-only");
    CHECK(ksl_ctx_set_option(cc, KSL_OPT_REVOCATION, 3) == KSL_ERROR, "negative: unknown policy");
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    CHECK(tcp_pump(c, s) == KSL_OK, "handshake");
    uint32_t code = 0;
    CHECK(ksl_ssl_set(s, KSL_SET_OCSP_RESPONSE, b.buf, b.len) == KSL_ERROR &&
              (ksl_ssl_last_error(s, &code, NULL, NULL, 0), code == KSL_E_TOO_LATE),
          "negative: too late after the handshake");
    free(b.buf);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}

#else
/* a build without OpenSSL's ocsp module: no status_request, and the OCSP entry points say so */
static void test_without_ocsp(void) {
    SECTION("revocation_without_ocsp");
    blob g = file_of("ocsp-good"), ch = framed(2, "rv-leaf", "rv-mid");
    CHECK(ksl_ocsp_check(g.buf, g.len, ch.buf, ch.len, 0, NULL) == KSL_ERROR, "ksl_ocsp_check unavailable");
    ksl_ctx *cc = ksl_ctx_new(KSL_CLIENT), *sc = rv_server("rv-leaf", 0);
    uint32_t code = 0;
    CHECK(ksl_ctx_set_option(cc, KSL_OPT_REVOCATION, KSL_REVOCATION_STAPLED_IF_PRESENT) == KSL_ERROR &&
              (ksl_ctx_last_error(cc, &code, NULL, 0), code == KSL_E_NOT_SUPPORTED),
          "negative: no stapling policy without OCSP");
    CHECK(ksl_ctx_set_option(cc, KSL_OPT_REVOCATION, KSL_REVOCATION_OFF) == KSL_OK, "off is always accepted");
    ksl_ssl *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(ksl_ssl_set(s, KSL_SET_OCSP_RESPONSE, g.buf, g.len) == KSL_ERROR &&
              (ksl_ssl_last_error(s, &code, NULL, NULL, 0), code == KSL_E_NOT_SUPPORTED),
          "negative: nothing to staple without OCSP");
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    free(g.buf);
    free(ch.buf);
    END();
}
#endif

static void test_crls(void) {
    SECTION("revocation_crls");
    hs good = {"rv-leaf", NULL, NULL, KSL_REVOCATION_OFF, KSL_MODE_QUIC, 0, 0};
    hs_out o = handshake_with(&good, "crl-mid");
    CHECK(o.done && o.rc != KSL_ERROR, "a leaf the CRL does not list passes");
    hs revoked = {"rv-leaf-revoked", NULL, NULL, KSL_REVOCATION_OFF, KSL_MODE_QUIC, 0, 0};
    o = handshake_with(&revoked, "crl-mid");
    CHECK(o.rc == KSL_ERROR && !o.done && o.alert == 44 && o.x509 == X509_V_ERR_CERT_REVOKED,
          "negative_crl_revoked: certificate_revoked (44)");
    revoked.mode = KSL_MODE_TCP;
    o = handshake_with(&revoked, "crl-mid");
    CHECK(o.rc == KSL_ERROR && o.alert == 44 && o.x509 == X509_V_ERR_CERT_REVOKED, "negative_crl_revoked over TCP");
    o = handshake_with(&revoked, "crl-root");
    CHECK(o.done && o.rc != KSL_ERROR, "an issuer without a configured CRL is not checked");
    o = handshake_with(&good, "crl-mid-stale");
    CHECK(o.rc == KSL_ERROR && o.x509 == X509_V_ERR_CRL_HAS_EXPIRED, "negative_crl_stale: an expired CRL fails");
    if (!(o.rc == KSL_ERROR && o.x509 == X509_V_ERR_CRL_HAS_EXPIRED))
        printf("  got rc=%d done=%d alert=%d x509=%d\n", o.rc, o.done, o.alert, o.x509);
    o = handshake_with(&good, "crl-mid-partitioned");
    CHECK(o.rc == KSL_ERROR && o.x509 == X509_V_ERR_DIFFERENT_CRL_SCOPE,
          "negative_crl_not_covering: the issuer's configured CRL does not cover the leaf (fail closed)");
    if (!(o.rc == KSL_ERROR && o.x509 == X509_V_ERR_DIFFERENT_CRL_SCOPE))
        printf("  got rc=%d done=%d alert=%d x509=%d\n", o.rc, o.done, o.alert, o.x509);
    /* a configured CRL whose issuer is not among the roots or on the path: the certificates of that issuer fail closed */
    client_root = "rv-mid";
    o = handshake_with(&good, "crl-root");
    CHECK(
        o.rc == KSL_ERROR && o.x509 == X509_V_ERR_CRL_SIGNATURE_FAILURE && o.alert == 51,
        "negative_crl_issuer_outside_path: roots = [rv-mid], crls = [rv-root's]: rv-mid's CRL cannot be verified (fail "
        "closed, decrypt_error)");
    if (!(o.rc == KSL_ERROR && o.x509 == X509_V_ERR_CRL_SIGNATURE_FAILURE))
        printf("  got rc=%d done=%d alert=%d x509=%d\n", o.rc, o.done, o.alert, o.x509);
    /* OpenSSL 4 no longer checks a trust anchor that is not self-signed (x509_vfy.c revocation_check_end); ksl does
       (ksl_ocsp.c anchor_status): with both CAs among the roots the path ends at rv-mid, which rv-root's CRL revokes */
    client_root2 = "rv-root";
    o = handshake_with(&good, "crl-root-revokes-mid");
    CHECK(o.rc == KSL_ERROR && !o.done && o.alert == 44 && o.x509 == X509_V_ERR_CERT_REVOKED,
          "negative_crl_anchor_revoked: roots = [rv-mid, rv-root], rv-root's CRL revokes the anchor rv-mid");
    if (!(o.rc == KSL_ERROR && o.x509 == X509_V_ERR_CERT_REVOKED))
        printf("  got rc=%d done=%d alert=%d x509=%d\n", o.rc, o.done, o.alert, o.x509);
    o = handshake_with(&good, "crl-root");
    CHECK(o.done && o.rc != KSL_ERROR, "the same anchors with a CRL of rv-root that revokes nothing pass");
    hs good_tcp = good;
    good_tcp.mode = KSL_MODE_TCP;
    o = handshake_with(&good_tcp, "crl-root-revokes-mid");
    CHECK(o.rc == KSL_ERROR && o.alert == 44 && o.x509 == X509_V_ERR_CERT_REVOKED,
          "negative_crl_anchor_revoked over TCP");
    client_root2 = NULL;
    client_root = "rv-root";
    o = handshake_with(&good, "crl-root-revokes-mid");
    CHECK(o.rc == KSL_ERROR && o.alert == 44 && o.x509 == X509_V_ERR_CERT_REVOKED,
          "negative_crl_intermediate_revoked: anchored at rv-root, rv-mid is on the path and revoked");
    o = handshake_with(&good, "crl-mid-impostor");
    CHECK(
        o.rc == KSL_ERROR && o.x509 == X509_V_ERR_UNABLE_TO_GET_CRL && o.alert == 48,
        "negative_crl_other_key: a CRL under the issuer's name and another key's identifier: no issuer for it, the issuer's "
        "status is unknown (fail closed, unknown_ca)");
    if (!(o.rc == KSL_ERROR && o.x509 == X509_V_ERR_UNABLE_TO_GET_CRL))
        printf("  got rc=%d done=%d alert=%d x509=%d\n", o.rc, o.done, o.alert, o.x509);
    {
        ksl_ctx *cc = rv_client(0, 0, 0, NULL), *sc = rv_server("rv-leaf", 0);
        blob t = framed(1, "crl-mid");
        t.buf[t.len - 1] ^= 0x01; /* the last byte of the CRL's signature */
        CHECK(ksl_ctx_set_crls(cc, t.buf, t.len) == KSL_OK,
              "a CRL with a damaged signature is stored (it is verified in use)");
        ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_TCP), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
        ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
        int a = 0;
        int rc = tcp_pump(c, s);
        ksl_ssl_last_error(c, NULL, &a, NULL, 0);
        CHECK(rc == KSL_ERROR && (a >> 16) == X509_V_ERR_CRL_SIGNATURE_FAILURE,
              "negative_crl_tampered_signature: CRL_SIGNATURE_FAILURE");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
        free(t.buf);
    }
    /* resumption's re-verification sees the CRL too */
    ksl_ctx *cc = rv_client(0, 0, 0, "crl-mid");
    blob bad = framed(3, "rv-leaf-revoked", "rv-mid", "rv-root"), ok = framed(2, "rv-leaf", "rv-mid");
    int err = 0;
    CHECK(ksl_ctx_verify_chain(cc, bad.buf, bad.len, "server.test", 0, &err) == KSL_ERROR &&
              err == X509_V_ERR_CERT_REVOKED,
          "negative_crl_reverify: ksl_ctx_verify_chain refuses a revoked leaf");
    CHECK(ksl_ctx_verify_chain(cc, ok.buf, ok.len, "server.test", 0, &err) == KSL_OK, "and passes a good one");
    free(bad.buf);
    free(ok.buf);
    ksl_ctx_free(cc);
    /* a server's client certificates */
    ksl_ctx *sc = rv_server("rv-leaf", 0);
    blob r = framed(1, "rv-root"), l = framed(1, "crl-mid");
    ksl_ctx_set_roots(sc, r.buf, r.len);
    CHECK(ksl_ctx_set_crls(sc, l.buf, l.len) == KSL_OK, "server CRL accepted");
    ksl_ctx_set_option(sc, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_REQUIRED);
    for (int k = 0; k < 2; k++) {
        const char *who = k ? "rv-client-revoked" : "rv-client";
        ksl_ctx *c2 = rv_client(0, 0, 0, NULL);
        char nm[64], kp[64];
        snprintf(nm, sizeof nm, "%s", who);
        snprintf(kp, sizeof kp, RV "%s", who);
        blob ch = framed(2, nm, "rv-mid");
        size_t kl;
        uint8_t *key = key_of(kp, &kl);
        ksl_ctx_set_identity(c2, ch.buf, ch.len, key, kl);
        ksl_ssl *c = ksl_ssl_new(c2, KSL_MODE_TCP), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
        ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
        int rc = tcp_pump(c, s);
        int a = 0;
        ksl_ssl_last_error(s, NULL, &a, NULL, 0);
        if (k)
            CHECK(rc == KSL_ERROR && (a >> 16) == X509_V_ERR_CERT_REVOKED,
                  "negative_crl_client_revoked: the server refuses a revoked client certificate");
        else
            CHECK(rc == KSL_OK, "a good client certificate passes the server's CRL");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(c2);
        free(ch.buf);
        free(key);
    }
    ksl_ctx_free(sc);
    /* the setter's rules */
    ksl_ctx *sys = ksl_ctx_new(KSL_CLIENT);
    CHECK(ksl_ctx_set_crls(sys, l.buf, l.len) == KSL_ERROR, "negative: no CRLs on a context without its own roots");
    ksl_ctx_free(sys);
    ksl_ctx *own = ksl_ctx_new(KSL_CLIENT);
    ksl_ctx_set_roots(own, r.buf, r.len);
    l.buf[l.len - 1] ^= 0xff;
    uint8_t junk[] = {0, 0, 0, 3, 1, 2, 3};
    CHECK(ksl_ctx_set_crls(own, junk, sizeof junk) == KSL_ERROR, "negative: not a CRL");
    const char *unsupported[] = {"crl-mid-delta", "crl-mid-indirect", "crl-mid-reasons",
                                 "crl-mid-attr",  "crl-mid-userca",   "crl-mid-badidp"};
    const char *unsupported_msg[] = {"negative_delta_crl: refused",
                                     "negative_indirect_crl: refused",
                                     "negative_reasons_crl: an onlySomeReasons CRL refused",
                                     "negative_attr_crl: an onlyAttributeCerts CRL refused",
                                     "negative_userca_crl: onlyUser and onlyCA together refused",
                                     "negative_bad_idp_crl: an issuingDistributionPoint that does not decode refused"};
    for (int i = 0; i < 6; i++) {
        blob u = framed(1, unsupported[i]);
        uint32_t code = 0;
        CHECK(ksl_ctx_set_crls(own, u.buf, u.len) == KSL_ERROR &&
                  (ksl_ctx_last_error(own, &code, NULL, 0), code == KSL_E_BAD_ARG),
              unsupported_msg[i]);
        free(u.buf);
    }
    CHECK(ksl_ctx_set_crls(own, l.buf, l.len - 1) == KSL_ERROR, "negative: bad framing");
    ksl_ctx_free(own);
    free(r.buf);
    free(l.buf);
    END();
}

/* CRL distribution points of a peer's certificate against configured CRLs that carry an issuingDistributionPoint
   (CVE-2026-121482, openssl/openssl@54e14955ef, carried as patch_11 under ADR-0019). OpenSSL 4.1.0 rebuilt the full name of
   every nameRelativeToCRLIssuer distribution point (issuer name + fragment, a copy and a re-encoding) for every CRL it
   scored, before any signature on the path is checked: a peer's certificate full of them, signed by nobody, cost
   (CRLs of its issuer) x (its distribution points) name builds per verification. Built here with OpenSSL's own API: a CA, its
   CRLs, and leaves with the distribution points each case needs. */
static void dp_ext(X509 *x, X509 *issuer, int nid, const char *value) {
    X509V3_CTX v;
    X509V3_set_ctx(&v, issuer, x, NULL, NULL, 0);
    X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &v, nid, value);
    CHECK(e != NULL && X509_add_ext(x, e, -1) == 1, "crldp: certificate extension");
    X509_EXTENSION_free(e);
}
static DIST_POINT_NAME *dp_name(int relative, const char *v) {
    DIST_POINT_NAME *n = DIST_POINT_NAME_new();
    if (relative) {
        n->type = 1;
        n->name.relativename = sk_X509_NAME_ENTRY_new_null();
        sk_X509_NAME_ENTRY_push(n->name.relativename, X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName, MBSTRING_ASC,
                                                                                    (const unsigned char *)v, -1));
    } else {
        n->type = 0;
        n->name.fullname = GENERAL_NAMES_new();
        ASN1_IA5STRING *s = ASN1_IA5STRING_new();
        ASN1_STRING_set1_string(s, v);
        GENERAL_NAME *g = GENERAL_NAME_new();
        GENERAL_NAME_set0_value(g, GEN_URI, s);
        sk_GENERAL_NAME_push(n->name.fullname, g);
    }
    return n;
}
static X509 *dp_ca(EVP_PKEY *k) {
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();
    const char *rdn[][2] = {
        {"C", "ZZ"}, {"O", "Kuicksilver test"}, {"OU", "CRL distribution points"}, {"CN", "ksl crldp CA"}};
    for (int i = 0; i < 4; i++)
        X509_NAME_add_entry_by_txt(n, rdn[i][0], MBSTRING_ASC, (const unsigned char *)rdn[i][1], -1, -1, 0);
    X509_set_version(x, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, n);
    X509_NAME_free(n);
    X509_gmtime_adj(X509_getm_notBefore(x), -86400);
    X509_gmtime_adj(X509_getm_notAfter(x), 30 * 86400);
    X509_set_pubkey(x, k);
    dp_ext(x, x, NID_basic_constraints, "critical,CA:TRUE");
    dp_ext(x, x, NID_key_usage, "critical,keyCertSign,cRLSign");
    dp_ext(x, x, NID_subject_key_identifier, "hash");
    CHECK(X509_sign(x, k, EVP_sha256()) > 0, "crldp: CA signed");
    return x;
}
/* A leaf of `ca` with `relative` distribution points CN=dp<i> (none names a CRL), with `interleave` a fullName one after every
   fourth of them, then `full` fullName ones (URIs naming no CRL), and last, when `match` is set, a relative one CN=<match>
   (relative = 0: the fullName URI <match>). Its key is `signer`'s, and `signer` signs it. */
static X509 *dp_leaf(X509 *ca, EVP_PKEY *signer, long serial, int relative, int interleave, int full, const char *match,
                     int match_relative) {
    X509 *x = X509_new();
    X509_set_version(x, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_set_issuer_name(x, X509_get_subject_name(ca));
    X509_NAME *n = X509_NAME_new();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"leaf.test", -1, -1, 0);
    X509_set_subject_name(x, n);
    X509_NAME_free(n);
    X509_gmtime_adj(X509_getm_notBefore(x), -86400);
    X509_gmtime_adj(X509_getm_notAfter(x), 30 * 86400);
    X509_set_pubkey(x, signer);
    dp_ext(x, ca, NID_subject_alt_name, "DNS:leaf.test");
    dp_ext(x, ca, NID_authority_key_identifier, "keyid:always");
    CRL_DIST_POINTS *dps = sk_DIST_POINT_new_null();
    char v[48];
    for (int i = 0; i < relative; i++) {
        DIST_POINT *dp = DIST_POINT_new();
        snprintf(v, sizeof v, "dp%d", i);
        dp->distpoint = dp_name(1, v);
        sk_DIST_POINT_push(dps, dp);
        if (interleave && i % 4 == 3) {
            dp = DIST_POINT_new();
            snprintf(v, sizeof v, "http://dp.invalid/%d.crl", i);
            dp->distpoint = dp_name(0, v);
            sk_DIST_POINT_push(dps, dp);
        }
    }
    for (int i = 0; i < full; i++) {
        DIST_POINT *dp = DIST_POINT_new();
        snprintf(v, sizeof v, "http://dp.invalid/f%d.crl", i);
        dp->distpoint = dp_name(0, v);
        sk_DIST_POINT_push(dps, dp);
    }
    if (match) {
        DIST_POINT *dp = DIST_POINT_new();
        dp->distpoint = dp_name(match_relative, match);
        sk_DIST_POINT_push(dps, dp);
    }
    X509_EXTENSION *e = X509V3_EXT_i2d(NID_crl_distribution_points, 0, dps);
    CHECK(e != NULL && X509_add_ext(x, e, -1) == 1, "crldp: distribution points");
    X509_EXTENSION_free(e);
    sk_DIST_POINT_pop_free(dps, DIST_POINT_free);
    CHECK(X509_sign(x, signer, EVP_sha256()) > 0, "crldp: leaf signed");
    return x;
}
/* A complete CRL of `ca` (number `number`) whose issuingDistributionPoint is CN=<idp> (relative) or the URI <idp>, revoking
   `revoked` (0: none) */
static X509_CRL *dp_crl(X509 *ca, EVP_PKEY *k, long number, const char *idp, int relative, long revoked) {
    X509_CRL *c = X509_CRL_new();
    X509_CRL_set_version(c, X509_CRL_VERSION_2);
    X509_CRL_set_issuer_name(c, X509_get_subject_name(ca));
    ASN1_TIME *t = X509_gmtime_adj(NULL, -3600);
    X509_CRL_set1_lastUpdate(c, t);
    X509_gmtime_adj(t, 86400);
    X509_CRL_set1_nextUpdate(c, t);
    if (revoked) {
        X509_REVOKED *r = X509_REVOKED_new();
        ASN1_INTEGER *s = ASN1_INTEGER_new();
        ASN1_INTEGER_set(s, revoked);
        X509_REVOKED_set_serialNumber(r, s);
        ASN1_INTEGER_free(s);
        X509_gmtime_adj(t, -1800);
        X509_REVOKED_set_revocationDate(r, t);
        X509_CRL_add0_revoked(c, r);
    }
    ASN1_TIME_free(t);
    ASN1_INTEGER *num = ASN1_INTEGER_new();
    ASN1_INTEGER_set(num, number);
    X509_EXTENSION *e = X509V3_EXT_i2d(NID_crl_number, 0, num);
    CHECK(e != NULL && X509_CRL_add_ext(c, e, -1) == 1, "crldp: CRL number");
    X509_EXTENSION_free(e);
    ASN1_INTEGER_free(num);
    X509V3_CTX v;
    X509V3_set_ctx(&v, ca, NULL, NULL, c, 0);
    e = X509V3_EXT_conf_nid(NULL, &v, NID_authority_key_identifier, "keyid:always");
    CHECK(e != NULL && X509_CRL_add_ext(c, e, -1) == 1, "crldp: CRL authorityKeyIdentifier");
    X509_EXTENSION_free(e);
    ISSUING_DIST_POINT *ip = ISSUING_DIST_POINT_new();
    ip->distpoint = dp_name(relative, idp);
    e = X509V3_EXT_i2d(NID_issuing_distribution_point, 1, ip);
    CHECK(e != NULL && X509_CRL_add_ext(c, e, -1) == 1, "crldp: issuingDistributionPoint");
    X509_EXTENSION_free(e);
    ISSUING_DIST_POINT_free(ip);
    X509_CRL_sort(c);
    CHECK(X509_CRL_sign(c, k, EVP_sha256()) > 0, "crldp: CRL signed");
    return c;
}
static void dp_append(blob *b, const unsigned char *der, int len) {
    b->buf = realloc(b->buf, b->len + 4 + (size_t)len);
    b->buf[b->len] = (uint8_t)(len >> 24);
    b->buf[b->len + 1] = (uint8_t)(len >> 16);
    b->buf[b->len + 2] = (uint8_t)(len >> 8);
    b->buf[b->len + 3] = (uint8_t)len;
    memcpy(b->buf + b->len + 4, der, (size_t)len);
    b->len += 4 + (size_t)len;
}
static blob dp_framed_cert(X509 *x) {
    blob b = {0};
    unsigned char *der = NULL;
    int l = i2d_X509(x, &der);
    dp_append(&b, der, l);
    OPENSSL_free(der);
    return b;
}
static ksl_ctx *dp_client(X509 *ca, X509_CRL **crls, int n) {
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT);
    blob r = dp_framed_cert(ca), l = {0};
    CHECK(ksl_ctx_set_roots(c, r.buf, r.len) == KSL_OK, "crldp: roots");
    for (int i = 0; i < n; i++) {
        unsigned char *der = NULL;
        int len = i2d_X509_CRL(crls[i], &der);
        dp_append(&l, der, len);
        OPENSSL_free(der);
    }
    CHECK(ksl_ctx_set_crls(c, l.buf, l.len) == KSL_OK, "crldp: CRLs accepted");
    free(r.buf);
    free(l.buf);
    return c;
}
/* the process's CPU time in milliseconds: clock() on POSIX hosts; on Windows, where clock() is wall time, GetProcessTimes */
static double dp_cpu_ms(void) {
#ifdef _WIN32
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        return 0;
    ULARGE_INTEGER k, u;
    k.LowPart = kernel.dwLowDateTime, k.HighPart = kernel.dwHighDateTime;
    u.LowPart = user.dwLowDateTime, u.HighPart = user.dwHighDateTime;
    return (double)(k.QuadPart + u.QuadPart) / 10000.0; /* 100 ns units */
#else
    return (double)clock() * 1000.0 / CLOCKS_PER_SEC;
#endif
}
static int dp_verify(ksl_ctx *c, X509 *leaf, double *cpu_ms) {
    blob ch = dp_framed_cert(leaf);
    int err = -1;
    double t0 = dp_cpu_ms();
    int rc = ksl_ctx_verify_chain(c, ch.buf, ch.len, "leaf.test", 0, &err);
    if (cpu_ms)
        *cpu_ms = dp_cpu_ms() - t0;
    free(ch.buf);
    return rc == KSL_OK ? X509_V_OK : err;
}
static void test_crl_dp_work(void) {
    SECTION("revocation_crl_distribution_points");
    EVP_PKEY *ck = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"), *ak = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *ca = dp_ca(ck);
    /* the work bound: a peer's leaf under the CA's name, signed by the peer's own key, with ~95 KB of relative distribution
       points that name none of the configured CRLs (the 100 KiB certificate list bound of a handshake: max_cert_list) */
    enum { MANY = 4400, CRLS = 32 };
    X509_CRL *crls[CRLS];
    char idp[48];
    for (int i = 0; i < CRLS; i++) {
        snprintf(idp, sizeof idp, "http://crl.invalid/%d.crl", i);
        crls[i] = dp_crl(ca, ck, i + 1, idp, 0, 0);
    }
    X509 *evil = dp_leaf(ca, ak, 66, MANY, 0, 0, NULL, 0);
    int evil_len = i2d_X509(evil, NULL);
    CHECK(evil_len > 80000 && evil_len < 100 * 1024, "crldp: the peer's leaf fits a handshake's certificate list");
    ksl_ctx *one = dp_client(ca, crls, 1), *all = dp_client(ca, crls, CRLS);
    double t1 = 1e9, tn = 1e9;
    int e1 = 0, en = 0;
    for (int round = 0; round < 3; round++) { /* the least CPU time of three: a loaded host only adds to it */
        double t;
        e1 = dp_verify(one, evil, &t);
        t1 = t < t1 ? t : t1;
        en = dp_verify(all, evil, &t);
        tn = t < tn ? t : tn;
    }
    printf(
        "  %d-byte leaf, %d relative distribution points: %.1f ms CPU against 1 CRL, %.1f ms against %d (x509 %d, %d)\n",
        evil_len, MANY, t1, tn, CRLS, e1, en);
    /* refused at the first CRL scored for it (patch 11's bound), reported as a CRL that cannot be used for it: the bound below
       holds because of that refusal, not because the verification stopped early for another reason */
    CHECK(e1 == X509_V_ERR_UNABLE_TO_GET_CRL && en == X509_V_ERR_UNABLE_TO_GET_CRL,
          "negative_crldp_flood: the unsigned leaf fails at the bound on relative distribution points");
    CHECK(tn <= 4 * t1 + 25.0,
          "negative_crldp_flood: the work does not grow with (CRLs of the issuer) x (relative distribution points)");
    /* within the bound: 16 relative distribution points (their names built once per certificate) and ~2,600 fullName ones
       compared against every CRL; nothing matches, so the leaf is out of every CRL's scope */
    enum { FULL = 2600 };
    X509 *mixed = dp_leaf(ca, ak, 67, 16, 0, FULL, NULL, 0);
    int mixed_len = i2d_X509(mixed, NULL);
    CHECK(mixed_len > 80000 && mixed_len < 100 * 1024, "crldp: the mixed leaf fits a handshake's certificate list");
    double m1 = 1e9, mn = 1e9;
    int f1 = 0, fn = 0;
    for (int round = 0; round < 3; round++) {
        double t;
        f1 = dp_verify(one, mixed, &t);
        m1 = t < m1 ? t : m1;
        fn = dp_verify(all, mixed, &t);
        mn = t < mn ? t : mn;
    }
    printf(
        "  %d-byte leaf, 16 relative and %d fullName distribution points: %.1f ms CPU against 1 CRL, %.1f ms against %d "
        "(x509 %d, %d)\n",
        mixed_len, FULL, m1, mn, CRLS, f1, fn);
    CHECK(f1 == X509_V_ERR_DIFFERENT_CRL_SCOPE && fn == X509_V_ERR_DIFFERENT_CRL_SCOPE,
          "negative_crldp_flood_mixed: the leaf is out of every CRL's scope");
    CHECK(mn <= 4 * m1 + 25.0, "negative_crldp_flood_mixed: 16 relative names are built once, not once per CRL");
    ksl_ctx_free(one);
    ksl_ctx_free(all);
    X509_free(evil);
    X509_free(mixed);
    for (int i = 0; i < CRLS; i++)
        X509_CRL_free(crls[i]);
    /* the names still match: CRL 1 covers CN=part-1 (relative) and revokes serial 2, CRL 2 covers the URI part-2 and revokes
       serial 5; a leaf names its CRL after 15 or 16 relative distribution points (fullName ones among them) */
    X509_CRL *parts[2] = {dp_crl(ca, ck, 1, "part-1", 1, 2), dp_crl(ca, ck, 2, "http://crl.invalid/part-2.crl", 0, 5)};
    ksl_ctx *c = dp_client(ca, parts, 2);
    X509 *l2 = dp_leaf(ca, ck, 2, 15, 1, 0, "part-1", 1), *l3 = dp_leaf(ca, ck, 3, 15, 1, 0, "part-1", 1),
         *l5 = dp_leaf(ca, ck, 5, 16, 1, 0, "http://crl.invalid/part-2.crl", 0),
         *l7 = dp_leaf(ca, ck, 7, 16, 1, 0, "http://crl.invalid/part-2.crl", 0),
         *l9 = dp_leaf(ca, ck, 9, 16, 1, 0, "part-1", 1);
    int e = dp_verify(c, l2, NULL);
    CHECK(e == X509_V_ERR_CERT_REVOKED, "negative_crldp_relative_revoked: 16th distribution point CN=part-1, revoked");
    if (e != X509_V_ERR_CERT_REVOKED)
        printf("  got x509=%d\n", e);
    e = dp_verify(c, l3, NULL);
    CHECK(e == X509_V_OK, "a leaf whose 16th distribution point is CN=part-1 and not revoked passes");
    if (e != X509_V_OK)
        printf("  got x509=%d\n", e);
    e = dp_verify(c, l5, NULL);
    CHECK(e == X509_V_ERR_CERT_REVOKED, "negative_crldp_full_revoked: fullName part-2 after 16 relative ones, revoked");
    e = dp_verify(c, l7, NULL);
    CHECK(e == X509_V_OK, "a leaf naming part-2 after 16 relative distribution points and not revoked passes");
    if (e != X509_V_OK)
        printf("  got x509=%d\n", e);
    /* upstream's bound (MAX_DP_NAMES): a 17th relative distribution point fails the certificate (fail closed), reported by ksl
       as a configured CRL that cannot be used for it (OpenSSL's X509_V_ERR_UNSPECIFIED would be internal_error, ksl's fault) */
    e = dp_verify(c, l9, NULL);
    CHECK(e == X509_V_ERR_UNABLE_TO_GET_CRL, "negative_crldp_relative_17: 17 relative distribution points fail closed");
    if (e != X509_V_ERR_UNABLE_TO_GET_CRL)
        printf("  got x509=%d\n", e);
    /* and in a handshake (TCP and QUIC): unknown_ca (48), as for any configured CRL that cannot be used for the certificate */
    for (int quic = 0; quic <= 1; quic++) {
        ksl_ctx *sc = ksl_ctx_new(KSL_SERVER), *cc = dp_client(ca, parts, 2);
        ksl_ctx_set_alpn(sc, ALPN_H3, sizeof ALPN_H3);
        ksl_ctx_set_alpn(cc, ALPN_H3, sizeof ALPN_H3);
        ksl_ctx_set_option(cc, KSL_OPT_VERIFY_MODE, KSL_VERIFY_OPENSSL);
        blob ch = dp_framed_cert(l9);
        unsigned char *kd = NULL;
        int kl = i2d_PrivateKey(ck, &kd);
        CHECK(ksl_ctx_set_identity(sc, ch.buf, ch.len, kd, (size_t)kl) == KSL_OK, "crldp: server identity");
        OPENSSL_free(kd);
        free(ch.buf);
        int mode = quic ? KSL_MODE_QUIC : KSL_MODE_TCP;
        ksl_ssl *cs = ksl_ssl_new(cc, mode), *ss = ksl_ssl_new(sc, mode);
        ksl_ssl_set(cs, KSL_SET_SNI, (const uint8_t *)"leaf.test", sizeof "leaf.test" - 1);
        ksl_ssl_set(cs, KSL_SET_VERIFY_NAME, (const uint8_t *)"leaf.test", sizeof "leaf.test" - 1);
        int rc;
        if (quic) {
            ksl_quic_set_transport_params(cs, TP, sizeof TP);
            ksl_quic_set_transport_params(ss, TP, sizeof TP);
            side a = {0}, b = {0};
            rc = pump(cs, ss, &a, &b, 40, accept_all, NULL);
        } else {
            rc = tcp_pump(cs, ss);
        }
        int al = 0;
        char m[256];
        uint32_t code;
        ksl_ssl_last_error(cs, &code, &al, m, sizeof m);
        CHECK(rc == KSL_ERROR && (al & 0x1ff) == 48 && (al >> 16) == X509_V_ERR_UNABLE_TO_GET_CRL,
              quic ? "negative_crldp_relative_17 over QUIC: unknown_ca (48), UNABLE_TO_GET_CRL"
                   : "negative_crldp_relative_17 over TCP: unknown_ca (48), UNABLE_TO_GET_CRL");
        if (!(rc == KSL_ERROR && (al & 0x1ff) == 48 && (al >> 16) == X509_V_ERR_UNABLE_TO_GET_CRL))
            printf("  got rc=%d alert=%d x509=%d\n", rc, al & 0x1ff, al >> 16);
        ksl_ssl_free(cs);
        ksl_ssl_free(ss);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    ksl_ctx_free(c);
    X509_free(l2);
    X509_free(l3);
    X509_free(l5);
    X509_free(l7);
    X509_free(l9);
    X509_CRL_free(parts[0]);
    X509_CRL_free(parts[1]);
    X509_free(ca);
    EVP_PKEY_free(ck);
    EVP_PKEY_free(ak);
    END();
}

#ifndef OPENSSL_NO_OCSP
extern int64_t ksl_test_ocsp_clock_skew;
extern int ksl_test_ocsp_server_checks;
/* One TCP handshake against the shared server context `sc` whose session staples `staple`: the client's KSL_GET_OCSP_STATUS
   status byte (0xee: the handshake failed), and the until it reports */
static int staple_status(ksl_ctx *sc, const char *staple, int64_t *until) {
    ksl_ctx *cc = rv_client(KSL_REVOCATION_STAPLED_IF_PRESENT, 0, 0, NULL);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_TCP), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    blob b = file_of(staple);
    ksl_ssl_set(s, KSL_SET_OCSP_RESPONSE, b.buf, b.len);
    free(b.buf);
    uint8_t st[9] = {0xee};
    size_t n = 0;
    if (tcp_pump(c, s) == KSL_OK)
        ksl_ssl_get(c, KSL_GET_OCSP_STATUS, st, sizeof st, &n);
    if (until) {
        *until = 0;
        for (int i = 1; i < 9; i++)
            *until = (*until << 8) | st[i];
    }
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    return st[0];
}
#ifndef _WIN32
static void *stapling_thread(void *arg) {
    for (int i = 0; i < 8; i++)
        if (staple_status(arg, "ocsp-good", NULL) != KSL_OCSP_GOOD)
            return arg;
    return NULL;
}
#endif
static void test_staple_cache(void) {
    SECTION("revocation_server_staple_cache");
    ksl_ctx *sc = rv_server("rv-leaf", 0);
    int before = ksl_test_ocsp_server_checks;
    CHECK(staple_status(sc, "ocsp-good", NULL) == KSL_OCSP_GOOD, "first handshake staples");
    CHECK(staple_status(sc, "ocsp-good", NULL) == KSL_OCSP_GOOD && ksl_test_ocsp_server_checks == before + 1,
          "a second handshake staples from the context's verdict (checked once)");
    CHECK(staple_status(sc, "ocsp-stale", NULL) == 0xff,
          "negative_cache_other_response: a stale response after a good one is checked and not stapled");
    CHECK(staple_status(sc, "ocsp-good", NULL) == KSL_OCSP_GOOD, "and the good one again");
    int checks = ksl_test_ocsp_server_checks;
    ksl_test_ocsp_clock_skew = 101LL * 366 * 86400; /* past the good response's nextUpdate (2126) */
    CHECK(staple_status(sc, "ocsp-good", NULL) == 0xff && ksl_test_ocsp_server_checks == checks + 1,
          "negative_cache_after_until: a verdict past its interval is not used, the response is not stapled");
    ksl_test_ocsp_clock_skew = 0;
    /* RFC 6960 section 4.2.2.2: a delegated responder's certificate bounds the interval too */
    int64_t until = 0;
    ksl_ctx *sc2 = rv_server("rv-leaf", 0);
    ksl_test_ocsp_clock_skew = SHORT_RESPONDER_AT - (int64_t)time(NULL); /* 2029: inside the responder's validity */
    CHECK(staple_status(sc2, "ocsp-short-responder", &until) == KSL_OCSP_GOOD && until == 1893456000LL,
          "the client's bound is the responder's notAfter (2030-01-01), not nextUpdate");
    ksl_test_ocsp_clock_skew = 1924992000LL - (int64_t)time(NULL); /* 2031 */
    CHECK(staple_status(sc2, "ocsp-short-responder", NULL) == 0xff,
          "negative_cache_responder_expired: after the responder's notAfter the cached verdict is not used");
    ksl_test_ocsp_clock_skew = 0;
    ksl_ctx_free(sc2);
#ifndef _WIN32
    pthread_t t[2];
    void *res[2] = {NULL, NULL};
    for (int i = 0; i < 2; i++)
        pthread_create(&t[i], NULL, stapling_thread, sc);
    for (int i = 0; i < 2; i++)
        pthread_join(t[i], &res[i]);
    CHECK(res[0] == NULL && res[1] == NULL, "two threads staple through one context's verdict");
#endif
    ksl_ctx_free(sc);
    END();
}
#endif

void run_revocation(void) {
#ifndef OPENSSL_NO_OCSP
    test_ocsp_check();
    test_stapling();
    test_staple_cache();
#else
    test_without_ocsp();
#endif
    test_crls();
    test_crl_dp_work();
}
