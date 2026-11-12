/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Certificate revocation (RFC 9325 section 7.5): ksl_ocsp_check on real responses (tools/certs/gen-revocation-certs.sh), a
 * client checking stapled responses and a server stapling its own over QUIC, TLS 1.3 and TLS 1.2, and CRLs in the store. */
#include "test_common.h"
#include "ksl_internal.h" /* the test server that staples whatever it is given, past ksl's own checks */
#include <time.h>
#include <openssl/ocsp.h>

#define RV "revocation/"

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
        size_t n = (size_t)ASN1_STRING_length(sig);
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
    CHECK(check_file("ocsp-good", "rv-leaf", "rv-mid", 0, &until) == KSL_OCSP_GOOD && until > now + 86400LL * 365 * 50,
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
static ksl_ctx *rv_server(const char *leaf, int tls12) {
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER);
    ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    char name[128];
    snprintf(name, sizeof name, "%s", leaf);
    blob ch = framed(2, name, "rv-mid");
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
static ksl_ctx *rv_client(int revocation, int verify_mode, int tls12, const char *crl) {
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT);
    ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    blob r = framed(1, "rv-root");
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
        CHECK(o_.done && o_.rc != KSL_ERROR && o_.status[0] == (st), msg);                                             \
        if (!(o_.done && o_.rc != KSL_ERROR && o_.status[0] == (st)))                                                  \
            printf("  got rc=%d done=%d alert=%d x509=%d status=%d\n", o_.rc, o_.done, o_.alert, o_.x509, o_.status[0]); \
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
    hs mismatch = {"rv-leaf", NULL, "ocsp-revoked", KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_FAIL(mismatch, X509_V_ERR_OCSP_VERIFY_FAILED, "negative_client_mismatch: another certificate's response");
    hs unauth = {"rv-leaf", NULL, "ocsp-unauthorized", KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, 0};
    EXPECT_FAIL(unauth, X509_V_ERR_OCSP_VERIFY_FAILED, "negative_client_unauthorized_responder");
    hs off = {"rv-leaf-revoked", "ocsp-revoked", NULL, KSL_REVOCATION_OFF, mode, tls12, 0};
    EXPECT_PASS(off, 0xff, "off: nothing requested, nothing checked");
    hs paused = {"rv-leaf-revoked", "ocsp-revoked", NULL, KSL_REVOCATION_STAPLED_IF_PRESENT, mode, tls12, KSL_VERIFY_PAUSE};
    EXPECT_PASS(paused, 0xff, "the pause path (an application verifier) is not checked by ksl");
}

static void test_stapling(void) {
    SECTION("revocation_stapling");
    stapling_over(KSL_MODE_QUIC, 0, "QUIC");
    stapling_over(KSL_MODE_TCP, 0, "TLS 1.3 over TCP");
    stapling_over(KSL_MODE_TCP, 1, "TLS 1.2 over TCP");
    /* the setter's rules */
    ksl_ctx *cc = rv_client(0, 0, 0, NULL), *sc = rv_server("rv-leaf", 0);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_TCP), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    blob b = file_of("ocsp-good");
    CHECK(ksl_ssl_set(c, KSL_SET_OCSP_RESPONSE, b.buf, b.len) == KSL_ERROR, "negative: a client staples nothing");
    CHECK(ksl_ssl_set(s, KSL_SET_OCSP_RESPONSE, b.buf, 0) == KSL_ERROR, "negative: empty response");
    CHECK(ksl_ctx_set_option(sc, KSL_OPT_REVOCATION, 1) == KSL_ERROR, "negative: revocation is client-only");
    CHECK(ksl_ctx_set_option(cc, KSL_OPT_REVOCATION, 3) == KSL_ERROR, "negative: unknown policy");
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    CHECK(tcp_pump(c, s) == KSL_OK, "handshake");
    uint32_t code = 0;
    CHECK(ksl_ssl_set(s, KSL_SET_OCSP_RESPONSE, b.buf, b.len) == KSL_ERROR && (ksl_ssl_last_error(s, &code, NULL, NULL, 0),
                                                                              code == KSL_E_TOO_LATE),
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
    CHECK(ksl_ctx_set_crls(own, l.buf, l.len - 1) == KSL_ERROR, "negative: bad framing");
    ksl_ctx_free(own);
    free(r.buf);
    free(l.buf);
    END();
}

void run_revocation(void) {
#ifndef OPENSSL_NO_OCSP
    test_ocsp_check();
    test_stapling();
#else
    test_without_ocsp();
#endif
    test_crls();
}
