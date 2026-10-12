/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Verification contract (ADR-0011, ADR-0012): OpenSSL verifier, client pause, matcher on every path, EKU, chains. */
#include "test_common.h"
#include <openssl/x509_vfy.h>

typedef struct { const char *cert; const char *root; const char *name; int mode; int accept; int alert_on_reject; } scenario;
static int on_verify(ksl_ssl *s, int rc, void *a) { scenario *x = a; if (rc != KSL_WANT_VERIFY) return 1; return ksl_ssl_verify_resume(s, x->accept, x->alert_on_reject) == KSL_OK; }
/* returns the client's drive result; alert receives the client's local alert */
static int run(scenario *x, int *alert, int *done) {
    ksl_ctx *cc = client_ctx(x->root, x->mode), *sc = server_ctx(x->cert);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC); ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    if (x->name) ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)x->name, strlen(x->name)); ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP);
    side cs = {0}, ss = {0}; int rc = pump(c, s, &cs, &ss, 40, on_verify, x); last_code(c, alert); *done = cs.done && ss.done;
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); return rc;
}
#define EXPECT_OK(sc, msg) do { int al, dn; int rc = run(&(sc), &al, &dn); CHECK(dn && rc != KSL_ERROR, msg); } while (0)
#define EXPECT_ALERT(sc, a, msg) do { int al, dn; int rc = run(&(sc), &al, &dn); CHECK(rc == KSL_ERROR && !dn && al == (a), msg); if (!(rc == KSL_ERROR && !dn && al == (a))) printf("  got rc=%d done=%d alert=%d\n", rc, dn, al); } while (0)

static void test_openssl_verifier(void) {
    SECTION("verify_openssl_verifier");
    scenario ok = {"server", "test-ca", "server.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_OK(ok, "anchored CA + matching name");
    scenario wild = {"server", "test-ca", "a.wild.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_OK(wild, "*.wild.test matches a.wild.test");
    scenario ip = {"server", "test-ca", "127.0.0.1", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_OK(ip, "IP literal against iPAddress SAN");
    scenario ca = {"server-other-ca", "test-ca", "server.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(ca, 48, "negative: unknown CA -> unknown_ca");
    scenario name = {"server", "test-ca", "wrong.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(name, 42, "negative: name mismatch -> bad_certificate");
    scenario cn = {"server-cn-only", "test-ca", "cn.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(cn, 42, "negative: CN without SAN rejected");
    scenario pw = {"server-partial-wildcard", "test-ca", "foo.wild.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(pw, 42, "negative: partial wildcard f*.wild.test rejected");
    scenario deep = {"server", "test-ca", "a.b.wild.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(deep, 42, "negative: *.wild.test does not match a.b.wild.test");
    scenario dnsip = {"server-dns-ip", "test-ca", "127.0.0.1", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(dnsip, 42, "negative: IP literal against dNSName=127.0.0.1 rejected");
    scenario eku = {"server-no-eku", "test-ca", "server.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_OK(eku, "absent EKU means any purpose (RFC 5280, as Go and webpki)");
    scenario ceku = {"server-client-eku", "test-ca", "server.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(ceku, 43, "negative: clientAuth-only EKU on a server");
    scenario exp = {"expired", "test-ca", "server.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(exp, 45, "negative: expired -> certificate_expired");
    scenario nyv = {"not-yet-valid", "test-ca", "server.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(nyv, 45, "negative: not yet valid -> certificate_expired");
    END();
}

static void test_pause_path(void) {
    SECTION("verify_pause_path_matcher_and_alerts");
    scenario ok = {"server", "test-ca", "server.test", KSL_VERIFY_PAUSE, 1, 0}; EXPECT_OK(ok, "platform accept + matching name");
    scenario name = {"server", "test-ca", "wrong.test", KSL_VERIFY_PAUSE, 1, 0}; EXPECT_ALERT(name, 42, "negative: platform accept but name mismatch -> rejected by the ksl matcher");
    scenario eku = {"server-client-eku", "test-ca", "server.test", KSL_VERIFY_PAUSE, 1, 0}; EXPECT_ALERT(eku, 43, "negative: platform accept but clientAuth-only EKU -> rejected by the ksl purpose check");
    scenario rej = {"server", "test-ca", "server.test", KSL_VERIFY_PAUSE, 0, 48}; EXPECT_ALERT(rej, 48, "platform reject with unknown_ca");
    scenario rej45 = {"server", "test-ca", "server.test", KSL_VERIFY_PAUSE, 0, 45}; EXPECT_ALERT(rej45, 45, "platform reject with certificate_expired");
    scenario untrusted = {"server-other-ca", "other-ca", "server.test", KSL_VERIFY_PAUSE, 1, 0}; EXPECT_OK(untrusted, "pause mode: trust is the platform's decision, roots in ksl are not consulted");
    END();
}

static void test_chains(void) {
    SECTION("verify_chains_and_spki");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = ksl_ctx_new(KSL_SERVER); ksl_ctx_set_alpn(sc, ALPN_H3, sizeof ALPN_H3);
    blob ch = chain_of(2, "server-via-intermediate", "intermediate"); size_t kl; uint8_t *k = key_of("server-via-intermediate", &kl);
    CHECK(ksl_ctx_set_identity(sc, ch.buf, ch.len, k, kl) == KSL_OK, "identity with an intermediate"); free(ch.buf); free(k);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC); ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP); side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK(cs.done && ss.done, "handshake through the intermediate");
    CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_PRESENTED, -1, NULL, 0, NULL) == 2, "presented: leaf + intermediate");
    CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_VALIDATED, -1, NULL, 0, NULL) == 3, "validated: leaf + intermediate + root");
    uint8_t der[4096], h1[32], h2[32]; size_t n, rl; uint8_t *root = read_file(TESTDATA "test-ca.der", &rl);
    CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_VALIDATED, 2, der, sizeof der, &n) == KSL_OK && ksl_spki_sha256(der, n, h1) == KSL_OK && ksl_spki_sha256(root, rl, h2) == KSL_OK && !memcmp(h1, h2, 32), "validated chain ends at the configured root (SPKI match)");
    CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_VALIDATED, 3, der, sizeof der, &n) == KSL_ERROR, "negative: index past the end");
    CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_PRESENTED, 0, der, 10, &n) == KSL_ERROR && n > 10, "negative: too small a buffer reports the needed size");
    free(root); ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static int client_cert_run(const char *client_cert, int *alert_on_server, int *done) {
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
    if (client_cert) { blob ch = chain_of(1, client_cert); size_t kl; uint8_t *k = key_of(client_cert, &kl); ksl_ctx_set_identity(cc, ch.buf, ch.len, k, kl); free(ch.buf); free(k); }
    blob r = chain_of(1, "test-ca"); ksl_ctx_set_roots(sc, r.buf, r.len); free(r.buf); ksl_ctx_set_option(sc, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_REQUIRED);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC); ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP); side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 40, NULL, NULL);
    int rc = ksl_drive(s); last_code(s, alert_on_server); *done = cs.done && ss.done;
    if (*done) { CHECK(ksl_ssl_get_peer_chain(s, KSL_CHAIN_VALIDATED, -1, NULL, 0, NULL) == 2, "server sees the validated client chain"); }
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); return rc;
}
static void test_client_cert(void) {
    SECTION("verify_server_client_cert_sync");
    int al, dn; client_cert_run("client", &al, &dn); CHECK(dn, "client certificate from the anchored CA accepted synchronously");
    int rc = client_cert_run("client-other-ca", &al, &dn); CHECK(rc == KSL_ERROR && !dn && al == 48, "negative: client cert from another CA -> unknown_ca");
    client_cert_run("client-no-eku", &al, &dn); CHECK(dn, "client cert without EKU accepted (absent EKU = any purpose)");
    rc = client_cert_run("server-client-eku", &al, &dn); CHECK(dn, "a clientAuth EKU cert works as a client cert");
    rc = client_cert_run("proxy", &al, &dn); CHECK(rc == KSL_ERROR && !dn && al == 43, "negative: serverAuth-only EKU as a client cert -> unsupported_certificate");
    rc = client_cert_run(NULL, &al, &dn); CHECK(rc == KSL_ERROR && !dn, "negative: required client certificate missing");
    END();
}

void run_verify_review(void);
void run_verify(void) { test_openssl_verifier(); test_pause_path(); test_chains(); test_client_cert(); run_verify_review(); }

/* ---- wire alerts, verify_err exposure, generic alerts, system store, resumed-session chain ---- */
static int raw_alert(ksl_ssl *s) { uint32_t c; int a; char m[256]; ksl_ssl_last_error(s, &c, &a, m, sizeof m); return a; }
static int alert_of(ksl_ssl *s) { return raw_alert(s) & 0xff; }
static int verify_err_of(ksl_ssl *s) { return raw_alert(s) >> 16; }
static void test_review_alerts(void) {
    SECTION("verify_review_alerts_and_verify_err");
    int al, dn; scenario name = {"server", "test-ca", "wrong.test", KSL_VERIFY_OPENSSL, 0, 0};
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC); ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"wrong.test", sizeof "wrong.test" - 1);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP); side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK(alert_of(c) == 42 && verify_err_of(c) == X509_V_ERR_HOSTNAME_MISMATCH, "hostname mismatch: alert 42 + X509_V_ERR_HOSTNAME_MISMATCH in verify_err");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); (void)name; (void)al; (void)dn;
    /* not-yet-valid keeps its own X509 code while the alert is 45 */
    cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL); sc = server_ctx("not-yet-valid"); c = ksl_ssl_new(cc, KSL_MODE_QUIC); s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP); memset(&cs, 0, sizeof cs); memset(&ss, 0, sizeof ss); pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK(alert_of(c) == 45 && verify_err_of(c) == X509_V_ERR_CERT_NOT_YET_VALID, "not yet valid: alert 45, verify_err NOT_YET_VALID");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    /* generic alerts: the OpenSSL path sends handshake_failure (40) */
    cc = client_ctx("other-ca", KSL_VERIFY_OPENSSL); ksl_ctx_set_option(cc, KSL_OPT_GENERIC_ALERTS, 1); sc = server_ctx("server"); c = ksl_ssl_new(cc, KSL_MODE_QUIC); s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP); memset(&cs, 0, sizeof cs); memset(&ss, 0, sizeof ss); pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK(alert_of(c) == 40 && verify_err_of(c) == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, "generic alerts: alert 40 on the wire, real reason kept in verify_err");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    /* pause path: the requested alerts 40/43/46 reach the wire unchanged */
    int want[3] = {40, 43, 46};
    for (int i = 0; i < 3; i++) { scenario sc2 = {"server", "test-ca", "server.test", KSL_VERIFY_PAUSE, 0, want[i]}; int a2, d2; run(&sc2, &a2, &d2); CHECK(a2 == want[i], "pause rejection alert reaches the wire as requested"); if (a2 != want[i]) printf("  wanted %d got %d\n", want[i], a2); }
    END();
}
static void test_system_store(void) {
    SECTION("verify_system_store_loads");
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT); uint32_t e; char m[256];
    int rc = ksl_ctx_set_roots(c, NULL, 0); ksl_ctx_last_error(c, &e, m, sizeof m);
    CHECK(rc == KSL_OK, "system certificate store located on this host (SSL_CERT_FILE/DIR or distribution paths)"); if (rc != KSL_OK) printf("  %s\n", m);
    ksl_ctx_free(c); END();
}
/* KSL_SET_VERIFY_NAME may be called more than once (a config applied to a session, then a redirect): the previous identifier of the
   other type must not linger in the X509_VERIFY_PARAM, or a host mismatch would be reported against the stale host. */
static void test_name_switch(void) {
    SECTION("verify_name_switch_clears_other_type");
    const char *seq[2][2] = {{"wrong.test", "127.0.0.1"}, {"127.0.0.1", "server.test"}};
    for (int i = 0; i < 2; i++) {
        ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
        ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
        ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1);
        CHECK(ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)seq[i][0], strlen(seq[i][0])) == KSL_OK, "first verify name accepted");
        CHECK(ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)seq[i][1], strlen(seq[i][1])) == KSL_OK, "second verify name accepted");
        ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP); side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 40, NULL, NULL);
        CHECK(cs.done && ss.done, "only the last verify name is checked");
        if (!(cs.done && ss.done)) { int al; last_code(c, &al); printf("  %s -> %s: alert=%d\n", seq[i][0], seq[i][1], al); }
        ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    }
    END();
}
/* KSL_OPT_CLIENT_CERT is a server option: on a client it would silently rewrite SSL_CTX_set_verify and switch peer verification off. */
static void test_client_cert_option_on_client(void) {
    SECTION("verify_client_cert_option_refused_on_client");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server-other-ca");
    CHECK(ksl_ctx_set_option(cc, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_NONE) == KSL_ERROR, "negative: client-cert mode refused on a client context");
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP); side cs = {0}, ss = {0}; int rc = pump(c, s, &cs, &ss, 40, NULL, NULL);
    int al; last_code(c, &al); CHECK(rc == KSL_ERROR && !cs.done && al == 48, "negative: verification stays on -> unknown_ca"); if (!(rc == KSL_ERROR && al == 48)) printf("  got rc=%d done=%d alert=%d\n", rc, cs.done, al);
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    /* out-of-range values are refused for both mode options */
    ksl_ctx *sc2 = server_ctx("server"), *cc2 = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
    CHECK(ksl_ctx_set_option(sc2, KSL_OPT_CLIENT_CERT, 3) == KSL_ERROR && ksl_ctx_set_option(sc2, KSL_OPT_CLIENT_CERT, -1) == KSL_ERROR, "negative: client-cert mode out of 0..2");
    CHECK(ksl_ctx_set_option(cc2, KSL_OPT_VERIFY_MODE, 3) == KSL_ERROR && ksl_ctx_set_option(cc2, KSL_OPT_VERIFY_MODE, -1) == KSL_ERROR, "negative: verify mode out of 0..2");
    CHECK(ksl_ctx_set_option(sc2, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_OPTIONAL) == KSL_OK, "client-cert mode accepted on a server");
    ksl_ctx_free(sc2); ksl_ctx_free(cc2);
    END();
}
void run_verify_review(void) { test_review_alerts(); test_system_store(); test_name_switch(); test_client_cert_option_on_client(); }
