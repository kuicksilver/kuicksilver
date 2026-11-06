/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Verification contract (ADR-0011, ADR-0012): OpenSSL verifier, client pause, matcher on every path, EKU, chains. */
#define _POSIX_C_SOURCE 200809L   /* setenv, unsetenv, strdup under -std=c11 with glibc */
#include "test_common.h"
#include "ksl_internal.h"   /* ksl_chain_security, for the bounds on chains built here */
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

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
    scenario mid = {"server-via-intermediate", "intermediate", "server.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_OK(mid, "an anchored intermediate is a trust anchor (AnchoredCa: each is trusted as a root)");
    scenario midother = {"server", "intermediate", "server.test", KSL_VERIFY_OPENSSL, 0, 0}; EXPECT_ALERT(midother, 48, "negative: a chain outside the anchored intermediate -> unknown_ca");
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

static void test_verify_cached_chain(void) {
    SECTION("verify_cached_chain_again");
    /* resumption (ADR-0011): a chain kept from a full handshake is verified again with the current store, time, name and purpose */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *mid = client_ctx("intermediate", KSL_VERIFY_OPENSSL), *other = client_ctx("other-ca", KSL_VERIFY_OPENSSL);
    blob leaf = chain_of(1, "server"), via = chain_of(2, "server-via-intermediate", "intermediate"), cl = chain_of(1, "client"); int err = -1;
    CHECK(ksl_ctx_verify_chain(cc, leaf.buf, leaf.len, "server.test", 0, &err) == KSL_OK && err == 0, "the cached chain still verifies");
    CHECK(ksl_ctx_verify_chain(cc, leaf.buf, leaf.len, "127.0.0.1", 0, &err) == KSL_OK, "an IP reference identifier");
    CHECK(ksl_ctx_verify_chain(mid, via.buf, via.len, "server.test", 0, &err) == KSL_OK, "an anchored intermediate (PARTIAL_CHAIN) as at the handshake");
    CHECK(ksl_ctx_verify_chain(cc, leaf.buf, leaf.len, "server.test", (int64_t)7258118400 /* 2200-01-01 */, &err) == KSL_ERROR && err == X509_V_ERR_CERT_HAS_EXPIRED, "negative: past the leaf's notAfter -> expired");
    CHECK(ksl_ctx_verify_chain(other, leaf.buf, leaf.len, "server.test", 0, &err) == KSL_ERROR && err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, "negative: anchor no longer trusted -> unknown issuer");
    CHECK(ksl_ctx_verify_chain(cc, leaf.buf, leaf.len, "wrong.test", 0, &err) == KSL_ERROR && err == X509_V_ERR_HOSTNAME_MISMATCH, "negative: another name -> hostname mismatch");
    CHECK(ksl_ctx_verify_chain(cc, cl.buf, cl.len, "client.test", 0, &err) == KSL_ERROR && err == X509_V_ERR_INVALID_PURPOSE, "negative: a clientAuth-only certificate as a server -> invalid purpose");
    CHECK(ksl_ctx_verify_chain(cc, leaf.buf, leaf.len, "", 0, &err) == KSL_ERROR && err == 0, "negative: a client needs a name");
    CHECK(ksl_ctx_verify_chain(cc, leaf.buf, 3, "server.test", 0, &err) == KSL_ERROR && err == 0, "negative: bad framing");
    ksl_ctx *sc = server_ctx("server"); blob r = chain_of(1, "test-ca"); ksl_ctx_set_roots(sc, r.buf, r.len); free(r.buf);
    CHECK(ksl_ctx_verify_chain(sc, cl.buf, cl.len, NULL, 0, &err) == KSL_OK, "a server verifies a cached client chain without a name");
    free(leaf.buf); free(via.buf); free(cl.buf); ksl_ctx_free(cc); ksl_ctx_free(mid); ksl_ctx_free(other); ksl_ctx_free(sc); END();
}

void run_verify_review(void);
void run_verify(void) { test_openssl_verifier(); test_pause_path(); test_chains(); test_client_cert(); test_verify_cached_chain(); run_verify_review(); }

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
static void env_set(const char *k, const char *v) {
#ifdef _WIN32
    _putenv_s(k, v ? v : "");
#else
    if (v) setenv(k, v, 1); else unsetenv(k);
#endif
}
static void mk_dir(const char *p) {
#ifdef _WIN32
    _mkdir(p);
#else
    mkdir(p, 0700);
#endif
}
static int roots_from(const char *file, const char *dir, char *m, size_t cap) {
    env_set("SSL_CERT_FILE", file); env_set("SSL_CERT_DIR", dir);
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT); uint32_t e; m[0] = 0; int rc = ksl_ctx_set_roots(c, NULL, 0); if (rc != KSL_OK) ksl_ctx_last_error(c, &e, m, cap); ksl_ctx_free(c); return rc;
}
/* verify_system_store_missing_names_the_paths: a host without any CA bundle (distroless, scratch) fails when the context is built,
   with every path searched and the variables that override them in the message; SSL_CERT_FILE / SSL_CERT_DIR replace the system
   paths instead of falling back to them; a directory counts only when it exists */
static void test_system_store_missing(void) {
    SECTION("verify_system_store_missing_names_the_paths");
    const char *of = getenv("SSL_CERT_FILE"), *od = getenv("SSL_CERT_DIR"); char *sf = of ? strdup(of) : NULL, *sd = od ? strdup(od) : NULL;
    static const char *const files[] = {"/nonexistent/ksl/ca-certificates.crt", "/nonexistent/ksl/cert.pem", NULL};
    static const char *const dirs[] = {"/nonexistent/ksl/certs", NULL};
    char m[512];
    ksl_trust_paths_for_test(files, dirs);
    CHECK(roots_from(NULL, NULL, m, sizeof m) == KSL_ERROR, "no bundle and no directory: the context is refused");
    CHECK(strstr(m, "/nonexistent/ksl/ca-certificates.crt") && strstr(m, "/nonexistent/ksl/cert.pem") && strstr(m, "/nonexistent/ksl/certs/"), "the message lists every path searched");
    CHECK(strstr(m, "SSL_CERT_FILE") && strstr(m, "SSL_CERT_DIR") && strstr(m, "AnchoredCa"), "the message names SSL_CERT_FILE, SSL_CERT_DIR and AnchoredCa"); printf("  %s\n", m);
    ksl_trust_paths_for_test(NULL, NULL);   /* the real distribution paths: the env variables must still replace them */
    CHECK(roots_from("/nonexistent/ksl/env.pem", NULL, m, sizeof m) == KSL_ERROR && strstr(m, "SSL_CERT_FILE=/nonexistent/ksl/env.pem"), "SSL_CERT_FILE that does not load: refused, named, no fallback");
    CHECK(roots_from(NULL, "/nonexistent/ksl/envdir", m, sizeof m) == KSL_ERROR && strstr(m, "SSL_CERT_DIR=/nonexistent/ksl/envdir"), "SSL_CERT_DIR that does not exist: refused, named");
    { size_t l = 0; uint8_t *d = read_file(TESTDATA "test-ca.der", &l); const unsigned char *p = d; X509 *x = d ? d2i_X509(NULL, &p, (long)l) : NULL; FILE *f = x ? fopen("ksl_test_ca_bundle.pem", "w") : NULL;
      int w = f && PEM_write_X509(f, x) == 1; if (f) fclose(f); X509_free(x); free(d);
      CHECK(w && roots_from("ksl_test_ca_bundle.pem", NULL, m, sizeof m) == KSL_OK, "SSL_CERT_FILE with a PEM bundle loads"); remove("ksl_test_ca_bundle.pem"); }
    /* a directory nobody ran c_rehash on: X509_STORE_load_path "succeeds" on it and then finds nothing at every handshake */
    CHECK(roots_from(NULL, TESTDATA, m, sizeof m) == KSL_ERROR && strstr(m, "SSL_CERT_DIR="), "negative: SSL_CERT_DIR without PEM files or hash links is refused, not an unknown issuer later");
    { size_t l = 0; uint8_t *d = read_file(TESTDATA "test-ca.der", &l); const unsigned char *p = d; X509 *x = d ? d2i_X509(NULL, &p, (long)l) : NULL;
      char hashed[64]; snprintf(hashed, sizeof hashed, "ksl_test_hashed/%08lx.0", x ? X509_subject_name_hash(x) : 0UL);
      mk_dir("ksl_test_plain"); mk_dir("ksl_test_hashed");
      FILE *f = x ? fopen("ksl_test_plain/test-ca.pem", "w") : NULL; int w = f && PEM_write_X509(f, x) == 1; if (f) fclose(f);
      f = x ? fopen(hashed, "w") : NULL; w = w && f && PEM_write_X509(f, x) == 1; if (f) fclose(f);
      CHECK(w && roots_from(NULL, "ksl_test_plain", m, sizeof m) == KSL_OK, "SSL_CERT_DIR with PEM files and no hash links loads them (as Go does)");
      CHECK(w && roots_from(NULL, "ksl_test_hashed", m, sizeof m) == KSL_OK, "SSL_CERT_DIR with c_rehash links loads");
      ksl_trust_paths_for_test(files, (const char *const[]){"ksl_test_plain", NULL});
      CHECK(roots_from(NULL, NULL, m, sizeof m) == KSL_OK, "a distribution directory of PEM files without hash links loads");
      ksl_trust_paths_for_test(files, (const char *const[]){TESTDATA, NULL});
      CHECK(roots_from(NULL, NULL, m, sizeof m) == KSL_ERROR, "negative: a distribution directory without certificates does not count");
      ksl_trust_paths_for_test(NULL, NULL);
      remove("ksl_test_plain/test-ca.pem"); remove(hashed); rmdir("ksl_test_plain"); rmdir("ksl_test_hashed"); X509_free(x); free(d); }
    env_set("SSL_CERT_FILE", sf); env_set("SSL_CERT_DIR", sd); free(sf); free(sd);
    END();
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
void run_verify_security_level(void);
void run_verify_review(void) { run_verify_security_level(); test_review_alerts(); test_system_store(); test_system_store_missing(); test_name_switch(); test_client_cert_option_on_client(); }

/* ---- OpenSSL security level 2 on the peer's chain, on every path (T.5) ---- */
/* A server whose context is at security level 0, so that it can present the weak chains of testdata/weak (at the default level 2
   OpenSSL refuses to load a key below 112 bits as its own identity) */
static ksl_ctx *weak_server_ctx(blob chain, const char *leaf) {
    ksl_ctx *sc = ksl_ctx_new(KSL_SERVER); ksl_ctx_set_alpn(sc, ALPN_H3, sizeof ALPN_H3);
    CHECK(ksl_ctx_set_ciphers(sc, NULL, "@SECLEVEL=0:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256") == KSL_OK, "test server at security level 0");
    size_t kl; uint8_t *k = key_of(leaf, &kl);
    if (ksl_ctx_set_identity(sc, chain.buf, chain.len, k, kl) != KSL_OK) { uint32_t e; char m[256]; ksl_ctx_last_error(sc, &e, m, sizeof m); printf("  identity %s: %s\n", leaf, m); CHECK(0, "weak identity loads at level 0"); }
    free(k); free(chain.buf); return sc;
}
static int weak_pauses, weak_level_after_pause;
static int weak_on_verify(ksl_ssl *s, int rc, void *a) { (void)a; if (rc != KSL_WANT_VERIFY) return 1; weak_pauses++; return ksl_ssl_verify_resume(s, 1, 0) == KSL_OK; }
/* the client's local alert and X509 error after a handshake against chain; pause mode accepts at the pause (the platform's yes) */
static void weak_run(blob chain, const char *leaf, const char *root, int mode, int generic, int *alert, int *verr, int *done, int *pauses) {
    ksl_ctx *sc = weak_server_ctx(chain, leaf), *cc = client_ctx(root, mode); if (generic) ksl_ctx_set_option(cc, KSL_OPT_GENERIC_ALERTS, 1);
    if (weak_level_after_pause) CHECK(ksl_ctx_set_option(cc, KSL_OPT_LEVEL_AFTER_PAUSE, 1) == KSL_OK, "level after pause set");
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP);
    side cs = {0}, ss = {0}; weak_pauses = 0; pump(c, s, &cs, &ss, 40, weak_on_verify, NULL);
    *alert = alert_of(c); *verr = verify_err_of(c); *done = cs.done && ss.done; *pauses = weak_pauses;
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
}
#define W(n) "weak/" n
typedef struct { const char *what; const char *leaf, *mid; int verr; } weak_case;   /* verr 0 = accepted */
static const weak_case WEAK_CASES[] = {
    {"a 1024-bit RSA leaf", W("leaf-rsa1024"), NULL, X509_V_ERR_EE_KEY_TOO_SMALL},
    {"a 1024-bit RSA intermediate", W("leaf-via-rsa1024"), W("mid-rsa1024"), X509_V_ERR_CA_KEY_TOO_SMALL},
    {"a P-192 intermediate", W("leaf-via-p192"), W("mid-p192"), X509_V_ERR_CA_KEY_TOO_SMALL},
    {"an intermediate signed with SHA-1", W("leaf-via-sha1"), W("mid-sha1"), X509_V_ERR_CA_MD_TOO_WEAK},
    {"a leaf signed with SHA-1", W("leaf-sha1"), NULL, X509_V_ERR_CA_MD_TOO_WEAK},
    {"a 2048-bit RSA leaf (112 bits, the floor)", W("leaf-rsa2048"), NULL, 0},
    {"a P-256 leaf", W("leaf-p256"), NULL, 0},
    {"a P-224 intermediate (112 bits, the floor)", W("leaf-via-p224"), W("mid-p224"), 0},
};
static blob weak_chain(const weak_case *w) { return w->mid ? chain_of(2, w->leaf, w->mid) : chain_of(1, w->leaf); }
static void test_chain_security_level(void) {
    SECTION("verify_peer_chain_security_level");
    for (size_t i = 0; i < sizeof WEAK_CASES / sizeof WEAK_CASES[0]; i++) {
        const weak_case *w = &WEAK_CASES[i]; int al, ve, dn, pa; char msg[160];
        /* pause mode (Custom, Tofu; Platform off Linux checks the path the platform built instead, verify_built_path_level): ksl checks before the pause */
        weak_run(weak_chain(w), w->leaf, NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
        snprintf(msg, sizeof msg, "pause: %s -> %s", w->what, w->verr ? "bad_certificate before the pause" : "reaches the pause, accepted");
        if (w->verr) CHECK(!dn && al == 42 && ve == w->verr && pa == 0, msg); else CHECK(dn && pa == 1, msg);
        if ((w->verr && !(!dn && al == 42 && ve == w->verr && pa == 0)) || (!w->verr && !(dn && pa == 1))) printf("  got done=%d alert=%d verify_err=%d pauses=%d\n", dn, al, ve, pa);
        /* the OpenSSL verifier (AnchoredCa, Linux Platform) under the same anchor: OpenSSL's own level 2, the same verdict */
        weak_run(weak_chain(w), w->leaf, W("weak-root"), KSL_VERIFY_OPENSSL, 0, &al, &ve, &dn, &pa);
        snprintf(msg, sizeof msg, "openssl: %s -> %s", w->what, w->verr ? "bad_certificate" : "accepted");
        if (w->verr) CHECK(!dn && al == 42 && ve == w->verr, msg); else CHECK(dn, msg);
        if ((w->verr && !(!dn && al == 42 && ve == w->verr)) || (!w->verr && !dn)) printf("  got done=%d alert=%d verify_err=%d\n", dn, al, ve);
    }
    int al, ve, dn, pa;
    /* RFC 9846 section 4.5.1.3: a certificate signed with MD5 MUST be refused with bad_certificate */
    weak_run(chain_of(1, W("leaf-md5")), W("leaf-md5"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 42 && ve == X509_V_ERR_CA_MD_TOO_WEAK && pa == 0, "negative: pause: an MD5-signed leaf -> bad_certificate before the pause");
    /* "endpoints can accept these algorithms for certificates that are self-signed or are trust anchors": the anchor the peer sent */
    weak_run(chain_of(2, W("leaf-under-sha1-root"), W("sha1-root")), W("leaf-under-sha1-root"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(dn && pa == 1, "pause: a self-signed root signed with SHA-1, sent along, is an anchor: accepted");
    weak_run(chain_of(2, W("leaf-under-sha1-root"), W("sha1-root")), W("leaf-under-sha1-root"), W("sha1-root"), KSL_VERIFY_OPENSSL, 0, &al, &ve, &dn, &pa);
    CHECK(dn, "openssl: the same chain anchored at the SHA-1 root: accepted");
    /* an anchor's key still counts (x509_vfy.c check_auth_level checks every key but the leaf's as a CA key) */
    weak_run(chain_of(2, W("leaf-under-rsa1024-root"), W("rsa1024-root")), W("leaf-under-rsa1024-root"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 42 && ve == X509_V_ERR_CA_KEY_TOO_SMALL && pa == 0, "negative: pause: a 1024-bit root sent along -> bad_certificate");
    weak_run(chain_of(2, W("leaf-under-rsa1024-root"), W("rsa1024-root")), W("leaf-under-rsa1024-root"), W("rsa1024-root"), KSL_VERIFY_OPENSSL, 0, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 42 && ve == X509_V_ERR_CA_KEY_TOO_SMALL, "negative: openssl: anchored at a 1024-bit root -> bad_certificate");
    /* self-issued but not self-signed: OpenSSL flags these EXFLAG_SS (subject = issuer, no key identifiers, the signature's algorithm
       fits the key) without checking the signature; only a signature that verifies under the certificate's own key exempts it */
    weak_run(chain_of(1, W("leaf-self-issued-md5")), W("leaf-self-issued-md5"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 42 && ve == X509_V_ERR_CA_MD_TOO_WEAK && pa == 0, "negative: pause: a self-issued MD5-signed leaf that is not self-signed -> bad_certificate");
    if (!(!dn && al == 42 && ve == X509_V_ERR_CA_MD_TOO_WEAK && pa == 0)) printf("  got done=%d alert=%d verify_err=%d pauses=%d\n", dn, al, ve, pa);
    weak_run(chain_of(2, W("leaf-via-self-issued-sha1"), W("mid-self-issued-sha1")), W("leaf-via-self-issued-sha1"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 42 && ve == X509_V_ERR_CA_MD_TOO_WEAK && pa == 0, "negative: pause: a self-issued SHA-1-signed intermediate that is not self-signed -> bad_certificate");
    if (!(!dn && al == 42 && ve == X509_V_ERR_CA_MD_TOO_WEAK && pa == 0)) printf("  got done=%d alert=%d verify_err=%d pauses=%d\n", dn, al, ve, pa);
    /* a decoy before the real intermediate: same subject, no key identifiers, genuinely self-signed with a strong key. Name
       matching alone (X509_check_issued) takes it for the leaf's issuer; only an issuer whose key verifies the signature counts */
    weak_run(chain_of(3, W("leaf-via-sha1"), W("decoy-sha1"), W("mid-sha1")), W("leaf-via-sha1"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 42 && ve == X509_V_ERR_CA_MD_TOO_WEAK && pa == 0, "negative: pause: a self-signed decoy before a SHA-1 intermediate -> the intermediate is still checked");
    if (!(!dn && al == 42 && ve == X509_V_ERR_CA_MD_TOO_WEAK && pa == 0)) printf("  got done=%d alert=%d verify_err=%d pauses=%d\n", dn, al, ve, pa);
    weak_run(chain_of(3, W("leaf-via-rsa1024"), W("decoy-rsa1024"), W("mid-rsa1024")), W("leaf-via-rsa1024"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 42 && ve == X509_V_ERR_CA_KEY_TOO_SMALL && pa == 0, "negative: pause: an RSA decoy before a 1024-bit intermediate -> the intermediate is still checked");
    if (!(!dn && al == 42 && ve == X509_V_ERR_CA_KEY_TOO_SMALL && pa == 0)) printf("  got done=%d alert=%d verify_err=%d pauses=%d\n", dn, al, ve, pa);
    /* a decoy alone in front of nothing weak changes nothing: the decoy is not on any verified path */
    weak_run(chain_of(2, W("leaf-p256"), W("decoy-sha1")), W("leaf-p256"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(dn && pa == 1, "pause: an unrelated certificate sent along is not on the path: accepted");
    /* a self-signed leaf (as Tofu meets one): its key counts, its own signature does not */
    weak_run(chain_of(1, W("self-signed-rsa1024")), W("self-signed-rsa1024"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 42 && ve == X509_V_ERR_EE_KEY_TOO_SMALL && pa == 0, "negative: pause: a self-signed 1024-bit leaf -> bad_certificate");
    weak_run(chain_of(1, W("self-signed-sha1")), W("self-signed-sha1"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
    CHECK(dn && pa == 1, "pause: a self-signed P-256 leaf signed with SHA-1 reaches the pause, accepted");
    /* generic alerts: handshake_failure on the wire, the reason kept */
    weak_run(chain_of(1, W("leaf-rsa1024")), W("leaf-rsa1024"), NULL, KSL_VERIFY_PAUSE, 1, &al, &ve, &dn, &pa);
    CHECK(!dn && al == 40 && ve == X509_V_ERR_EE_KEY_TOO_SMALL && pa == 0, "pause + generic alerts: alert 40, verify_err EE_KEY_TOO_SMALL");
    /* a client certificate (a server verifies only through OpenSSL, AnchoredCa): OpenSSL's level 2 refuses a 1024-bit key */
    {
        ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
        CHECK(ksl_ctx_set_ciphers(cc, NULL, "@SECLEVEL=0:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256") == KSL_OK, "test client at security level 0");
        blob ch = chain_of(1, W("client-rsa1024")); size_t kl; uint8_t *k = key_of(W("client-rsa1024"), &kl);
        CHECK(ksl_ctx_set_identity(cc, ch.buf, ch.len, k, kl) == KSL_OK, "weak client identity loads at level 0"); free(ch.buf); free(k);
        blob r = chain_of(1, W("weak-root")); ksl_ctx_set_roots(sc, r.buf, r.len); free(r.buf); ksl_ctx_set_option(sc, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_REQUIRED);
        ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
        ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", sizeof "server.test" - 1); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1);
        ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP); side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 40, NULL, NULL); ksl_drive(s);
        CHECK(!ss.done && alert_of(s) == 42 && verify_err_of(s) == X509_V_ERR_EE_KEY_TOO_SMALL, "negative: a 1024-bit client certificate -> the server sends bad_certificate");
        ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    }
    END();
}
/* RFC 9325 section 4.5: this endpoint's own certificates are held to the same level when they are configured: OpenSSL checks only
   their keys (ssl_security_cert), not their signatures, so a SHA-1 or MD5-signed chain loaded before */
static int identity_ok(const char *leaf, const char *mid, char *msg, size_t msg_len) {
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER); blob ch = mid ? chain_of(2, leaf, mid) : chain_of(1, leaf); size_t kl; uint8_t *k = key_of(leaf, &kl);
    int r = ksl_ctx_set_identity(c, ch.buf, ch.len, k, kl); uint32_t e; msg[0] = 0; if (r != KSL_OK) ksl_ctx_last_error(c, &e, msg, msg_len);
    if (r != KSL_OK) CHECK(SSL_CTX_get0_certificate(c->ctx) == NULL && !c->has_leaf, "a refused identity is not installed in the context");
    free(ch.buf); free(k); ksl_ctx_free(c); return r == KSL_OK;
}
static void test_own_identity_security_level(void) {
    SECTION("identity_security_level");
    char m[256];
    CHECK(!identity_ok(W("leaf-md5"), NULL, m, sizeof m) && strstr(m, "SHA-1 or MD5"), "negative: an MD5-signed leaf is refused as an identity");
    if (!strstr(m, "SHA-1 or MD5")) printf("  message: %s\n", m);
    CHECK(!identity_ok(W("leaf-sha1"), NULL, m, sizeof m) && strstr(m, "SHA-1 or MD5"), "negative: a SHA-1-signed leaf is refused as an identity");
    CHECK(!identity_ok(W("leaf-via-sha1"), W("mid-sha1"), m, sizeof m) && strstr(m, "SHA-1 or MD5"), "negative: a SHA-1-signed intermediate in the identity is refused");
    CHECK(!identity_ok(W("leaf-self-issued-md5"), NULL, m, sizeof m), "negative: a self-issued, not self-signed MD5 leaf is refused as an identity");
    CHECK(identity_ok(W("leaf-under-sha1-root"), W("sha1-root"), m, sizeof m), "a SHA-1 self-signed root at the end of the configured chain is accepted");
    if (m[0]) printf("  message: %s\n", m);
    CHECK(identity_ok(W("leaf-p256"), NULL, m, sizeof m) && identity_ok("server", NULL, m, sizeof m), "SHA-256 identities load");
    /* a client certificate goes through the same call */
    ksl_ctx *cc = ksl_ctx_new(KSL_CLIENT); blob ch = chain_of(1, W("leaf-sha1")); size_t kl; uint8_t *k = key_of(W("leaf-sha1"), &kl);
    CHECK(ksl_ctx_set_identity(cc, ch.buf, ch.len, k, kl) == KSL_ERROR, "negative: a SHA-1-signed client certificate is refused"); free(ch.buf); free(k); ksl_ctx_free(cc);
    END();
}
/* A certificate with subject CN=<subject>, issued by issuer_name with issuer_key (itself when NULL), no extensions: no key
   identifiers, so X509_check_issued matches by names alone */
static X509 *make_cert(EVP_PKEY *key, const char *subject, const char *issuer_name, EVP_PKEY *issuer_key) {
    X509 *x = X509_new(); X509_NAME *sn = X509_NAME_new(), *in = X509_NAME_new();
    X509_NAME_add_entry_by_txt(sn, "CN", MBSTRING_ASC, (const unsigned char *)subject, -1, -1, 0);
    X509_NAME_add_entry_by_txt(in, "CN", MBSTRING_ASC, (const unsigned char *)(issuer_name ? issuer_name : subject), -1, -1, 0);
    X509_set_version(x, X509_VERSION_3); ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_set_subject_name(x, sn); X509_set_issuer_name(x, in); X509_gmtime_adj(X509_getm_notBefore(x), 0); X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, key); X509_sign(x, issuer_key ? issuer_key : key, EVP_sha256());
    X509_NAME_free(sn); X509_NAME_free(in); return x;
}
static void test_chain_security_bounds(void) {
    SECTION("chain_security_bounds");
    /* a straight chain of 103 certificates, each signed by the next, the last self-signed: past 101 visited it is refused */
    {
        enum { N = 103 }; EVP_PKEY *k[N]; STACK_OF(X509) *sk = sk_X509_new_null(); char name[N][16];
        for (int i = 0; i < N; i++) { k[i] = EVP_EC_gen("P-256"); snprintf(name[i], sizeof name[i], "c%d", i); }
        for (int i = 0; i < N; i++) sk_X509_push(sk, make_cert(k[i], name[i], i + 1 < N ? name[i + 1] : NULL, i + 1 < N ? k[i + 1] : NULL));
        CHECK(ksl_chain_security(2, sk) == X509_V_ERR_CERT_CHAIN_TOO_LONG, "negative: 103 certificates on one path -> CERT_CHAIN_TOO_LONG");
        X509 *last = sk_X509_pop(sk); X509_free(sk_X509_pop(sk)); X509_free(last);   /* 101 left: within the bound */
        X509 *top = make_cert(k[100], name[100], NULL, NULL); X509_free(sk_X509_pop(sk)); sk_X509_push(sk, top);
        CHECK(ksl_chain_security(2, sk) == X509_V_OK, "101 certificates, the last self-signed: within the bound");
        sk_X509_pop_free(sk, X509_free); for (int i = 0; i < N; i++) EVP_PKEY_free(k[i]);
    }
    /* one subject for all: a path of 10 (each signed by the next, the last self-signed) and 10 self-signed decoys; every visited
       certificate matches every other by name, so verification would take ~10 x 15; past 2n + 2 = 44 the chain is refused */
    {
        enum { M = 10, D = 10 }; EVP_PKEY *k[M + D]; STACK_OF(X509) *sk = sk_X509_new_null();
        for (int i = 0; i < M + D; i++) k[i] = EVP_EC_gen("P-256");
        for (int i = 0; i < M; i++) sk_X509_push(sk, make_cert(k[i], "same", i + 1 < M ? "same" : NULL, i + 1 < M ? k[i + 1] : NULL));
        for (int i = 0; i < D; i++) sk_X509_push(sk, make_cert(k[M + i], "same", NULL, NULL));
        CHECK(ksl_chain_security(2, sk) == X509_V_ERR_CERT_CHAIN_TOO_LONG, "negative: decoys of one subject past the 2n + 2 verifications -> CERT_CHAIN_TOO_LONG");
        sk_X509_pop_free(sk, X509_free); for (int i = 0; i < M + D; i++) EVP_PKEY_free(k[i]);
    }
    ERR_clear_error(); END();
}
/* ---- T.5b: under TrustConfig.Platform the level holds on the path the platform built, not on what the peer sent ---- */
static int level_of(int built, int n, ...) {
    blob b = {0}; va_list ap; va_start(ap, n);
    for (int i = 0; i < n; i++) { blob one = chain_of(1, va_arg(ap, const char *)); b.buf = realloc(b.buf, b.len + one.len); memcpy(b.buf + b.len, one.buf, one.len); b.len += one.len; free(one.buf); }
    va_end(ap); int r = ksl_chain_level(b.buf, b.len, built); free(b.buf); return r;
}
static void test_built_path_level(void) {
    SECTION("verify_built_path_level");
    /* L <- I <- R plus X (R's name and key, signed with SHA-1 by another root): a walk over the presented chain reaches X ... */
    CHECK(level_of(0, 3, W("leaf-via-cross-mid"), W("cross-mid"), W("cross-root-by-sha1")) == X509_V_ERR_CA_MD_TOO_WEAK,
          "negative: presented L, I, X: the walk reaches the SHA-1 cross-certificate -> CA_MD_TOO_WEAK");
    /* ... the path a platform anchored at R built does not */
    CHECK(level_of(1, 3, W("leaf-via-cross-mid"), W("cross-mid"), W("cross-root")) == X509_V_OK, "built path L, I, R: X is not on it -> accepted");
    /* a weak certificate on the built path is refused with the error OpenSSL's check_auth_level gives */
    CHECK(level_of(1, 3, W("leaf-via-sha1"), W("mid-sha1"), W("weak-root")) == X509_V_ERR_CA_MD_TOO_WEAK, "negative: built path through a SHA-1 intermediate -> CA_MD_TOO_WEAK");
    CHECK(level_of(1, 3, W("leaf-via-rsa1024"), W("mid-rsa1024"), W("weak-root")) == X509_V_ERR_CA_KEY_TOO_SMALL, "negative: built path through a 1024-bit intermediate -> CA_KEY_TOO_SMALL");
    CHECK(level_of(1, 3, W("leaf-via-p192"), W("mid-p192"), W("weak-root")) == X509_V_ERR_CA_KEY_TOO_SMALL, "negative: built path through a P-192 intermediate -> CA_KEY_TOO_SMALL");
    CHECK(level_of(1, 2, W("leaf-rsa1024"), W("weak-root")) == X509_V_ERR_EE_KEY_TOO_SMALL, "negative: a 1024-bit leaf on the built path -> EE_KEY_TOO_SMALL");
    CHECK(level_of(1, 2, W("leaf-sha1"), W("weak-root")) == X509_V_ERR_CA_MD_TOO_WEAK, "negative: a SHA-1-signed leaf on the built path -> CA_MD_TOO_WEAK");
    CHECK(level_of(1, 2, W("leaf-md5"), W("rsa-root")) == X509_V_ERR_CA_MD_TOO_WEAK, "negative: an MD5-signed leaf on the built path -> CA_MD_TOO_WEAK");
    CHECK(level_of(1, 3, W("leaf-via-p224"), W("mid-p224"), W("weak-root")) == X509_V_OK, "built path through a P-224 intermediate (112 bits, the floor) -> accepted");
    /* the anchor: its signature is not checked (it begins the path, even when it is not self-signed), its key is */
    CHECK(level_of(1, 2, W("leaf-via-sha1"), W("mid-sha1")) == X509_V_OK, "a SHA-1-signed intermediate that is the trust anchor -> accepted");
    CHECK(level_of(0, 2, W("leaf-via-sha1"), W("mid-sha1")) == X509_V_ERR_CA_MD_TOO_WEAK, "negative: the same certificates as a presented chain -> CA_MD_TOO_WEAK");
    CHECK(level_of(1, 2, W("leaf-under-sha1-root"), W("sha1-root")) == X509_V_OK, "a SHA-1 self-signed root as the anchor -> accepted");
    CHECK(level_of(1, 2, W("leaf-under-rsa1024-root"), W("rsa1024-root")) == X509_V_ERR_CA_KEY_TOO_SMALL, "negative: a 1024-bit anchor -> CA_KEY_TOO_SMALL");
    CHECK(level_of(1, 1, W("leaf-sha1")) == X509_V_OK, "a leaf that is itself the anchor: its signature is not checked");
    CHECK(level_of(1, 1, W("self-signed-rsa1024")) == X509_V_ERR_EE_KEY_TOO_SMALL, "negative: a 1024-bit leaf that is itself the anchor -> EE_KEY_TOO_SMALL");
    /* unusable input */
    { uint8_t bad[] = {0, 0, 0, 9, 1, 2}; CHECK(ksl_chain_level(bad, sizeof bad, 1) == -1 && ksl_chain_level(NULL, 0, 1) == -1, "negative: bad framing or no certificate -> -1"); }
    /* the pause: with KSL_OPT_LEVEL_AFTER_PAUSE the presented chain reaches the verifier, which holds its own path to the level */
    {
        int al, ve, dn, pa;
        weak_level_after_pause = 1;
        weak_run(chain_of(3, W("leaf-via-cross-mid"), W("cross-mid"), W("cross-root-by-sha1")), W("leaf-via-cross-mid"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
        CHECK(dn && pa == 1, "pause + level after pause: L, I, X reaches the verifier and is accepted on its yes");
        weak_run(chain_of(1, W("leaf-rsa1024")), W("leaf-rsa1024"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
        CHECK(pa == 1, "pause + level after pause: a 1024-bit leaf reaches the verifier (it refuses it on its built path)");
        weak_level_after_pause = 0;
        weak_run(chain_of(3, W("leaf-via-cross-mid"), W("cross-mid"), W("cross-root-by-sha1")), W("leaf-via-cross-mid"), NULL, KSL_VERIFY_PAUSE, 0, &al, &ve, &dn, &pa);
        CHECK(!dn && al == 42 && ve == X509_V_ERR_CA_MD_TOO_WEAK && pa == 0, "negative: pause without it (Custom, Tofu): L, I, X -> bad_certificate before the pause");
    }
    {
        ksl_ctx *sc = ksl_ctx_new(KSL_SERVER), *cc = ksl_ctx_new(KSL_CLIENT);
        CHECK(ksl_ctx_set_option(sc, KSL_OPT_LEVEL_AFTER_PAUSE, 1) == KSL_ERROR, "negative: level after pause is client-only");
        CHECK(ksl_ctx_set_option(cc, KSL_OPT_LEVEL_AFTER_PAUSE, 1) == KSL_OK, "level after pause on a client");
        ksl_ctx_free(sc); ksl_ctx_free(cc);
    }
    ERR_clear_error(); END();
}
void run_verify_security_level(void) { test_chain_security_level(); test_own_identity_security_level(); test_chain_security_bounds(); test_built_path_level(); }
