/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* TLS over TCP through memory: echo, close_notify, truncation, TLS 1.2 profile, tickets, key update, exporter, SNI pause. */
#include "test_common.h"
#include "ksl_internal.h"   /* tests may poke the SSL_CTX to simulate misbehaving peers */

static ksl_ssl *tcp_client(ksl_ctx *c, const char *sni) { ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_TCP); if (sni) ksl_ssl_set(s, KSL_SET_SNI, (const uint8_t *)sni, strlen(sni)); ksl_ssl_set(s, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", sizeof "server.test" - 1); return s; }
/* moves all pending ciphertext from a to b */
static size_t shuttle(ksl_ssl *a, ksl_ssl *b) {
    uint8_t buf[4096]; size_t total = 0, n, used;
    while (ksl_tcp_drain(a, buf, sizeof buf, &n) == KSL_OK && n) { size_t off = 0; while (off < n) { if (ksl_tcp_feed(b, buf + off, n - off, &used) != KSL_OK || !used) break; off += used; } total += n; }
    return total;
}
static int tcp_pump(ksl_ssl *c, ksl_ssl *s, int (*on_want)(ksl_ssl *, int, void *), void *arg) {
    int rc = KSL_WANT_READ;
    for (int i = 0; i < 60; i++) {
        int r = ksl_drive(c); if ((r == KSL_WANT_VERIFY || r == KSL_WANT_SNI) && on_want && !on_want(c, r, arg)) return r; shuttle(c, s);
        int r2 = ksl_drive(s); if ((r2 == KSL_WANT_VERIFY || r2 == KSL_WANT_SNI) && on_want && !on_want(s, r2, arg)) return r2; shuttle(s, c);
        if (r == KSL_ERROR || r2 == KSL_ERROR) { if (r2 == KSL_ERROR) ksl_drive(c); return KSL_ERROR; }   /* let the client consume the server's alert */
        if (c->done && s->done) { rc = KSL_OK; ksl_drive(c); shuttle(c, s); ksl_drive(s); shuttle(s, c); return rc; }
    }
    return rc;
}
/* The message of a session's last error */
static int last_message_has(ksl_ssl *s, const char *part) { uint32_t c; int a; char m[256]; ksl_ssl_last_error(s, &c, &a, m, sizeof m); return strstr(m, part) != NULL; }
static int echo_bytes(ksl_ssl *c, ksl_ssl *s, size_t total) {
    uint8_t *data = malloc(total), *back = malloc(total); for (size_t i = 0; i < total; i++) data[i] = (uint8_t)(i * 7); size_t sent = 0, got = 0, n;
    for (int i = 0; i < 100000 && got < total; i++) {
        if (sent < total && ksl_tcp_write(c, data + sent, total - sent > 16384 ? 16384 : total - sent, &n) == KSL_OK) sent += n;
        shuttle(c, s);
        uint8_t buf[16384]; size_t r;
        while (ksl_tcp_read(s, buf, sizeof buf, &r) == KSL_OK && r) { size_t w = 0; while (w < r) { size_t k; if (ksl_tcp_write(s, buf + w, r - w, &k) != KSL_OK) break; w += k; } }
        shuttle(s, c);
        while (ksl_tcp_read(c, back + got, total - got, &r) == KSL_OK && r) got += r;
    }
    int ok = got == total && !memcmp(data, back, total); free(data); free(back); return ok;
}

static void test_echo(void) {
    SECTION("tcp_handshake_tls13_echo_1mb");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake"); uint8_t v[2]; size_t n; CHECK(ksl_ssl_get(c, KSL_GET_VERSION, v, 2, &n) == KSL_OK && v[1] == 0x04, "TLS 1.3");
    CHECK(echo_bytes(c, s, 1 << 20), "1 MiB echoed through both directions");
    uint8_t cb[2][32]; CHECK(ksl_ssl_get(c, KSL_GET_CHANNEL_BINDING, cb[0], 32, &n) == KSL_OK && ksl_ssl_get(s, KSL_GET_CHANNEL_BINDING, cb[1], 32, &n) == KSL_OK && !memcmp(cb[0], cb[1], 32), "tls-exporter channel binding matches");
    CHECK(ksl_ssl_key_update(c, 1) == KSL_OK && echo_bytes(c, s, 1000) && ksl_ssl_key_update(s, 0) == KSL_OK && echo_bytes(c, s, 1000), "key update in both directions keeps the stream intact");
    /* close_notify: client shuts down, server reads EOF, server answers */
    int r = ksl_tcp_shutdown(c); shuttle(c, s); uint8_t buf[16]; CHECK(r == KSL_WANT_READ && ksl_tcp_read(s, buf, sizeof buf, &n) == KSL_EOF, "server sees KSL_EOF after close_notify");
    ksl_tcp_shutdown(s); shuttle(s, c); CHECK(ksl_tcp_shutdown(c) == KSL_OK, "client shutdown completes after the peer's close_notify");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_truncation(void) {
    SECTION("tcp_truncated_without_close_notify_is_error");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake");
    (void)BIO_shutdown_wr(c->net); /* the transport ends without close_notify: the network side of the pair is closed for writing */
    BIO_set_mem_eof_return(c->net, 0); uint8_t buf[16]; size_t n; int r = ksl_tcp_read(c, buf, sizeof buf, &n);
    CHECK(r != KSL_EOF, "a bare transport EOF is never reported as a clean KSL_EOF");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_tls12(void) {
    SECTION("tcp_tls12_profile_and_ems");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
    ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2); ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake with EMS"); uint8_t v[2]; size_t n; CHECK(ksl_ssl_get(c, KSL_GET_VERSION, v, 2, &n) == KSL_OK && v[1] == 0x03, "version 1.2");
    uint8_t ems; CHECK(ksl_ssl_get(c, KSL_GET_EMS, &ems, 1, &n) == KSL_OK && ems == 1, "extended master secret used");
    CHECK((SSL_CTX_get_options(cc->ctx) & SSL_OP_NO_RENEGOTIATION) && (SSL_CTX_get_options(cc->ctx) & SSL_OP_NO_COMPRESSION), "renegotiation and compression disabled");
    CHECK(echo_bytes(c, s, 5000), "data over TLS 1.2 ECDHE+AEAD");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* negative: a client without EMS. The server refuses it before Finished, so that OpenSSL sends handshake_failure (RFC 9846
       section 6.1 / RFC 5246 section 7.2: an error alert, not a bare transport end; RFC 7627 section 5.2, RFC 9325 section 3.5) */
    SSL_CTX_set_options(cc->ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); int r = tcp_pump(c, s, NULL, NULL), alert = 0;
    CHECK(r == KSL_ERROR && last_code(s, &alert) == KSL_E_EMS_REQUIRED, "negative: the server refuses a TLS 1.2 client without EMS (KSL_E_EMS_REQUIRED)");
    CHECK(alert == SSL_AD_HANDSHAKE_FAILURE, "the server sent handshake_failure");
    last_code(c, &alert); CHECK(alert == (SSL_AD_HANDSHAKE_FAILURE | 0x100) && !c->done, "the client received handshake_failure before the handshake completed");
    uint8_t cb[32]; CHECK(ksl_ssl_get(c, KSL_GET_CHANNEL_BINDING, cb, 32, &n) == KSL_ERROR, "negative: channel binding unavailable without EMS");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* negative: a server without EMS (one that does not refuse a client without it: ksl's check removed) */
    SSL_CTX_clear_options(cc->ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET); ksl_ctx *legacy = server_ctx("server"); ksl_ctx_set_option(legacy, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    SSL_CTX_set_options(legacy->ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET); SSL_CTX_set_tlsext_servername_callback(legacy->ctx, NULL);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(legacy, KSL_MODE_TCP); r = tcp_pump(c, s, NULL, NULL);
    CHECK(r == KSL_ERROR && last_code(c, &alert) == KSL_E_EMS_REQUIRED, "negative: the client refuses a TLS 1.2 server without EMS (KSL_E_EMS_REQUIRED)");
    CHECK(alert == SSL_AD_HANDSHAKE_FAILURE && !c->done, "the client sent handshake_failure before its Finished");
    last_code(s, &alert); CHECK(alert == (SSL_AD_HANDSHAKE_FAILURE | 0x100) && !s->done, "the server received handshake_failure");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* the same with a client that verifies nothing (KSL_VERIFY_NONE): OpenSSL ignores a failed verification then, so the refusal
       must still come before the client's Finished */
    ksl_ctx *none = client_ctx(NULL, KSL_VERIFY_NONE); ksl_ctx_set_option(none, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(none, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    c = ksl_ssl_new(none, KSL_MODE_TCP); s = ksl_ssl_new(legacy, KSL_MODE_TCP); r = tcp_pump(c, s, NULL, NULL);
    CHECK(r == KSL_ERROR && last_code(c, &alert) == KSL_E_EMS_REQUIRED, "negative: a client without verification refuses a TLS 1.2 server without EMS");
    CHECK(alert == SSL_AD_HANDSHAKE_FAILURE && !c->done, "it sent handshake_failure before its Finished");
    last_code(s, &alert); CHECK(alert == (SSL_AD_HANDSHAKE_FAILURE | 0x100) && !s->done, "the server received handshake_failure");
    ksl_ssl_free(c); ksl_ssl_free(s);
    c = ksl_ssl_new(none, KSL_MODE_TCP); s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && echo_bytes(c, s, 1000), "control: the client without verification accepts a server with EMS (an untrusted certificate)");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(none); ksl_ctx_free(legacy); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

/* Answers a paused verification with a rejection (unknown_ca), as Kotlin's verifier does for an untrusted chain */
static int reject_chain(ksl_ssl *s, int rc, void *a) { (void)a; return rc != KSL_WANT_VERIFY || ksl_ssl_verify_resume(s, 0, 48) == KSL_OK; }
static void test_client_verification_still_refuses(void) {
    SECTION("tcp_client_verification_still_refuses_bad_chains");
    /* A client SSL is always SSL_VERIFY_PEER and ksl_cert_verify_cb accepts every chain only under KSL_VERIFY_NONE (its guard reads
       the client context's verify mode, which cannot change once the context is frozen). With verification configured, a chain
       from another CA still fails the handshake with unknown_ca, in TLS 1.3 and TLS 1.2, under the OpenSSL verifier and under a
       paused verification that is rejected; also for a context that was set to KSL_VERIFY_NONE before. */
    for (int v = 0; v < 2; v++) {
        int version = v ? KSL_TLS1_2 : KSL_TLS1_3, alert = 0;
        struct { int mode, none_first; } cases[] = {{KSL_VERIFY_OPENSSL, 0}, {KSL_VERIFY_OPENSSL, 1}, {KSL_VERIFY_PAUSE, 0}};
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            ksl_ctx *cc = client_ctx("test-ca", cases[i].none_first ? KSL_VERIFY_NONE : cases[i].mode), *sc = server_ctx("server-other-ca");
            if (cases[i].none_first) ksl_ctx_set_option(cc, KSL_OPT_VERIFY_MODE, cases[i].mode);
            ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, version); ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, version); ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
            ksl_ctx_freeze(cc);
            CHECK(ksl_ctx_set_option(cc, KSL_OPT_VERIFY_MODE, KSL_VERIFY_NONE) == KSL_ERROR, "negative: a frozen context cannot switch verification off");
            ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
            int r = tcp_pump(c, s, cases[i].mode == KSL_VERIFY_PAUSE ? reject_chain : NULL, NULL); last_code(c, &alert);
            CHECK(r == KSL_ERROR && !c->done && alert == 48, "negative: a chain from another CA fails the handshake with unknown_ca");
            last_code(s, &alert); CHECK(!s->done && alert == (48 | 0x100), "the server received unknown_ca");
            ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
        }
    }
    END();
}

static void test_resumption(void) {
    SECTION("tcp_resumption_and_ticket_key_rotation");
    uint8_t keys[160]; for (int i = 0; i < 160; i++) keys[i] = (uint8_t)(i * 13 + 1);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ctx_set_option(sc, KSL_OPT_NUM_TICKETS, 1); ksl_ctx_set_ticket_keys(sc, keys, 1);
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "first handshake");
    uint8_t buf[16]; size_t n; ksl_tcp_read(c, buf, sizeof buf, &n);   /* consume the NewSessionTicket */
    ksl_session *sess = ksl_ssl_get1_session(c); CHECK(sess != NULL, "ticket received: a resumable session handle");
    ksl_session *again = ksl_ssl_get1_session(c); CHECK(again == sess, "the same session while it does not change"); ksl_session_free(again);
    uint8_t der[4096]; size_t dl; CHECK(ksl_ssl_get(c, 3 /* KSL_GET_SESSION of ABI 3 */, der, sizeof der, &dl) == KSL_ERROR, "negative: no getter serializes the session out of ksl (review I-2)");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* rotate: new current key, old key kept as previous */
    uint8_t rotated[160]; memcpy(rotated, keys + 80, 80); memcpy(rotated + 80, keys, 80); for (int i = 0; i < 80; i++) rotated[i] = (uint8_t)(i * 29 + 7);
    ksl_ctx *sc2 = server_ctx("server"); ksl_ctx_set_option(sc2, KSL_OPT_NUM_TICKETS, 1); ksl_ctx_set_ticket_keys(sc2, rotated, 2);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc2, KSL_MODE_TCP); CHECK(ksl_ssl_set_session(c, sess) == KSL_OK && tcp_pump(c, s, NULL, NULL) == KSL_OK, "second handshake");
    uint8_t reused; CHECK(ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "resumed with the previous ticket key");
    CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_PRESENTED, -1, NULL, 0, NULL) == 1 && ksl_ssl_get_peer_chain(c, KSL_CHAIN_VALIDATED, -1, NULL, 0, NULL) == 1, "resumed handshake: the peer leaf from the session is exposed through both selectors");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* negative: unknown key name -> full handshake */
    uint8_t other[80]; for (int i = 0; i < 80; i++) other[i] = (uint8_t)(200 - i); ksl_ctx *sc3 = server_ctx("server"); ksl_ctx_set_ticket_keys(sc3, other, 1);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc3, KSL_MODE_TCP); ksl_ssl_set_session(c, sess); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake with an unknown ticket key");
    CHECK(ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 0, "negative: ticket under an unknown key is not resumed");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_session_free(sess); ksl_ctx_free(cc); ksl_ctx_free(sc); ksl_ctx_free(sc2); ksl_ctx_free(sc3); END();
}

typedef struct { ksl_ctx *override; int alert; int saw_sni; char sni[64]; } sni_arg;
static int on_sni(ksl_ssl *s, int rc, void *a) {
    sni_arg *x = a; if (rc != KSL_WANT_SNI) return 1; ksl_client_hello ch;
    if (ksl_ssl_client_hello(s, &ch) == KSL_OK && ch.sni) { x->saw_sni = 1; memcpy(x->sni, ch.sni, ch.sni_len); x->sni[ch.sni_len] = 0; }
    return ksl_ssl_sni_resume(s, x->override, x->alert) == KSL_OK;
}
static void test_sni_pause(void) {
    SECTION("tcp_sni_pause_override_and_unrecognized_name");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server-other-ca"), *proxy = server_ctx("server");
    ksl_ctx_set_option(sc, KSL_OPT_SNI_PAUSE, 1);
    /* override: the default identity (other CA) would fail; the selector swaps in the trusted one */
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); sni_arg a = {proxy, 0, 0, {0}};
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_OK && a.saw_sni && !strcmp(a.sni, "server.test"), "selector saw the SNI and its override identity was used");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* unrecognized_name (112) */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); sni_arg b = {NULL, 112, 0, {0}}; int r = tcp_pump(c, s, on_sni, &b); int alert = 0; last_code(c, &alert);
    CHECK(r == KSL_ERROR && alert == (112 | 0x100), "client receives alert unrecognized_name(112)");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* no SNI: default identity is used (here it is the untrusted one, so the client rejects it with unknown_ca) */
    c = tcp_client(cc, NULL); s = ksl_ssl_new(sc, KSL_MODE_TCP); sni_arg d = {NULL, 0, 0, {0}}; r = tcp_pump(c, s, on_sni, &d); last_code(c, &alert);
    CHECK(!d.saw_sni && r == KSL_ERROR && alert == 48, "without SNI the default identity is offered (client: unknown_ca)");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); ksl_ctx_free(proxy); END();
}

static void test_sni_override_alpn(void) {
    SECTION("tcp_sni_override_leaves_base_ctx_alpn");
    /* the override's ALPN list must not be written into the frozen base context other connections share */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server-other-ca"), *proxy = server_ctx("server");
    static const uint8_t two[] = {2, 'h', '3', 2, 'x', '1'}; ksl_ctx_set_alpn(proxy, two, sizeof two);
    ksl_ctx_set_option(sc, KSL_OPT_SNI_PAUSE, 1); ksl_ctx_freeze(sc); ksl_ctx_freeze(proxy);
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); sni_arg a = {proxy, 0, 0, {0}};
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_OK, "handshake with the override identity");
    uint8_t alpn[16]; size_t n; CHECK(ksl_ssl_get(c, KSL_GET_ALPN, alpn, sizeof alpn, &n) == KSL_OK && n == 2 && !memcmp(alpn, "h3", 2), "h3 selected from the override's list");
    CHECK(sc->alpn_len == sizeof ALPN_H3 && !memcmp(sc->alpn, ALPN_H3, sizeof ALPN_H3), "the base context's ALPN list is unchanged");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* negative: an override must be a server context. A client context's settings (its verify mode among them: a client one under
       KSL_VERIFY_NONE accepts every chain) would otherwise judge the server's client certificates */
    ksl_ctx *client_role = client_ctx(NULL, KSL_VERIFY_NONE); ksl_ctx_freeze(client_role);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); int rc = KSL_OK;
    for (int i = 0; i < 10 && (rc = ksl_drive(s)) != KSL_WANT_SNI; i++) { ksl_drive(c); shuttle(c, s); }
    CHECK(rc == KSL_WANT_SNI && ksl_ssl_sni_resume(s, client_role, 0) == KSL_ERROR && last_code(s, NULL) == KSL_E_BAD_ARG, "negative: a client-role context is refused as an SNI override");
    CHECK(ksl_ssl_sni_resume(s, proxy, 0) == KSL_OK && tcp_pump(c, s, NULL, NULL) == KSL_OK, "control: a server override still works after the refusal");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(client_role); ksl_ctx_free(cc); ksl_ctx_free(sc); ksl_ctx_free(proxy); END();
}

static ksl_session *client_session_after(ksl_ssl *c) { uint8_t buf[16]; size_t n; ksl_tcp_read(c, buf, sizeof buf, &n); return ksl_ssl_get1_session(c); }   /* consumes a NewSessionTicket */
static void test_sni_override_settings_effective(void) {
    SECTION("tcp_sni_override_settings_effective");
    /* SSL_new copies per-connection settings out of the base SSL_CTX and SSL_set_SSL_CTX moves only the certificate and the
       session id context: every other setting of the override must be applied to the session too (review T1) */
    uint8_t keys[80]; for (int i = 0; i < 80; i++) keys[i] = (uint8_t)(i * 3 + 1);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
    blob ch = chain_of(1, "client"); size_t kl; uint8_t *k = key_of("client", &kl); CHECK(ksl_ctx_set_identity(cc, ch.buf, ch.len, k, kl) == KSL_OK, "client identity"); free(ch.buf); free(k);
    ksl_ctx *base = server_ctx("server"); ksl_ctx_set_ticket_keys(base, keys, 1); ksl_ctx_set_option(base, KSL_OPT_NUM_TICKETS, 1);
    ksl_ctx_set_option(base, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_session_context(base, (const uint8_t *)"base-ctx", 8); ksl_ctx_set_option(base, KSL_OPT_SNI_PAUSE, 1); ksl_ctx_freeze(base);
    /* the override as KslContext builds it for Pinned + clientAuth: NUM_TICKETS 0, tickets only after the pin verdict */
    ksl_ctx *ovr = server_ctx("server"); ksl_ctx_set_ticket_keys(ovr, keys, 1); ksl_ctx_set_option(ovr, KSL_OPT_NUM_TICKETS, 0);
    blob r = chain_of(1, "test-ca"); ksl_ctx_set_roots(ovr, r.buf, r.len); free(r.buf); ksl_ctx_set_option(ovr, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_REQUIRED);
    ksl_ctx_set_session_context(ovr, (const uint8_t *)"ovr-pinned", 10); CHECK(ksl_ctx_set_ciphers(ovr, "TLS_CHACHA20_POLY1305_SHA256", NULL) == KSL_OK, "override suites");
    SSL_CTX_set_options(ovr->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE); SSL_CTX_set_verify_depth(ovr->ctx, 7); ksl_ctx_freeze(ovr);
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(base, KSL_MODE_TCP); sni_arg a = {ovr, 0, 0, {0}};
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_OK, "handshake under the override, client certificate verified by the CA");
    CHECK(SSL_get_num_tickets(s->ssl) == 0, "the override's ticket count (0) is in effect");
    CHECK(SSL_get_current_cipher(s->ssl) && SSL_CIPHER_get_id(SSL_get_current_cipher(s->ssl)) == 0x03001303, "the override's TLS 1.3 suites are in effect");
    CHECK((SSL_get_options(s->ssl) & SSL_OP_CIPHER_SERVER_PREFERENCE) != 0, "the override's options are in effect");
    CHECK(SSL_get_verify_depth(s->ssl) == 7, "the override's verify parameters are in effect");
    CHECK(SSL_get_min_proto_version(s->ssl) == TLS1_3_VERSION, "the override's minimum version is in effect");
    ksl_session *sess = client_session_after(c); CHECK(sess == NULL, "negative: no ticket before the pin verdict");
    ksl_session_free(sess); ksl_ssl_free(c); ksl_ssl_free(s);
    /* a TLS 1.2-only client: the base context allows 1.2, the override does not */
    ksl_ctx *cc12 = client_ctx("test-ca", KSL_VERIFY_OPENSSL); ksl_ctx_set_option(cc12, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc12, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    ch = chain_of(1, "client"); k = key_of("client", &kl); ksl_ctx_set_identity(cc12, ch.buf, ch.len, k, kl); free(ch.buf); free(k);
    c = tcp_client(cc12, "server.test"); s = ksl_ssl_new(base, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_ERROR, "negative: the override's TLS 1.3 floor refuses a TLS 1.2 client");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc12);
    /* a ticket for the override's session context issued without a verdict (here by an ungated context sharing keys and
       context) is never resumed under the gated override: only explicit, post-verdict tickets are */
    ksl_ctx *ungated = server_ctx("server"); ksl_ctx_set_ticket_keys(ungated, keys, 1); ksl_ctx_set_option(ungated, KSL_OPT_NUM_TICKETS, 1);
    blob r2 = chain_of(1, "test-ca"); ksl_ctx_set_roots(ungated, r2.buf, r2.len); free(r2.buf); ksl_ctx_set_option(ungated, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_REQUIRED);
    ksl_ctx_set_session_context(ungated, (const uint8_t *)"ovr-pinned", 10); ksl_ctx_freeze(ungated);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(ungated, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake with the ungated context");
    sess = client_session_after(c); CHECK(sess != NULL, "control: the ungated context issued a ticket"); ksl_ssl_free(c); ksl_ssl_free(s);
    uint8_t reused = 9; size_t n;
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(base, KSL_MODE_TCP); ksl_ssl_set_session(c, sess);
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 0, "negative: a ticket issued before any verdict does not resume under the gated override");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_session_free(sess);
    /* control: the explicit ticket (the pin verdict passed) resumes */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(base, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_OK && ksl_ssl_new_session_ticket(s) == KSL_OK, "explicit ticket after the verdict");
    ksl_drive(s); shuttle(s, c); sess = client_session_after(c); CHECK(sess != NULL, "the explicit ticket arrived"); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(base, KSL_MODE_TCP); ksl_ssl_set_session(c, sess);
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "control: the post-verdict ticket resumes");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_session_free(sess);
    ksl_ctx_free(cc); ksl_ctx_free(base); ksl_ctx_free(ovr); ksl_ctx_free(ungated); END();
}

static void test_no_tls12_ticket_without_num_tickets(void) {
    SECTION("tcp_tls12_no_ticket_when_num_tickets_zero");
    /* KSL_OPT_NUM_TICKETS 0 means tickets only through ksl_ssl_new_session_ticket (after the pin verdict); TLS 1.2 issues its
       ticket inside the handshake, before any verdict, so it must not issue one at all */
    uint8_t keys[80]; for (int i = 0; i < 80; i++) keys[i] = (uint8_t)(i * 7 + 3);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL); ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    ksl_ctx *with = server_ctx("server"), *without = server_ctx("server");
    for (int k = 0; k < 2; k++) { ksl_ctx *sc = k ? without : with; ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_ticket_keys(sc, keys, 1); ksl_ctx_set_option(sc, KSL_OPT_NUM_TICKETS, k ? 0 : 1); }
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(with, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake, tickets on");
    ksl_session *sess = ksl_ssl_get1_session(c); CHECK(sess != NULL, "control: a TLS 1.2 ticket with KSL_OPT_NUM_TICKETS 1"); ksl_session_free(sess); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(without, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake, KSL_OPT_NUM_TICKETS 0");
    sess = ksl_ssl_get1_session(c); CHECK(sess == NULL, "negative: no resumable TLS 1.2 session before the verdict"); ksl_session_free(sess);
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(with); ksl_ctx_free(without); END();
}

static void test_session_context(void) {
    SECTION("tcp_session_context_binds_tickets");
    /* a ticket resumes only under the session context that issued it, even with shared ticket keys */
    uint8_t keys[80]; for (int i = 0; i < 80; i++) keys[i] = (uint8_t)(i * 5 + 9);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *a = server_ctx("server"), *a2 = server_ctx("server"), *b = server_ctx("server");
    ksl_ctx *srv[3] = { a, a2, b }; const char *ids[3] = { "config-a", "config-a", "config-b" };
    for (int k = 0; k < 3; k++) { ksl_ctx_set_ticket_keys(srv[k], keys, 1); ksl_ctx_set_option(srv[k], KSL_OPT_NUM_TICKETS, 1); CHECK(ksl_ctx_set_session_context(srv[k], (const uint8_t *)ids[k], 8) == KSL_OK, "session context set"); }
    uint8_t big[33] = {0}; CHECK(ksl_ctx_set_session_context(b, big, 33) == KSL_ERROR, "negative: more than 32 bytes rejected");
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(a, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "first handshake under config-a");
    ksl_session *sess = ksl_ssl_get1_session(c); CHECK(sess != NULL, "ticket"); ksl_ssl_free(c); ksl_ssl_free(s);
    uint8_t reused = 9; size_t n;
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(a2, KSL_MODE_TCP); ksl_ssl_set_session(c, sess); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "same context: resumed"); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(b, KSL_MODE_TCP); ksl_ssl_set_session(c, sess); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 0, "negative: another context runs a full handshake");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_session_free(sess); ksl_ctx_free(cc); ksl_ctx_free(a); ksl_ctx_free(a2); ksl_ctx_free(b); END();
}

/* Two virtual hosts behind one TCP server, as an SNI selector builds them: the same trust (so the same session context) and
   the same ticket keys (the process-wide generated ones). RFC 6066 section 3: a server "MUST NOT accept the request to resume
   the session if the server_name extension contains a different name. Instead, it proceeds with a full handshake to establish
   a new session"; RFC 9846 sections 4.3.11 and 4.7.1 leave the ticket's binding to the server, which must ensure a compatible PSK. */
typedef struct { ksl_ctx *a, *b; } vhosts;
static int on_vhost(ksl_ssl *s, int rc, void *arg) {
    vhosts *v = arg; if (rc != KSL_WANT_SNI) return 1; ksl_client_hello ch; ksl_ctx *pick = NULL;
    if (ksl_ssl_client_hello(s, &ch) == KSL_OK && ch.sni) {
        if (ch.sni_len == 6 && !memcmp(ch.sni, "a.test", 6)) pick = v->a;
        else if (ch.sni_len == 6 && !memcmp(ch.sni, "B.TEST", 6)) pick = v->b;   /* host names compare case-insensitively */
        else if (ch.sni_len == 6 && !memcmp(ch.sni, "b.test", 6)) pick = v->b;
    }
    return ksl_ssl_sni_resume(s, pick, pick ? 0 : 112) == KSL_OK;
}
static int leaf_is(ksl_ssl *c, const char *name) {
    char path[256]; snprintf(path, sizeof path, TESTDATA "%s.der", name); size_t l; uint8_t *want = read_file(path, &l);
    uint8_t got[4096]; size_t n = 0; int ok = ksl_ssl_get_peer_chain(c, KSL_CHAIN_PRESENTED, 0, got, sizeof got, &n) == KSL_OK && n == l && !memcmp(got, want, l);
    free(want); return ok;
}
static void test_ticket_bound_to_server_name(void) {
    SECTION("tcp_ticket_bound_to_server_name");
    uint8_t keys[80]; for (int i = 0; i < 80; i++) keys[i] = (uint8_t)(i * 11 + 5);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *base = server_ctx("server-other-ca");
    ksl_ctx *a = server_ctx("server"), *b = server_ctx("server-other-key");   /* both valid for the client's reference name server.test */
    ksl_ctx *srv[3] = { base, a, b };
    for (int k = 0; k < 3; k++) { ksl_ctx_set_ticket_keys(srv[k], keys, 1); ksl_ctx_set_option(srv[k], KSL_OPT_NUM_TICKETS, 1); }
    ksl_ctx_set_option(base, KSL_OPT_SNI_PAUSE, 1); for (int k = 0; k < 3; k++) ksl_ctx_freeze(srv[k]);
    vhosts v = { a, b }; uint8_t reused = 9; size_t n;
    ksl_ssl *c = tcp_client(cc, "a.test"), *s = ksl_ssl_new(base, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, on_vhost, &v) == KSL_OK && leaf_is(c, "server"), "full handshake with a.test");
    ksl_session *sess = client_session_after(c); CHECK(sess != NULL, "a.test issued a ticket"); ksl_ssl_free(c); ksl_ssl_free(s);
    /* the ticket of a.test offered with the server name b.test */
    c = tcp_client(cc, "b.test"); s = ksl_ssl_new(base, KSL_MODE_TCP); ksl_ssl_set_session(c, sess);
    CHECK(tcp_pump(c, s, on_vhost, &v) == KSL_OK, "handshake with b.test");
    CHECK(ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 0, "negative: a.test's ticket does not resume under b.test (RFC 6066 section 3)");
    CHECK(ksl_ssl_get(c, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 0, "negative: the client sees a full handshake");
    CHECK(leaf_is(c, "server-other-key"), "b.test's certificate is presented");
    ksl_session *sess_b = client_session_after(c); CHECK(sess_b != NULL, "the full handshake issued b.test its own ticket"); ksl_ssl_free(c); ksl_ssl_free(s);
    /* controls: each ticket resumes under its own name (case-insensitively) */
    c = tcp_client(cc, "a.test"); s = ksl_ssl_new(base, KSL_MODE_TCP); ksl_ssl_set_session(c, sess);
    CHECK(tcp_pump(c, s, on_vhost, &v) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "control: a.test's ticket resumes under a.test");
    ksl_session *renewed = client_session_after(c); CHECK(renewed != NULL, "the resumption renewed the ticket"); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "a.test"); s = ksl_ssl_new(base, KSL_MODE_TCP); ksl_ssl_set_session(c, renewed);
    CHECK(tcp_pump(c, s, on_vhost, &v) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "control: the renewed ticket keeps the name and resumes");
    ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "B.TEST"); s = ksl_ssl_new(base, KSL_MODE_TCP); ksl_ssl_set_session(c, sess_b);
    CHECK(tcp_pump(c, s, on_vhost, &v) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "control: b.test's ticket resumes under B.TEST");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* no server name at all is a different name too */
    c = tcp_client(cc, NULL); s = ksl_ssl_new(a, KSL_MODE_TCP); ksl_ssl_set_session(c, sess);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 0, "negative: a.test's ticket does not resume without SNI");
    ksl_ssl_free(c); ksl_ssl_free(s);
    ksl_session_free(sess); ksl_session_free(sess_b); ksl_session_free(renewed);
    for (int k = 0; k < 3; k++) ksl_ctx_free(srv[k]);
    ksl_ctx_free(cc); END();
}

static void test_keyless_server_no_tickets(void) {
    SECTION("tcp_server_without_ticket_keys_issues_and_accepts_none");
    /* RFC 9846 section 4.7.1: a server may send no ticket. A context without ticket keys must not fall back to OpenSSL's own random
       keys for its SSL_CTX: it issues no ticket and resumes none */
    uint8_t keys[80]; for (int i = 0; i < 80; i++) keys[i] = (uint8_t)(i * 17 + 2);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *keyless = server_ctx("server"), *keyed = server_ctx("server");
    ksl_ctx_set_option(keyless, KSL_OPT_NUM_TICKETS, 1); ksl_ctx_set_option(keyed, KSL_OPT_NUM_TICKETS, 1); ksl_ctx_set_ticket_keys(keyed, keys, 1);
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(keyless, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake with the keyless context");
    ksl_session *sess = client_session_after(c); CHECK(sess == NULL, "negative: no ticket without ticket keys"); ksl_session_free(sess); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(keyless, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_new_session_ticket(s) == KSL_OK, "an explicit ticket request without keys");
    ksl_drive(s); shuttle(s, c); sess = client_session_after(c); CHECK(sess == NULL, "negative: still no ticket"); ksl_session_free(sess); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(keyed, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake with the keyed context");
    sess = client_session_after(c); CHECK(sess != NULL, "control: the keyed context issues a ticket"); ksl_ssl_free(c); ksl_ssl_free(s);
    uint8_t reused = 9; size_t n;
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(keyless, KSL_MODE_TCP); ksl_ssl_set_session(c, sess);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 0, "negative: the keyless context resumes no ticket");
    ksl_session *after = client_session_after(c); CHECK(after == NULL, "negative: nor renews it"); ksl_session_free(after); ksl_ssl_free(c); ksl_ssl_free(s); ksl_session_free(sess);
    /* a keyed SNI override under a keyless base: its keys are the ones in use (OpenSSL takes the callback from the base context) */
    ksl_ctx *base = server_ctx("server-other-ca"); ksl_ctx_set_option(base, KSL_OPT_SNI_PAUSE, 1); ksl_ctx_freeze(base); ksl_ctx_freeze(keyed);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(base, KSL_MODE_TCP); sni_arg a = {keyed, 0, 0, {0}};
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_OK, "handshake under the keyed override");
    sess = client_session_after(c); CHECK(sess != NULL, "the override issued a ticket"); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(keyed, KSL_MODE_TCP); ksl_ssl_set_session(c, sess);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "the override's ticket is sealed with the override's keys");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_session_free(sess);
    ksl_ctx_free(cc); ksl_ctx_free(keyless); ksl_ctx_free(keyed); ksl_ctx_free(base); END();
}

/* What the client saw of one extension in the server's hello messages (ServerHello; in TLS 1.3 EncryptedExtensions), from a
   message callback on the client: -1 none, else the length of the extension's data. */
typedef struct { unsigned type; int in_server_hello, in_encrypted_extensions; } ext_seen;
static int find_ext(const uint8_t *p, size_t len, unsigned type) {   /* p: the extensions block with its 2-byte length */
    if (len < 2) return -1; size_t total = ((size_t)p[0] << 8) | p[1], off = 2; if (total + 2 > len) return -1;
    while (off + 4 <= total + 2) {
        unsigned t = ((unsigned)p[off] << 8) | p[off + 1]; size_t l = ((size_t)p[off + 2] << 8) | p[off + 3];
        if (off + 4 + l > total + 2) return -1; if (t == type) return (int)l; off += 4 + l;
    }
    return -1;
}
static void server_ext_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl; ext_seen *e = arg; const uint8_t *m = buf;
    if (write_p || content_type != SSL3_RT_HANDSHAKE || len < 4) return;
    if (m[0] == SSL3_MT_SERVER_HELLO && len >= 4 + 2 + 32 + 1) {
        size_t off = 4 + 2 + 32; off += 1 + m[off]; off += 2 + 1;   /* session id, cipher suite, compression */
        if (off <= len) e->in_server_hello = find_ext(m + off, len - off, e->type);
    } else if (m[0] == SSL3_MT_ENCRYPTED_EXTENSIONS) e->in_encrypted_extensions = find_ext(m + 4, len - 4, e->type);
}
static void watch_server_ext(ksl_ssl *c, ext_seen *e, unsigned type) {
    e->type = type; e->in_server_hello = e->in_encrypted_extensions = -1;
    ksl_ssl_msg_observer_for_test(c, server_ext_cb, e);   /* next to ksl's own message callback (a client's ServerHello check) */
}

static void test_server_acknowledges_server_name(void) {
    SECTION("tcp_server_acknowledges_server_name");
    /* RFC 6066 section 3: a server that used the server_name extension "SHALL include an extension of type 'server_name' in the
       (extended) server hello. The 'extension_data' field of this extension SHALL be empty"; in TLS 1.3 it travels in
       EncryptedExtensions (RFC 9846 section 4.3). "When resuming a session, the server MUST NOT include a server_name extension in
       the server hello" (TLS 1.2; TLS 1.3 negotiates the name in every handshake). */
    uint8_t keys[80]; for (int i = 0; i < 80; i++) keys[i] = (uint8_t)(i * 11 + 5);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ext_seen e;
    ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(sc, KSL_OPT_NUM_TICKETS, 1); ksl_ctx_set_ticket_keys(sc, keys, 1);
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); watch_server_ext(c, &e, TLSEXT_TYPE_server_name);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake with SNI");
    CHECK(e.in_encrypted_extensions == 0 && e.in_server_hello == -1, "TLS 1.3: an empty server_name in EncryptedExtensions");
    ksl_session *sess = client_session_after(c); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); watch_server_ext(c, &e, TLSEXT_TYPE_server_name); ksl_ssl_set_session(c, sess);
    uint8_t reused = 0; size_t n;
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(c, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "TLS 1.3 resumption");
    CHECK(e.in_encrypted_extensions == 0, "TLS 1.3 resumption: server_name acknowledged again");
    ksl_session_free(sess); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, NULL); s = ksl_ssl_new(sc, KSL_MODE_TCP); watch_server_ext(c, &e, TLSEXT_TYPE_server_name);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake without SNI");
    CHECK(e.in_encrypted_extensions == -1 && e.in_server_hello == -1, "negative: no server_name answers a ClientHello without one");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* TLS 1.2: in the ServerHello, and not on a resumption */
    ksl_ctx *cc12 = client_ctx("test-ca", KSL_VERIFY_OPENSSL); ksl_ctx_set_option(cc12, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc12, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    c = tcp_client(cc12, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); watch_server_ext(c, &e, TLSEXT_TYPE_server_name);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake with SNI");
    CHECK(e.in_server_hello == 0, "TLS 1.2: an empty server_name in the ServerHello");
    sess = ksl_ssl_get1_session(c); CHECK(sess != NULL, "a TLS 1.2 ticket"); ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc12, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); watch_server_ext(c, &e, TLSEXT_TYPE_server_name); ksl_ssl_set_session(c, sess);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(c, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "TLS 1.2 resumption");
    CHECK(e.in_server_hello == -1, "negative: a resumed TLS 1.2 session gets no server_name");
    ksl_session_free(sess); ksl_ssl_free(c); ksl_ssl_free(s);
    /* an SNI override's context acknowledges too (OpenSSL reads the callback from the session's current context) */
    ksl_ctx *base = server_ctx("server-other-ca"), *proxy = server_ctx("server"); ksl_ctx_set_option(base, KSL_OPT_SNI_PAUSE, 1);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(base, KSL_MODE_TCP); watch_server_ext(c, &e, TLSEXT_TYPE_server_name); sni_arg a = {proxy, 0, 0, {0}};
    CHECK(tcp_pump(c, s, on_sni, &a) == KSL_OK, "handshake under the SNI override");
    CHECK(e.in_encrypted_extensions == 0, "the override acknowledges server_name");
    ksl_ssl_free(c); ksl_ssl_free(s);
    ksl_ctx_free(cc); ksl_ctx_free(cc12); ksl_ctx_free(sc); ksl_ctx_free(base); ksl_ctx_free(proxy); END();
}

/* What a session's peer saw of KeyUpdates: how many, how many with request_update = update_requested */
typedef struct { int updates, requested; } key_updates;
static void key_update_kind_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl; const uint8_t *m = buf; key_updates *k = arg;
    if (!write_p && content_type == SSL3_RT_HANDSHAKE && len >= 5 && m[0] == SSL3_MT_KEY_UPDATE) { k->updates++; if (m[4] == SSL_KEY_UPDATE_REQUESTED) k->requested++; }
}
/* Counts the KeyUpdate messages a session received (message callback on the receiving side) */
static void key_update_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl; const uint8_t *m = buf;
    if (!write_p && content_type == SSL3_RT_HANDSHAKE && len >= 5 && m[0] == SSL3_MT_KEY_UPDATE) { int *n = arg; (*n)++; }
}
static int write_all(ksl_ssl *c, ksl_ssl *s, size_t total) {   /* client -> server only, the server reads and discards */
    uint8_t chunk[16384] = {0}, buf[16384]; size_t sent = 0, n, got = 0, r;
    for (int i = 0; i < 100000 && got < total; i++) {
        if (sent < total && ksl_tcp_write(c, chunk, total - sent > sizeof chunk ? sizeof chunk : total - sent, &n) == KSL_OK) sent += n;
        shuttle(c, s); while (ksl_tcp_read(s, buf, sizeof buf, &r) == KSL_OK && r) got += r; shuttle(s, c);
    }
    return got == total;
}
/* Puts the session in init while its first application record is being written, so that the automatic KeyUpdate after the write is
   refused (SSL_R_STILL_IN_INIT). OpenSSL 3.5 leaves no session in init after a successful write, and SSL_key_update refuses during
   one (the record is pending): the state is forced with libssl's internal ossl_statem_set_in_init (a TLS SSL is its SSL_CONNECTION). */
void ossl_statem_set_in_init(void *connection, int init);
static void in_init_during_write_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; int *done = arg;
    if (write_p && content_type == SSL3_RT_INNER_CONTENT_TYPE && len == 1 && ((const uint8_t *)buf)[0] == SSL3_RT_APPLICATION_DATA && !*done) { *done = 1; ossl_statem_set_in_init(ssl, 1); }
}
static void test_key_update_before_record_limit(void) {
    SECTION("tcp_key_update_before_record_limit");
    /* RFC 9846 section 5.5: for AES-GCM up to 2^24.5 full-size records under a given set of keys; "Implementations MUST either close
       the connection or do a key update ... prior to reaching these limits"; OpenSSL sends KeyUpdate only on SSL_key_update. ksl
       sends one every 2^23 records it wrote under AES-GCM; here the bound is lowered to 4 records (test hook). */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); int updates = 0;
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    ksl_ssl_msg_observer_for_test(s, key_update_cb, &updates);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    CHECK(write_all(c, s, 1 << 20) && updates == 0, "control: 64 records under the default bound, no KeyUpdate");
    ksl_tcp_set_key_update_records_for_test(c, 4);
    CHECK(write_all(c, s, 16384 * 3) && updates == 0, "3 records: below the lowered bound");
    CHECK(write_all(c, s, 16384 * 2) && updates == 1, "a KeyUpdate once 4 records were written");
    CHECK(write_all(c, s, 16384 * 5) && updates == 2, "and again after 4 more, the stream intact");
    CHECK(echo_bytes(c, s, 100000), "both directions still work after the updates");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* a refused automatic KeyUpdate leaves no error behind the write that succeeded (nothing reads one then, but the session's last
       error must stay the last failure's) */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); int injected = 0; CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    ksl_ssl_msg_observer_for_test(c, in_init_during_write_cb, &injected); ksl_tcp_set_key_update_records_for_test(c, 1);
    uint8_t one = 1; size_t wn; CHECK(ksl_tcp_write(c, &one, 1, &wn) == KSL_OK && wn == 1 && injected, "a write whose automatic KeyUpdate is refused (the session is in init)");
    CHECK(last_code(c, NULL) == 0 && !last_message_has(c, "key update"), "negative: the successful write left no error behind");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* TLS 1.2 has no KeyUpdate: the writes go on (nothing is sent, nothing fails) */
    ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2); ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake");
    ksl_tcp_set_key_update_records_for_test(c, 4); CHECK(write_all(c, s, 16384 * 10), "TLS 1.2: the writes past the bound succeed");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

/* Counts the ClientHellos a server received (message callback) */
static void client_hello_count_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl; const uint8_t *m = buf;
    if (!write_p && content_type == SSL3_RT_HANDSHAKE && len >= 4 && m[0] == SSL3_MT_CLIENT_HELLO) { int *n = arg; (*n)++; }
}
/* After one side aborted: what the other side reads, and the alert it got */
static int read_after_abort(ksl_ssl *peer, int *alert) {
    uint8_t buf[256]; size_t n; int r = KSL_OK;
    for (int i = 0; i < 10 && r == KSL_OK; i++) r = ksl_tcp_read(peer, buf, sizeof buf, &n);
    last_code(peer, alert); return r;
}
static void test_abort_sends_an_alert(void) {
    SECTION("tcp_abort_sends_internal_error");
    /* RFC 9846 section 6.1: "Each party MUST send a 'close_notify' alert before closing its write side of the connection, unless it
       has already sent some error alert"; a session whose application failed must not end with close_notify (the peer would take a
       cut stream for a whole one), so ksl_tcp_abort sends internal_error (80) where OpenSSL 3.5 can: a TLS 1.3 server (a
       NewSessionTicket whose construction ksl fails) and a TLS 1.2 client (a renegotiation ClientHello whose construction ksl
       fails, so none is sent). */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); int alert = 0, hellos = 0; uint8_t out[512]; size_t n;
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(ksl_tcp_abort(s) == KSL_ERROR, "negative: no abort before the handshake completed");
    ksl_ssl_free(s); s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && echo_bytes(c, s, 1000), "TLS 1.3 handshake and data");
    CHECK(ksl_tcp_abort(s) == KSL_OK, "a TLS 1.3 server aborts with an alert");
    CHECK(shuttle(s, c) > 0 && read_after_abort(c, &alert) == KSL_ERROR && alert == (SSL_AD_INTERNAL_ERROR | 0x100), "the client receives internal_error, not a clean end");
    CHECK(ksl_tcp_write(s, out, 1, &n) == KSL_ERROR && ksl_tcp_shutdown(s) == KSL_ERROR, "the aborted session takes no more data and sends no close_notify");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* TLS 1.3 client: OpenSSL has no way to send an alert there; nothing is sent, close_notify least of all */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    uint32_t code; CHECK(ksl_tcp_abort(c) == KSL_ERROR && (code = last_code(c, NULL)) == KSL_E_NOT_SUPPORTED, "a TLS 1.3 client: no alert (KSL_E_NOT_SUPPORTED)");
    CHECK(ksl_tcp_drain(c, out, sizeof out, &n) == KSL_OK && n == 0 && ksl_tcp_shutdown(c) == KSL_ERROR, "negative: nothing leaves the client, no close_notify");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* TLS 1.2 */
    ksl_ctx *cc12 = client_ctx("test-ca", KSL_VERIFY_OPENSSL); ksl_ctx_set_option(cc12, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc12, KSL_OPT_MAX_VERSION, KSL_TLS1_2); ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    c = tcp_client(cc12, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); ksl_ssl_msg_observer_for_test(s, client_hello_count_cb, &hellos);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && echo_bytes(c, s, 1000) && hellos == 1, "TLS 1.2 handshake and data");
    CHECK(ksl_tcp_abort(c) == KSL_OK, "a TLS 1.2 client aborts with an alert");
    CHECK(shuttle(c, s) > 0 && read_after_abort(s, &alert) == KSL_ERROR && alert == (SSL_AD_INTERNAL_ERROR | 0x100), "the server receives internal_error");
    CHECK(hellos == 1, "negative: no renegotiation ClientHello left the client");
    CHECK((SSL_get_options(ksl_ssl_raw_for_test(c)) & SSL_OP_NO_RENEGOTIATION) != 0, "renegotiation is refused again on the aborted session");
    /* the extension that fails the ClientHello is never sent; its type is from the Private Use range all the same (RFC 9846 section
       11: "Values with the first byte 255 (decimal) are reserved for Private Use") */
    int outside = 0, inside = 0; for (unsigned t = 0; t <= 0xffff; t++) if (SSL_CTX_has_client_custom_ext(cc12->ctx, t)) { if (t >> 8 == 0xff) inside++; else outside++; }
    CHECK(inside == 1 && outside == 0, "the client's custom extension type has the first byte 255");
    ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc12, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake");
    CHECK(ksl_tcp_abort(s) == KSL_ERROR && last_code(s, NULL) == KSL_E_NOT_SUPPORTED, "a TLS 1.2 server: no alert (KSL_E_NOT_SUPPORTED)");
    CHECK(ksl_tcp_drain(s, out, sizeof out, &n) == KSL_OK && n == 0, "negative: nothing leaves the server");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(cc12); ksl_ctx_free(sc); END();
}

/* Moves from a to b as much ciphertext as b's end of the pair has room for (shuttle drops what does not fit) */
static size_t shuttle_room(ksl_ssl *a, ksl_ssl *b) {
    uint8_t buf[4096]; size_t total = 0, n, used, room;
    while ((room = BIO_ctrl_get_write_guarantee(b->net)) > 0 && ksl_tcp_drain(a, buf, room < sizeof buf ? room : sizeof buf, &n) == KSL_OK && n) {
        for (size_t off = 0; off < n; off += used) if (ksl_tcp_feed(b, buf + off, n - off, &used) != KSL_OK || !used) return total;
        total += n;
    }
    return total;
}
/* Reads at peer what the aborted session sent, moving it over as the reads make room: the bytes before the alert, then the alert */
static size_t read_all_after_abort_from(ksl_ssl *aborted, ksl_ssl *peer, int *alert, int *rc) {
    uint8_t buf[16384]; size_t n, total = 0; int r = KSL_OK;
    for (int i = 0; i < 100 && r != KSL_ERROR && r != KSL_EOF; i++) {
        if (aborted) shuttle_room(aborted, peer);
        while ((r = ksl_tcp_read(peer, buf, sizeof buf, &n)) == KSL_OK && n) total += n;
    }
    *rc = r; last_code(peer, alert); return total;
}
static size_t read_all_after_abort(ksl_ssl *peer, int *alert, int *rc) { return read_all_after_abort_from(NULL, peer, alert, rc); }
static void test_abort_after_pending_messages(void) {
    SECTION("tcp_abort_flushes_what_is_pending");
    /* ksl_tcp_abort on a TLS 1.3 server sends its internal_error also when the connection was busy: a KeyUpdate queued and not yet
       written (SSL_new_session_ticket starts nothing while it is), or a record write the transport had no room for (OpenSSL drops
       an alert behind a pending write). Both go out first, then the alert. */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); int alert = 0, rc; uint8_t b = 9, out[512]; size_t n;
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    CHECK(ksl_ssl_key_update(s, 0) == KSL_OK, "a KeyUpdate is queued, nothing written after it");
    CHECK(ksl_tcp_abort(s) == KSL_OK, "the server still aborts with an alert");
    CHECK(shuttle(s, c) > 0 && read_all_after_abort(c, &alert, &rc) == 0 && rc == KSL_ERROR && alert == (SSL_AD_INTERNAL_ERROR | 0x100), "the client receives the KeyUpdate, then internal_error");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* the automatic KeyUpdate (the record bound, lowered to 1 by the test hook) is queued after a write and goes out ahead of the next one */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); key_updates k = {0, 0}; ksl_ssl_msg_observer_for_test(c, key_update_kind_cb, &k);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    ksl_tcp_set_key_update_records_for_test(s, 1);
    CHECK(ksl_tcp_write(s, &b, 1, &n) == KSL_OK && n == 1 && ksl_tcp_abort(s) == KSL_OK, "a write that queued the automatic KeyUpdate, then the abort");
    CHECK(shuttle(s, c) > 0 && read_all_after_abort(c, &alert, &rc) == 1 && alert == (SSL_AD_INTERNAL_ERROR | 0x100) && k.updates == 1, "the client receives the byte, the KeyUpdate, then internal_error");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* a record the transport had no room for: the BIO pair holds one full record, the next stays pending in OpenSSL */
    static uint8_t big[16384]; for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 3);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    CHECK(ksl_tcp_write(s, big, sizeof big, &n) == KSL_OK && n == sizeof big, "one record fills the pair");
    CHECK(ksl_tcp_write(s, big, sizeof big, &n) == KSL_WANT_READ && n == 0, "the next one is pending");
    CHECK(ksl_tcp_abort(s) == KSL_ERROR && last_code(s, NULL) == KSL_E_NOT_SUPPORTED && last_message_has(s, "pending"), "negative: no room for the pending record: no alert, and the error names the cause");
    ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    CHECK(ksl_tcp_write(s, big, sizeof big, &n) == KSL_OK && ksl_tcp_write(s, big, sizeof big, &n) == KSL_WANT_READ, "a pending record");
    uint8_t held[17 * 1024]; size_t held_n = 0, k2;
    while (held_n < sizeof held && ksl_tcp_drain(s, held + held_n, sizeof held - held_n, &k2) == KSL_OK && k2) held_n += k2;   /* the transport took what the pair held */
    CHECK(held_n > 0 && ksl_tcp_abort(s) == KSL_OK, "the pending record goes out, then the alert");
    size_t used; for (size_t off = 0; off < held_n; off += used) if (ksl_tcp_feed(c, held + off, held_n - off, &used) != KSL_OK || !used) break;
    CHECK(read_all_after_abort_from(s, c, &alert, &rc) == 2 * sizeof big && rc == KSL_ERROR && alert == (SSL_AD_INTERNAL_ERROR | 0x100), "the client receives both records, then internal_error");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* a pending write is retried from another buffer holding the same bytes (the JNI layer copies each call's bytes) */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    uint8_t *copy = malloc(sizeof big); memcpy(copy, big, sizeof big);
    CHECK(ksl_tcp_write(s, big, sizeof big, &n) == KSL_OK && ksl_tcp_write(s, big, sizeof big, &n) == KSL_WANT_READ, "a pending record");
    shuttle(s, c); CHECK(ksl_tcp_write(s, copy, sizeof big, &n) == KSL_OK && n == sizeof big, "its retry from a copy completes it");
    uint8_t got[16384]; size_t total = 0, r; int same = 1;
    for (int i = 0; i < 10 && total < 2 * sizeof big; i++) {
        shuttle_room(s, c);
        while (ksl_tcp_read(c, got, sizeof got, &r) == KSL_OK && r) { for (size_t j = 0; j < r; j++) same = same && got[j] == big[(total + j) % sizeof big]; total += r; }
    }
    CHECK(total == 2 * sizeof big && same, "the client reads both records intact");
    free(copy); ksl_ssl_free(c); ksl_ssl_free(s);
    /* a write longer than one record takes one record: what is left of it is never pending inside OpenSSL */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    uint8_t *large = calloc(1, 3 * sizeof big); CHECK(ksl_tcp_write(s, large, 3 * sizeof big, &n) == KSL_OK && n == sizeof big, "a 48 KiB write takes 16 KiB");
    free(large); ksl_ssl_free(c); ksl_ssl_free(s);
    /* TLS 1.2 client: a received record read in part (OpenSSL starts no renegotiation while received bytes are unprocessed),
       and two records of which the first was read: the abort still sends internal_error */
    ksl_ctx *cc12 = client_ctx("test-ca", KSL_VERIFY_OPENSSL); ksl_ctx_set_option(cc12, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc12, KSL_OPT_MAX_VERSION, KSL_TLS1_2); ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    for (int unread = 0; unread < 2; unread++) {
        int hellos = 0; c = tcp_client(cc12, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); ksl_ssl_msg_observer_for_test(s, client_hello_count_cb, &hellos);
        CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake");
        uint8_t hundred[100] = {0}, part[16];
        CHECK(ksl_tcp_write(s, hundred, sizeof hundred, &n) == KSL_OK && (!unread || ksl_tcp_write(s, hundred, sizeof hundred, &n) == KSL_OK), "the server sends 100 bytes (and 100 more)");
        shuttle(s, c); CHECK(ksl_tcp_read(c, part, sizeof part, &n) == KSL_OK && n == sizeof part, "the client reads 16 of them");
        CHECK(ksl_tcp_abort(c) == KSL_OK, "the TLS 1.2 client aborts with an alert");
        CHECK(shuttle(c, s) > 0 && read_after_abort(s, &alert) == KSL_ERROR && alert == (SSL_AD_INTERNAL_ERROR | 0x100) && hellos == 1, "the server receives internal_error, no ClientHello");
        ksl_ssl_free(c); ksl_ssl_free(s);
    }
    /* a record that arrived in part: OpenSSL keeps its first bytes in the record layer, and while any are there it starts no
       renegotiation (ssl3_renegotiate_check) and has no other message a TLS 1.2 client could fail: no alert, and the error says why */
    c = tcp_client(cc12, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake");
    { uint8_t hundred[100] = {0}, wire[256], part[16]; size_t w = 0, used;
      CHECK(ksl_tcp_write(s, hundred, sizeof hundred, &n) == KSL_OK && ksl_tcp_drain(s, wire, sizeof wire, &w) == KSL_OK && w > 20, "a 100-byte record");
      CHECK(ksl_tcp_feed(c, wire, 20, &used) == KSL_OK && used == 20 && ksl_tcp_read(c, part, sizeof part, &n) == KSL_WANT_READ, "its first 20 bytes reached the client");
      CHECK(ksl_tcp_abort(c) == KSL_ERROR && last_code(c, NULL) == KSL_E_NOT_SUPPORTED && last_message_has(c, "incomplete"), "negative: no alert behind an incomplete record, and the error names the cause");
      CHECK(ksl_tcp_drain(c, out, sizeof out, &n) == KSL_OK && n == 0, "nothing left the client"); }
    ksl_ssl_free(c); ksl_ssl_free(s);
    ksl_ctx_free(cc12); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_record_limits_per_cipher(void) {
    SECTION("tcp_record_limits_per_cipher");
    /* RFC 9846 section 5.5: "For AES-GCM, up to 2^24.5 full-size records (about 24 million) may be encrypted under a given set of
       keys ... For ChaCha20/Poly1305, the record sequence number would wrap before the safety limit is reached"; for AES-CCM
       (CCM_8 alike) RFC 9147 appendix B.1 derives the same margin at "q <= 2^23". The automatic KeyUpdate comes well before the
       limit of the negotiated AEAD: 2^23 records for AES-GCM, 2^22 for AES-CCM, none for ChaCha20-Poly1305 */
    struct { const char *suite; uint64_t update_at, limit; } want[] = {
        {"TLS_AES_128_GCM_SHA256", UINT64_C(1) << 23, UINT64_C(23726566)}, {"TLS_AES_256_GCM_SHA384", UINT64_C(1) << 23, UINT64_C(23726566)},
        {"TLS_CHACHA20_POLY1305_SHA256", UINT64_MAX, UINT64_MAX},
        {"TLS_AES_128_CCM_SHA256", UINT64_C(1) << 22, UINT64_C(1) << 23},
    };   /* TLS_AES_128_CCM_8_SHA256 (64-bit strength in OpenSSL) is below OpenSSL's default security level: never negotiated */
    for (size_t i = 0; i < sizeof want / sizeof want[0]; i++) {
        ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
        ksl_ctx_set_ciphers(cc, want[i].suite, NULL); ksl_ctx_set_ciphers(sc, want[i].suite, NULL);
        ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); uint64_t at = 0, limit = 0;
        CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && echo_bytes(c, s, 100), want[i].suite);
        ksl_tcp_record_bounds_for_test(c, &at, &limit);
        CHECK(at == want[i].update_at && limit == want[i].limit && (at < limit || limit == UINT64_MAX), "the KeyUpdate point and the record limit of the suite");
        ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    }
    /* a session whose KeyUpdates do not go out ends before its keys reach the limit (here 4 records, test hook): with internal_error
       where an alert can be sent (a TLS 1.3 server), else with nothing more (a TLS 1.3 client) */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); uint8_t b = 3, r[16], out[64]; size_t n; int alert = 0, rc;
    for (int server = 1; server >= 0; server--) {
        ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
        ksl_ssl *w = server ? s : c, *peer = server ? c : s;
        ksl_tcp_set_key_update_records_for_test(w, UINT64_MAX); ksl_tcp_set_record_limit_for_test(w, 4);
        int ok = 1; for (int k = 0; k < 3; k++) { ok = ok && ksl_tcp_write(w, &b, 1, &n) == KSL_OK; shuttle(w, peer); ok = ok && ksl_tcp_read(peer, r, sizeof r, &n) == KSL_OK && n == 1; }
        CHECK(ok, "three records under the keys");
        CHECK(ksl_tcp_write(w, &b, 1, &n) == KSL_ERROR && last_message_has(w, "record limit"), "negative: the fourth would reach the limit: the session ends");
        CHECK(ksl_tcp_abort(w) == KSL_ERROR && last_message_has(w, "record limit"), "an abort of the ended session keeps the error that ended it");
        if (server) CHECK(shuttle(w, peer) > 0 && read_all_after_abort(peer, &alert, &rc) == 0 && alert == (SSL_AD_INTERNAL_ERROR | 0x100), "the client receives internal_error");
        else CHECK(ksl_tcp_drain(w, out, sizeof out, &n) == KSL_OK && n == 0 && ksl_tcp_shutdown(w) == KSL_ERROR, "the client sends nothing more, no close_notify");
        ksl_ssl_free(c); ksl_ssl_free(s);
    }
    ksl_ctx_free(cc); ksl_ctx_free(sc);
    /* RFC 9325 section 4.4: "When a sender is approaching CL, the implementation SHOULD initiate a new handshake ... it is RECOMMENDED
       that the same limit of 2^24.5 records is used for both versions" (AES-GCM). TLS 1.2 has no KeyUpdate and ksl allows no
       renegotiation: the connection ends before its keys reach the limit, with internal_error where an alert can be sent (a TLS 1.2
       client). ChaCha20-Poly1305 has no limit. */
    struct { const char *list; uint64_t limit; } want12[] = {
        {"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256", UINT64_C(23726566)}, {"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384", UINT64_C(23726566)},
        {"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305", UINT64_MAX},
    };
    for (size_t i = 0; i < sizeof want12 / sizeof want12[0]; i++) {
        cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL); sc = server_ctx("server");
        ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2); ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
        ksl_ctx_set_ciphers(cc, NULL, want12[i].list); ksl_ctx_set_ciphers(sc, NULL, want12[i].list);
        ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); uint64_t at = 0, limit = 0;
        CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && echo_bytes(c, s, 100), want12[i].list);
        ksl_tcp_record_bounds_for_test(c, &at, &limit);
        CHECK(at == UINT64_MAX && limit == want12[i].limit, "TLS 1.2: no KeyUpdate, the record limit of the suite");
        ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    }
    cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL); sc = server_ctx("server");
    ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2); ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    for (int client = 1; client >= 0; client--) {
        ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake");
        ksl_ssl *w = client ? c : s, *peer = client ? s : c;
        ksl_tcp_set_record_limit_for_test(w, 4);
        int ok = 1; for (int k = 0; k < 3; k++) { ok = ok && ksl_tcp_write(w, &b, 1, &n) == KSL_OK; shuttle(w, peer); ok = ok && ksl_tcp_read(peer, r, sizeof r, &n) == KSL_OK && n == 1; }
        CHECK(ok, "TLS 1.2: three records under the keys");
        CHECK(ksl_tcp_write(w, &b, 1, &n) == KSL_ERROR && last_message_has(w, "record limit"), "negative: TLS 1.2: the fourth would reach the limit: the session ends");
        if (client) CHECK(shuttle(w, peer) > 0 && read_after_abort(peer, &alert) == KSL_ERROR && alert == (SSL_AD_INTERNAL_ERROR | 0x100), "the server receives internal_error");
        else CHECK(ksl_tcp_drain(w, out, sizeof out, &n) == KSL_OK && n == 0 && ksl_tcp_shutdown(w) == KSL_ERROR, "the server sends nothing more, no close_notify");
        ksl_ssl_free(c); ksl_ssl_free(s);
    }
    ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

/* Moves a's pending ciphertext to b with the legacy_version of the first record's hello (bytes 9-10: record header 5, handshake
   header 4) set to v */
static void shuttle_patched(ksl_ssl *a, ksl_ssl *b, uint16_t v) {
    uint8_t buf[16384]; size_t n = 0, got, used;
    while (n < sizeof buf && ksl_tcp_drain(a, buf + n, sizeof buf - n, &got) == KSL_OK && got) n += got;
    if (n > 10 && buf[0] == 22) { buf[9] = (uint8_t)(v >> 8); buf[10] = (uint8_t)v; }
    for (size_t off = 0; off < n; off += used) if (ksl_tcp_feed(b, buf + off, n - off, &used) != KSL_OK || !used) break;
}
static void test_legacy_version_must_be_0303(void) {
    SECTION("tcp_legacy_version_must_be_0303");
    /* RFC 9846 section 4.2.2: "A server which receives a legacy_version value not equal to 0x0303 MUST abort the handshake with a
       protocol_version alert"; section 4.2.3: "A client which receives a TLS 1.3 Server Hello with a legacy_version value not equal
       to 0x0303 MUST abort the handshake with a protocol_version alert". OpenSSL 3.5 tolerates 0x0301 and 0x0302 on both sides. */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); int alert = 0;
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    ksl_drive(c); shuttle_patched(c, s, 0x0302);
    CHECK(ksl_drive(s) == KSL_ERROR && (last_code(s, &alert), alert) == SSL_AD_PROTOCOL_VERSION, "negative: the server refuses a ClientHello with legacy_version 0x0302 (protocol_version)");
    shuttle(s, c); ksl_drive(c); last_code(c, &alert); CHECK(alert == (SSL_AD_PROTOCOL_VERSION | 0x100), "the client received protocol_version");
    ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP);
    ksl_drive(c); shuttle(c, s); ksl_drive(s); shuttle_patched(s, c, 0x0301);
    CHECK(ksl_drive(c) == KSL_ERROR && (last_code(c, &alert), alert) == SSL_AD_PROTOCOL_VERSION, "negative: the client refuses a TLS 1.3 ServerHello with legacy_version 0x0301 (protocol_version)");
    shuttle(c, s); ksl_drive(s); last_code(s, &alert); CHECK(alert == (SSL_AD_PROTOCOL_VERSION | 0x100), "the server received protocol_version");
    ksl_ssl_free(c); ksl_ssl_free(s);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP);
    ksl_drive(c); shuttle_patched(c, s, 0x0303); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "control: 0x0303 passes the same path");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static int send_one(ksl_ssl *c, ksl_ssl *s) {   /* one byte client -> server: carries any pending KeyUpdate */
    uint8_t b = 7, r[16]; size_t n; if (ksl_tcp_write(c, &b, 1, &n) != KSL_OK) return 0;
    shuttle(c, s); return ksl_tcp_read(s, r, sizeof r, &n) == KSL_OK && n == 1;
}
static void test_key_update_request_waits_for_the_peer(void) {
    SECTION("tcp_second_update_requested_waits_for_the_peer");
    /* RFC 9846 section 4.7.3: "Until receiving a subsequent KeyUpdate from the peer, the sender MUST NOT send another KeyUpdate with
       request_update set to update_requested"; OpenSSL tracks no outstanding request: ksl sends update_not_requested meanwhile */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); key_updates k = {0, 0};
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); ksl_ssl_msg_observer_for_test(s, key_update_kind_cb, &k);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake");
    CHECK(ksl_ssl_key_update(c, 1) == KSL_OK && send_one(c, s), "a requested key update");
    CHECK(ksl_ssl_key_update(c, 1) == KSL_OK && send_one(c, s), "a second one before the server's answer reached the client");
    CHECK(k.updates == 2 && k.requested == 1, "negative: only the first asked the server to update");
    shuttle(s, c); uint8_t r[16]; size_t n; ksl_tcp_read(c, r, sizeof r, &n);   /* the server's answer */
    CHECK(ksl_ssl_key_update(c, 1) == KSL_OK && send_one(c, s) && k.updates == 3 && k.requested == 2, "after the answer the client may ask again");
    CHECK(echo_bytes(c, s, 5000), "the stream is intact");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* "Note that implementations may receive an arbitrary number of messages between sending a KeyUpdate with request_update set
       to update_requested and receiving the peer's KeyUpdate, including unrelated KeyUpdates, because those messages may already be
       in flight": a KeyUpdate of the server's that had arrived before the client's request left is not the answer to it */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); k.updates = k.requested = 0; ksl_ssl_msg_observer_for_test(s, key_update_kind_cb, &k);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake");
    uint8_t b = 5; CHECK(ksl_ssl_key_update(s, 0) == KSL_OK && ksl_tcp_write(s, &b, 1, &n) == KSL_OK, "the server updates its key on its own");
    shuttle(s, c);   /* its KeyUpdate is at the client, not yet read */
    CHECK(ksl_ssl_key_update(c, 1) == KSL_OK && send_one(c, s) && k.requested == 1, "the client's update_requested crosses it");
    ksl_tcp_read(c, r, sizeof r, &n);   /* the client reads the server's earlier KeyUpdate */
    CHECK(ksl_ssl_key_update(c, 1) == KSL_OK && send_one(c, s) && k.updates == 2 && k.requested == 1, "negative: the crossing KeyUpdate is no answer: the next request goes out as update_not_requested");
    CHECK(ksl_tcp_write(s, &b, 1, &n) == KSL_OK, "the server answers the request ahead of its next write");
    shuttle(s, c); ksl_tcp_read(c, r, sizeof r, &n);
    CHECK(ksl_ssl_key_update(c, 1) == KSL_OK && send_one(c, s) && k.updates == 3 && k.requested == 2, "after the answer the client may ask again");
    CHECK(echo_bytes(c, s, 5000), "the stream is intact");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_key_update_epoch_is_bounded(void) {
    SECTION("tcp_key_update_epoch_is_bounded");
    /* RFC 9846 section 4.7.3: "sending implementations MUST NOT allow the epoch -- and hence the number of key updates -- to exceed
       2^48-1"; "receiving implementations MUST NOT enforce this rule"; "If a sending implementation receives a KeyUpdate with
       request_update set to update_requested, it MUST NOT send its own KeyUpdate if that would cause it to exceed these limits and
       SHOULD instead ignore the update_requested flag. This may result in an eventual need to terminate the connection when the
       limits in Section 5.5 are reached." The bound is the number of KeyUpdates sent; lowered here by the test hook. */
    CHECK(KSL_MAX_KEY_UPDATES == (UINT64_C(1) << 48) - 1, "the bound is 2^48-1 updates");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); key_updates k = {0, 0};
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); ksl_ssl_msg_observer_for_test(s, key_update_kind_cb, &k);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake");
    ksl_ssl_set_key_update_limit_for_test(c, 3); ksl_ssl_set_key_update_limit_for_test(s, 1);
    for (int i = 0; i < 3; i++) CHECK(ksl_ssl_key_update(c, 0) == KSL_OK && send_one(c, s), "a key update up to the bound");
    CHECK(k.updates == 3, "three KeyUpdates reached the server: the server, bounded at 1 itself, does not enforce the bound on what it receives");
    CHECK(ksl_ssl_key_update(c, 0) == KSL_ERROR && last_message_has(c, "2^48-1"), "negative: no fourth key update, and the error says why");
    ksl_tcp_set_key_update_records_for_test(c, 1);
    CHECK(send_one(c, s) && send_one(c, s) && k.updates == 3, "negative: no automatic KeyUpdate either; the data goes on under the last keys");
    CHECK(echo_bytes(c, s, 5000), "the stream is intact both ways");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* a peer's update_requested at the bound: the flag is ignored, the connection goes on */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); key_updates kc = {0, 0}; ksl_ssl_msg_observer_for_test(c, key_update_kind_cb, &kc);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake");
    ksl_ssl_set_key_update_limit_for_test(c, 1); k.updates = k.requested = 0; ksl_ssl_msg_observer_for_test(s, key_update_kind_cb, &k);
    uint8_t b = 1, r[16]; size_t n;
    CHECK(ksl_ssl_key_update(s, 1) == KSL_OK && ksl_tcp_write(s, &b, 1, &n) == KSL_OK, "the server asks for an update");
    shuttle(s, c); ksl_tcp_read(c, r, sizeof r, &n); CHECK(send_one(c, s) && kc.updates == 1 && k.updates == 1, "the client answers with its one allowed KeyUpdate");
    shuttle(s, c); ksl_tcp_read(c, r, sizeof r, &n);   /* the server's next request may follow its answer */
    CHECK(ksl_ssl_key_update(s, 1) == KSL_OK && ksl_tcp_write(s, &b, 1, &n) == KSL_OK, "the server asks again");
    shuttle(s, c); CHECK(ksl_tcp_read(c, r, sizeof r, &n) == KSL_OK && n == 1 && kc.updates == 2, "the client reads the request and the byte");
    CHECK(send_one(c, s) && k.updates == 1, "negative: no KeyUpdate past the client's bound, the update_requested flag ignored");
    CHECK(echo_bytes(c, s, 5000), "the connection goes on both ways");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* past the bound the keys stay in use until their record limit (4 records here, test hook); then the session ends, a server with
       internal_error */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake");
    ksl_ssl_set_key_update_limit_for_test(s, 1); ksl_tcp_set_key_update_records_for_test(s, 2); ksl_tcp_set_record_limit_for_test(s, 4);
    int ok = 1; for (int i = 0; i < 5; i++) { ok = ok && ksl_tcp_write(s, &b, 1, &n) == KSL_OK; shuttle(s, c); ok = ok && ksl_tcp_read(c, r, sizeof r, &n) == KSL_OK && n == 1; }
    CHECK(ok, "two records, the one allowed KeyUpdate, three records under its keys");
    int alert = 0, rc;
    CHECK(ksl_tcp_write(s, &b, 1, &n) == KSL_ERROR && last_message_has(s, "record limit"), "negative: the fourth record would reach the keys' limit: the session ends");
    CHECK(shuttle(s, c) > 0 && read_all_after_abort(c, &alert, &rc) == 0 && alert == (SSL_AD_INTERNAL_ERROR | 0x100), "the client receives internal_error");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_client_keeps_every_ticket(void) {
    SECTION("tcp_client_keeps_every_ticket");
    /* RFC 9846 appendix C.4: "Servers that issue tickets SHOULD offer at least as many tickets as the number of connections that a
       client might use; for example, a web browser using HTTP/1.1 [RFC9112] might open six connections to a server". Six tickets
       that arrive in one read are all handed out by ksl_ssl_get1_session, oldest first, and each resumes a connection of its own. */
    uint8_t keys[80]; for (int i = 0; i < 80; i++) keys[i] = (uint8_t)(i * 5 + 9);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ctx_set_option(sc, KSL_OPT_NUM_TICKETS, 6); ksl_ctx_set_ticket_keys(sc, keys, 1);
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "full handshake");
    uint8_t buf[16]; size_t n; ksl_tcp_read(c, buf, sizeof buf, &n);   /* the six NewSessionTickets in one read */
    ksl_session *ts[6]; int distinct = 1; for (int i = 0; i < 6; i++) { ts[i] = ksl_ssl_get1_session(c); for (int j = 0; j < i; j++) distinct = distinct && ts[i] && ts[i] != ts[j]; }
    ksl_session *t7 = ksl_ssl_get1_session(c);
    CHECK(ts[0] && distinct, "six tickets, one after the other");
    CHECK(t7 == ts[5], "then the current session again");
    ksl_ssl_free(c); ksl_ssl_free(s);
    uint8_t reused;
    for (int i = 0; i < 6; i++) {
        c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); ksl_ssl_set_session(c, ts[i]);
        CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &n) == KSL_OK && reused == 1, "each ticket resumes");
        ksl_ssl_free(c); ksl_ssl_free(s);
    }
    for (int i = 0; i < 6; i++) ksl_session_free(ts[i]);
    ksl_session_free(t7); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

#define TLS12_PROFILE_FOR_TEST "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
static void test_default_versions_and_tls12_profile(void) {
    SECTION("tcp_default_versions_and_tls12_profile");
    /* RFC 9852 section 4 (TLS 1.3 by default), RFC 9846 section 4.2.3 and App. E.5 (TLS 1.0 and 1.1 "MUST NOT be negotiated for any
       reason"), RFC 10015 sections 2-4 (no static RSA, no FFDH or FFDHE in TLS 1.2) */
    int roles[2] = {KSL_CLIENT, KSL_SERVER};
    for (int i = 0; i < 2; i++) {
        ksl_ctx *c = ksl_ctx_new(roles[i]);
        CHECK(SSL_CTX_get_min_proto_version(c->ctx) == TLS1_3_VERSION && SSL_CTX_get_max_proto_version(c->ctx) == TLS1_3_VERSION, "a new context speaks TLS 1.3 only");
        CHECK(ksl_ctx_set_option(c, KSL_OPT_MIN_VERSION, TLS1_1_VERSION) == KSL_ERROR && ksl_ctx_set_option(c, KSL_OPT_MIN_VERSION, TLS1_VERSION) == KSL_ERROR, "negative: TLS 1.0 and 1.1 refused as minimum");
        CHECK(ksl_ctx_set_option(c, KSL_OPT_MAX_VERSION, TLS1_1_VERSION) == KSL_ERROR && ksl_ctx_set_option(c, KSL_OPT_MIN_VERSION, 0) == KSL_ERROR, "negative: TLS 1.1 as maximum, or no bound at all, refused");
        CHECK(SSL_CTX_get_min_proto_version(c->ctx) == TLS1_3_VERSION, "the refused values changed nothing");
        CHECK(ksl_ctx_set_option(c, KSL_OPT_MIN_VERSION, KSL_TLS1_2) == KSL_OK && SSL_CTX_get_min_proto_version(c->ctx) == TLS1_2_VERSION && SSL_CTX_get_max_proto_version(c->ctx) == TLS1_3_VERSION, "TLS 1.2 as the floor, 1.3 still the top");
        STACK_OF(SSL_CIPHER) *sk = SSL_CTX_get_ciphers(c->ctx); int tls12 = 0, ok = 1;
        for (int k = 0; k < sk_SSL_CIPHER_num(sk); k++) {
            const SSL_CIPHER *ci = sk_SSL_CIPHER_value(sk, k); if (SSL_CIPHER_get_kx_nid(ci) == NID_kx_any) continue;   /* a TLS 1.3 suite */
            tls12++; int auth = SSL_CIPHER_get_auth_nid(ci);
            ok = ok && SSL_CIPHER_get_kx_nid(ci) == NID_kx_ecdhe && (auth == NID_auth_rsa || auth == NID_auth_ecdsa) && SSL_CIPHER_is_aead(ci);
        }
        CHECK(tls12 == 6 && ok, "the TLS 1.2 suites: six, all ECDHE with RSA or ECDSA and AEAD (no static RSA, no FFDHE, no static (EC)DH)");
        /* RFC 10015 sections 2-4: "Clients MUST NOT offer and servers MUST NOT select" non-ephemeral FFDH, FFDHE or RSA cipher suites in
           TLS 1.2; RFC 9325 section 4.1: no NULL encryption, nothing below 112 bits. ksl_ctx_set_ciphers holds a TLS 1.2 list to the
           profile too: ECDHE, authenticated with RSA or ECDSA, an AEAD of at least 128 bits */
        const char *refused[] = {"AES128-GCM-SHA256", "DHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-SHA256", "ECDHE-ECDSA-AES128-CCM8", "AECDH-AES128-SHA", "ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384", "PSK-AES128-GCM-SHA256"};
        int all_refused = 1; for (size_t k = 0; k < sizeof refused / sizeof refused[0]; k++) all_refused = all_refused && ksl_ctx_set_ciphers(c, NULL, refused[k]) == KSL_ERROR;
        CHECK(all_refused, "negative: static RSA, FFDHE, CBC, CCM_8 (64-bit), anonymous and PSK TLS 1.2 lists are refused, also as part of a list");
        STACK_OF(SSL_CIPHER) *after = SSL_CTX_get_ciphers(c->ctx); int still = 0;
        for (int k = 0; k < sk_SSL_CIPHER_num(after); k++) if (SSL_CIPHER_get_kx_nid(sk_SSL_CIPHER_value(after, k)) != NID_kx_any) still++;
        CHECK(still == 6 && !strcmp(c->list12, TLS12_PROFILE_FOR_TEST), "the refused lists changed nothing");
        CHECK(ksl_ctx_set_ciphers(c, NULL, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-CCM") == KSL_OK, "control: ECDHE with an AEAD is accepted");
        ksl_ctx_free(c);
    }
    END();
}

void run_tcp(void) { test_echo(); test_truncation(); test_tls12(); test_client_verification_still_refuses(); test_resumption(); test_sni_pause(); test_sni_override_alpn(); test_sni_override_settings_effective(); test_no_tls12_ticket_without_num_tickets(); test_session_context(); test_ticket_bound_to_server_name(); test_keyless_server_no_tickets(); test_server_acknowledges_server_name(); test_key_update_before_record_limit(); test_abort_sends_an_alert(); test_abort_after_pending_messages(); test_record_limits_per_cipher(); test_legacy_version_must_be_0303(); test_key_update_request_waits_for_the_peer(); test_key_update_epoch_is_bounded(); test_client_keeps_every_ticket(); test_default_versions_and_tls12_profile(); }
