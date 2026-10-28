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
       section 6.1 / RFC 5246 section 7.2: an error alert, not a bare transport end; RFC 9846 appendix D, RFC 9325 section 3.6) */
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
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(legacy); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
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
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); ksl_ctx_free(proxy); END();
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
static void test_key_update_before_record_limit(void) {
    SECTION("tcp_key_update_before_record_limit");
    /* RFC 9846 section 5.5: for AES-GCM up to 2^24.5 full-size records under a given set of keys; "Implementations MUST either close
       the connection or do a key update ... prior to reaching these limits"; OpenSSL sends KeyUpdate only on SSL_key_update. ksl
       sends one every 2^23 records it wrote; here the bound is lowered to 4 records (test hook). */
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
    /* TLS 1.2 has no KeyUpdate: the writes go on (nothing is sent, nothing fails) */
    ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2); ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2); ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.2 handshake");
    ksl_tcp_set_key_update_records_for_test(c, 4); CHECK(write_all(c, s, 16384 * 10), "TLS 1.2: the writes past the bound succeed");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
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
static void test_pending_write_retried_from_a_copy(void) {
    SECTION("tcp_pending_write_retried_from_another_buffer");
    /* A write the BIO pair had no room for stays pending in OpenSSL; its retry comes with the same bytes from another buffer (the JNI
       layer copies each call's bytes into a fresh one). Without SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER OpenSSL refused it with bad write
       retry and failed the session. */
    static uint8_t big[16384]; for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 3);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); size_t n;
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "TLS 1.3 handshake");
    uint8_t *copy = malloc(sizeof big); memcpy(copy, big, sizeof big);
    CHECK(ksl_tcp_write(s, big, sizeof big, &n) == KSL_OK && n == sizeof big, "one record fills the pair");
    CHECK(ksl_tcp_write(s, big, sizeof big, &n) == KSL_WANT_READ && n == 0, "the next one is pending");
    shuttle(s, c); CHECK(ksl_tcp_write(s, copy, sizeof big, &n) == KSL_OK && n == sizeof big, "its retry from a copy completes it");
    uint8_t got[16384]; size_t total = 0, r; int same = 1;
    for (int i = 0; i < 10 && total < 2 * sizeof big; i++) {
        shuttle_room(s, c);
        while (ksl_tcp_read(c, got, sizeof got, &r) == KSL_OK && r) { for (size_t j = 0; j < r; j++) same = same && got[j] == big[(total + j) % sizeof big]; total += r; }
    }
    CHECK(total == 2 * sizeof big && same, "the client reads both records intact");
    free(copy); ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
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

/* What a session's peer saw of KeyUpdates: how many, how many with request_update = update_requested */
typedef struct { int updates, requested; } key_updates;
static void key_update_kind_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl; const uint8_t *m = buf; key_updates *k = arg;
    if (!write_p && content_type == SSL3_RT_HANDSHAKE && len >= 5 && m[0] == SSL3_MT_KEY_UPDATE) { k->updates++; if (m[4] == SSL_KEY_UPDATE_REQUESTED) k->requested++; }
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
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_key_update_epoch_is_bounded(void) {
    SECTION("tcp_key_update_epoch_is_bounded");
    /* RFC 9846 section 4.7.3: "sending implementations MUST NOT allow the epoch -- and hence the number of key updates -- to exceed
       2^48-1"; "receiving implementations MUST NOT enforce this rule". The bound is lowered to 3 KeyUpdates (test hook); the session
       that reached it ends, as the section allows ("an eventual need to terminate the connection") */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); key_updates k = {0, 0};
    ksl_ssl *c = tcp_client(cc, "server.test"), *s = ksl_ssl_new(sc, KSL_MODE_TCP); ksl_ssl_msg_observer_for_test(s, key_update_kind_cb, &k);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake");
    ksl_ssl_set_key_update_limit_for_test(c, 3); ksl_ssl_set_key_update_limit_for_test(s, 1);
    for (int i = 0; i < 2; i++) CHECK(ksl_ssl_key_update(c, 0) == KSL_OK && send_one(c, s), "a key update below the bound");
    CHECK(ksl_ssl_key_update(c, 0) == KSL_OK, "the third is queued");
    uint8_t b = 1, r[16]; size_t n; ksl_tcp_write(c, &b, 1, &n); shuttle(c, s); ksl_tcp_read(s, r, sizeof r, &n);
    CHECK(k.updates == 3, "three KeyUpdates reached the server: the server, bounded at 1 itself, does not enforce the bound on what it receives");
    CHECK(ksl_ssl_key_update(c, 0) == KSL_ERROR && ksl_tcp_write(c, &b, 1, &n) == KSL_ERROR, "negative: past the bound no key update and no data");
    uint8_t out[64]; CHECK(ksl_tcp_drain(c, out, sizeof out, &n) == KSL_OK && n == 0, "negative: nothing more leaves the client");
    ksl_ssl_free(c); ksl_ssl_free(s);
    /* a peer's update_requested answered with the last allowed KeyUpdate: the session ends there, a further request is never answered */
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); key_updates kc = {0, 0}; ksl_ssl_msg_observer_for_test(c, key_update_kind_cb, &kc);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "handshake");
    ksl_ssl_set_key_update_limit_for_test(c, 1);
    CHECK(ksl_ssl_key_update(s, 1) == KSL_OK, "the server asks for an update");
    ksl_tcp_write(s, &b, 1, &n); shuttle(s, c); ksl_tcp_read(c, r, sizeof r, &n); ksl_tcp_write(c, &b, 1, &n); shuttle(c, s);   /* the answer leaves ahead of the next write */
    k.updates = 0; ksl_ssl_msg_observer_for_test(s, key_update_kind_cb, &k); ksl_tcp_read(s, r, sizeof r, &n);
    CHECK(kc.updates == 1 && k.updates == 1, "the client answered with its one allowed KeyUpdate");
    CHECK(ksl_ssl_key_update(s, 1) == KSL_OK, "the server asks again");
    ksl_tcp_write(s, &b, 1, &n); shuttle(s, c); ksl_tcp_read(c, r, sizeof r, &n); ksl_tcp_write(c, &b, 1, &n); shuttle(c, s); ksl_tcp_read(s, r, sizeof r, &n);
    CHECK(kc.updates == 1 && k.updates == 1, "negative: no KeyUpdate past the client's bound");
    CHECK(ksl_tcp_write(c, &b, 1, &n) == KSL_ERROR, "the client's session ended");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

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
        ksl_ctx_free(c);
    }
    END();
}

void run_tcp(void) { test_echo(); test_truncation(); test_tls12(); test_resumption(); test_sni_pause(); test_sni_override_alpn(); test_sni_override_settings_effective(); test_no_tls12_ticket_without_num_tickets(); test_session_context(); test_ticket_bound_to_server_name(); test_keyless_server_no_tickets(); test_server_acknowledges_server_name(); test_key_update_before_record_limit(); test_legacy_version_must_be_0303(); test_key_update_request_waits_for_the_peer(); test_key_update_epoch_is_bounded(); test_default_versions_and_tls12_profile(); test_pending_write_retried_from_a_copy(); }
