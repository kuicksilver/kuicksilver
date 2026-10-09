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
    /* negative: a peer without EMS */
    SSL_CTX_set_options(cc->ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET);
    c = tcp_client(cc, "server.test"); s = ksl_ssl_new(sc, KSL_MODE_TCP); int r = tcp_pump(c, s, NULL, NULL);
    CHECK(r == KSL_ERROR && (last_code(c, NULL) == KSL_E_EMS_REQUIRED || last_code(s, NULL) == KSL_E_EMS_REQUIRED), "negative: TLS 1.2 without EMS rejected (KSL_E_EMS_REQUIRED)");
    uint8_t cb[32]; CHECK(ksl_ssl_get(c, KSL_GET_CHANNEL_BINDING, cb, 32, &n) == KSL_ERROR, "negative: channel binding unavailable without EMS");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
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

void run_tcp(void) { test_echo(); test_truncation(); test_tls12(); test_resumption(); test_sni_pause(); test_sni_override_alpn(); test_no_tls12_ticket_without_num_tickets(); test_session_context(); }
