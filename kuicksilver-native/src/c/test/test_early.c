/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* 0-RTT (ABI 6): server early-data option, early context bound into tickets, the transport's per-hello verdict, status getter. */
#include "test_common.h"

static const uint8_t TICKET_KEY[80] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x11, 0x22, 0x33};
static int set_str(ksl_ssl *s, int what, const char *v) { return ksl_ssl_set(s, what, (const uint8_t *)v, strlen(v)); }
static ksl_ctx *early_server_ctx(int early) {
    ksl_ctx *c = server_ctx("server"); ksl_ctx_set_ticket_keys(c, TICKET_KEY, 1); ksl_ctx_set_option(c, KSL_OPT_NUM_TICKETS, 2);
    if (early && ksl_ctx_set_option(c, KSL_OPT_EARLY_DATA, 1) != KSL_OK) printf("KSL_OPT_EARLY_DATA rejected\n");
    ksl_ctx_freeze(c); return c;
}
static ksl_ssl *qclient(ksl_ctx *c) { ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC); set_str(s, KSL_SET_SNI, "server.test"); set_str(s, KSL_SET_VERIFY_NAME, "server.test"); ksl_quic_set_transport_params(s, TP, sizeof TP); return s; }
static ksl_ssl *qserver(ksl_ctx *c, const char *early_ctx) { ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC); ksl_quic_set_transport_params(s, TP, sizeof TP); if (early_ctx) set_str(s, KSL_SET_EARLY_CONTEXT, early_ctx); return s; }

typedef struct { int levels[2][4]; int done; } track;   /* levels[direction][level]: KEY events seen */
static void pump_early(ksl_ssl *c, ksl_ssl *s, track *ct, track *st) {
    ksl_ssl *who[2] = {c, s}, *peer[2] = {s, c}; track *t[2] = {ct, st};
    for (int round = 0; round < 40; round++) {
        int progressed = 0;
        for (int k = 0; k < 2; k++) {
            if (ksl_drive(who[k]) == KSL_ERROR) return;
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                progressed = 1;
                if (ev.type == KSL_EV_CRYPTO_SEND) ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len);
                else if (ev.type == KSL_EV_KEY) { t[k]->levels[ev.direction][ev.level]++; ksl_key_free(ev.key); }
                else if (ev.type == KSL_EV_HANDSHAKE_DONE) t[k]->done = 1;
            }
        }
        if (!progressed && round > 3) return;
    }
}
static uint8_t early_status(ksl_ssl *s) { uint8_t b = 0xee; size_t n = 0; if (ksl_ssl_get(s, KSL_GET_EARLY_DATA, &b, 1, &n) != KSL_OK || n != 1) return 0xee; return b; }
static uint8_t reused(ksl_ssl *s) { uint8_t b = 0; size_t n; ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &b, 1, &n); return b; }

/* a full handshake with an early-data server; returns the client's resumable session */
static ksl_session *first_session(ksl_ctx *cc, ksl_ctx *sc, const char *early_ctx) {
    ksl_ssl *c = qclient(cc), *s = qserver(sc, early_ctx); track ct = {0}, st = {0}; pump_early(c, s, &ct, &st);
    ksl_session *sess = ct.done && st.done ? ksl_ssl_get1_session(c) : NULL;
    ksl_ssl_free(c); ksl_ssl_free(s); return sess;
}
/* the second connection: client asks for 0-RTT, server stamps `ctx2` and gives verdict `allow` */
static void resume(ksl_ctx *cc, ksl_ctx *sc, ksl_session *sess, const char *ctx2, int allow, int *client_rc, uint8_t *cst, uint8_t *sst, track *ct, track *st, uint8_t *re) {
    ksl_ssl *c = qclient(cc), *s = qserver(sc, ctx2); uint8_t one = 1, verdict = (uint8_t)allow;
    ksl_ssl_set_session(c, sess);
    *client_rc = ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1);
    ksl_ssl_set(s, KSL_SET_EARLY_DATA, &verdict, 1);
    pump_early(c, s, ct, st); *cst = early_status(c); *sst = early_status(s); *re = reused(c);
    ksl_ssl_free(c); ksl_ssl_free(s);
}

static void test_early_accepted(void) {
    SECTION("quic_early_data_accepted");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1"); CHECK(sess != NULL, "first handshake leaves a session");
    int rc; uint8_t cst, sst, re; track ct = {0}, st = {0};
    resume(cc, sc, sess, "cfg-1", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK, "client may request 0-RTT with an early-data ticket");
    CHECK(ct.levels[KSL_DIR_WRITE][KSL_LEVEL_EARLY] == 1, "client got the 0-RTT write key");
    CHECK(st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 1, "server got the 0-RTT read key");
    CHECK(cst == 2 && sst == 2, "both report accepted");
    CHECK(ct.done && st.done && re == 1, "resumed handshake completes");
    ksl_session_free(sess); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_resumption_renews_ticket(void) {
    SECTION("quic_early_resumption_issues_fresh_ticket");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    ksl_ssl *c = qclient(cc), *s = qserver(sc, "cfg-1"); track ct = {0}, st = {0};
    ksl_ssl_set_session(c, sess); pump_early(c, s, &ct, &st);
    ksl_session *next = ksl_ssl_get1_session(c);
    CHECK(reused(c) == 1 && next != NULL && next != sess, "a resumed connection receives a new ticket (single-use tickets)");
    ksl_session_free(next); ksl_ssl_free(c); ksl_ssl_free(s); ksl_session_free(sess); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static int done_events(ksl_ssl *who, ksl_ssl *peer) {
    int done = 0; ksl_event ev;
    while (ksl_quic_next_event(who, &ev)) {
        if (ev.type == KSL_EV_CRYPTO_SEND && peer) ksl_quic_provide(peer, ev.level, ev.buf, ev.len);
        else if (ev.type == KSL_EV_KEY) ksl_key_free(ev.key);
        else if (ev.type == KSL_EV_HANDSHAKE_DONE) done = 1;
    }
    return done;
}
static void test_server_done_waits_for_finished(void) {
    SECTION("quic_early_server_done_waits_for_client_finished");
    /* OpenSSL stops an early-data server at TLS_ST_EARLY_DATA (SSL_do_handshake returns 1) before the client's Finished */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_ssl *c = qclient(cc), *s = qserver(sc, "cfg-1");
    ksl_drive(c); done_events(c, s);
    int rc = ksl_drive(s); int sdone = done_events(s, NULL);
    CHECK(rc == KSL_WANT_READ && !sdone, "no HANDSHAKE_DONE before the client's Finished");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_early_context_mismatch(void) {
    SECTION("quic_early_data_context_mismatch_rejects");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    int rc; uint8_t cst, sst, re; track ct = {0}, st = {0};
    resume(cc, sc, sess, "cfg-2", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK, "client requested 0-RTT");
    CHECK(st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0, "server installs no 0-RTT key");
    CHECK(cst == 1 && sst == 1, "both report rejected");
    CHECK(ct.done && st.done && re == 1, "the session still resumes");
    ksl_session_free(sess); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_early_verdict_refused(void) {
    SECTION("quic_early_data_needs_transport_verdict");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    int rc; uint8_t cst, sst, re; track ct = {0}, st = {0};
    resume(cc, sc, sess, "cfg-1", 0, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0 && cst == 1 && sst == 1, "no verdict: rejected");
    CHECK(ct.done && st.done, "handshake completes in 1-RTT");
    ksl_session_free(sess); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_ticket_without_early_data(void) {
    SECTION("quic_ticket_without_early_data_refuses_0rtt");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(0);
    ksl_session *sess = first_session(cc, sc, NULL); CHECK(sess != NULL, "plain server issues a ticket");
    ksl_ssl *c = qclient(cc); uint8_t one = 1; ksl_ssl_set_session(c, sess);
    CHECK(ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_ERROR, "0-RTT refused for a ticket without early_data");
    uint32_t code; char m[128]; int a; ksl_ssl_last_error(c, &code, &a, m, sizeof m); CHECK(code == KSL_E_NOT_SUPPORTED, "KSL_E_NOT_SUPPORTED");
    CHECK(early_status(c) == 0, "status none");
    ksl_ssl_free(c); ksl_session_free(sess); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_early_option_server_only(void) {
    SECTION("quic_early_data_option_server_only");
    ksl_ctx *cc = ksl_ctx_new(KSL_CLIENT); CHECK(ksl_ctx_set_option(cc, KSL_OPT_EARLY_DATA, 1) == KSL_ERROR, "client context refuses the option");
    ksl_ssl *s = ksl_ssl_new(cc, KSL_MODE_QUIC); CHECK(set_str(s, KSL_SET_EARLY_CONTEXT, "x") == KSL_ERROR, "client session refuses an early context");
    ksl_ssl_free(s); ksl_ctx_free(cc); END();
}
void run_early(void) { test_server_done_waits_for_finished(); test_early_accepted(); test_resumption_renews_ticket(); test_early_context_mismatch(); test_early_verdict_refused(); test_ticket_without_early_data(); test_early_option_server_only(); }
