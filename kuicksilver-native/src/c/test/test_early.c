/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* 0-RTT (ABI 6): server early-data option, early context bound into tickets, the transport's per-hello verdict, status getter. */
#include "test_common.h"
#include <openssl/ssl.h>

static const uint8_t TICKET_KEY[80] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x11, 0x22, 0x33};
static int set_str(ksl_ssl *s, int what, const char *v) {
    return ksl_ssl_set(s, what, (const uint8_t *)v, strlen(v));
}
static ksl_ctx *early_server_ctx(int early) {
    ksl_ctx *c = server_ctx("server");
    ksl_ctx_set_ticket_keys(c, TICKET_KEY, 1);
    ksl_ctx_set_option(c, KSL_OPT_NUM_TICKETS, 2);
    if (early && ksl_ctx_set_option(c, KSL_OPT_EARLY_DATA, 1) != KSL_OK)
        printf("KSL_OPT_EARLY_DATA rejected\n");
    ksl_ctx_freeze(c);
    return c;
}
static ksl_ssl *qclient(ksl_ctx *c) {
    ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC);
    set_str(s, KSL_SET_SNI, "server.test");
    set_str(s, KSL_SET_VERIFY_NAME, "server.test");
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    return s;
}
static ksl_ssl *qserver(ksl_ctx *c, const char *early_ctx) {
    ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC);
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    if (early_ctx)
        set_str(s, KSL_SET_EARLY_CONTEXT, early_ctx);
    return s;
}

typedef struct {
    int levels[2][4];
    int done;
} track;                    /* levels[direction][level]: KEY events seen */
static ksl_ctx *sni_choice; /* the override pump_early answers a server's SNI pause with (NULL: the base context) */
static void pump_early(ksl_ssl *c, ksl_ssl *s, track *ct, track *st) {
    ksl_ssl *who[2] = {c, s}, *peer[2] = {s, c};
    track *t[2] = {ct, st};
    for (int round = 0; round < 40; round++) {
        int progressed = 0;
        for (int k = 0; k < 2; k++) {
            int r = ksl_drive(who[k]);
            if (r == KSL_ERROR)
                return;
            if (r == KSL_WANT_SNI) {
                if (ksl_ssl_sni_resume(who[k], sni_choice, 0) != KSL_OK)
                    return;
                progressed = 1;
            }
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                progressed = 1;
                if (ev.type == KSL_EV_CRYPTO_SEND)
                    ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len);
                else if (ev.type == KSL_EV_KEY) {
                    t[k]->levels[ev.direction][ev.level]++;
                    ksl_key_free(ev.key);
                } else if (ev.type == KSL_EV_HANDSHAKE_DONE)
                    t[k]->done = 1;
            }
        }
        if (!progressed && round > 3)
            return;
    }
}
static uint8_t early_status(ksl_ssl *s) {
    uint8_t b = 0xee;
    size_t n = 0;
    if (ksl_ssl_get(s, KSL_GET_EARLY_DATA, &b, 1, &n) != KSL_OK || n != 1)
        return 0xee;
    return b;
}
static uint8_t reused(ksl_ssl *s) {
    uint8_t b = 0;
    size_t n;
    ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &b, 1, &n);
    return b;
}

/* a full handshake with an early-data server; returns the client's resumable session */
static ksl_session *first_session(ksl_ctx *cc, ksl_ctx *sc, const char *early_ctx) {
    ksl_ssl *c = qclient(cc), *s = qserver(sc, early_ctx);
    track ct = {0}, st = {0};
    pump_early(c, s, &ct, &st);
    ksl_session *sess = ct.done && st.done ? ksl_ssl_get1_session(c) : NULL;
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    return sess;
}
/* the second connection: client asks for 0-RTT, server stamps `ctx2` and gives verdict `allow` */
static void resume(ksl_ctx *cc, ksl_ctx *sc, ksl_session *sess, const char *ctx2, int allow, int *client_rc,
                   uint8_t *cst, uint8_t *sst, track *ct, track *st, uint8_t *re) {
    ksl_ssl *c = qclient(cc), *s = qserver(sc, ctx2);
    uint8_t one = 1, verdict = (uint8_t)allow;
    ksl_ssl_set_session(c, sess);
    *client_rc = ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1);
    ksl_ssl_set(s, KSL_SET_EARLY_DATA, &verdict, 1);
    pump_early(c, s, ct, st);
    *cst = early_status(c);
    *sst = early_status(s);
    *re = reused(c);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
}

static void test_early_accepted(void) {
    SECTION("quic_early_data_accepted");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    CHECK(sess != NULL, "first handshake leaves a session");
    int rc;
    uint8_t cst, sst, re;
    track ct = {0}, st = {0};
    resume(cc, sc, sess, "cfg-1", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK, "client may request 0-RTT with an early-data ticket");
    CHECK(ct.levels[KSL_DIR_WRITE][KSL_LEVEL_EARLY] == 1, "client got the 0-RTT write key");
    CHECK(st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 1, "server got the 0-RTT read key");
    CHECK(cst == 2 && sst == 2, "both report accepted");
    CHECK(ct.done && st.done && re == 1, "resumed handshake completes");
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
static void test_resumption_renews_ticket(void) {
    SECTION("quic_early_resumption_issues_fresh_ticket");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    ksl_ssl *c = qclient(cc), *s = qserver(sc, "cfg-1");
    track ct = {0}, st = {0};
    ksl_ssl_set_session(c, sess);
    pump_early(c, s, &ct, &st);
    ksl_session *next = ksl_ssl_get1_session(c);
    CHECK(reused(c) == 1 && next != NULL && next != sess,
          "a resumed connection receives a new ticket (single-use tickets)");
    ksl_session_free(next);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
static int done_events(ksl_ssl *who, ksl_ssl *peer) {
    int done = 0;
    ksl_event ev;
    while (ksl_quic_next_event(who, &ev)) {
        if (ev.type == KSL_EV_CRYPTO_SEND && peer)
            ksl_quic_provide(peer, ev.level, ev.buf, ev.len);
        else if (ev.type == KSL_EV_KEY)
            ksl_key_free(ev.key);
        else if (ev.type == KSL_EV_HANDSHAKE_DONE)
            done = 1;
    }
    return done;
}
static void test_server_done_waits_for_finished(void) {
    SECTION("quic_early_server_done_waits_for_client_finished");
    /* OpenSSL stops an early-data server at TLS_ST_EARLY_DATA (SSL_do_handshake returns 1) before the client's Finished */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_ssl *c = qclient(cc), *s = qserver(sc, "cfg-1");
    ksl_drive(c);
    done_events(c, s);
    int rc = ksl_drive(s);
    int sdone = done_events(s, NULL);
    CHECK(rc == KSL_WANT_READ && !sdone, "no HANDSHAKE_DONE before the client's Finished");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
static void test_early_context_mismatch(void) {
    SECTION("quic_early_data_context_mismatch_rejects");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    int rc;
    uint8_t cst, sst, re;
    track ct = {0}, st = {0};
    resume(cc, sc, sess, "cfg-2", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK, "client requested 0-RTT");
    CHECK(st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0, "server installs no 0-RTT key");
    CHECK(cst == 1 && sst == 1, "both report rejected");
    CHECK(ct.done && st.done && re == 1, "the session still resumes");
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
/* RFC 8446 section 4.2.10 (RFC 9846 section 4.3.10): the server accepts early data only when the selected cipher suite and ALPN
   protocol are "the same as those associated with the selected PSK", that is "those negotiated in the connection during which the
   ticket was established". OpenSSL 3.5 compares only the suite's hash (4.1 adds the suite check, PR 32032) and keeps a resumed
   session's original ALPN in the tickets it renews (fixed in 4.1, PR 32401); ksl checks both itself (allow_early_data_cb). */
static ksl_ctx *suite_server_ctx(const char *suites, const uint8_t *alpn, size_t alpn_len) {
    ksl_ctx *c = server_ctx("server");
    ksl_ctx_set_ticket_keys(c, TICKET_KEY, 1);
    ksl_ctx_set_option(c, KSL_OPT_NUM_TICKETS, 2);
    if (suites && ksl_ctx_set_ciphers(c, suites, NULL) != KSL_OK)
        printf("suites %s rejected\n", suites);
    if (alpn)
        ksl_ctx_set_alpn(c, alpn, alpn_len);
    ksl_ctx_set_option(c, KSL_OPT_EARLY_DATA, 1);
    ksl_ctx_freeze(c);
    return c;
}
static void test_negative_early_cipher_mismatch(void) {
    SECTION("negative_quic_early_data_cipher_suite_mismatch_rejects");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
    ksl_ctx *aes = suite_server_ctx("TLS_AES_128_GCM_SHA256", NULL, 0),
            *chacha = suite_server_ctx("TLS_CHACHA20_POLY1305_SHA256", NULL, 0);
    ksl_session *sess = first_session(cc, aes, "cfg-1");
    CHECK(sess != NULL, "a ticket issued under TLS_AES_128_GCM_SHA256");
    /* the client offers every suite; the second server (same ticket keys) can only pick ChaCha20, whose hash (SHA-256) is the same */
    int rc;
    uint8_t cst, sst, re;
    track ct = {0}, st = {0};
    resume(cc, chacha, sess, "cfg-1", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK, "client requested 0-RTT");
    CHECK(st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0, "server installs no 0-RTT key under another suite");
    CHECK(cst == 1 && sst == 1, "both report rejected");
    CHECK(ct.done && st.done && re == 1, "the PSK still resumes in 1-RTT");
    /* the control: the same suite on both connections accepts */
    ksl_session *again = first_session(cc, aes, "cfg-1");
    track ct2 = {0}, st2 = {0};
    resume(cc, aes, again, "cfg-1", 1, &rc, &cst, &sst, &ct2, &st2, &re);
    CHECK(cst == 2 && sst == 2 && ct2.done && st2.done, "the same suite accepts 0-RTT");
    ksl_session_free(again);
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(aes);
    ksl_ctx_free(chacha);
    END();
}
/* RFC 9001 section 4.6.2: "A server will always reject 0-RTT if it sends a TLS HelloRetryRequest", and RFC 9846 section 4.2.2 has
   the second ClientHello drop early_data. A server whose groups changed since the ticket (it takes only secp384r1, for which the
   client sent no share) asks again: no 0-RTT key is installed, both report the rejection, and the PSK still resumes. */
static void test_negative_early_data_after_hello_retry_request(void) {
    SECTION("negative_quic_early_data_rejected_after_hello_retry_request");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
    ksl_ctx *sc = suite_server_ctx(NULL, NULL, 0), *p384 = server_ctx("server");
    ksl_ctx_set_ticket_keys(p384, TICKET_KEY, 1);
    ksl_ctx_set_option(p384, KSL_OPT_NUM_TICKETS, 2);
    ksl_ctx_set_option(p384, KSL_OPT_EARLY_DATA, 1);
    CHECK(ksl_ctx_set_groups(p384, "secp384r1") == KSL_OK, "a server of secp384r1 alone");
    ksl_ctx_freeze(p384);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    CHECK(sess != NULL, "a ticket that allows 0-RTT");
    int rc;
    uint8_t cst, sst, re;
    track ct = {0}, st = {0};
    resume(cc, p384, sess, "cfg-1", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK, "client requested 0-RTT");
    CHECK(st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0,
          "the server installs no 0-RTT key after its HelloRetryRequest");
    CHECK(
        ct.levels[KSL_DIR_WRITE][KSL_LEVEL_EARLY] == 1,
        "the client gets one 0-RTT key, none from its second ClientHello (whose CRYPTO stays at the Initial level: the server reads it)");
    CHECK(cst == 1 && sst == 1, "both report rejected");
    CHECK(ct.done && st.done && re == 1, "the PSK still resumes in 1-RTT");
    ksl_session *again = first_session(cc, sc, "cfg-1");
    track ct2 = {0}, st2 = {0};
    resume(cc, sc, again, "cfg-1", 1, &rc, &cst, &sst, &ct2, &st2, &re);
    CHECK(cst == 2 && sst == 2 && ct2.done && st2.done, "control: without the HelloRetryRequest it accepts");
    ksl_session_free(again);
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    ksl_ctx_free(p384);
    END();
}
static const uint8_t ALPN_H3_HQ[] = {2, 'h', '3', 10, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p'};
static const uint8_t ALPN_HQ_H3[] = {10, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p', 2, 'h', '3'};
static const uint8_t ALPN_HQ[] = {10, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p'};
/* The ALPN of the connection that issued the ticket. OpenSSL 3.5 compares it with the selected protocol (statem_srvr.c,
   tls_handle_alpn) and writes the selected protocol into every renewed ticket (tls_construct_new_session_ticket); it keeps the
   old one only when a resumption selects none (fixed in 4.1, PR 32401), which a QUIC connection cannot complete (RFC 9001
   section 8.1: ksl_client_hello_cb, ksl_drive). */
static void test_negative_early_alpn_mismatch(void) {
    SECTION("negative_quic_early_data_alpn_mismatch_rejects");
    ksl_ctx *h3 = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *hq = client_ctx("test-ca", KSL_VERIFY_OPENSSL),
            *both = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
    ksl_ctx_set_alpn(hq, ALPN_HQ, sizeof ALPN_HQ);
    ksl_ctx_set_alpn(both, ALPN_H3_HQ, sizeof ALPN_H3_HQ);
    ksl_ctx *sc = suite_server_ctx(NULL, ALPN_H3_HQ, sizeof ALPN_H3_HQ),
            *hq_first = suite_server_ctx(NULL, ALPN_HQ_H3, sizeof ALPN_HQ_H3);
    ksl_session *t1 = first_session(h3, sc, "cfg-1");
    CHECK(t1 != NULL, "ticket of an h3 connection");
    /* 0-RTT with the h3 ticket where the server selects hq-interop */
    int rc;
    uint8_t cst, sst, re;
    track ct = {0}, st = {0};
    resume(both, hq_first, t1, "cfg-1", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK && st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0 && cst == 1 && sst == 1,
          "an h3 ticket under hq-interop: 0-RTT rejected");
    CHECK(ct.done && st.done && re == 1, "the PSK still resumes in 1-RTT");
    /* a fresh h3 ticket resumed under hq-interop without 0-RTT: the renewed ticket belongs to an hq-interop connection; one
       renewed ticket per attempt (a client uses a ticket once, RFC 9846 appendix C.4) */
    ksl_session *t2[2] = {NULL, NULL};
    for (int i = 0; i < 2; i++) {
        ksl_session *fresh = first_session(h3, sc, "cfg-1");
        ksl_ssl *c = qclient(hq), *s = qserver(sc, "cfg-1");
        track ct1 = {0}, st1 = {0};
        ksl_ssl_set_session(c, fresh);
        pump_early(c, s, &ct1, &st1);
        uint8_t alpn[32];
        size_t an = 0;
        ksl_ssl_get(s, KSL_GET_ALPN, alpn, sizeof alpn, &an);
        CHECK(ct1.done && st1.done && reused(c) == 1 && an == 10 && !memcmp(alpn, "hq-interop", 10),
              "resumed under hq-interop");
        t2[i] = ksl_ssl_get1_session(c);
        CHECK(t2[i] != NULL && t2[i] != fresh, "a renewed ticket");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_session_free(fresh);
    }
    /* 0-RTT with that ticket where the server selects h3 (the protocol of the ticket's original full handshake) */
    track ct2 = {0}, st2 = {0};
    if (t2[0])
        resume(both, sc, t2[0], "cfg-1", 1, &rc, &cst, &sst, &ct2, &st2, &re);
    CHECK(t2[0] && rc == KSL_OK && st2.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0 && cst == 1 && sst == 1,
          "a renewed hq-interop ticket under h3: 0-RTT rejected");
    CHECK(ct2.done && st2.done && re == 1, "the PSK still resumes in 1-RTT");
    /* the control: the renewed ticket under its own protocol accepts */
    track ct3 = {0}, st3 = {0};
    if (t2[1])
        resume(both, hq_first, t2[1], "cfg-1", 1, &rc, &cst, &sst, &ct3, &st3, &re);
    CHECK(t2[1] && cst == 2 && sst == 2 && ct3.done && st3.done,
          "a renewed hq-interop ticket under hq-interop accepts 0-RTT");
    ksl_session_free(t2[0]);
    ksl_session_free(t2[1]);
    ksl_session_free(t1);
    ksl_ctx_free(h3);
    ksl_ctx_free(hq);
    ksl_ctx_free(both);
    ksl_ctx_free(sc);
    ksl_ctx_free(hq_first);
    END();
}
static void test_early_verdict_refused(void) {
    SECTION("quic_early_data_needs_transport_verdict");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    int rc;
    uint8_t cst, sst, re;
    track ct = {0}, st = {0};
    resume(cc, sc, sess, "cfg-1", 0, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0 && cst == 1 && sst == 1, "no verdict: rejected");
    CHECK(ct.done && st.done, "handshake completes in 1-RTT");
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
static void test_ticket_without_early_data(void) {
    SECTION("quic_ticket_without_early_data_refuses_0rtt");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(0);
    ksl_session *sess = first_session(cc, sc, NULL);
    CHECK(sess != NULL, "plain server issues a ticket");
    ksl_ssl *c = qclient(cc);
    uint8_t one = 1;
    ksl_ssl_set_session(c, sess);
    CHECK(ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_ERROR, "0-RTT refused for a ticket without early_data");
    uint32_t code;
    char m[128];
    int a;
    ksl_ssl_last_error(c, &code, &a, m, sizeof m);
    CHECK(code == KSL_E_NOT_SUPPORTED, "KSL_E_NOT_SUPPORTED");
    CHECK(early_status(c) == 0, "status none");
    ksl_ssl_free(c);
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
static void test_early_option_server_only(void) {
    SECTION("quic_early_data_option_server_only");
    ksl_ctx *cc = ksl_ctx_new(KSL_CLIENT);
    CHECK(ksl_ctx_set_option(cc, KSL_OPT_EARLY_DATA, 1) == KSL_ERROR, "client context refuses the option");
    ksl_ssl *s = ksl_ssl_new(cc, KSL_MODE_QUIC);
    CHECK(set_str(s, KSL_SET_EARLY_CONTEXT, "x") == KSL_ERROR, "client session refuses an early context");
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    END();
}

/* ---- SNI overrides on QUIC: 0-RTT under the chosen identity (RFC 9001 section 4.6.1), tickets bound to it ---- */
/* a server context of `cert`: the shared ticket keys, two tickets, early data when asked, the SNI pause when asked */
static ksl_ctx *sni_server_ctx(const char *cert, int early, int pause) {
    ksl_ctx *c = server_ctx(cert);
    ksl_ctx_set_ticket_keys(c, TICKET_KEY, 1);
    ksl_ctx_set_option(c, KSL_OPT_NUM_TICKETS, 2);
    if (early)
        ksl_ctx_set_option(c, KSL_OPT_EARLY_DATA, 1);
    if (pause)
        ksl_ctx_set_option(c, KSL_OPT_SNI_PAUSE, 1);
    ksl_ctx_freeze(c);
    return c;
}
static void test_sni_override_keeps_early_data(void) {
    SECTION("quic_sni_override_keeps_early_data");
    /* the base identity (another CA) would fail the client: a completed handshake proves the override's certificate was sent */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *base = sni_server_ctx("server-other-ca", 1, 1),
            *a = sni_server_ctx("server", 1, 0);
    sni_choice = a;
    ksl_session *sess = first_session(cc, base, "cfg-1");
    CHECK(sess != NULL, "the override's handshake completes and leaves a ticket");
    int rc;
    uint8_t cst, sst, re;
    track ct = {0}, st = {0};
    resume(cc, base, sess, "cfg-1", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK, "the override's ticket allows 0-RTT (max_early_data_size 0xffffffff)");
    CHECK(cst == 2 && sst == 2 && st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 1,
          "0-RTT accepted under the same override");
    CHECK(ct.done && st.done && re == 1, "the resumed handshake completes");
    sni_choice = NULL;
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(base);
    ksl_ctx_free(a);
    END();
}
static void test_negative_sni_ticket_other_identity(void) {
    SECTION("negative_quic_sni_ticket_not_resumed_under_another_identity");
    /* RFC 9846 section 4.7.1: a ticket resumes only under the leaf it was issued under. Same name, same ticket keys, same session
       context: only the identity the selector chose differs */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *base = sni_server_ctx("server-other-ca", 1, 1),
            *a = sni_server_ctx("server", 1, 0), *b = sni_server_ctx("server-other-key", 1, 0);
    sni_choice = a;
    ksl_session *sess = first_session(cc, base, "cfg-1");
    CHECK(sess != NULL, "a ticket issued under identity A");
    sni_choice = b;
    int rc;
    uint8_t cst, sst, re;
    track ct = {0}, st = {0};
    resume(cc, base, sess, "cfg-1", 1, &rc, &cst, &sst, &ct, &st, &re);
    CHECK(rc == KSL_OK, "the client offers A's ticket with 0-RTT");
    CHECK(re == 0 && cst == 1 && sst == 1 && st.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0,
          "under identity B: no resumption, 0-RTT rejected, no 0-RTT read key");
    CHECK(ct.done && st.done, "a full handshake with B's certificate completes");
    sni_choice = NULL;
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(base);
    ksl_ctx_free(a);
    ksl_ctx_free(b);
    END();
}
/* NewSessionTickets the client read, and how many of them carried early_data (RFC 9846 section 4.6.1: lifetime, age_add, nonce,
   ticket, then the extensions) */
typedef struct {
    int tickets, with_early_data;
} nst_seen;
static void count_nst(int write_p, int version, int content_type, const void *buf, size_t len, struct ssl_st *ssl,
                      void *arg) {
    (void)version;
    (void)ssl;
    const uint8_t *m = buf;
    nst_seen *n = arg;
    if (write_p || content_type != 22 || len < 4 + 9 || m[0] != 4)
        return;
    n->tickets++;
    size_t off = 4 + 8;
    off += 1 + m[off];
    if (off + 2 > len)
        return;
    off += 2 + (((size_t)m[off] << 8) | m[off + 1]);
    if (off + 2 > len)
        return;
    size_t end = off + 2 + (((size_t)m[off] << 8) | m[off + 1]);
    for (off += 2; off + 4 <= end && end <= len; off += 4 + (((size_t)m[off + 2] << 8) | m[off + 3]))
        if (((m[off] << 8) | m[off + 1]) == 42)
            n->with_early_data++;
}
static void test_negative_sni_override_without_early_data(void) {
    SECTION("negative_quic_sni_override_without_early_data_refuses_0rtt");
    /* the same identity, but an override that accepts no early data (as one with client certificates): the ticket still resumes,
       0-RTT is rejected, and the tickets it issues carry no early_data (RFC 9001 section 4.6.1: "To indicate that the server does
       not accept 0-RTT data, the early_data extension is omitted from the NewSessionTicket") */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *base = sni_server_ctx("server-other-ca", 1, 1),
            *a = sni_server_ctx("server", 1, 0), *n = sni_server_ctx("server", 0, 0);
    sni_choice = a;
    nst_seen under_a = {0, 0}, under_n = {0, 0};
    ksl_ssl *c = qclient(cc), *s = qserver(base, "cfg-1");
    ksl_ssl_msg_observer_for_test(c, count_nst, &under_a);
    track ct = {0}, st = {0};
    pump_early(c, s, &ct, &st);
    ksl_session *sess = ksl_ssl_get1_session(c);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    CHECK(sess != NULL && under_a.tickets > 0 && under_a.with_early_data == under_a.tickets,
          "control: the early-data override's tickets carry early_data");
    sni_choice = n;
    c = qclient(cc);
    s = qserver(base, "cfg-1");
    ksl_ssl_msg_observer_for_test(c, count_nst, &under_n);
    uint8_t one = 1;
    ksl_ssl_set_session(c, sess);
    CHECK(ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_OK, "A's ticket allows 0-RTT");
    ksl_ssl_set(s, KSL_SET_EARLY_DATA, &one, 1);
    track ct2 = {0}, st2 = {0};
    pump_early(c, s, &ct2, &st2);
    CHECK(reused(c) == 1 && early_status(c) == 1 && early_status(s) == 1 &&
              st2.levels[KSL_DIR_READ][KSL_LEVEL_EARLY] == 0,
          "resumed, 0-RTT rejected by the override without early data");
    CHECK(under_n.tickets > 0 && under_n.with_early_data == 0, "its tickets carry no early_data extension");
    ksl_session *next = ksl_ssl_get1_session(c);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    /* RFC 9846 section 4.6.1: max_early_data_size is "the maximum amount of 0-RTT data that the client is allowed to send when
       using this ticket": a ticket without the extension allows none, also one renewed on a resumption of a ticket that did */
    c = qclient(cc);
    ksl_ssl_set_session(c, next);
    CHECK(next != NULL && ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_ERROR,
          "the renewed ticket without early_data allows no 0-RTT (OpenSSL's client kept the old ticket's value)");
    ksl_ssl_free(c);
    ksl_session_free(next);
    sni_choice = NULL;
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(base);
    ksl_ctx_free(a);
    ksl_ctx_free(n);
    END();
}

/* The same without SNI overrides: a server that stopped accepting early data renews a 0-RTT ticket without early_data, and the
   client offers no 0-RTT with the renewed one (RFC 9846 section 4.6.1, RFC 9001 section 4.6.1: "To indicate that the server does
   not accept 0-RTT data, the early_data extension is omitted from the NewSessionTicket") */
static void test_negative_renewed_ticket_without_early_data(void) {
    SECTION("negative_quic_renewed_ticket_without_early_data_refuses_0rtt");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *e = early_server_ctx(1), *n = early_server_ctx(0);
    ksl_session *sess = first_session(cc, e, "cfg-1");
    ksl_ssl *c = qclient(cc), *s = qserver(n, NULL);
    ksl_ssl_set_session(c, sess);
    track ct = {0}, st = {0};
    pump_early(c, s, &ct, &st);
    ksl_session *next = ksl_ssl_get1_session(c);
    CHECK(reused(c) == 1 && next != NULL && next != sess, "resumed on the server without early data, a renewed ticket");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    c = qclient(cc);
    uint8_t one = 1;
    ksl_ssl_set_session(c, next);
    CHECK(ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_ERROR, "no 0-RTT with the renewed ticket");
    CHECK(early_status(c) == 0, "status none");
    ksl_ssl_free(c);
    c = qclient(cc);
    ksl_ssl_set_session(c, sess);
    CHECK(ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_OK, "control: the original ticket still allows it");
    ksl_ssl_free(c);
    ksl_session_free(next);
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(e);
    ksl_ctx_free(n);
    END();
}

/* RFC 9846 section 4.7.1: clients "SHOULD only resume if the SNI value matches the one used in the original session", and early
   data under another name is refused by OpenSSL's client mid-handshake ("inconsistent early data sni"): ksl_ssl_set_session takes
   only a session of the name set with KSL_SET_SNI (DNS names compare case-insensitively; no name only with no name) */
static ksl_ssl *qclient_named(ksl_ctx *c, const char *sni, const char *verify) {
    ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC);
    if (sni)
        set_str(s, KSL_SET_SNI, sni);
    set_str(s, KSL_SET_VERIFY_NAME, verify);
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    return s;
}
static void test_negative_session_of_another_name(void) {
    SECTION("negative_session_of_another_server_name_is_not_offered");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1");
    ksl_ssl *c = qclient_named(cc, "proxy.internal", "server.test");
    CHECK(sess != NULL && ksl_ssl_set_session(c, sess) == KSL_ERROR && last_code(c, NULL) == KSL_E_BAD_ARG,
          "a session of server.test is refused for proxy.internal");
    uint8_t one = 1;
    CHECK(ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_ERROR, "and no 0-RTT without it");
    ksl_ssl_free(c);
    c = qclient_named(cc, NULL, "server.test");
    CHECK(ksl_ssl_set_session(c, sess) == KSL_ERROR, "nor without a name");
    ksl_ssl_free(c);
    /* a client that offers it anyway (OpenSSL directly, without early data): the QUIC server does not resume it (RFC 6066 3) */
    {
        ksl_ssl *raw = qclient_named(cc, "proxy.internal", "server.test"), *srv = qserver(sc, "cfg-1");
        SSL_set_session(ksl_ssl_raw_for_test(raw), (SSL_SESSION *)sess);
        track rt = {0}, rs = {0};
        pump_early(raw, srv, &rt, &rs);
        CHECK(rt.done && rs.done && reused(raw) == 0 && reused(srv) == 0,
              "negative: the QUIC server runs a full handshake for another name's ticket");
        ksl_ssl_free(raw);
        ksl_ssl_free(srv);
    }
    c = qclient_named(cc, "SERVER.Test", "server.test");
    CHECK(ksl_ssl_set_session(c, sess) == KSL_OK,
          "the same name in another case resumes (DNS names are case-insensitive)");
    CHECK(ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_ERROR && last_code(c, NULL) == KSL_E_NOT_SUPPORTED,
          "but offers no 0-RTT: OpenSSL compares the bytes and would fail the handshake");
    ksl_ssl_free(c);
    c = qclient(cc);
    CHECK(ksl_ssl_set_session(c, sess) == KSL_OK && ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1) == KSL_OK,
          "control: the name itself resumes with 0-RTT");
    track ct = {0}, st = {0};
    ksl_ssl *s = qserver(sc, "cfg-1");
    ksl_ssl_set(s, KSL_SET_EARLY_DATA, &one, 1);
    pump_early(c, s, &ct, &st);
    CHECK(ct.done && st.done && reused(c) == 1 && early_status(c) == 2,
          "and the handshake resumes with 0-RTT accepted");
    ksl_ssl_free(s);
    ksl_ssl_free(c);
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}

/* ksl_nst_has_early_data, the NewSessionTicket scan behind the renewed-ticket fix: every read stays inside the message (ASan),
   malformed messages answer 0. Message: type 4, u24 body length, lifetime, age_add, nonce<1>, ticket<2>, extensions<2>. */
int ksl_nst_has_early_data(const uint8_t *m, size_t len);
static size_t nst(uint8_t *out, const uint8_t *exts, size_t exts_len) {
    size_t n = 4;
    memset(out + n, 7, 8); /* lifetime, age_add */
    n += 8;
    out[n++] = 2; /* nonce */
    out[n++] = 0xaa;
    out[n++] = 0xbb;
    out[n++] = 0; /* ticket, 3 bytes */
    out[n++] = 3;
    out[n++] = 1;
    out[n++] = 2;
    out[n++] = 3;
    out[n++] = (uint8_t)(exts_len >> 8);
    out[n++] = (uint8_t)exts_len;
    memcpy(out + n, exts, exts_len);
    n += exts_len;
    out[0] = 4;
    out[1] = (uint8_t)((n - 4) >> 16);
    out[2] = (uint8_t)((n - 4) >> 8);
    out[3] = (uint8_t)(n - 4);
    return n;
}
static void test_nst_parser(void) {
    SECTION("negative_new_session_ticket_scan_bounds");
    static const uint8_t EARLY[] = {0x00, 0x2a, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff};
    static const uint8_t OTHER[] = {0xfa, 0xfa, 0x00, 0x00};
    static const uint8_t TWICE[] = {0x00, 0x2a, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff,
                                    0x00, 0x2a, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff};
    static const uint8_t OVERRUN[] = {0x00, 0x2a, 0x00, 0x09, 0xff, 0xff, 0xff, 0xff}; /* claims 9 bytes, has 4 */
    static const uint8_t HALF_HEADER[] = {0xfa, 0xfa, 0x00, 0x00, 0x00, 0x2a};         /* the second header cut */
    uint8_t *m = malloc(4 + 17 + 65535);
    size_t n = nst(m, EARLY, sizeof EARLY);
    CHECK(ksl_nst_has_early_data(m, n) == 1, "a ticket with early_data");
    int out_of_range = 0;
    for (size_t k = 0; k < n; k++) {
        uint8_t *cut = malloc(k ? k : 1); /* its own allocation: ASan sees any read past k */
        memcpy(cut, m, k);
        out_of_range |= ksl_nst_has_early_data(cut, k) != 0;
        free(cut);
    }
    CHECK(!out_of_range, "every truncation (the header still claiming the whole body) answers 0");
    m[3] = (uint8_t)(m[3] + 1);
    CHECK(ksl_nst_has_early_data(m, n) == 0, "a body length past the message answers 0");
    CHECK(ksl_nst_has_early_data(m, nst(m, NULL, 0)) == 0, "no extensions");
    CHECK(ksl_nst_has_early_data(m, nst(m, OTHER, sizeof OTHER)) == 0, "another extension only");
    CHECK(ksl_nst_has_early_data(m, nst(m, TWICE, sizeof TWICE)) == 1,
          "early_data twice (OpenSSL refuses the message)");
    CHECK(ksl_nst_has_early_data(m, nst(m, OVERRUN, sizeof OVERRUN)) == 0, "an extension past its block answers 0");
    CHECK(ksl_nst_has_early_data(m, nst(m, HALF_HEADER, sizeof HALF_HEADER)) == 0, "a cut extension header answers 0");
    n = nst(m, EARLY, sizeof EARLY);
    m[n - sizeof EARLY - 1] = (uint8_t)(sizeof EARLY + 20); /* the extensions block claims more than the body has */
    CHECK(ksl_nst_has_early_data(m, n) == 0, "an extensions block past the body answers 0");
    uint8_t zero[4] = {4, 0, 0, 0};
    CHECK(ksl_nst_has_early_data(zero, 4) == 0 && ksl_nst_has_early_data(NULL, 0) == 0, "an empty body and no message");
    /* the largest extensions block: an unknown extension filling it, early_data last */
    uint8_t *big = malloc(65533);
    size_t filler = 65533 - sizeof EARLY - 4;
    big[0] = 0xfa;
    big[1] = 0xfa;
    big[2] = (uint8_t)(filler >> 8);
    big[3] = (uint8_t)filler;
    memset(big + 4, 0x5a, filler);
    memcpy(big + 4 + filler, EARLY, sizeof EARLY);
    CHECK(ksl_nst_has_early_data(m, nst(m, big, 65533)) == 1, "early_data after a 64 KiB extension");
    free(big);
    /* random byte flips of a valid message: any answer, but always 0 or 1 and never a read out of bounds */
    uint32_t x = 2463534242u;
    int bad = 0;
    for (int i = 0; i < 20000; i++) {
        n = nst(m, TWICE, sizeof TWICE);
        for (int f = 0; f < 3; f++) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            m[x % n] = (uint8_t)(x >> 8);
        }
        uint8_t *copy = malloc(n);
        memcpy(copy, m, n);
        int r = ksl_nst_has_early_data(copy, n);
        bad |= r != 0 && r != 1;
        free(copy);
    }
    CHECK(!bad, "random flips answer 0 or 1");
    free(m);
    END();
}

/* ---- RFC 9369 sections 4.1 and 5: 0-RTT keys in the original version, tickets bound to their version ---- */
#define V2 0x6b3343cfu
static void be32(uint8_t *o, uint32_t v) {
    o[0] = (uint8_t)(v >> 24);
    o[1] = (uint8_t)(v >> 16);
    o[2] = (uint8_t)(v >> 8);
    o[3] = (uint8_t)v;
}
static void set_version(ksl_ssl *s, uint32_t v) {
    uint8_t b[4];
    be32(b, v);
    ksl_ssl_set(s, KSL_SET_QUIC_VERSION, b, 4);
}
/* max_idle_timeout + version_information(chosen, available...) */
static void tp_versions(ksl_ssl *s, uint32_t chosen, uint32_t a0, uint32_t a1) {
    uint8_t t[18] = {0x01, 0x02, 0x67, 0x10, 0x11, 12};
    be32(t + 6, chosen);
    be32(t + 10, a0);
    be32(t + 14, a1);
    ksl_quic_set_transport_params(s, t, sizeof t);
}
typedef struct {
    ksl_key *early;
    uint32_t client_switch;
    ksl_ssl *client;
} vtrack;
/* like pump_early, keeping the first 0-RTT key seen (write for the client, read for the server) and flipping the client to
   the server's version before the ServerHello is provided (the transport does so from the server's Initial header) */
static void pump_versions(ksl_ssl *c, ksl_ssl *s, track *ct, track *st, vtrack *cv, vtrack *sv) {
    ksl_ssl *who[2] = {c, s}, *peer[2] = {s, c};
    track *t[2] = {ct, st};
    vtrack *v[2] = {cv, sv};
    for (int round = 0; round < 40; round++) {
        int progressed = 0;
        for (int k = 0; k < 2; k++) {
            if (ksl_drive(who[k]) == KSL_ERROR)
                return;
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                progressed = 1;
                if (ev.type == KSL_EV_CRYPTO_SEND) {
                    if (k == 1 && ev.level == KSL_LEVEL_INITIAL && sv->client_switch) {
                        set_version(c, sv->client_switch);
                        sv->client_switch = 0;
                    }
                    ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len);
                } else if (ev.type == KSL_EV_KEY) {
                    t[k]->levels[ev.direction][ev.level]++;
                    if (ev.level == KSL_LEVEL_EARLY && !v[k]->early)
                        v[k]->early = ev.key;
                    else
                        ksl_key_free(ev.key);
                } else if (ev.type == KSL_EV_HANDSHAKE_DONE)
                    t[k]->done = 1;
            }
        }
        if (!progressed && round > 3)
            return;
    }
}
static void test_early_key_in_original_version(void) {
    SECTION("quic_early_key_in_original_version_after_upgrade");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    ksl_session *sess = first_session(cc, sc, "cfg-1"); /* a v1 connection: a v1 ticket */
    ksl_ssl *c = qclient(cc), *s = qserver(sc, "cfg-1");
    uint8_t one = 1;
    tp_versions(c, 1u, 1u, V2);
    tp_versions(s, V2, V2, 1u); /* the client starts in v1 and offers v2; the server prefers v2 */
    ksl_ssl_set_session(c, sess);
    ksl_ssl_set(c, KSL_SET_EARLY_DATA, &one, 1);
    ksl_ssl_set(s, KSL_SET_EARLY_DATA, &one, 1);
    track ct = {0}, st = {0};
    vtrack cv = {0}, sv = {.client_switch = V2};
    pump_versions(c, s, &ct, &st, &cv, &sv);
    uint8_t vb[4];
    size_t n;
    ksl_ssl_get(s, KSL_GET_QUIC_VERSION, vb, 4, &n);
    CHECK(vb[0] == 0x6b && ct.done && st.done && reused(c) == 1 && early_status(s) == 2,
          "resumed with 0-RTT, upgraded to v2");
    CHECK(cv.early && sv.early, "both 0-RTT keys");
    uint8_t hdr[5] = {0xd0, 0, 0, 0, 1}, buf[40] = "0-RTT in the original version";
    int len = cv.early ? ksl_seal(cv.early, 3, hdr, 5, buf, 24, sizeof buf) : -1;
    CHECK(len == 40 && sv.early && ksl_open(sv.early, 3, hdr, 5, buf, (size_t)len) == 24,
          "the server's 0-RTT key opens the client's: both use v1 labels (RFC 9369 4.1)");
    ksl_key_free(cv.early);
    ksl_key_free(sv.early);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
static void test_ticket_bound_to_version(void) {
    SECTION("quic_ticket_bound_to_its_version");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = early_server_ctx(1);
    /* the first connection starts in v1 and is upgraded to v2: its tickets belong to v2 (RFC 9369 section 5) */
    ksl_ssl *c = qclient(cc), *s = qserver(sc, "cfg-1");
    tp_versions(c, 1u, 1u, V2);
    tp_versions(s, V2, V2, 1u);
    track ct = {0}, st = {0};
    vtrack cv = {0}, sv = {.client_switch = V2};
    pump_versions(c, s, &ct, &st, &cv, &sv);
    ksl_session *sess = ct.done && st.done ? ksl_ssl_get1_session(c) : NULL;
    CHECK(sess != NULL, "upgraded connection leaves a session");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    for (int start_v2 = 0; start_v2 < 2; start_v2++) {
        c = qclient(cc);
        s = qserver(sc, "cfg-1");
        if (start_v2) {
            set_version(c, V2);
            set_version(s, V2);
            tp_versions(c, V2, V2, 1u);
        } else
            tp_versions(c, 1u, 1u, V2);
        tp_versions(s, start_v2 ? V2 : 1u, start_v2 ? V2 : 1u, start_v2 ? 1u : V2);
        ksl_ssl_set_session(c, sess);
        track a = {0}, b = {0};
        vtrack x = {0}, y = {0};
        pump_versions(c, s, &a, &b, &x, &y);
        CHECK(a.done && b.done, "handshake completes");
        CHECK(reused(c) == (uint8_t)start_v2, start_v2 ? "a v2 ticket resumes a connection started in v2"
                                                       : "a v2 ticket does not resume a connection started in v1");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
    }
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
void run_early(void) {
    test_server_done_waits_for_finished();
    test_early_accepted();
    test_resumption_renews_ticket();
    test_early_context_mismatch();
    test_negative_early_cipher_mismatch();
    test_negative_early_data_after_hello_retry_request();
    test_negative_early_alpn_mismatch();
    test_early_verdict_refused();
    test_ticket_without_early_data();
    test_early_option_server_only();
    test_early_key_in_original_version();
    test_ticket_bound_to_version();
    test_sni_override_keeps_early_data();
    test_negative_sni_ticket_other_identity();
    test_negative_sni_override_without_early_data();
    test_negative_renewed_ticket_without_early_data();
    test_negative_session_of_another_name();
    test_nst_parser();
}
