/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl_live_objects: every object ksl makes is counted while it lives and only then (the soak harness reads these counters;
 * docs/spec/threat-model.md, resource exhaustion). The counters are process-wide, so each check compares deltas. */
#include "test_common.h"

static int64_t live(int which) { int64_t v[KSL_LIVE_COUNT]; ksl_live_objects(v, KSL_LIVE_COUNT); return v[which]; }
static void set_str(ksl_ssl *s, int what, const char *v) { ksl_ssl_set(s, what, (const uint8_t *)v, strlen(v)); }

static void test_counters_shape(void) {
    SECTION("live_counters_shape");
    CHECK(ksl_live_objects(NULL, 0) == KSL_LIVE_COUNT, "the count of counters without writing any");
    int64_t one[1] = { -7 }; ksl_live_objects(one, 1); CHECK(one[0] == live(KSL_LIVE_CTX), "a short array gets the first counter only");
    int64_t all[KSL_LIVE_COUNT + 1]; all[KSL_LIVE_COUNT] = -7; ksl_live_objects(all, KSL_LIVE_COUNT + 1); CHECK(all[KSL_LIVE_COUNT] == -7, "never more than KSL_LIVE_COUNT written");
    END();
}

/* a full QUIC handshake with a ticket: contexts, sessions, keys from KSL_EV_KEY, a pkey and a session handle all come back to zero */
static void test_handshake_objects_return(void) {
    SECTION("live_counters_handshake_objects_return");
    int64_t ctx0 = live(KSL_LIVE_CTX), ssl0 = live(KSL_LIVE_SSL), key0 = live(KSL_LIVE_KEY), pkey0 = live(KSL_LIVE_PKEY), sess0 = live(KSL_LIVE_SESSION);
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = ksl_ctx_new(KSL_SERVER);
    ksl_ctx_set_alpn(sc, ALPN_H3, sizeof ALPN_H3);
    uint8_t tk[80]; for (int i = 0; i < 80; i++) tk[i] = (uint8_t)(i * 23 + 6); ksl_ctx_set_ticket_keys(sc, tk, 1);   /* no keys, no ticket */
    blob ch = chain_of(1, "server"); size_t kl; uint8_t *kd = key_of("server", &kl);
    ksl_pkey *pk = ksl_pkey_new(kd, kl); free(kd);
    CHECK(live(KSL_LIVE_PKEY) == pkey0 + 1, "a parsed key is one live reference");
    CHECK(ksl_ctx_set_identity_pkey(sc, ch.buf, ch.len, pk) == KSL_OK, "identity from the handle"); free(ch.buf);
    ksl_pkey_free(pk);
    CHECK(live(KSL_LIVE_PKEY) == pkey0, "the context's own reference is not a handle: dropping ours returns the counter");
    CHECK(live(KSL_LIVE_CTX) == ctx0 + 2, "two contexts live");
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    set_str(c, KSL_SET_SNI, "server.test"); set_str(c, KSL_SET_VERIFY_NAME, "server.test");
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP);
    CHECK(live(KSL_LIVE_SSL) == ssl0 + 2, "two sessions live");
    side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK(cs.done && ss.done, "handshake done");
    CHECK(live(KSL_LIVE_KEY) == key0, "every KSL_EV_KEY handle the pump freed is gone");
    ksl_ssl_new_session_ticket(s); pump(c, s, &cs, &ss, 6, NULL, NULL);
    ksl_session *a = ksl_ssl_get1_session(c), *b = ksl_ssl_get1_session(c);
    CHECK(a != NULL && a == b, "a resumable session, the same pointer twice");
    CHECK(live(KSL_LIVE_SESSION) == sess0 + 2, "each get1 is its own reference");
    ksl_session_free(a); ksl_session_free(b); ksl_session_free(NULL);
    CHECK(live(KSL_LIVE_SESSION) == sess0, "references dropped (NULL is not counted)");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ssl_free(NULL);
    ksl_ctx_free(cc); ksl_ctx_free(sc); ksl_ctx_free(NULL);
    CHECK(live(KSL_LIVE_SSL) == ssl0 && live(KSL_LIVE_CTX) == ctx0, "sessions and contexts back to where they were");
    CHECK(ksl_pkey_new((const uint8_t *)"junk", 4) == NULL && live(KSL_LIVE_PKEY) == pkey0, "a refused key is never counted");
    END();
}

static void test_keys(void) {
    SECTION("live_counters_keys");
    int64_t k0 = live(KSL_LIVE_KEY);
    static const uint8_t dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    ksl_key *i = ksl_key_initial(dcid, sizeof dcid, 0, KSL_DIR_WRITE, 1), *n = ksl_key_next(i);
    ksl_key *t = ksl_key_random(KSL_EKEY_TOKEN), *r = ksl_key_random(KSL_EKEY_RESET);
    CHECK(live(KSL_LIVE_KEY) == k0 + 4, "initial, next, token and reset keys counted");
    CHECK(ksl_key_random(99) == NULL && live(KSL_LIVE_KEY) == k0 + 4, "an unknown kind makes nothing");
    ksl_key_free(i); ksl_key_free(n); ksl_key_free(t); ksl_key_free(r); ksl_key_free(NULL);
    CHECK(live(KSL_LIVE_KEY) == k0, "all freed");
    END();
}

static void test_udp(void) {
    SECTION("live_counters_udp_and_wake");
    int64_t u0 = live(KSL_LIVE_UDP), w0 = live(KSL_LIVE_WAKE);
    uint8_t a[KSL_UDP_ADDR_LEN] = { 4 }; a[3] = 127; a[6] = 1; uint32_t err = 0; char msg[128];
    ksl_udp *u = ksl_udp_open(a, 0, &err, msg, sizeof msg);
    if (!u) { CHECK(err == KSL_E_NOT_SUPPORTED, "no accelerated UDP here: nothing counted"); CHECK(live(KSL_LIVE_UDP) == u0, "unchanged"); END(); return; }
    CHECK(live(KSL_LIVE_UDP) == u0 + 1, "an open socket object is live");
#if defined(__APPLE__)
    CHECK(live(KSL_LIVE_WAKE) == w0 + 2, "Darwin: both ends of the wake pipe");
#elif defined(__linux__)
    CHECK(live(KSL_LIVE_WAKE) == w0 + 2 || live(KSL_LIVE_WAKE) == w0, "Linux: both pipe ends, or none when pipe2 failed");
#else
    CHECK(live(KSL_LIVE_WAKE) <= w0 + 1, "Windows: one wake socket at most");
#endif
    ksl_udp_shutdown(u);
    CHECK(live(KSL_LIVE_UDP) == u0 + 1, "shut down, not freed: still live");
    ksl_udp_close(u); ksl_udp_close(NULL);
    CHECK(live(KSL_LIVE_UDP) == u0 && live(KSL_LIVE_WAKE) == w0, "closed: socket and wake descriptors gone");
    uint8_t bad[KSL_UDP_ADDR_LEN] = { 9 };
    CHECK(ksl_udp_open(bad, 0, &err, msg, sizeof msg) == NULL && live(KSL_LIVE_UDP) == u0, "a refused open counts nothing");
    END();
}

void run_live(void) { test_counters_shape(); test_handshake_objects_return(); test_keys(); test_udp(); }
