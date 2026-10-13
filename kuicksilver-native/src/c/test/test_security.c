/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Findings of the 0.2.0 security review: framing bounds, keylog buffer growth, native session ticket keys. */
#include "test_common.h"
#include "ksl_internal.h"
#include <limits.h>
void ksl_secret_move(void *dst, void *old, size_t used, size_t old_cap);   /* ksl_ctx.c */

/* review finding 10: a 32-bit length field near 2^32 must not wrap the bounds check (32-bit size_t, armeabi-v7a). The same
   arithmetic is checked here with SIZE_MAX-sized values, which wrap on any size_t. */
static void test_span_fits_never_wraps(void) {
    SECTION("negative_frameLengthDoesNotWrap");
    CHECK(ksl_span_fits(4, 12, 16), "a span that fits");
    CHECK(ksl_span_fits(16, 0, 16), "an empty span at the end fits");
    CHECK(!ksl_span_fits(4, 13, 16), "one byte too long");
    CHECK(!ksl_span_fits(8, SIZE_MAX - 3, 16), "negative: off + n wraps to a small value");
    CHECK(!ksl_span_fits(4, SIZE_MAX, 16), "negative: n = SIZE_MAX");
    CHECK(!ksl_span_fits(17, 0, 16), "negative: off past the end");
    /* a framed chain whose length field claims 0xffffffff bytes is refused, not parsed */
    uint8_t framed[8] = {0xff, 0xff, 0xff, 0xff, 0x30, 0x03, 0x02, 0x01};
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT);
    CHECK(ksl_ctx_set_roots(c, framed, sizeof framed) == KSL_ERROR, "negative: a huge frame length is refused");
    ksl_ctx_free(c);
    END();
}

/* review finding 11: the keylog buffer holds TLS secrets; growing it must leave no copy behind in the freed block (realloc did) */
static void test_secret_buffer_growth_wipes_old_block(void) {
    SECTION("negative_keylogGrowthLeavesNoCopy");
    char old[64]; memset(old, 'S', sizeof old);
    char *grown = malloc(128); CHECK(grown != NULL, "allocated");
    ksl_secret_move(grown, old, 40, sizeof old);
    CHECK(!memcmp(grown, "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS", 40), "the used bytes are copied");
    int clean = 1; for (size_t i = 0; i < sizeof old; i++) clean &= old[i] == 0;
    CHECK(clean, "negative: the old block (all of its capacity) is zeroed before it is freed");
    free(grown);
    /* a real handshake: every keylog line survives several growth steps */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
    ksl_ctx_set_option(sc, KSL_OPT_KEYLOG, 1);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", 11); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", 11);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP);
    side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 50, NULL, NULL); CHECK(cs.done && ss.done, "handshake completes");
    char log[4096]; size_t n = 0; CHECK(ksl_ssl_get(s, KSL_GET_KEYLOG, (uint8_t *)log, sizeof log - 1, &n) == KSL_OK, "keylog read"); log[n] = 0;
    int lines = 0; for (size_t i = 0; i < n; i++) lines += log[i] == '\n';
    CHECK(lines >= 4 && strstr(log, "SERVER_TRAFFIC_SECRET_0 ") && strstr(log, "CLIENT_HANDSHAKE_TRAFFIC_SECRET "), "every secret line is kept across growth");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    END();
}

/* --- review finding 1: session ticket keys generated, rotated and kept in ksl --- */
extern int64_t (*ksl_ticket_clock)(void);
static int64_t fake_now;
static int64_t fake_clock(void) { return fake_now; }

static void tpump(ksl_ssl *c, ksl_ssl *s, int *done) {
    ksl_ssl *who[2] = {c, s}, *peer[2] = {s, c}; done[0] = done[1] = 0;
    for (int round = 0; round < 40; round++) {
        int progressed = 0;
        for (int k = 0; k < 2; k++) {
            if (ksl_drive(who[k]) == KSL_ERROR) return;
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                progressed = 1;
                if (ev.type == KSL_EV_CRYPTO_SEND) ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len);
                else if (ev.type == KSL_EV_KEY) ksl_key_free(ev.key);
                else if (ev.type == KSL_EV_HANDSHAKE_DONE) done[k] = 1;
            }
        }
        if (!progressed && round > 3) return;
    }
}
static ksl_ssl *tclient(ksl_ctx *c) {
    ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC);
    ksl_ssl_set(s, KSL_SET_SNI, (const uint8_t *)"server.test", 11); ksl_ssl_set(s, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", 11);
    ksl_quic_set_transport_params(s, TP, sizeof TP); return s;
}
static ksl_ctx *ticket_server(int how, int id_or_rotate) {   /* how: 0 default keys, 1 registered keys */
    ksl_ctx *c = server_ctx("server");
    int rc = how == 0 ? ksl_ctx_use_default_ticket_keys(c, (uint32_t)id_or_rotate) : ksl_ctx_use_ticket_keys(c, id_or_rotate);
    if (rc != KSL_OK) printf("ticket keys rejected\n");
    ksl_ctx_set_option(c, KSL_OPT_NUM_TICKETS, 2); ksl_ctx_freeze(c); return c;
}
/* a full handshake against `first`, then a resumption attempt against `second`; returns 1 when the session was reused */
static int resumes_across(ksl_ctx *first, ksl_ctx *second) {
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL); int done[2], reused = 0;
    ksl_ssl *c = tclient(cc), *s = ksl_ssl_new(first, KSL_MODE_QUIC); ksl_quic_set_transport_params(s, TP, sizeof TP);
    tpump(c, s, done); ksl_session *sess = done[0] && done[1] ? ksl_ssl_get1_session(c) : NULL; ksl_ssl_free(c); ksl_ssl_free(s);
    if (sess) {
        c = tclient(cc); s = ksl_ssl_new(second, KSL_MODE_QUIC); ksl_quic_set_transport_params(s, TP, sizeof TP);
        ksl_ssl_set_session(c, sess); tpump(c, s, done);
        uint8_t b = 0; size_t n; ksl_ssl_get(c, KSL_GET_SESSION_REUSED, &b, 1, &n); reused = done[0] && done[1] && b == 1;
        ksl_ssl_free(c); ksl_ssl_free(s); ksl_session_free(sess);
    } else printf("no session from the first handshake\n");
    ksl_ctx_free(cc); return reused;
}
static int key_eq(const uint8_t *a, const uint8_t *b) { return !memcmp(a, b, 80); }

static void test_default_ticket_keys_rotate_in_ksl(void) {
    SECTION("tickets_default_keys_generated_and_rotated_in_ksl");
    int64_t (*saved)(void) = ksl_ticket_clock; ksl_ticket_clock = fake_clock; fake_now = 1000000;
    ksl_ctx *a = ticket_server(0, 100), *b = ticket_server(0, 100);
    CHECK(a->ticket_key_count >= 1 && b->ticket_key_count == a->ticket_key_count && key_eq(a->ticket_keys, b->ticket_keys), "contexts made together share the current key");
    CHECK(resumes_across(a, b), "a ticket of one context resumes on another with the process keys");
    uint8_t k0[80]; memcpy(k0, a->ticket_keys, 80);
    fake_now += 99; ksl_ctx *same = ticket_server(0, 100);
    CHECK(key_eq(same->ticket_keys, k0), "no rotation before the period ends");
    fake_now += 1; ksl_ctx *r1 = ticket_server(0, 100);
    CHECK(r1->ticket_key_count == 2 && !key_eq(r1->ticket_keys, k0) && key_eq(r1->ticket_keys + 80, k0), "rotation: a new current key, the old one kept as previous");
    CHECK(resumes_across(a, r1), "a ticket under the previous key still resumes after one rotation");
    uint8_t k1[80]; memcpy(k1, r1->ticket_keys, 80);
    fake_now += 100; ksl_ctx *r2 = ticket_server(0, 100);
    CHECK(r2->ticket_key_count == 2 && key_eq(r2->ticket_keys + 80, k1) && !key_eq(r2->ticket_keys, k0) && !key_eq(r2->ticket_keys + 80, k0), "two rotations drop the first key");
    CHECK(!resumes_across(a, r2), "negative: a ticket two rotations old does not resume");
    uint8_t k2[80]; memcpy(k2, r2->ticket_keys, 80);
    fake_now -= 1000; ksl_ctx *back = ticket_server(0, 100);
    CHECK(!key_eq(back->ticket_keys, k2) && key_eq(back->ticket_keys + 80, k2), "a clock step back by more than a period rotates");
    ksl_ctx *bad = server_ctx("server");
    CHECK(ksl_ctx_use_default_ticket_keys(bad, 0) == KSL_ERROR, "negative: a zero period is refused");
    ksl_ctx_freeze(bad); CHECK(ksl_ctx_use_default_ticket_keys(bad, 100) == KSL_ERROR, "negative: a frozen context is refused");
    ksl_ctx *all[] = {a, b, same, r1, r2, back, bad}; for (size_t i = 0; i < sizeof all / sizeof *all; i++) ksl_ctx_free(all[i]);
    ksl_ticket_clock = saved; END();
}
static void test_registered_ticket_keys(void) {
    SECTION("tickets_explicit_keys_registered_once");
    uint8_t k[160]; for (int i = 0; i < 160; i++) k[i] = (uint8_t)(i * 7 + 1);
    int id = ksl_ticket_keys_register(k, 2), again = ksl_ticket_keys_register(k, 2), one = ksl_ticket_keys_register(k, 1);
    CHECK(id > 0 && again == id, "the same keys get the same id");
    CHECK(one > 0 && one != id, "other keys (here: only the first) get another id");
    CHECK(ksl_ticket_keys_register(k, 0) == KSL_ERROR && ksl_ticket_keys_register(NULL, 1) == KSL_ERROR && ksl_ticket_keys_register(k, 65) == KSL_ERROR, "negative: empty, null or more than 64 keys refused");
    ksl_ctx *a = ticket_server(1, id), *b = ticket_server(1, id);
    CHECK(a->ticket_key_count == 2 && !memcmp(a->ticket_keys, k, 160), "the context holds its own copy of the set");
    CHECK(resumes_across(a, b), "two servers with the same explicit keys resume each other's tickets");
    ksl_ctx *c1 = ticket_server(1, one); ksl_ctx *bad = server_ctx("server");
    uint8_t other[80]; for (int i = 0; i < 80; i++) other[i] = (uint8_t)(255 - i);
    ksl_ctx *o = ticket_server(1, ksl_ticket_keys_register(other, 1));
    CHECK(!resumes_across(a, o), "negative: other keys do not resume");
    CHECK(resumes_across(c1, a), "a ticket of the current key resumes where it is the first of two");
    CHECK(ksl_ctx_use_ticket_keys(bad, 0) == KSL_ERROR && ksl_ctx_use_ticket_keys(bad, 999999) == KSL_ERROR, "negative: unknown ids refused");
    ksl_ctx_free(a); ksl_ctx_free(b); ksl_ctx_free(c1); ksl_ctx_free(o); ksl_ctx_free(bad);
    END();
}
#ifndef _WIN32
#include <pthread.h>
static uint8_t seen[8][80];
static void *make_ctx(void *arg) { ksl_ctx *c = ticket_server(0, 7 * 86400); memcpy(seen[(intptr_t)arg], c->ticket_keys, 80); ksl_ctx_free(c); return NULL; }
static void test_default_keys_concurrent_first_use(void) {
    SECTION("tickets_concurrent_contexts_agree_on_one_key");
    int64_t (*saved)(void) = ksl_ticket_clock; ksl_ticket_clock = fake_clock; fake_now += 30 * 86400;   /* the next use rotates */
    pthread_t t[8]; for (intptr_t i = 0; i < 8; i++) pthread_create(&t[i], NULL, make_ctx, (void *)i);
    for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
    int same = 1; for (int i = 1; i < 8; i++) same &= key_eq(seen[0], seen[i]);
    CHECK(same, "servers created at the same moment encrypt with one current key");
    ksl_ticket_clock = saved; END();
}
#else
static void test_default_keys_concurrent_first_use(void) {}
#endif

void run_security(void) {
    test_span_fits_never_wraps(); test_secret_buffer_growth_wipes_old_block();
    test_default_ticket_keys_rotate_in_ksl(); test_registered_ticket_keys(); test_default_keys_concurrent_first_use();
}
