/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* libFuzzer harness for the parsing code of ksl (kuicksilver-native/src/c), built with ASan/UBSan by tools/fuzz/ksl/build.sh.
   The first byte selects what the rest is:
     0  the client's QUIC transport parameters: a ClientHello carrying them reaches a server session, whose
        transport-parameter callback scans them for version_information and negotiates the version (RFC 9368)
     1  a framed certificate list ((u32 length || DER)*) for ksl_ctx_set_roots (ksl_parse_chain)
     2  a private key for ksl_pkey_new
     3  a ClientHello (CRYPTO at the Initial level) to a server session that pauses at it and reads its SNI, ALPN and
        signature algorithms (ksl_ssl_client_hello), then resumes
     4  a ClientHello to a server session with 0-RTT on and fixed ticket keys (the ticket and early-data callbacks)
     5  the server's Initial CRYPTO (ServerHello) to a client that sent its ClientHello
     6  a program over the ticket-key API of ksl_tickets.c (register explicit key sets, use them by id, the generated
        keys under a moving clock and a rotation period from the input) on a fresh server context
     7  `[ctx][ClientHello]`: a resumption ClientHello (pre_shared_key with a ticket, early_data) to a server whose ticket
        keys came from ksl_ctx_set_ticket_keys (0), a registered set (1) or the generated keys (2): ticket decryption and
        the 0-RTT verdict on a fuzzed ticket
   Every session is driven until it wants more input; every event is drained and every key freed. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ksl.h"

#ifndef KSL_FUZZ_TESTDATA
#define KSL_FUZZ_TESTDATA "kuicksilver-native/src/c/test/testdata/"
#endif

static uint8_t *read_all(const char *name, size_t *len) {
    char path[1024]; snprintf(path, sizeof path, "%s%s", KSL_FUZZ_TESTDATA, name);
    FILE *f = fopen(path, "rb"); if (!f) { perror(path); abort(); }
    fseek(f, 0, SEEK_END); *len = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*len ? *len : 1); if (fread(b, 1, *len, f) != *len) abort(); fclose(f); return b;
}
static uint8_t *framed(const uint8_t *der, size_t len, size_t *out_len) {
    uint8_t *b = malloc(len + 4); b[0] = (uint8_t)(len >> 24); b[1] = (uint8_t)(len >> 16); b[2] = (uint8_t)(len >> 8); b[3] = (uint8_t)len;
    memcpy(b + 4, der, len); *out_len = len + 4; return b;
}

static const uint8_t ALPN_H3[] = {2, 'h', '3'};
/* server transport parameters with version_information (0x11): Chosen v1, Available v2, v1 */
static const uint8_t SERVER_TP[] = {0x01, 0x02, 0x67, 0x10, 0x11, 0x0c, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1};
static const uint8_t CLIENT_TP[] = {0x01, 0x02, 0x67, 0x10, 0x11, 0x08, 0, 0, 0, 1, 0, 0, 0, 1};
static uint8_t TICKET_KEYS[80];

static ksl_ctx *server_ctx, *server_sni_ctx, *server_early_ctx, *client_ctx, *server_registered_ctx, *server_default_ctx;

extern int64_t (*ksl_ticket_clock)(void);
static int64_t fake_now = 1000000;
static int64_t fake_clock(void) { return fake_now; }

static ksl_ctx *new_server(int sni_pause, int early) {
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER); ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    size_t cl, kl, fl; uint8_t *cert = read_all("server.der", &cl), *key = read_all("server.key.der", &kl), *chain = framed(cert, cl, &fl);
    if (ksl_ctx_set_identity(c, chain, fl, key, kl) != KSL_OK) abort();
    free(cert); free(key); free(chain);
    if (sni_pause) ksl_ctx_set_option(c, KSL_OPT_SNI_PAUSE, 1);
    if (early) {
        for (int i = 0; i < 80; i++) TICKET_KEYS[i] = (uint8_t)(i * 7 + 1);
        ksl_ctx_set_ticket_keys(c, TICKET_KEYS, 1);
        ksl_ctx_set_option(c, KSL_OPT_EARLY_DATA, 1);
    }
    return c;
}

static int debug;   /* KSL_FUZZ_DEBUG: report what a served hello did (checking that seeds reach their path) */

static void init(void) {
    static int done; if (done) return; done = 1;
    debug = getenv("KSL_FUZZ_DEBUG") != NULL;
    if (ksl_init() != KSL_OK) abort();
    ksl_ticket_clock = fake_clock;
    server_ctx = new_server(0, 0); server_sni_ctx = new_server(1, 0); server_early_ctx = new_server(0, 1);
    /* the same fixed keys registered (mode 7, ctx 1), and the generated keys at a fixed clock (ctx 2) */
    server_registered_ctx = new_server(0, 1); server_default_ctx = new_server(0, 1);
    int id = ksl_ticket_keys_register(TICKET_KEYS, 1);
    if (id < 1 || ksl_ctx_use_ticket_keys(server_registered_ctx, id) != KSL_OK) abort();
    if (ksl_ctx_use_default_ticket_keys(server_default_ctx, 3600) != KSL_OK) abort();
    client_ctx = ksl_ctx_new(KSL_CLIENT); ksl_ctx_set_alpn(client_ctx, ALPN_H3, sizeof ALPN_H3);
    ksl_ctx_set_option(client_ctx, KSL_OPT_VERIFY_MODE, KSL_VERIFY_NONE);
}

/* Drains every event; returns the CRYPTO bytes of [level] (malloc'ed, *len) when out is non-NULL. */
static void drain(ksl_ssl *s, int level, uint8_t **out, size_t *len) {
    ksl_event ev;
    while (ksl_quic_next_event(s, &ev)) {
        if (ev.type == KSL_EV_KEY) ksl_key_free(ev.key);
        else if (ev.type == KSL_EV_CRYPTO_SEND && out && ev.level == level) {
            *out = realloc(*out, *len + ev.len + 1); memcpy(*out + *len, ev.buf, ev.len); *len += ev.len;
        } else if (ev.buf) {
            volatile uint8_t sum = 0; for (size_t i = 0; i < ev.len; i++) sum ^= ev.buf[i];   /* ASan checks the reported range */
        }
    }
}

static void touch(const uint8_t *p, size_t n) { volatile uint8_t sum = 0; for (size_t i = 0; p && i < n; i++) sum ^= p[i]; }

static void serve(ksl_ctx *ctx, const uint8_t *hello, size_t len, int early) {
    ksl_ssl *s = ksl_ssl_new(ctx, KSL_MODE_QUIC); if (!s) return;
    ksl_quic_set_transport_params(s, SERVER_TP, sizeof SERVER_TP);
    if (early) { uint8_t one = 1; ksl_ssl_set(s, KSL_SET_EARLY_CONTEXT, &one, 1); ksl_ssl_set(s, KSL_SET_EARLY_DATA, &one, 1); }
    ksl_quic_provide(s, KSL_LEVEL_INITIAL, hello, len);
    for (int round = 0; round < 4; round++) {
        int rc = ksl_drive(s);
        drain(s, -1, NULL, NULL);
        if (rc == KSL_WANT_SNI) {
            ksl_client_hello ch;
            if (ksl_ssl_client_hello(s, &ch) == KSL_OK) { touch(ch.sni, ch.sni_len); touch(ch.alpn, ch.alpn_len); touch(ch.sig_algs, ch.sig_algs_len); }
            ksl_ssl_sni_resume(s, NULL, 0);
            continue;
        }
        if (rc != KSL_OK) break;
    }
    uint8_t buf[64]; size_t l; ksl_ssl_get(s, KSL_GET_ALPN, buf, sizeof buf, &l);
    if (debug) {
        uint8_t reused = 0, early = 0; size_t rl;
        ksl_ssl_get(s, KSL_GET_SESSION_REUSED, &reused, 1, &rl); ksl_ssl_get(s, KSL_GET_EARLY_DATA, &early, 1, &rl);
        fprintf(stderr, "served: reused %d early %d\n", reused, early);
    }
    ksl_ssl_free(s);
}

/* A client's ClientHello with transport parameters [tp]; the session is returned for mode 5 (else freed). */
static uint8_t *client_hello(const uint8_t *tp, size_t tp_len, size_t *len, ksl_ssl **keep) {
    ksl_ssl *c = ksl_ssl_new(client_ctx, KSL_MODE_QUIC); if (!c) return NULL;
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", 11);
    if (ksl_quic_set_transport_params(c, tp, tp_len) != KSL_OK) { ksl_ssl_free(c); return NULL; }
    ksl_drive(c);
    uint8_t *hello = NULL; *len = 0; drain(c, KSL_LEVEL_INITIAL, &hello, len);
    if (keep) *keep = c; else ksl_ssl_free(c);
    return hello;
}

/* Seeds only: a full handshake of a client with [sctx], then a resumption ClientHello (with 0-RTT) on the session it got. */
static uint8_t *resumption_hello(ksl_ctx *sctx, size_t *len) {
    ksl_ssl *c = ksl_ssl_new(client_ctx, KSL_MODE_QUIC), *s = ksl_ssl_new(sctx, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", 11);
    ksl_quic_set_transport_params(c, CLIENT_TP, sizeof CLIENT_TP); ksl_quic_set_transport_params(s, SERVER_TP, sizeof SERVER_TP);
    uint8_t one = 1; ksl_ssl_set(s, KSL_SET_EARLY_CONTEXT, &one, 1); ksl_ssl_set(s, KSL_SET_EARLY_DATA, &one, 1);
    int done[2] = {0, 0};
    for (int round = 0; round < 40; round++) {
        ksl_ssl *who[2] = {c, s}, *peer[2] = {s, c};
        if (round == 20) ksl_ssl_new_session_ticket(s);
        for (int k = 0; k < 2; k++) {
            int rc = ksl_drive(who[k]);
            if (rc == KSL_ERROR && getenv("KSL_FUZZ_DEBUG")) { uint32_t code; int al; char m[256]; ksl_ssl_last_error(who[k], &code, &al, m, sizeof m); fprintf(stderr, "side %d: %s\n", k, m); }
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                if (ev.type == KSL_EV_CRYPTO_SEND) ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len);
                else if (ev.type == KSL_EV_KEY) ksl_key_free(ev.key);
                else if (ev.type == KSL_EV_HANDSHAKE_DONE) done[k] = 1;
            }
        }
    }
    if (getenv("KSL_FUZZ_DEBUG")) fprintf(stderr, "handshake done: client %d server %d\n", done[0], done[1]);
    ksl_session *sess = ksl_ssl_get1_session(c);
    ksl_ssl_free(c); ksl_ssl_free(s);
    if (!sess) return NULL;
    ksl_ssl *r = ksl_ssl_new(client_ctx, KSL_MODE_QUIC);
    ksl_ssl_set(r, KSL_SET_SNI, (const uint8_t *)"server.test", 11);
    ksl_quic_set_transport_params(r, CLIENT_TP, sizeof CLIENT_TP);
    ksl_ssl_set_session(r, sess); ksl_ssl_set(r, KSL_SET_EARLY_DATA, &one, 1);
    ksl_drive(r);
    uint8_t *hello = NULL; *len = 0; drain(r, KSL_LEVEL_INITIAL, &hello, len);
    ksl_ssl_free(r); ksl_session_free(sess);
    return hello;
}

/* Mode 6: `[op][args]*` over the ticket-key API. op % 4: 0 register `[n 1..3][n x 80 bytes]` (a set may already exist:
   the same id comes back; at most 1024 sets per process); 1 use the set `[id i8]` (unknown ids are refused); 2 the
   generated keys with period `[p u8]` (0 refused) after the clock moved by `[d i8]` x 37 s; 3 freeze the context
   (later calls are refused). The context is freed at the end (its copies are cleansed). */
static void ticket_program(const uint8_t *p, size_t n) {
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER); if (!c) return;
    size_t i = 0;
    for (int ops = 0; ops < 64 && i < n; ops++) {
        uint8_t op = p[i++];
        switch (op % 4) {
        case 0: {
            if (i >= n) break;
            size_t k = 1 + p[i++] % 3;
            if (n - i < k * 80) { i = n; break; }
            int id = ksl_ticket_keys_register(p + i, k); i += k * 80;
            if (id >= 1) ksl_ctx_use_ticket_keys(c, id);
            break;
        }
        case 1: if (i < n) ksl_ctx_use_ticket_keys(c, (int8_t)p[i++]); break;
        case 2: {
            if (n - i < 2) { i = n; break; }
            fake_now += (int64_t)(int8_t)p[i + 1] * 37;
            ksl_ctx_use_default_ticket_keys(c, p[i]); i += 2;
            break;
        }
        default: ksl_ctx_freeze(c); break;
        }
    }
    ksl_ctx_free(c);
    fake_now = 1000000;   /* the generated keys of mode 7 stay valid: every input starts at the same clock */
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init();
    if (size < 1) return 0;
    const uint8_t *rest = data + 1; size_t n = size - 1;
    switch (data[0] % 8) {
    case 0: {
        size_t hl; uint8_t *hello = client_hello(rest, n, &hl, NULL);
        if (hello) serve(server_ctx, hello, hl, 0);
        free(hello);
        break;
    }
    case 1: {
        ksl_ctx *c = ksl_ctx_new(KSL_CLIENT); ksl_ctx_set_roots(c, rest, n); ksl_ctx_free(c);
        break;
    }
    case 2: {
        ksl_pkey *k = ksl_pkey_new(rest, n); if (k) ksl_pkey_free(k);
        break;
    }
    case 3: serve(server_sni_ctx, rest, n, 0); break;
    case 4: serve(server_early_ctx, rest, n, 1); break;
    case 6: ticket_program(rest, n); break;
    case 7: {
        if (n < 1) break;
        ksl_ctx *ctx[3] = {server_early_ctx, server_registered_ctx, server_default_ctx};
        serve(ctx[rest[0] % 3], rest + 1, n - 1, 1);
        break;
    }
    default: {
        ksl_ssl *c = NULL; size_t hl; uint8_t *hello = client_hello(CLIENT_TP, sizeof CLIENT_TP, &hl, &c); free(hello);
        if (!c) break;
        ksl_quic_provide(c, KSL_LEVEL_INITIAL, rest, n);
        for (int round = 0; round < 3; round++) { int rc = ksl_drive(c); drain(c, -1, NULL, NULL); if (rc != KSL_OK) break; }
        ksl_ssl_free(c);
        break;
    }
    }
    return 0;
}

/* Seeds (tools/fuzz/ksl/build.sh --seeds <dir>): one input per mode from a real handshake and the test data. */
int ksl_fuzz_write_seeds(const char *dir) {
    init();
    char path[1024]; size_t l, hl;
#define PUT(name, mode, bytes, len) do { snprintf(path, sizeof path, "%s/seed-%s", dir, name); FILE *f = fopen(path, "wb"); if (!f) return 1; \
        uint8_t m = (uint8_t)(mode); fwrite(&m, 1, 1, f); fwrite(bytes, 1, len, f); fclose(f); } while (0)
    PUT("client-tp", 0, CLIENT_TP, sizeof CLIENT_TP);
    PUT("server-tp-as-client-tp", 0, SERVER_TP, sizeof SERVER_TP);
    uint8_t *cert = read_all("server.der", &l), *chain = framed(cert, l, &hl); PUT("roots", 1, chain, hl); free(cert); free(chain);
    uint8_t *key = read_all("server.key.der", &l); PUT("key", 2, key, l); free(key);
    ksl_ssl *c = NULL; uint8_t *hello = client_hello(CLIENT_TP, sizeof CLIENT_TP, &hl, &c);
    PUT("client-hello-sni", 3, hello, hl); PUT("client-hello-early", 4, hello, hl);
    /* the server's answer at the Initial level, for mode 5 */
    ksl_ssl *s = ksl_ssl_new(server_ctx, KSL_MODE_QUIC); ksl_quic_set_transport_params(s, SERVER_TP, sizeof SERVER_TP);
    ksl_quic_provide(s, KSL_LEVEL_INITIAL, hello, hl); ksl_drive(s);
    uint8_t *sh = NULL; size_t shl = 0; drain(s, KSL_LEVEL_INITIAL, &sh, &shl); PUT("server-hello", 5, sh, shl);
    free(sh); free(hello); ksl_ssl_free(s); ksl_ssl_free(c);
    /* mode 7: a full handshake against the 0-RTT server (fixed ticket keys), then the client's resumption ClientHello */
    for (int which = 0; which < 3; which++) {
        ksl_ctx *ctx[3] = {server_early_ctx, server_registered_ctx, server_default_ctx};
        uint8_t *rh = resumption_hello(ctx[which], &hl); if (!rh) { fprintf(stderr, "no resumption hello for ctx %d\n", which); return 1; }
        uint8_t *framed7 = malloc(hl + 1); framed7[0] = (uint8_t)which; memcpy(framed7 + 1, rh, hl);
        char name[32]; snprintf(name, sizeof name, "resumption-hello-%d", which); PUT(name, 7, framed7, hl + 1);
        free(framed7); free(rh);
    }
    /* mode 6: register a set, use it, rotate the generated keys twice, use an unknown id, freeze */
    uint8_t prog[128]; size_t pl = 0;
    prog[pl++] = 0; prog[pl++] = 0; for (int i = 0; i < 80; i++) prog[pl++] = (uint8_t)(i * 3 + 5);
    prog[pl++] = 1; prog[pl++] = 1;
    prog[pl++] = 2; prog[pl++] = 100; prog[pl++] = 2; prog[pl++] = 100; prog[pl++] = 2; prog[pl++] = 3; prog[pl++] = 3;
    prog[pl++] = 1; prog[pl++] = 0x7f;
    prog[pl++] = 3;
    PUT("ticket-keys-program", 6, prog, pl);
    return 0;
}
