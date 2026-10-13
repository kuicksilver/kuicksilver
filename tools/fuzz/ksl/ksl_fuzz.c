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

static ksl_ctx *server_ctx, *server_sni_ctx, *server_early_ctx, *client_ctx;

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

static void init(void) {
    static int done; if (done) return; done = 1;
    if (ksl_init() != KSL_OK) abort();
    server_ctx = new_server(0, 0); server_sni_ctx = new_server(1, 0); server_early_ctx = new_server(0, 1);
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init();
    if (size < 1) return 0;
    const uint8_t *rest = data + 1; size_t n = size - 1;
    switch (data[0] % 6) {
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
    return 0;
}
