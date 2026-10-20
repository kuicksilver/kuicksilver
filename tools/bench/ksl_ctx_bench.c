/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* What a fresh SSL_CTX per QUIC session / TCP connection costs (security review 2026-10-14, finding 12; threat model 3.2):
 * the contexts KslContext.create builds for a server and for a client (AnchoredCa and TrustConfig.Platform, which loads the
 * system CA bundle), against a full QUIC handshake for scale. Run with tools/bench/ksl-ctx-bench.sh; prints microseconds. */
#include "ksl_internal.h"   /* ksl_load_system_roots: the parse each connection paid before the cache */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TD "kuicksilver-native/src/c/test/testdata/"
static uint8_t *slurp(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb"); if (!f) { perror(p); exit(2); }
    fseek(f, 0, SEEK_END); *n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*n + 4); if (fread(b + 4, 1, *n, f) != *n) exit(2); fclose(f);
    b[0] = (uint8_t)(*n >> 24); b[1] = (uint8_t)(*n >> 16); b[2] = (uint8_t)(*n >> 8); b[3] = (uint8_t)*n; *n += 4; return b;   /* framed */
}
static double now_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e6 + t.tv_nsec / 1e3; }
static const uint8_t ALPN[] = {2, 'h', '3'}, TP[] = {0x01, 0x02, 0x67, 0x10};
static uint8_t *chain, *ca; static size_t chain_len, ca_len; static ksl_pkey *pkey;

static ksl_ctx *server_ctx(void) {   /* KslContext.configure + quicServerTickets for a QUIC server with 0-RTT */
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER); ksl_ctx_set_alpn(c, ALPN, sizeof ALPN); ksl_ctx_set_ciphers(c, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", NULL);
    ksl_ctx_set_identity_pkey(c, chain, chain_len, pkey); ksl_ctx_set_option(c, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_NONE);
    ksl_ctx_use_default_ticket_keys(c, 86400); ksl_ctx_set_option(c, KSL_OPT_TICKET_LIFETIME, 43200);
    uint8_t sid[32] = {1}; ksl_ctx_set_session_context(c, sid, 32); ksl_ctx_set_option(c, KSL_OPT_NUM_TICKETS, 2); ksl_ctx_set_option(c, KSL_OPT_EARLY_DATA, 1);
    ksl_ctx_freeze(c); return c;
}
static ksl_ctx *client_groups(int platform, const char *groups) {
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT);
    if (groups) { c->groups = groups; SSL_CTX_set1_groups_list(c->ctx, groups); }   /* before the freeze, like every other setting */ ksl_ctx_set_alpn(c, ALPN, sizeof ALPN); ksl_ctx_set_ciphers(c, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", NULL);
    if (ksl_ctx_set_roots(c, platform ? NULL : ca, platform ? 0 : ca_len) != KSL_OK) { uint32_t e; char m[512]; ksl_ctx_last_error(c, &e, m, sizeof m); printf("roots: %s\n", m); exit(3); }
    ksl_ctx_set_option(c, KSL_OPT_VERIFY_MODE, KSL_VERIFY_OPENSSL); ksl_ctx_freeze(c); return c;
}
static ksl_ctx *client_ctx(int platform) { return client_groups(platform, NULL); }
static double server_us;   /* time spent in the server's ksl calls (SSL_new, drive, provide, events, free) over all handshakes */
static int handshake(ksl_ctx *cc, ksl_ctx *sc) {
    double t = now_us(); ksl_ssl *s = ksl_ssl_new(sc, KSL_MODE_QUIC); server_us += now_us() - t;
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *who[2] = {c, s}, *peer[2] = {s, c}; int done[2] = {0, 0};
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)"server.test", 11); ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"server.test", 11);
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, TP, sizeof TP);
    for (int r = 0; r < 20 && !(done[0] && done[1]); r++) for (int k = 0; k < 2; k++) {
        double t0 = now_us(); int rc = ksl_drive(who[k]);
        if (rc == KSL_ERROR) { ksl_ssl_free(c); ksl_ssl_free(s); return 0; }
        ksl_event ev; while (ksl_quic_next_event(who[k], &ev)) {
            double t1 = now_us();
            if (ev.type == KSL_EV_CRYPTO_SEND) ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len);   /* provide: the peer's cost */
            else if (ev.type == KSL_EV_KEY) ksl_key_free(ev.key); else if (ev.type == KSL_EV_HANDSHAKE_DONE) done[k] = 1;
            if (k == 0) server_us += now_us() - t1; else t0 += now_us() - t1;
        }
        if (k == 1) server_us += now_us() - t0;
    }
    ksl_ssl_free(c); double t2 = now_us(); ksl_ssl_free(s); server_us += now_us() - t2; return done[0] && done[1];
}
static double per_op(int n, ksl_ctx *(*make)(int), int arg) {
    double t0 = now_us(); for (int i = 0; i < n; i++) ksl_ctx_free(make(arg)); return (now_us() - t0) / n;
}
static ksl_ctx *server_any(int unused) { (void)unused; return server_ctx(); }

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 2000;
    if (ksl_init() != KSL_OK) return 2;
    chain = slurp(TD "server.der", &chain_len); ca = slurp(TD "test-ca.der", &ca_len);
    size_t kl; uint8_t *k = slurp(TD "server.key.der", &kl); pkey = ksl_pkey_new(k + 4, kl - 4); free(k);
    printf("%s, %d iterations\n", ksl_version(), n);
    per_op(n / 10, server_any, 0); per_op(n / 10, client_ctx, 0);   /* warm-up */
    printf("server context (QUIC, 0-RTT, ticket keys): %8.1f us\n", per_op(n, server_any, 0));
    printf("client context, AnchoredCa (1 root):       %8.1f us\n", per_op(n, client_ctx, 0));
    int pn = n / 20 > 0 ? n / 20 : 1;
    printf("client context, Platform (shared store):   %8.1f us\n", per_op(pn, client_ctx, 1));
    double t1 = now_us();
    for (int i = 0; i < pn; i++) { ksl_ctx *c = ksl_ctx_new(KSL_CLIENT); X509_STORE *st = X509_STORE_new(); ksl_load_system_roots(c, st); X509_STORE_free(st); ksl_ctx_free(c); }
    printf("  system bundle parsed per context (before): %6.1f us\n", (now_us() - t1) / pn);
    ksl_ctx *cc = client_ctx(0), *sc = server_ctx(); int hn = n / 10, ok = 1; double t0 = now_us(); server_us = 0;
    for (int i = 0; i < hn; i++) ok &= handshake(cc, sc);
    printf("full QUIC handshake (both sides, P-256):  %8.1f us%s\n", (now_us() - t0) / hn, ok ? "" : " (FAILED)");
    printf("  the server's share (X25519MLKEM768):    %8.1f us\n", server_us / hn);
    /* a client that offers X25519 only (quinn's and msquic's interop clients, and every client without ML-KEM): the server answers with X25519 */
    ksl_ctx *cx = client_groups(0, "X25519"); server_us = 0; t0 = now_us();
    for (int i = 0; i < hn; i++) ok &= handshake(cx, sc);
    printf("full QUIC handshake, X25519 only:         %8.1f us%s\n", (now_us() - t0) / hn, ok ? "" : " (FAILED)");
    printf("  the server's share (X25519):            %8.1f us\n", server_us / hn);
    ksl_ctx_free(cx);
    t0 = now_us();
    for (int i = 0; i < hn; i++) { ksl_ctx *s2 = server_ctx(); ok &= handshake(cc, s2); ksl_ctx_free(s2); }
    printf("  the same with a new server context each: %8.1f us%s\n", (now_us() - t0) / hn, ok ? "" : " (FAILED)");
    ksl_ctx_free(cc); ksl_ctx_free(sc); ksl_pkey_free(pkey); free(chain); free(ca); return ok ? 0 : 1;
}
