/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Shared harness for the ksl C tests: CHECK, test data loading, context builders and the in-memory QUIC pump. */
#ifndef KSL_TEST_COMMON_H
#define KSL_TEST_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "ksl.h"

#define TESTDATA "kuicksilver-native/src/c/test/testdata/"
extern int failures;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); failures++; } } while (0)
#define SECTION(name) static int _sec_fail; static const char *_sec_name; _sec_fail = failures; _sec_name = name
#define END() printf("%s: %s\n", _sec_name, failures == _sec_fail ? "OK" : "FAIL")

static inline uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb"); if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END); *len = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*len + 1); if (fread(b, 1, *len, f) != *len) exit(2); fclose(f); return b;
}
/* (uint32 BE length || DER)* framing used by ksl_ctx_set_identity / set_roots */
typedef struct { uint8_t *buf; size_t len; } blob;
static inline blob chain_of(int n, ...) {
    blob b = {0}; va_list ap; va_start(ap, n);
    for (int i = 0; i < n; i++) {
        const char *name = va_arg(ap, const char *); char path[256]; snprintf(path, sizeof path, TESTDATA "%s.der", name);
        size_t l; uint8_t *d = read_file(path, &l);
        b.buf = realloc(b.buf, b.len + 4 + l); b.buf[b.len] = (uint8_t)(l >> 24); b.buf[b.len + 1] = (uint8_t)(l >> 16); b.buf[b.len + 2] = (uint8_t)(l >> 8); b.buf[b.len + 3] = (uint8_t)l;
        memcpy(b.buf + b.len + 4, d, l); b.len += 4 + l; free(d);
    }
    va_end(ap); return b;
}
static inline uint8_t *key_of(const char *name, size_t *len) { char p[256]; snprintf(p, sizeof p, TESTDATA "%s.key.der", name); return read_file(p, len); }

static const uint8_t ALPN_H3[] = {2, 'h', '3'};
static const uint8_t TP[] = {0x01, 0x02, 0x67, 0x10};

static inline ksl_ctx *client_ctx(const char *root, int verify_mode) {
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT); ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    if (root) { blob r = chain_of(1, root); ksl_ctx_set_roots(c, r.buf, r.len); free(r.buf); }
    ksl_ctx_set_option(c, KSL_OPT_VERIFY_MODE, verify_mode); return c;
}
static inline ksl_ctx *server_ctx(const char *cert) {
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER); ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    blob ch = chain_of(1, cert); size_t kl; uint8_t *k = key_of(cert, &kl);
    if (ksl_ctx_set_identity(c, ch.buf, ch.len, k, kl) != KSL_OK) { uint32_t e; char m[256]; ksl_ctx_last_error(c, &e, m, sizeof m); printf("identity %s: %s\n", cert, m); }
    free(ch.buf); free(k); return c;
}

typedef struct { int done, keys, crypto_events; uint8_t tp[64]; size_t tp_len; } side;
/* Drives both sessions, moving CRYPTO between them; frees KEY handles. on_verify runs when the client pauses (return 0 to stop). */
static inline int pump(ksl_ssl *c, ksl_ssl *s, side *cs, side *ss, int max, int (*on_want)(ksl_ssl *, int rc, void *), void *arg) {
    int rc = KSL_OK;
    for (int round = 0; round < max; round++) {
        ksl_ssl *who[2] = {c, s}; side *me[2] = {cs, ss}; ksl_ssl *peer[2] = {s, c}; int progressed = 0;
        for (int k = 0; k < 2; k++) {
            int r = ksl_drive(who[k]); if (k == 0) rc = r;
            if ((r == KSL_WANT_VERIFY || r == KSL_WANT_SNI) && on_want && !on_want(who[k], r, arg)) return r;
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                progressed = 1;
                if (ev.type == KSL_EV_CRYPTO_SEND) { me[k]->crypto_events++; ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len); }
                else if (ev.type == KSL_EV_KEY) { me[k]->keys++; ksl_key_free(ev.key); }
                else if (ev.type == KSL_EV_TRANSPORT_PARAMS) { me[k]->tp_len = ev.len < sizeof me[k]->tp ? ev.len : sizeof me[k]->tp; memcpy(me[k]->tp, ev.buf, me[k]->tp_len); }
                else if (ev.type == KSL_EV_HANDSHAKE_DONE) me[k]->done = 1;
            }
            if (r == KSL_ERROR) return KSL_ERROR;
        }
        if (cs->done && ss->done && !progressed) return rc;
        if (!progressed && round > 3) return rc;
    }
    return rc;
}
static inline uint32_t last_code(ksl_ssl *s, int *alert) { uint32_t c; char m[256]; int a; ksl_ssl_last_error(s, &c, &a, m, sizeof m); if (alert) *alert = a & 0x1ff; return c; }   /* alert code (+0x100 if received); verify_err lives in the upper bits */

void run_quic(void); void run_live(void); void run_early(void); void run_key(void); void run_crypto(void); void run_tcp(void); void run_verify(void); void run_udp(void);
/* test hooks of ksl_udp.c (KSL_TEST builds) */
struct ssl_st *ksl_ssl_raw_for_test(ksl_ssl *);
void ksl_trust_paths_for_test(const char *const *files, const char *const *dirs);   /* ksl_ctx.c: NULL restores the distribution paths */
uint32_t ksl_udp_syscalls_for_test(ksl_udp *); void ksl_udp_fail_next_gso_for_test(ksl_udp *, int err); void ksl_udp_fail_next_send_for_test(ksl_udp *, int err); int ksl_udp_df_mode_for_test(int fd); int ksl_udp_close_wakes_for_test(ksl_udp *); void ksl_udp_no_ipv6_for_test(int on);
#endif
