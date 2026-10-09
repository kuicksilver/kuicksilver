/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* TLS over TCP through memory: ciphertext moves via feed/drain on a BIO pair, plaintext via write/read. */
#include "ksl_internal.h"

static int tcp_only(ksl_ssl *s) { if (s->mode != KSL_MODE_TCP) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: not a TCP session"); return 0; } return 1; }

int ksl_tcp_feed(ksl_ssl *s, const uint8_t *ciphertext, size_t len, size_t *consumed) {
    if (!tcp_only(s)) return KSL_ERROR; *consumed = 0; if (!len) return KSL_OK;
    int n = BIO_write(s->net, ciphertext, (int)(len > INT32_MAX ? INT32_MAX : len));
    if (n > 0) *consumed = (size_t)n; return n > 0 || BIO_should_retry(s->net) ? KSL_OK : KSL_ERROR;
}
int ksl_tcp_drain(ksl_ssl *s, uint8_t *out, size_t cap, size_t *written) {
    if (!tcp_only(s)) return KSL_ERROR; *written = 0; if (!cap) return KSL_OK;
    int n = BIO_read(s->net, out, (int)(cap > INT32_MAX ? INT32_MAX : cap));
    if (n > 0) *written = (size_t)n; return n > 0 || BIO_should_retry(s->net) ? KSL_OK : KSL_ERROR;
}
static int map_error(ksl_ssl *s, int r) {
    switch (SSL_get_error(s->ssl, r)) {
    case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: ERR_clear_error(); return KSL_WANT_READ;
    case SSL_ERROR_ZERO_RETURN: ERR_clear_error(); return KSL_EOF;
    case SSL_ERROR_SYSCALL: if (!ERR_peek_error()) return ksl_ssl_fail(s, KSL_E_TRUNCATED, "ksl: peer closed without close_notify"); /* fallthrough */
    default: s->fatal = 1; ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: TLS error"); return KSL_ERROR;
    }
}
int ksl_tcp_write(ksl_ssl *s, const uint8_t *plaintext, size_t len, size_t *consumed) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal) return KSL_ERROR; *consumed = 0; if (!s->done) return KSL_WANT_READ;
    ERR_clear_error(); size_t n = 0; int r = SSL_write_ex(s->ssl, plaintext, len, &n);
    if (r == 1) { *consumed = n; return KSL_OK; }
    return map_error(s, r);
}
int ksl_tcp_read(ksl_ssl *s, uint8_t *out, size_t cap, size_t *read) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal) return KSL_ERROR; *read = 0; if (!s->done) return KSL_WANT_READ;
    ERR_clear_error(); size_t n = 0; int r = SSL_read_ex(s->ssl, out, cap, &n);
    if (r == 1) { *read = n; return KSL_OK; }
    return map_error(s, r);
}
int ksl_tcp_shutdown(ksl_ssl *s) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal) return KSL_ERROR; ERR_clear_error();
    int r = SSL_shutdown(s->ssl);
    if (r == 1) return KSL_OK;                 /* both close_notify alerts exchanged */
    if (r == 0) return KSL_WANT_READ;          /* ours sent, waiting for the peer's */
    return map_error(s, r);
}
