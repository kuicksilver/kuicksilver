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
    if (n > 0) *written = (size_t)n; return n > 0 || BIO_should_retry(s->net) || s->key_updates_exhausted ? KSL_OK : KSL_ERROR;   /* shut at the KeyUpdate bound */
}
static int map_error(ksl_ssl *s, int r) {
    if (ksl_key_update_limit_check(s) != KSL_OK) return KSL_ERROR;
    switch (SSL_get_error(s->ssl, r)) {
    case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: ERR_clear_error(); return KSL_WANT_READ;
    case SSL_ERROR_ZERO_RETURN: ERR_clear_error(); return KSL_EOF;
    case SSL_ERROR_SYSCALL: if (!ERR_peek_error()) return ksl_ssl_fail(s, KSL_E_TRUNCATED, "ksl: peer closed without close_notify"); /* fallthrough */
    default: s->fatal = 1; ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: TLS error"); return KSL_ERROR;
    }
}
/* RFC 8446 section 5.5: for AES-GCM "up to 2^24.5 full-size records (about 24 million) may be encrypted on a given connection while
   keeping a safety margin of approximately 2^-57 ... Implementations SHOULD do a key update before reaching this limit". OpenSSL
   sends a KeyUpdate only on SSL_key_update, so ksl requests one every 2^23 records it wrote under one key (a third of the limit;
   one bound for every suite: ChaCha20-Poly1305's limit is far higher). Records are counted as full ones of the negotiated size
   (16 KiB, or the max_fragment_length), at least one per write: never fewer than were sent. The KeyUpdate goes out ahead of the
   next record. TLS 1.2 has no KeyUpdate (and renegotiation is off): its records are not counted. */
#define KSL_KEY_UPDATE_RECORDS (UINT64_C(1) << 23)
static void count_records(ksl_ssl *s, size_t n) {
    if (SSL_version(s->ssl) < TLS1_3_VERSION) return;
    uint8_t mfl = SSL_SESSION_get_max_fragment_length(SSL_get_session(s->ssl)); size_t frag = mfl >= 1 && mfl <= 4 ? (size_t)256 << mfl : 16384;
    s->records_sent += (n + frag - 1) / frag;
    uint64_t bound = s->key_update_records ? s->key_update_records : KSL_KEY_UPDATE_RECORDS;
    if (s->records_sent < bound) return;
    /* refused while a write is pending or a handshake message is under way (a KeyUpdate the peer asked for): tried after the next write */
    if (ksl_ssl_key_update(s, 0) == KSL_OK) s->records_sent = 0; else ERR_clear_error();
}
int ksl_tcp_write(ksl_ssl *s, const uint8_t *plaintext, size_t len, size_t *consumed) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal || ksl_key_update_limit_check(s) != KSL_OK) return KSL_ERROR; *consumed = 0; if (!s->done) return KSL_WANT_READ;
    ERR_clear_error(); size_t n = 0; int r = SSL_write_ex(s->ssl, plaintext, len, &n);
    if (r == 1) { *consumed = n; if (!s->key_updates_exhausted) count_records(s, n); return KSL_OK; }
    return map_error(s, r);
}
int ksl_tcp_read(ksl_ssl *s, uint8_t *out, size_t cap, size_t *read) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal || ksl_key_update_limit_check(s) != KSL_OK) return KSL_ERROR; *read = 0; if (!s->done) return KSL_WANT_READ;
    ERR_clear_error(); size_t n = 0; int r = SSL_read_ex(s->ssl, out, cap, &n);
    if (r == 1) { *read = n; return KSL_OK; }
    return map_error(s, r);
}
/* RFC 8446 section 6.1: "Each party MUST send a 'close_notify' alert before closing its write side of the connection, unless it has
   already sent some error alert". A session whose application failed must not end with close_notify: the peer would take the cut
   stream for a whole one. OpenSSL 3.5 has no call that sends an alert on an established connection, but it sends one whenever
   building a handshake message fails, and two of those messages run a ksl callback first: a TLS 1.3 server's NewSessionTicket
   (ksl_ctx.c ticket_gen_cb) and a TLS 1.2 client's renegotiation ClientHello (ksl_ctx.c abort_ext_add_cb, before any byte of it is
   written). With abort_alert set both fail with internal_error (80), and OpenSSL writes the alert under the current keys, after
   everything it wrote before. A TLS 1.3 client (it can only start a KeyUpdate, which runs no callback) and a TLS 1.2 server (its
   HelloRequest runs none either) have no such message: they send nothing, and the caller resets the transport. */
int ksl_tcp_abort(ksl_ssl *s) {
    if (!tcp_only(s)) return KSL_ERROR;
    (void)ksl_key_update_limit_check(s);   /* a session past the KeyUpdate bound writes nothing more */
    if (s->fatal || !s->done) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: no alert: the session is not established"); s->fatal = 1; return KSL_ERROR; }
    ERR_clear_error(); int started = 0, client = s->owner->role == KSL_CLIENT;
    s->abort_alert = 1; s->last_alert = 0;
    if (SSL_version(s->ssl) >= TLS1_3_VERSION) started = !client && SSL_new_session_ticket(s->ssl) == 1;
    else if (client) {
        SSL_clear_options(s->ssl, SSL_OP_NO_RENEGOTIATION);   /* SSL_renegotiate refuses otherwise; the ClientHello is never sent */
        started = SSL_renegotiate(s->ssl) == 1;
        SSL_set_options(s->ssl, SSL_OP_NO_RENEGOTIATION);
    }
    if (started) (void)SSL_do_handshake(s->ssl);
    int sent = s->last_alert == SSL_AD_INTERNAL_ERROR;   /* info_cb: a fatal alert we sent */
    ksl_ssl_fail(s, KSL_E_NOT_SUPPORTED, sent ? "ksl: session aborted with internal_error" : "ksl: session aborted; OpenSSL can send no alert for this role and version");
    return sent ? KSL_OK : KSL_ERROR;
}
int ksl_tcp_shutdown(ksl_ssl *s) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal || ksl_key_update_limit_check(s) != KSL_OK) return KSL_ERROR; ERR_clear_error();
    int r = SSL_shutdown(s->ssl);
    if (r == 1) return KSL_OK;                 /* both close_notify alerts exchanged */
    if (r == 0) return KSL_WANT_READ;          /* ours sent, waiting for the peer's */
    return map_error(s, r);
}

#ifdef KSL_TEST
/* Test hook: the number of records after which ksl_tcp_write updates the sending key (KSL_KEY_UPDATE_RECORDS otherwise), counted from now. */
void ksl_tcp_set_key_update_records_for_test(ksl_ssl *s, uint64_t records) { s->key_update_records = records; s->records_sent = 0; }
#endif
