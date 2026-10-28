/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* TLS over TCP through memory: ciphertext moves via feed/drain on a BIO pair, plaintext via write/read. */
#include "ksl_internal.h"

static int tcp_only(ksl_ssl *s) { if (s->mode != KSL_MODE_TCP) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: not a TCP session"); return 0; } return 1; }

int ksl_tcp_feed(ksl_ssl *s, const uint8_t *ciphertext, size_t len, size_t *consumed) {
    if (!tcp_only(s)) return KSL_ERROR; *consumed = 0; if (!len) return KSL_OK;
    int n = BIO_write(s->net, ciphertext, (int)(len > INT32_MAX ? INT32_MAX : len));
    if (n > 0) { *consumed = (size_t)n; s->fed += (uint64_t)n; } return n > 0 || BIO_should_retry(s->net) ? KSL_OK : KSL_ERROR;
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
/* RFC 9846 section 5.5: "For AES-GCM, up to 2^24.5 full-size records (about 24 million) may be encrypted under a given set of keys
   ... For ChaCha20/Poly1305, the record sequence number would wrap before the safety limit is reached", and "Implementations MUST
   either close the connection or do a key update as described in Section 4.7.3 prior to reaching these limits". RFC 9846 gives no
   figure for AES-CCM; RFC 9147 appendix B.1 derives it for the same margin as TLS 1.3's: "q <= 2^23" records (the confidentiality
   bound; CCM_8 alike, appendix B.3), for records of 2^14 bytes. OpenSSL sends a KeyUpdate only on SSL_key_update, so ksl requests
   one well before the negotiated AEAD's limit: every 2^23 records for AES-GCM, 2^22 for AES-CCM (and any other AEAD), none for
   ChaCha20-Poly1305. Records are counted as full ones of the negotiated size (16 KiB, or the max_fragment_length), at least one per
   write: never fewer than were sent. The KeyUpdate goes out ahead of the next record. A session whose KeyUpdates do not go out ends
   before its keys reach the limit (ksl_tcp_write).
   TLS 1.2 has no KeyUpdate. RFC 9325 section 4.4: "When a sender is approaching CL, the implementation SHOULD initiate a new
   handshake", and for AES-GCM "it is RECOMMENDED that the same limit of 2^24.5 records is used for both versions". ksl allows no
   renegotiation (a new handshake on the connection), so a TLS 1.2 connection ends before its keys reach the same limit of its
   AEAD (the CCM figure is the AEAD's, not the version's), with internal_error where an alert can be sent (a TLS 1.2 client):
   close_notify would end the application's stream as if it were complete. */
#define KSL_GCM_RECORD_LIMIT UINT64_C(23726566)   /* 2^24.5, rounded down */
#define KSL_CCM_RECORD_LIMIT (UINT64_C(1) << 23)
#define KSL_NO_RECORD_LIMIT UINT64_MAX
static uint64_t aead_record_limit(ksl_ssl *s) {
    const SSL_CIPHER *c = SSL_get_current_cipher(s->ssl); int nid = c ? SSL_CIPHER_get_cipher_nid(c) : NID_undef;
    if (nid == NID_chacha20_poly1305) return KSL_NO_RECORD_LIMIT;
    if (nid == NID_aes_128_gcm || nid == NID_aes_256_gcm) return KSL_GCM_RECORD_LIMIT;
    return KSL_CCM_RECORD_LIMIT;   /* AES-CCM and CCM_8; the lowest figure for anything else */
}
static uint64_t record_limit(ksl_ssl *s) {
    if (!s->record_limit) s->record_limit = aead_record_limit(s);
    return s->record_limit;
}
/* The record count at which the sending key is updated: half of AES-CCM's limit and a third of AES-GCM's */
static uint64_t key_update_records(ksl_ssl *s) {
    if (SSL_version(s->ssl) < TLS1_3_VERSION) return KSL_NO_RECORD_LIMIT;
    if (s->key_update_records) return s->key_update_records;
    uint64_t limit = record_limit(s);
    return limit == KSL_NO_RECORD_LIMIT ? KSL_NO_RECORD_LIMIT : limit == KSL_GCM_RECORD_LIMIT ? UINT64_C(1) << 23 : UINT64_C(1) << 22;
}
/* The plaintext size of a full record: 16 KiB, or the negotiated max_fragment_length (RFC 6066 section 4) */
static size_t record_size(ksl_ssl *s) { uint8_t mfl = SSL_SESSION_get_max_fragment_length(SSL_get_session(s->ssl)); return mfl >= 1 && mfl <= 4 ? (size_t)256 << mfl : 16384; }
static void count_records(ksl_ssl *s, size_t n) {
    size_t frag = record_size(s);
    s->records_sent += (n + frag - 1) / frag;
    if (s->records_sent < key_update_records(s) || s->key_updates_exhausted) return;   /* past the epoch bound: the record limit ends the session */
    /* refused while a write is pending or a handshake message is under way (a KeyUpdate the peer asked for): tried after the next
       write. Called directly: the write succeeded, and the session's last error stays the last failure's */
    if (SSL_key_update(s->ssl, SSL_KEY_UPDATE_NOT_REQUESTED) == 1) s->records_sent = 0; else ERR_clear_error();
}
static int abort_session(ksl_ssl *s, const char *why);
static void drop_pending_write(ksl_ssl *s) {
    if (!s->pending_write) return;
    OPENSSL_cleanse(s->pending_write, s->pending_write_len); free(s->pending_write); s->pending_write = NULL; s->pending_write_len = 0;
}
/* One record per call: a write the transport has no room for leaves exactly that record pending inside OpenSSL, whose bytes ksl
   keeps (pending_write), so that ksl_tcp_abort can complete it ahead of its alert. The caller retries a KSL_WANT_READ with the same
   bytes, from any buffer (SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER). */
int ksl_tcp_write(ksl_ssl *s, const uint8_t *plaintext, size_t len, size_t *consumed) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal) return KSL_ERROR; *consumed = 0; if (!s->done) return KSL_WANT_READ;
    size_t frag = record_size(s); if (len > frag) len = frag;
    /* one more record would reach the keys' limit: the session ends, with internal_error where an alert can be sent */
    if (len && !s->pending_write && record_limit(s) != KSL_NO_RECORD_LIMIT && s->records_sent + 1 >= record_limit(s))
        { (void)abort_session(s, "ksl: the sending keys reached their record limit (RFC 9846 section 5.5)"); return KSL_ERROR; }
    ERR_clear_error(); size_t n = 0; int r = SSL_write_ex(s->ssl, plaintext, len, &n);
    if (r == 1) { drop_pending_write(s); *consumed = n; count_records(s, n); return KSL_OK; }
    if (SSL_get_error(s->ssl, r) == SSL_ERROR_WANT_WRITE && !s->pending_write && len) {
        s->pending_write = malloc(len); if (s->pending_write) { memcpy(s->pending_write, plaintext, len); s->pending_write_len = len; }
    }
    return map_error(s, r);
}
int ksl_tcp_read(ksl_ssl *s, uint8_t *out, size_t cap, size_t *read) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal) return KSL_ERROR; *read = 0; if (!s->done) return KSL_WANT_READ;
    ERR_clear_error(); size_t n = 0; int r = SSL_read_ex(s->ssl, out, cap, &n);
    if (r == 1) { *read = n; return KSL_OK; }
    return map_error(s, r);
}
/* RFC 9846 section 6.1: "Each party MUST send a 'close_notify' alert before closing its write side of the connection, unless it has
   already sent some error alert". A session whose application failed must not end with close_notify: the peer would take the cut
   stream for a whole one. OpenSSL 3.5 has no call that sends an alert on an established connection, but it sends one whenever
   building a handshake message fails, and two of those messages run a ksl callback first: a TLS 1.3 server's NewSessionTicket
   (ksl_ctx.c ticket_gen_cb) and a TLS 1.2 client's renegotiation ClientHello (ksl_ctx.c abort_ext_add_cb, before any byte of it is
   written). With abort_alert set both fail with internal_error (80), and OpenSSL writes the alert under the current keys, after
   everything it wrote before. A TLS 1.3 client (it can only start a KeyUpdate, which runs no callback) and a TLS 1.2 server (its
   HelloRequest runs none either) have no such message: they send nothing, and the caller resets the transport.
   What is under way goes out first, as OpenSSL would send it before anything after it: a record ksl_tcp_write left pending (OpenSSL
   drops an alert behind a pending write, ssl3_dispatch_alert), then a handshake message in progress (a KeyUpdate ksl_ssl_key_update
   or the record bound queued, or the answer to the peer's update_requested), during which SSL_new_session_ticket starts nothing.
   Either needs room in the BIO pair: the caller drained it before (ksl_tcp_drain), else no alert can follow. */
static int abort_session(ksl_ssl *s, const char *why) {
    /* a session that failed already (its record limit included) keeps the error that ended it */
    if (s->fatal) return KSL_ERROR;
    if (!s->done) { ksl_ssl_fail(s, KSL_E_NOT_SUPPORTED, "ksl: no alert: the session is not established"); return KSL_ERROR; }
    ERR_clear_error(); int started = 0, client = s->owner->role == KSL_CLIENT; const char *stuck = NULL;
    s->abort_alert = 1; s->last_alert = 0;
    if (s->pending_write) {
        size_t n = 0;
        if (SSL_write_ex(s->ssl, s->pending_write, s->pending_write_len, &n) == 1) drop_pending_write(s);
        else stuck = "ksl: session aborted without an alert: a record write is pending and the transport takes no more";
    }
    if (!stuck && SSL_in_init(s->ssl) && SSL_do_handshake(s->ssl) != 1 && s->last_alert != SSL_AD_INTERNAL_ERROR)
        stuck = "ksl: session aborted without an alert: a handshake message is pending and the transport takes no more";
    if (!stuck && s->last_alert != SSL_AD_INTERNAL_ERROR) {   /* a queued ticket fails as soon as it is built (ticket_gen_cb) */
        if (SSL_version(s->ssl) >= TLS1_3_VERSION) started = !client && SSL_new_session_ticket(s->ssl) == 1;
        else if (client) {
            SSL_clear_options(s->ssl, SSL_OP_NO_RENEGOTIATION);   /* SSL_renegotiate refuses otherwise; the ClientHello is never sent */
            started = SSL_renegotiate(s->ssl) == 1;
            SSL_set_options(s->ssl, SSL_OP_NO_RENEGOTIATION);
        }
        if (started) (void)SSL_do_handshake(s->ssl);
    }
    int sent = s->last_alert == SSL_AD_INTERNAL_ERROR;   /* info_cb: a fatal alert we sent */
    /* a TLS 1.2 client whose last received record arrived in part: OpenSSL keeps its first bytes and starts no renegotiation while
       it does (ssl3_renegotiate_check), and only the rest of the record, from the peer, would release them */
    if (!sent && !stuck && client && started && SSL_version(s->ssl) < TLS1_3_VERSION && SSL_has_pending(s->ssl) && SSL_pending(s->ssl) == 0)
        stuck = "ksl: session aborted without an alert: a received record is incomplete, and OpenSSL starts no renegotiation before its rest arrives";
    char m[KSL_MSG];
    const char *how = sent ? "ksl: session aborted with internal_error" : stuck ? stuck : "ksl: session aborted; OpenSSL can send no alert for this role and version";
    if (why) snprintf(m, sizeof m, "%s; %s", why, how + 5); else snprintf(m, sizeof m, "%s", how);   /* how without its "ksl: " */
    ksl_ssl_fail(s, KSL_E_NOT_SUPPORTED, m);
    return sent ? KSL_OK : KSL_ERROR;
}
int ksl_tcp_abort(ksl_ssl *s) { return tcp_only(s) ? abort_session(s, NULL) : KSL_ERROR; }
int ksl_tcp_shutdown(ksl_ssl *s) {
    if (!tcp_only(s)) return KSL_ERROR; if (s->fatal) return KSL_ERROR; ERR_clear_error();
    int r = SSL_shutdown(s->ssl);
    if (r == 1) return KSL_OK;                 /* both close_notify alerts exchanged */
    if (r == 0) return KSL_WANT_READ;          /* ours sent, waiting for the peer's */
    return map_error(s, r);
}

#ifdef KSL_TEST
/* Test hook: the number of records after which ksl_tcp_write updates the sending key (by the AEAD otherwise; UINT64_MAX, never), counted from now. */
void ksl_tcp_set_key_update_records_for_test(ksl_ssl *s, uint64_t records) { s->key_update_records = records; s->records_sent = 0; }
/* Test hook: the records the keys may protect (the AEAD's limit otherwise); UINT64_MAX, none */
void ksl_tcp_set_record_limit_for_test(ksl_ssl *s, uint64_t records) { s->record_limit = records; }
/* Test hook: the record count of the automatic KeyUpdate and the record limit, as the session applies them */
void ksl_tcp_record_bounds_for_test(ksl_ssl *s, uint64_t *key_update_at, uint64_t *limit) { *key_update_at = key_update_records(s); *limit = record_limit(s); }
#endif
