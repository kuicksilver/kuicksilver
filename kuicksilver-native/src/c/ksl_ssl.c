/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Sessions: lifecycle, names, getters, pause/resume, drive loop shared by QUIC and TCP modes. */
#include "ksl_internal.h"

extern const OSSL_DISPATCH ksl_quic_dispatch[];

ksl_ssl *ksl_ssl_new(ksl_ctx *c, int mode) {
    ksl_ssl *s = calloc(1, sizeof *s); if (!s) return NULL;
    s->owner = c; s->verify_mode = c->verify_mode; s->mode = mode; s->rcd_level = -1; s->quic_version = 0x00000001u; s->ssl = SSL_new(c->ctx);
    if (!s->ssl) { free(s); return NULL; }
    SSL_set_ex_data(s->ssl, 1, s);
    if (c->role == KSL_CLIENT) SSL_set_connect_state(s->ssl); else SSL_set_accept_state(s->ssl);
    if (mode == KSL_MODE_QUIC) {
        if (!SSL_set_quic_tls_cbs(s->ssl, ksl_quic_dispatch, s)) { SSL_free(s->ssl); free(s); return NULL; }
        /* max_early_data 0xffffffff (RFC 9001 section 4.6.1) on every server session, so each ticket it issues allows 0-RTT */
        if (c->role == KSL_SERVER && c->early_data && !SSL_set_quic_tls_early_data_enabled(s->ssl, 1)) { SSL_free(s->ssl); free(s); return NULL; }
    } else {
        BIO *internal = NULL; if (!BIO_new_bio_pair(&internal, 0, &s->net, 0)) { SSL_free(s->ssl); free(s); return NULL; }
        SSL_set_bio(s->ssl, internal, internal);
        /* a write left pending is retried from another buffer holding the same bytes: the JNI layer copies each call's bytes */
        SSL_set_mode(s->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    }
    /* TCP: for the session's life (KeyUpdate accounting); a QUIC client: until the handshake ends (its ServerHello) */
    if (mode == KSL_MODE_TCP || c->role == KSL_CLIENT) { SSL_set_msg_callback(s->ssl, ksl_msg_cb); SSL_set_msg_callback_arg(s->ssl, s); }
    ksl_live_add(KSL_LIVE_SSL, 1);
    return s;
}
void ksl_ssl_free(ksl_ssl *s) {
    if (!s) return;
    ksl_live_add(KSL_LIVE_SSL, -1);
    SSL_set_shutdown(s->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);   /* keeps the session resumable */
    SSL_free(s->ssl); BIO_free(s->net);
    for (int i = 0; i < KSL_NLEVELS; i++) { free(s->in[i].buf); free(s->stash[i].buf); }
    while (s->qh != s->qt) { if (s->q[s->qh].type == KSL_EV_KEY) ksl_key_free(s->q[s->qh].key); free(s->qbuf[s->qh]); s->qh = (s->qh + 1) % KSL_EVQ; }
    free(s->last_popped); free(s->tp); free(s->verify_host); free(s->verify_ip);
    sk_X509_pop_free(s->presented_chain, X509_free); sk_X509_pop_free(s->validated_chain, X509_free);
    if (s->keylog) { OPENSSL_cleanse(s->keylog, s->keylog_cap); free(s->keylog); }
    free(s);
}
static int set_sni(ksl_ssl *s, const char *host) {
    if (!host || !*host) return ksl_ssl_fail(s, KSL_E_BAD_ARG, "ksl: empty SNI"), s->fatal = 0, KSL_ERROR;
    return SSL_set_tlsext_host_name(s->ssl, host) == 1 ? KSL_OK : (ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: SNI rejected"), KSL_ERROR);
}
static char *dup_str(const char *s) { size_t n = strlen(s) + 1; char *d = malloc(n); if (d) memcpy(d, s, n); return d; }   /* portable duplicate (C11) */
static int ascii_host(const char *n) { for (; *n; n++) if ((unsigned char)*n >= 0x80 || *n == ' ') return 0; return 1; }
static int set_verify_name(ksl_ssl *s, const char *name) {
    if (!name || !*name || !ascii_host(name)) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: verify name must be a non-empty ASCII host or IP literal"); return KSL_ERROR; }
    X509_VERIFY_PARAM *p = SSL_get0_param(s->ssl);
    s->verify_flags = X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
    X509_VERIFY_PARAM_set_hostflags(p, s->verify_flags);
    free(s->verify_host); free(s->verify_ip); s->verify_host = s->verify_ip = NULL; s->verify_name_set = 0;
    /* set1_host replaces only the host list and set1_ip only the address: a previous identifier of the other type would stay and be checked too */
    X509_VERIFY_PARAM_set1_host(p, NULL, 0); X509_VERIFY_PARAM_set1_ip(p, NULL, 0);
    ERR_clear_error();
    if (X509_VERIFY_PARAM_set1_ip_asc(p, name) == 1) { s->verify_ip = dup_str(name); s->verify_name_set = 1; return KSL_OK; }   /* IP-ID: no SNI (RFC 6066 section 3) */
    ERR_clear_error();
    if (X509_VERIFY_PARAM_set1_host(p, name, 0) != 1) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: host name rejected"); return KSL_ERROR; }
    s->verify_host = dup_str(name); s->verify_name_set = 1; return KSL_OK;
}
int ksl_ssl_set(ksl_ssl *s, int what, const uint8_t *data, size_t len) {
    ERR_clear_error();
    switch (what) {
    case KSL_SET_SNI: case KSL_SET_VERIFY_NAME: {
        if (!data || len == 0 || len > 255 || memchr(data, 0, len)) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: name must be 1..255 bytes without NUL"); return KSL_ERROR; }
        char name[256]; memcpy(name, data, len); name[len] = 0;
        return what == KSL_SET_SNI ? set_sni(s, name) : set_verify_name(s, name);
    }
    case KSL_SET_QUIC_VERSION: {
        if (!data || len != 4) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: QUIC version is 4 bytes"); return KSL_ERROR; }
        uint32_t v = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
        if (v != 0x00000001u && v != 0x6b3343cfu) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: unknown QUIC version"); return KSL_ERROR; }
        if (s->hs_keys) { ksl_ssl_set_error(s, KSL_E_TOO_LATE, "ksl: QUIC version is fixed once Handshake keys exist"); return KSL_ERROR; }
        s->quic_version = v; return KSL_OK;
    }
    case KSL_SET_EARLY_CONTEXT:
        if (s->owner->role != KSL_SERVER) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: early context is server-only"); return KSL_ERROR; }
        if (!data || len == 0 || len > sizeof s->early_ctx) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: early context is 1..64 bytes"); return KSL_ERROR; }
        memcpy(s->early_ctx, data, len); s->early_ctx_len = len; return KSL_OK;
    case KSL_SET_EARLY_DATA:
        if (!data || len != 1 || s->mode != KSL_MODE_QUIC) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: early data flag is 1 byte, QUIC only"); return KSL_ERROR; }
        if (s->owner->role == KSL_SERVER) {
            if (!s->owner->early_data) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: the context does not accept early data"); return KSL_ERROR; }
            s->early_allow = data[0] != 0; return KSL_OK;
        }
        if (!data[0]) return KSL_OK;
        if (!SSL_set_quic_tls_early_data_enabled(s->ssl, 1)) { ERR_clear_error(); ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: the session does not allow early data"); return KSL_ERROR; }
        return KSL_OK;
    default: ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: unknown setter"); return KSL_ERROR;
    }
}
static int copy_out(uint8_t *out, size_t cap, size_t *len, const void *src, size_t n) {
    if (len) *len = n; if (n > cap) return KSL_ERROR; if (n) memcpy(out, src, n); return KSL_OK;
}
int ksl_ssl_get(ksl_ssl *s, int what, uint8_t *out, size_t cap, size_t *len) {
    ERR_clear_error();
    if (s->fatal && what != KSL_GET_VERSION && what != KSL_GET_KEYLOG && what != KSL_GET_QUIC_PENDING) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: session failed"); return KSL_ERROR; }
    switch (what) {
    case KSL_GET_ALPN: { const unsigned char *a; unsigned l; SSL_get0_alpn_selected(s->ssl, &a, &l); return copy_out(out, cap, len, a, l); }
    case KSL_GET_VERSION: { int v = SSL_version(s->ssl); uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v}; return copy_out(out, cap, len, b, 2); }
    case KSL_GET_CHANNEL_BINDING: {
        uint8_t cb[32];
        if (SSL_version(s->ssl) < TLS1_3_VERSION && !SSL_get_extms_support(s->ssl)) { ksl_ssl_set_error(s, KSL_E_EMS_REQUIRED, "ksl: tls-exporter needs extended master secret"); return KSL_ERROR; }
        if (SSL_export_keying_material(s->ssl, cb, 32, "EXPORTER-Channel-Binding", 24, (const unsigned char *)"", 0, 1) != 1) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: exporter failed"); return KSL_ERROR; }
        return copy_out(out, cap, len, cb, 32);
    }
    case KSL_GET_KEYLOG: { int rc = copy_out(out, cap, len, s->keylog, s->keylog_len); if (rc == KSL_OK && s->keylog) { OPENSSL_cleanse(s->keylog, s->keylog_len); s->keylog_len = 0; } return rc; }
    case KSL_GET_SESSION_REUSED: { uint8_t b = SSL_session_reused(s->ssl) ? 1 : 0; return copy_out(out, cap, len, &b, 1); }
    case KSL_GET_EMS: { uint8_t b = SSL_get_extms_support(s->ssl) == 1; return copy_out(out, cap, len, &b, 1); }
    case KSL_GET_QUIC_PENDING: {
        uint8_t b[4 * KSL_NLEVELS];
        for (int l = 0; l < KSL_NLEVELS; l++) { uint32_t v = (uint32_t)ksl_quic_pending(s, l); b[4 * l] = (uint8_t)(v >> 24); b[4 * l + 1] = (uint8_t)(v >> 16); b[4 * l + 2] = (uint8_t)(v >> 8); b[4 * l + 3] = (uint8_t)v; }
        return copy_out(out, cap, len, b, sizeof b);
    }
    case KSL_GET_QUIC_VERSION: { uint32_t v = s->quic_version; uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v}; return copy_out(out, cap, len, b, 4); }
    case KSL_GET_EARLY_DATA: {
        int st = SSL_get_early_data_status(s->ssl);
        uint8_t b = st == SSL_EARLY_DATA_ACCEPTED ? 2 : st == SSL_EARLY_DATA_REJECTED ? 1 : 0; return copy_out(out, cap, len, &b, 1);
    }
    default: ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: unknown getter"); return KSL_ERROR;
    }
}
int ksl_ssl_get_peer_chain(ksl_ssl *s, int which, int idx, uint8_t *out, size_t cap, size_t *len) {
    STACK_OF(X509) *chain = which == KSL_CHAIN_VALIDATED ? s->validated_chain : s->presented_chain;
    X509 *single = NULL;
    if (!chain || sk_X509_num(chain) == 0) single = SSL_get0_peer_certificate(s->ssl);   /* resumed session: only the leaf survives in the session */
    int count = chain && sk_X509_num(chain) ? sk_X509_num(chain) : (single ? 1 : 0);
    if (idx < 0) return count;
    if (idx >= count) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: chain index out of range"); return KSL_ERROR; }
    unsigned char *der = NULL; int l = i2d_X509(single ? single : sk_X509_value(chain, idx), &der); if (l < 0) return KSL_ERROR;
    int rc = copy_out(out, cap, len, der, (size_t)l); OPENSSL_free(der); return rc;
}
int ksl_ssl_verify_resume(ksl_ssl *s, int accept, int alert) {
    if (s->verify_pending != 1) { ksl_ssl_set_error(s, KSL_E_NOT_PAUSED, "ksl: no verification is pending"); return KSL_ERROR; }
    s->verify_pending = 2; s->verify_decision = accept; s->verify_alert = alert; return KSL_OK;
}
int ksl_ssl_export_keying_material(ksl_ssl *s, uint8_t *out, size_t out_len, const char *label, size_t label_len, const uint8_t *context, size_t context_len) {
    if (!s->done) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: exporter before the handshake completed"); return KSL_ERROR; }
    ERR_clear_error();
    if (SSL_export_keying_material(s->ssl, out, out_len, label, label_len, context, context_len, context != NULL) != 1) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: exporter failed"); return KSL_ERROR; }
    return KSL_OK;
}
/* Each session handed out carries the verify mode of the session it came from (ex data, KSL_VERIFY_* + 1), and ksl_ssl_set_session
   resumes one made without verification only where verification is off as well: a resumed handshake carries no Certificate, so
   nothing would verify the server there. KSL_VERIFY_PAUSE and KSL_VERIFY_OPENSSL both verify; Kotlin's cache key binds a ticket to
   its trust configuration besides (and re-verifies the cached chain, ksl_ctx_verify_chain). */
static CRYPTO_ONCE session_mode_once = CRYPTO_ONCE_STATIC_INIT;
static int session_mode_idx = -1;
static void session_mode_index(void) { session_mode_idx = SSL_SESSION_get_ex_new_index(0, NULL, NULL, NULL, NULL); }
static int session_mode_ready(void) { return CRYPTO_THREAD_run_once(&session_mode_once, session_mode_index) && session_mode_idx >= 0; }
static void stamp_session(ksl_ssl *s, SSL_SESSION *sess) { if (session_mode_ready()) (void)SSL_SESSION_set_ex_data(sess, session_mode_idx, (void *)(intptr_t)(s->verify_mode + 1)); }
/* ksl_session is an SSL_SESSION: reference-counted, its master key cleansed by OpenSSL on the last free (never serialized to Kotlin, so the secret stays in native memory) */
ksl_session *ksl_ssl_get1_session(ksl_ssl *s) {
    ERR_clear_error(); SSL_SESSION *sess = SSL_get1_session(s->ssl);
    if (sess && !SSL_SESSION_is_resumable(sess)) { SSL_SESSION_free(sess); sess = NULL; }
    if (sess) { stamp_session(s, sess); ksl_live_add(KSL_LIVE_SESSION, 1); }
    return (ksl_session *)sess;
}
int ksl_ssl_set_session(ksl_ssl *s, ksl_session *session) {
    ERR_clear_error();
    if (session && s->verify_mode != KSL_VERIFY_NONE) {
        intptr_t made = session_mode_ready() ? (intptr_t)SSL_SESSION_get_ex_data((SSL_SESSION *)session, session_mode_idx) : 0;
        if (made == 0 || made - 1 == KSL_VERIFY_NONE) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: a session made without verification does not resume where verification is on"); return KSL_ERROR; }
    }
    if (!session || SSL_set_session(s->ssl, (SSL_SESSION *)session) != 1) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: session rejected"); return KSL_ERROR; }
    return KSL_OK;
}
void ksl_session_free(ksl_session *session) { if (session) ksl_live_add(KSL_LIVE_SESSION, -1); SSL_SESSION_free((SSL_SESSION *)session); }
int ksl_ssl_new_session_ticket(ksl_ssl *s) { ERR_clear_error(); s->ticket_authorized = 1; if (SSL_new_session_ticket(s->ssl) != 1) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: ticket request failed"); return KSL_ERROR; } return KSL_OK; }
/* RFC 9846 section 4.7.3: "Until receiving a subsequent KeyUpdate from the peer, the sender MUST NOT send another KeyUpdate with
   request_update set to update_requested": while ours is unanswered (ksl_msg_cb clears it on the peer's KeyUpdate) a request is
   sent as update_not_requested, which still updates our sending key. Past the epoch bound no key update is sent at all. */
int ksl_ssl_key_update(ksl_ssl *s, int request_peer) {
    ERR_clear_error();
    if (ksl_key_update_limit_check(s) != KSL_OK) return KSL_ERROR;
    int requested = request_peer && !s->update_requested_pending;
    if (SSL_key_update(s->ssl, requested ? SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED) != 1) { ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: key update failed"); return KSL_ERROR; }
    if (requested) s->update_requested_pending = 1;
    return KSL_OK;
}
int ksl_key_update_limit_check(ksl_ssl *s) {
    if (!s->key_updates_exhausted) return KSL_OK;
    if (!s->fatal) ksl_ssl_fail(s, KSL_E_NOT_SUPPORTED, "ksl: the session reached the key update bound (RFC 9846 section 4.7.3)");
    return KSL_ERROR;
}
int ksl_ssl_client_hello(ksl_ssl *s, ksl_client_hello *out) {
    if (!s->sni_pending) { ksl_ssl_set_error(s, KSL_E_NOT_PAUSED, "ksl: not paused at ClientHello"); return KSL_ERROR; }
    memset(out, 0, sizeof *out); const unsigned char *p; size_t l;
    ksl_client_hello_sni(s->ssl, &out->sni, &out->sni_len);
    if (SSL_client_hello_get0_ext(s->ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &p, &l) == 1 && l >= 2) { out->alpn = p + 2; out->alpn_len = l - 2; }
    if (SSL_client_hello_get0_ext(s->ssl, TLSEXT_TYPE_signature_algorithms, &p, &l) == 1 && l >= 2) { out->sig_algs = p + 2; out->sig_algs_len = l - 2; }
    return KSL_OK;
}
int ksl_ssl_sni_resume(ksl_ssl *s, ksl_ctx *override, int alert) {
    if (!s->sni_pending) { ksl_ssl_set_error(s, KSL_E_NOT_PAUSED, "ksl: not paused at ClientHello"); return KSL_ERROR; }
    /* the override's settings become the session's (ksl_client_hello_cb, ksl_ctx_apply_to_ssl): a client context's would judge
       client certificates by a client's rules */
    if (override && override->role != KSL_SERVER) { ERR_clear_error(); ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: an SNI override must be a server context"); return KSL_ERROR; }
    s->sni_pending = 2; s->sni_override = override; s->sni_decision_alert = alert; return KSL_OK;
}

/* Drives the handshake, then post-handshake messages. The verify name rule (ADR-0011: the host name is always checked by the shared matcher, also after a platform verdict) is enforced here. */
int ksl_drive(ksl_ssl *s) {
    if (s->fatal || ksl_key_update_limit_check(s) != KSL_OK) return KSL_ERROR;
    if (!s->done && s->owner->role == KSL_CLIENT && s->verify_mode != KSL_VERIFY_NONE && !s->verify_name_set)
        return ksl_ssl_fail(s, KSL_E_NO_VERIFY_NAME, "ksl: verify name not set (reference identifier is mandatory)");
    ERR_clear_error(); int r;
    if (!s->done) {
        r = SSL_do_handshake(s->ssl);
        /* A server with early data enabled stops at TLS_ST_EARLY_DATA once its own Finished is out (SSL_do_handshake returns 1, as for
           SSL_read_early_data over TCP); the handshake is complete only with the client's Finished: calling again re-enters it. */
        if (r == 1 && s->owner->role == KSL_SERVER && SSL_get_state(s->ssl) == TLS_ST_EARLY_DATA) r = SSL_do_handshake(s->ssl);
        if (r == 1) {
            s->done = 1;
            int ours = s->mode == KSL_MODE_QUIC && s->owner->role == KSL_CLIENT;
#ifdef KSL_TEST
            ours = ours && !s->msg_observer;
#endif
            if (ours) SSL_set_msg_callback(s->ssl, NULL);   /* a QUIC client needs ksl_msg_cb for the handshake only */
            /* both sides refuse TLS 1.2 without EMS before Finished, with handshake_failure (server_name_cb, ksl_cert_verify_cb): this
               is the last line, for a handshake that reached the end without a certificate to check (a resumption) */
            if (s->mode == KSL_MODE_TCP && SSL_version(s->ssl) < TLS1_3_VERSION && !SSL_get_extms_support(s->ssl)) return ksl_ssl_fail(s, KSL_E_EMS_REQUIRED, "ksl: TLS 1.2 without extended master secret rejected");
            if (s->mode == KSL_MODE_QUIC) {
                /* RFC 9001 section 8.1: "QUIC clients MUST use error 0x0178 to terminate a connection when ALPN negotiation fails"; an
                   OpenSSL client accepts a server that answered without ALPN (the server side is refused in ksl_client_hello_cb) */
                const unsigned char *a; unsigned al; SSL_get0_alpn_selected(s->ssl, &a, &al);
                if (al == 0) { s->last_alert = SSL_AD_NO_APPLICATION_PROTOCOL; s->done = 0; return ksl_ssl_fail(s, KSL_E_NOT_SUPPORTED, "ksl: no application protocol negotiated (RFC 9001 section 8.1)"); }
                ksl_push_event(s, KSL_EV_HANDSHAKE_DONE, NULL, 0);
            }
            return KSL_OK;
        }
    } else {
        size_t n; unsigned char dummy[1]; r = SSL_read_ex(s->ssl, dummy, 0, &n);   /* post-handshake processing (QUIC pod) */
        if (r == 1) return KSL_OK;
    }
    switch (SSL_get_error(s->ssl, r)) {
    case SSL_ERROR_WANT_READ: case SSL_ERROR_WANT_WRITE: ERR_clear_error(); return KSL_WANT_READ;
    case SSL_ERROR_WANT_RETRY_VERIFY: ERR_clear_error(); return KSL_WANT_VERIFY;
    case SSL_ERROR_WANT_CLIENT_HELLO_CB: ERR_clear_error(); return KSL_WANT_SNI;
    case SSL_ERROR_ZERO_RETURN: ERR_clear_error(); return KSL_EOF;
    case SSL_ERROR_SYSCALL: if (!ERR_peek_error()) return ksl_ssl_fail(s, KSL_E_TRUNCATED, "ksl: unexpected EOF"); /* fallthrough */
    default:
        if (s->ems_refused) return ksl_ssl_fail(s, KSL_E_EMS_REQUIRED, "ksl: TLS 1.2 without extended master secret rejected");
        s->fatal = 1; ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: handshake failed"); return KSL_ERROR;
    }
}

/* Whether a ServerHello (handshake header included) carries extended_master_secret (RFC 9846 appendix D). */
static int server_hello_has_ems(const uint8_t *m, size_t len) {
    size_t off = 4 + 2 + 32; if (len < off + 1) return 0;   /* header, legacy_version, random */
    off += 1 + m[off] + 2 + 1;   /* session id, cipher suite, compression method */
    if (len < off + 2) return 0;
    size_t end = off + 2 + (((size_t)m[off] << 8) | m[off + 1]); if (end > len) return 0;
    for (off += 2; off + 4 <= end;) {
        unsigned type = ((unsigned)m[off] << 8) | m[off + 1]; size_t l = ((size_t)m[off + 2] << 8) | m[off + 3];
        if (type == TLSEXT_TYPE_extended_master_secret) return 1;
        off += 4 + l;
    }
    return 0;
}
/* A client's message callback during the handshake, called with each message before OpenSSL processes it. ServerHello:
   - notes whether it carried extended_master_secret, which ksl_cert_verify_cb needs before Finished (SSL_get_extms_support answers
     only after the handshake);
   - RFC 9846 section 4.2.3: "A client which receives a TLS 1.3 Server Hello with a legacy_version value not equal to 0x0303 MUST
     abort the handshake with a protocol_version alert". OpenSSL takes the version from supported_versions and ignores the field;
     ksl disables every version on the session here, so that OpenSSL's own version check, which runs next, aborts with
     protocol_version (a TLS 1.2 ServerHello's legacy_version is its version, which OpenSSL checks itself). */
void ksl_msg_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    ksl_ssl *s = arg; const uint8_t *m = buf;
    /* RFC 9846 section 4.7.3: "sending implementations MUST NOT allow the epoch -- and hence the number of key updates -- to exceed
       2^48-1", also when answering the peer's update_requested ("it MUST NOT send its own KeyUpdate if that would cause it to exceed
       these limits"). OpenSSL counts nothing and answers a request by itself. Once the last allowed KeyUpdate is written the session
       ends: ksl sends no key update of its own any more and fails the session at its next call (ksl_key_update_limit_check). A
       request from the peer that would need one more answer shuts the session's end of the BIO pair for writing before OpenSSL
       processes it (this callback runs first), so the answer cannot leave. What the peer sends is never counted ("receiving
       implementations MUST NOT enforce this rule"). */
    if (s->mode == KSL_MODE_TCP && content_type == SSL3_RT_HANDSHAKE && len >= 5 && m[0] == SSL3_MT_KEY_UPDATE) {
        uint64_t bound = s->key_update_limit ? s->key_update_limit : KSL_MAX_KEY_UPDATES;
        if (write_p) { if (++s->key_updates_sent >= bound) s->key_updates_exhausted = 1; }
        else {
            s->update_requested_pending = 0;
            if (m[4] == SSL_KEY_UPDATE_REQUESTED && s->key_updates_sent >= bound) { s->key_updates_exhausted = 1; (void)BIO_shutdown_wr(SSL_get_wbio(ssl)); }
        }
    }
    if (!write_p && content_type == SSL3_RT_HANDSHAKE && len >= 6 && m[0] == SSL3_MT_SERVER_HELLO && s->owner->role == KSL_CLIENT) {
        s->server_hello_ems = server_hello_has_ems(m, len);
        if (((m[4] << 8) | m[5]) != TLS1_2_VERSION) SSL_set_options(ssl, SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3);
    }
#ifdef KSL_TEST
    if (s->msg_observer) s->msg_observer(write_p, version, content_type, buf, len, ssl, s->msg_observer_arg);
#else
    (void)version; (void)ssl;
#endif
}

#ifdef KSL_TEST
/* Test hook: the OpenSSL object behind a session, for tests that need to shape the client (groups, message callbacks). */
SSL *ksl_ssl_raw_for_test(ksl_ssl *s) { return s->ssl; }
/* Test hook: the KeyUpdate bound of ksl_msg_cb (KSL_MAX_KEY_UPDATES otherwise) */
void ksl_ssl_set_key_update_limit_for_test(ksl_ssl *s, uint64_t updates) { s->key_update_limit = updates; }
/* Test hook: a message callback for tests, called for every message of the session after ksl's own (ksl_msg_cb) */
void ksl_ssl_msg_observer_for_test(ksl_ssl *s, void (*cb)(int, int, int, const void *, size_t, SSL *, void *), void *arg) {
    s->msg_observer = cb; s->msg_observer_arg = arg; SSL_set_msg_callback(s->ssl, ksl_msg_cb); SSL_set_msg_callback_arg(s->ssl, s);
}
#endif
