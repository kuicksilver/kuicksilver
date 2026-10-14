/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* QUIC TLS interface: OpenSSL callbacks append to the event queue; CRYPTO input lives in ksl buffers. */
#include "ksl_internal.h"
#include <openssl/core_dispatch.h>

/* QUIC variable-length integer (RFC 9000 section 16): returns bytes consumed or 0 */
static int ksl_varint_read(const uint8_t *b, size_t len, uint64_t *out) {
    if (len == 0) return 0; int n = 1 << (b[0] >> 6); if ((size_t)n > len) return 0;
    uint64_t v = b[0] & 0x3f; for (int i = 1; i < n; i++) v = (v << 8) | b[i]; *out = v; return n;
}

static int inbuf_append(ksl_inbuf *b, const uint8_t *data, size_t len) {
    if (b->len + len > b->cap) { size_t nc = (b->len + len) * 2 + 64; uint8_t *nb = realloc(b->buf, nc); if (!nb) return 0; b->buf = nb; b->cap = nc; }
    memcpy(b->buf + b->len, data, len); b->len += len; return 1;
}
ksl_event *ksl_push_event(ksl_ssl *s, int type, const uint8_t *copy_from, size_t len) {
    int next = (s->qt + 1) % KSL_EVQ; if (next == s->qh) return NULL;   /* full: the caller must drain more often */
    ksl_event *e = &s->q[s->qt]; memset(e, 0, sizeof *e); e->type = type; s->qbuf[s->qt] = NULL;
    if (copy_from) { uint8_t *c = malloc(len ? len : 1); if (!c) return NULL; memcpy(c, copy_from, len); e->buf = c; e->len = len; s->qbuf[s->qt] = c; }
    s->qt = next; return e;
}
int ksl_quic_peek_event(ksl_ssl *s, ksl_event *out) { if (s->qh == s->qt) return 0; *out = s->q[s->qh]; return 1; }
int ksl_quic_next_event(ksl_ssl *s, ksl_event *out) {
    free(s->last_popped); s->last_popped = NULL;
    if (s->qh == s->qt) return 0;
    *out = s->q[s->qh]; s->last_popped = s->qbuf[s->qh]; s->qh = (s->qh + 1) % KSL_EVQ; return 1;
}

static int cb_crypto_send(SSL *ssl, const unsigned char *buf, size_t len, size_t *consumed, void *arg) {
    (void)ssl; ksl_ssl *s = arg; ksl_event *e = ksl_push_event(s, KSL_EV_CRYPTO_SEND, buf, len); if (!e) return 0;
    e->level = s->write_level; *consumed = len; return 1;
}
static int cb_crypto_recv_rcd(SSL *ssl, const unsigned char **buf, size_t *bytes_read, void *arg) {
    (void)ssl; ksl_ssl *s = arg; ksl_inbuf *b = &s->in[s->read_level];
    *buf = b->buf + b->consumed; *bytes_read = b->len - b->consumed;
    if (*bytes_read) s->rcd_level = s->read_level;   /* the pointer stays valid until release; provide() must not move it */
    return 1;
}
static int cb_crypto_release_rcd(SSL *ssl, size_t bytes_read, void *arg) {
    (void)ssl; ksl_ssl *s = arg; if (s->rcd_level < 0) return 1;
    ksl_inbuf *b = &s->in[s->rcd_level], *st = &s->stash[s->rcd_level];
    b->consumed += bytes_read; if (b->consumed == b->len) b->len = b->consumed = 0;
    s->rcd_level = -1;
    if (st->len) { if (!inbuf_append(b, st->buf, st->len)) return 0; st->len = 0; }
    return 1;
}
static int cb_yield_secret(SSL *ssl, uint32_t prot_level, int direction, const unsigned char *secret, size_t secret_len, void *arg) {
    ksl_ssl *s = arg; if (prot_level >= KSL_NLEVELS) return 0;
    if (direction == 0) s->read_level = (int)prot_level; else s->write_level = (int)prot_level;
    int aead = ksl_aead_of_cipher(SSL_get_current_cipher(ssl)); if (!aead) return 0;
    if (prot_level >= 2) s->hs_keys = 1;                                                    /* Handshake-level keys: the version is final (RFC 9368 2.2) */
    /* labels of the negotiated version (RFC 9369 3.3), but 0-RTT stays in the original one (RFC 9369 4.1): a server derives its 0-RTT
       key after negotiating */
    uint32_t v = prot_level == KSL_LEVEL_EARLY && s->orig_version ? s->orig_version : s->quic_version;
    ksl_key *k = ksl_key_from_secret(aead, secret, secret_len, v); if (!k) return 0;
    ksl_event *e = ksl_push_event(s, KSL_EV_KEY, NULL, 0); if (!e) { ksl_key_free(k); return 0; }
    e->level = (int)prot_level; e->direction = direction; e->aead = aead; e->key = k; return 1;
}
/* version_information (0x11, RFC 9368 section 3) inside a transport parameter blob: returns the value or NULL */
static const uint8_t *find_version_information(const uint8_t *tp, size_t len, size_t *vlen) {
    size_t p = 0;
    while (p < len) {
        uint64_t id, l; int n;
        n = ksl_varint_read(tp + p, len - p, &id); if (n <= 0) return NULL; p += (size_t)n;
        n = ksl_varint_read(tp + p, len - p, &l); if (n <= 0) return NULL; p += (size_t)n;
        if (l > len - p) return NULL;
        if (id == 0x11) { *vlen = (size_t)l; return tp + p; }
        p += (size_t)l;
    }
    return NULL;
}
static uint32_t rd32(const uint8_t *b) { return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3]; }
static void wr32(uint8_t *b, uint32_t v) { b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; }
/* Server rule (RFC 9368 section 2.3): first of our Available Versions listed by the client, else the client's Original Version. */
static int negotiate_version(ksl_ssl *s, const uint8_t *peer, size_t peer_len) {
    size_t cl = 0, sl = 0; const uint8_t *cv = find_version_information(peer, peer_len, &cl), *sv = s->tp ? find_version_information(s->tp, s->tp_len, &sl) : NULL;
    int client_has = cv && cl >= 4 && cl % 4 == 0;                   /* none (or malformed: the transport rejects it): keep the set version, still announce it as Chosen */
    uint32_t original = client_has ? rd32(cv) : s->quic_version, chosen = original;
    s->orig_version = original;
    if (client_has && sv && sl >= 4 && sl % 4 == 0) {
        for (size_t i = 0; i + 4 <= sl && chosen == original; i += 4) {   /* our Chosen Version heads our preference order */
            uint32_t ours = rd32(sv + i); if (ours == original) break;
            for (size_t j = 4; j + 4 <= cl; j += 4) if (rd32(cv + j) == ours) { chosen = ours; break; }
        }
    }
    if (chosen != 0x00000001u && chosen != 0x6b3343cfu) return 1;
    s->quic_version = chosen;
    if (sv && rd32(sv) != chosen) {                                   /* RFC 9368 section 4: our Chosen Version must be the version of our packets */
        wr32((uint8_t *)sv, chosen);
        if (!SSL_set_quic_tls_transport_params(s->ssl, s->tp, s->tp_len)) return 0;
    }
    return 1;
}
static int cb_got_transport_params(SSL *ssl, const unsigned char *params, size_t params_len, void *arg) {
    ksl_ssl *s = arg; (void)ssl;
    if (s->owner->role == KSL_SERVER && !s->hs_keys && !negotiate_version(s, params, params_len)) return 0;
    return ksl_push_event(s, KSL_EV_TRANSPORT_PARAMS, params, params_len) != NULL;
}
static int cb_alert(SSL *ssl, unsigned char alert_code, void *arg) { (void)ssl; (void)alert_code; (void)arg; return 1; }   /* recorded by the info callback */

const OSSL_DISPATCH ksl_quic_dispatch[] = {
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))cb_crypto_send},
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))cb_crypto_recv_rcd},
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))cb_crypto_release_rcd},
    {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))cb_yield_secret},
    {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))cb_got_transport_params},
    {OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))cb_alert},
    {0, NULL}
};

int ksl_quic_set_transport_params(ksl_ssl *s, const uint8_t *tp, size_t len) {
    ERR_clear_error();
    uint8_t *copy = malloc(len ? len : 1); if (!copy) return KSL_ERROR;
    if (len) memcpy(copy, tp, len);
    /* OpenSSL keeps the pointer (a second ClientHello after HelloRetryRequest reads it again): the old buffer goes only once the new one is in */
    if (!SSL_set_quic_tls_transport_params(s->ssl, copy, len)) { free(copy); ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: transport params rejected"); return KSL_ERROR; }
    free(s->tp); s->tp = copy; s->tp_len = len;
    return KSL_OK;
}
size_t ksl_quic_pending(const ksl_ssl *s, int level) { return s->in[level].len - s->in[level].consumed + s->stash[level].len; }
int ksl_quic_provide(ksl_ssl *s, int level, const uint8_t *data, size_t len) {
    if (level < 0 || level >= KSL_NLEVELS) { ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: bad level"); return KSL_ERROR; }
    /* RFC 9001 section 4.1.3: TLS never reads a level below its current one again, so such bytes would only sit here until the
       connection ends; the transport closes with PROTOCOL_VIOLATION before this, the check is the backstop of the memory bound */
    if (level < s->read_level) { ksl_ssl_set_error(s, KSL_E_CRYPTO_LEVEL, "ksl: CRYPTO data at a level TLS no longer reads"); return KSL_ERROR; }
    if (len > KSL_QUIC_LEVEL_MAX - ksl_quic_pending(s, level)) { ksl_ssl_set_error(s, KSL_E_CRYPTO_LEVEL, "ksl: too much unread CRYPTO data at one level"); return KSL_ERROR; }
    ksl_inbuf *b = s->rcd_level == level ? &s->stash[level] : &s->in[level];
    return inbuf_append(b, data, len) ? KSL_OK : KSL_ERROR;
}
