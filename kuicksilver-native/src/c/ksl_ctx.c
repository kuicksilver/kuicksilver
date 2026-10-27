/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* TLS contexts: identity, roots, ALPN, cipher profile, ticket keys, options; immutable after freeze. */
#include "ksl_internal.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>

#define TLS12_PROFILE "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
#define TLS13_DEFAULT "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; ksl_ctx *c = arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, c->alpn, (unsigned)c->alpn_len, in, inlen) == OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;   /* no_application_protocol (120) */
}
/* Records alerts for both modes: sent -> code, received -> code | 0x100 (ksl_ssl_last_error). Fatal ones and close_notify; in TLS
   1.3 also an error alert at level warning, since RFC 9846 section 6: error alerts "MUST be treated as error alerts when received
   regardless of the AlertLevel" (OpenSSL ends the connection on them; only user_canceled is not one). */
static void info_cb(const SSL *ssl, int where, int ret) {
    if (!(where & SSL_CB_ALERT)) return; ksl_ssl *s = SSL_get_ex_data(ssl, 1); if (!s) return;
    int code = ret & 0xff;
    if ((ret >> 8) != SSL3_AL_FATAL && code != SSL_AD_CLOSE_NOTIFY && (SSL_version(ssl) < TLS1_3_VERSION || code == SSL_AD_USER_CANCELLED)) return;
    s->last_alert = (where & SSL_CB_READ) ? (code | 0x100) : code;
}
/* Moves a buffer of secrets into a larger one and zeroes the whole old block before the caller frees it: realloc would free
   (or leave behind) a copy of the TLS secrets uncleansed (threat model 3.7). */
void ksl_secret_move(void *dst, void *old, size_t used, size_t old_cap) {
    if (!old) return;
    memcpy(dst, old, used); OPENSSL_cleanse(old, old_cap);
}
static void keylog_cb(const SSL *ssl, const char *line) {
    ksl_ssl *s = SSL_get_ex_data(ssl, 1); if (!s || !s->owner->keylog) return;
    size_t l = strlen(line);
    if (s->keylog_len + l + 2 > s->keylog_cap) {
        size_t nc = (s->keylog_len + l + 2) * 2; char *nb = malloc(nc); if (!nb) return;
        ksl_secret_move(nb, s->keylog, s->keylog_len, s->keylog_cap); free(s->keylog); s->keylog = nb; s->keylog_cap = nc;
    }
    memcpy(s->keylog + s->keylog_len, line, l); s->keylog_len += l; s->keylog[s->keylog_len++] = '\n'; s->keylog[s->keylog_len] = 0;
}
/* RFC 8446 section 4.6.1 tickets: name16 | aes-256 key 32 | hmac-sha256 key 32; current key encrypts, all keys decrypt. */
static int ticket_cb(SSL *ssl, unsigned char key_name[16], unsigned char iv[EVP_MAX_IV_LENGTH], EVP_CIPHER_CTX *ectx, EVP_MAC_CTX *hctx, int enc) {
    ksl_ssl *s = SSL_get_ex_data(ssl, 1); ksl_ctx *c = s->owner;
    const uint8_t *k = NULL; if (!c->ticket_keys) return 0;   /* an override context without keys: no ticket (TLS 1.3 sends none), none decrypts */
    /* KSL_OPT_NUM_TICKETS 0: tickets only from ksl_ssl_new_session_ticket (after Kotlin's pin verdict); 0 here makes TLS 1.3 send none, so a
       ticket can never precede the verdict, whatever count the SSL carries. TLS 1.2 issues its ticket inside the handshake, before any
       verdict: 0 sends an empty one, so no 1.2 session is resumable. SSL_OP_NO_TICKET would switch TLS 1.3 to stateful tickets, which
       need the server cache ksl keeps off. */
    if (enc && c->num_tickets == 0 && (SSL_version(ssl) < TLS1_3_VERSION || !s->ticket_authorized)) return 0;
    if (enc) { k = c->ticket_keys; memcpy(key_name, k, 16); if (RAND_bytes(iv, 16) != 1) return -1; }
    else { for (size_t i = 0; i < c->ticket_key_count; i++) if (!memcmp(c->ticket_keys + i * 80, key_name, 16)) { k = c->ticket_keys + i * 80; break; } if (!k) return 0; }
    if (EVP_CipherInit_ex(ectx, EVP_aes_256_cbc(), NULL, k + 16, iv, enc) != 1) return -1;
    OSSL_PARAM p[3]; p[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)(k + 48), 32);
    p[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0); p[2] = OSSL_PARAM_construct_end();
    if (EVP_MAC_CTX_set_params(hctx, p) != 1) return -1;
    return enc ? 1 : (k == c->ticket_keys ? 1 : 2);   /* 2 = decrypted with a previous key: renew the ticket */
}

/* Ticket app data: one flag byte (KSL_TICKET_AFTER_VERDICT: issued by ksl_ssl_new_session_ticket, after the pin verdict;
   KSL_TICKET_NAME_BOUND: the name tag follows), the QUIC version of the issuing connection (4 bytes big-endian, the negotiated one; 0 for
   TLS over TCP), the server name tag (32 bytes, ksl_client_hello_cb), then the server's early context (0-RTT, ADR-0015). A ticket of
   another version than the one the client started this connection with is not resumed (RFC 9369 section 5: a full handshake, without
   0-RTT), nor is a ticket of another server name or without a name tag (RFC 6066 section 3: "MUST NOT accept the request to resume the
   session if the server_name extension contains a different name. Instead, it proceeds with a full handshake"); a resumed ticket whose
   early context differs keeps the resumption but gets no early data. The final
   early-data decision also needs the transport's verdict for this hello (its replay register). Both callbacks are the base (session)
   context's: OpenSSL keeps them across an SNI override, and they read the settings of the session's current owner. */
#define KSL_TICKET_AFTER_VERDICT 1
#define KSL_TICKET_NAME_BOUND 2
#define KSL_TICKET_HEAD (5 + sizeof ((ksl_ssl *)0)->sni_tag)   /* flags, version, name tag */
static uint32_t ticket_version(const ksl_ssl *s, int issuing) {
    if (s->mode != KSL_MODE_QUIC) return 0;
    return issuing || !s->orig_version ? s->quic_version : s->orig_version;   /* issued: the negotiated version; resumed: the original one */
}
static int ticket_gen_cb(SSL *ssl, void *arg) {
    (void)arg; ksl_ssl *s = SSL_get_ex_data(ssl, 1); SSL_SESSION *sess = SSL_get0_session(ssl);
    if (!s || !sess) return 0;
    uint8_t data[KSL_TICKET_HEAD + sizeof s->early_ctx]; uint32_t v = ticket_version(s, 1);
    data[0] = KSL_TICKET_NAME_BOUND | (s->ticket_authorized ? KSL_TICKET_AFTER_VERDICT : 0);
    data[1] = (uint8_t)(v >> 24); data[2] = (uint8_t)(v >> 16); data[3] = (uint8_t)(v >> 8); data[4] = (uint8_t)v;
    memcpy(data + 5, s->sni_tag, sizeof s->sni_tag); memcpy(data + KSL_TICKET_HEAD, s->early_ctx, s->early_ctx_len);
    return SSL_SESSION_set1_ticket_appdata(sess, data, KSL_TICKET_HEAD + s->early_ctx_len);
}
static SSL_TICKET_RETURN ticket_dec_cb(SSL *ssl, SSL_SESSION *sess, const unsigned char *keyname, size_t keyname_len, SSL_TICKET_STATUS status, void *arg) {
    (void)keyname; (void)keyname_len; (void)arg; ksl_ssl *s = SSL_get_ex_data(ssl, 1);
    switch (status) {
    case SSL_TICKET_SUCCESS: case SSL_TICKET_SUCCESS_RENEW: {
        void *d = NULL; size_t l = 0; const uint8_t *p;
        if (SSL_SESSION_get0_ticket_appdata(sess, &d, &l) != 1 || l < KSL_TICKET_HEAD) { d = NULL; l = 0; }
        p = d;
        /* a context that issues tickets only after the pin verdict (NUM_TICKETS 0) resumes only such tickets: a ticket from anywhere else
           (another configuration sharing keys and session context, an in-handshake ticket) proves no verdict, so a full handshake runs */
        if (s && s->owner->num_tickets == 0 && !(p && (p[0] & KSL_TICKET_AFTER_VERDICT))) return SSL_TICKET_RETURN_IGNORE;
        if (!s || !p) return SSL_TICKET_RETURN_IGNORE_RENEW;
        uint32_t v = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4];
        if (v != ticket_version(s, 0)) { s->early_ctx_match = 0; return SSL_TICKET_RETURN_IGNORE_RENEW; }
        /* RFC 6066 section 3: another server name (or a ticket from before names were bound) gets a full handshake and a new ticket */
        if (!(p[0] & KSL_TICKET_NAME_BOUND) || CRYPTO_memcmp(p + 5, s->sni_tag, sizeof s->sni_tag) != 0) { s->early_ctx_match = 0; return SSL_TICKET_RETURN_IGNORE_RENEW; }
        s->early_ctx_match = l > KSL_TICKET_HEAD && l - KSL_TICKET_HEAD == s->early_ctx_len && !memcmp(p + KSL_TICKET_HEAD, s->early_ctx, l - KSL_TICKET_HEAD);
        return SSL_TICKET_RETURN_USE_RENEW;   /* client tickets are single-use: every resumption gets a fresh one */
    }
    case SSL_TICKET_EMPTY: case SSL_TICKET_NO_DECRYPT: return SSL_TICKET_RETURN_IGNORE_RENEW;
    default: return SSL_TICKET_RETURN_IGNORE;
    }
}
/* Runs once the ClientHello's extensions are parsed and the version is chosen, before the server's first flight is built.
   TLS 1.2 without extended master secret is refused here (RFC 7627, RFC 9325 section 3.6; the exporter and tls-exporter need it):
   failing now makes OpenSSL send handshake_failure, where the check after Finished (ksl_drive) could only drop the connection
   without an alert (RFC 8446 section 6.1, RFC 5246 section 7.2.2). OpenSSL ignores the client's extension under
   SSL_OP_NO_EXTENDED_MASTER_SECRET, so that option counts as its absence.
   RFC 6066 section 3: a server that used server_name "SHALL include an extension of type 'server_name' in the (extended) server
   hello" with empty data (TLS 1.3: in EncryptedExtensions). OpenSSL sends it only when this callback answers SSL_TLSEXT_ERR_OK, and
   itself leaves it out of a resumed TLS 1.2 ServerHello, as the RFC requires. The name is already chosen by then
   (ksl_client_hello_cb); OpenSSL reads this callback from the session's current context, so every server context carries it, an
   SNI override too. */
static int server_name_cb(SSL *ssl, int *al, void *arg) {
    (void)arg; ksl_ssl *s = SSL_get_ex_data(ssl, 1);
    if (s && s->mode == KSL_MODE_TCP && SSL_version(ssl) < TLS1_3_VERSION
        && (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_extended_master_secret, NULL, NULL) != 1 || (SSL_get_options(ssl) & SSL_OP_NO_EXTENDED_MASTER_SECRET))) {
        s->ems_refused = 1; *al = SSL_AD_HANDSHAKE_FAILURE; return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}
static int allow_early_data_cb(SSL *ssl, void *arg) { (void)arg; ksl_ssl *s = SSL_get_ex_data(ssl, 1); return s && s->early_allow && s->early_ctx_match; }
void ksl_ctx_enable_early_data(SSL_CTX *ctx) {
    /* OpenSSL's own anti-replay makes tickets stateful in the server cache ksl keeps off: with it every early data would be refused */
    SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
    SSL_CTX_set_allow_early_data_cb(ctx, allow_early_data_cb, NULL);
}
/* SSL_new copies these settings from the SSL_CTX into the session, and SSL_set_SSL_CTX moves only the certificate and the session id
   context: an SNI override (ksl_client_hello_cb) applies the rest itself, so that every setting of the override is in effect (ticket
   count, version range, options, verify mode and parameters, suites, groups, early data). The ALPN select, ticket key, keylog and
   verify callbacks are read from the current or the session context and look up the session's owner. */
int ksl_ctx_apply_to_ssl(ksl_ctx *o, SSL *ssl) {
    SSL_CTX *x = o->ctx; ERR_clear_error();
    SSL_clear_options(ssl, SSL_get_options(ssl) & ~SSL_CTX_get_options(x)); SSL_set_options(ssl, SSL_CTX_get_options(x));
    if (SSL_set_min_proto_version(ssl, SSL_CTX_get_min_proto_version(x)) != 1 || SSL_set_max_proto_version(ssl, SSL_CTX_get_max_proto_version(x)) != 1) return 0;
    if (SSL_set_num_tickets(ssl, SSL_CTX_get_num_tickets(x)) != 1) return 0;
    SSL_set_verify(ssl, SSL_CTX_get_verify_mode(x), SSL_CTX_get_verify_callback(x));
    X509_VERIFY_PARAM *p = SSL_get0_param(ssl); uint32_t inh = X509_VERIFY_PARAM_get_inh_flags(p);
    X509_VERIFY_PARAM_set_inh_flags(p, X509_VP_FLAG_OVERWRITE | X509_VP_FLAG_RESET_FLAGS);
    int ok = X509_VERIFY_PARAM_inherit(p, SSL_CTX_get0_param(x)) == 1; X509_VERIFY_PARAM_set_inh_flags(p, inh);
    if (!ok || SSL_set_ciphersuites(ssl, o->suites13) != 1 || SSL_set_cipher_list(ssl, o->list12) != 1 || SSL_set1_groups_list(ssl, o->groups) != 1) return 0;
    if (SSL_set_session_id_context(ssl, o->sid_ctx, (unsigned)o->sid_ctx_len) != 1) return 0;
    if (SSL_set_max_early_data(ssl, SSL_CTX_get_max_early_data(x)) != 1 || SSL_set_recv_max_early_data(ssl, SSL_CTX_get_recv_max_early_data(x)) != 1) return 0;
    SSL_set_allow_early_data_cb(ssl, o->early_data ? allow_early_data_cb : NULL, NULL);
    return 1;
}

ksl_ctx *ksl_ctx_new(int role) {
    ksl_ctx *c = calloc(1, sizeof *c); if (!c) return NULL;
    c->role = role; c->verify_mode = KSL_VERIFY_OPENSSL;
    c->ctx = SSL_CTX_new_ex(NULL, NULL, TLS_method()); if (!c->ctx) { free(c); return NULL; }
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_3_VERSION); SSL_CTX_set_max_proto_version(c->ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(c->ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
    SSL_CTX_clear_options(c->ctx, SSL_OP_LEGACY_SERVER_CONNECT);
    SSL_CTX_set_cipher_list(c->ctx, TLS12_PROFILE); SSL_CTX_set_ciphersuites(c->ctx, TLS13_DEFAULT);
    snprintf(c->list12, sizeof c->list12, "%s", TLS12_PROFILE); snprintf(c->suites13, sizeof c->suites13, "%s", TLS13_DEFAULT);
    /* One tuple of key-exchange groups: a server takes the client's X25519 key share instead of answering HelloRetryRequest for
       X25519MLKEM768 when the client supports it but sent no share for it (OpenSSL's default puts the hybrid alone in the first
       tuple; ngtcp2 and others ship X25519 shares only, and the extra round trip doubled handshake loss in interop). A client
       still sends shares for the hybrid and X25519 (the '*' marks), so a post-quantum server picks the hybrid in one flight. */
    c->groups = role == KSL_SERVER ? "X25519MLKEM768:X25519:secp256r1:X448:secp384r1:secp521r1" : "*X25519MLKEM768:*X25519:secp256r1:X448:secp384r1:secp521r1";
    if (SSL_CTX_set1_groups_list(c->ctx, c->groups) != 1) { SSL_CTX_free(c->ctx); free(c); return NULL; }
    SSL_CTX_set_cert_verify_callback(c->ctx, ksl_cert_verify_cb, c);
    SSL_CTX_set_verify(c->ctx, role == KSL_CLIENT ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_num_tickets(c->ctx, 0); SSL_CTX_set_keylog_callback(c->ctx, keylog_cb); SSL_CTX_set_info_callback(c->ctx, info_cb);
    SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_OFF);
    /* required by OpenSSL to resume a session whose handshake verified a client certificate */
    SSL_CTX_set_session_id_context(c->ctx, (const unsigned char *)"ksl", 3); memcpy(c->sid_ctx, "ksl", 3); c->sid_ctx_len = 3;
    /* every server stamps its tickets (the flag byte of ticket_gen_cb) and checks them on resumption */
    if (role == KSL_SERVER) SSL_CTX_set_session_ticket_cb(c->ctx, ticket_gen_cb, ticket_dec_cb, NULL);
    /* the ticket key callback too, keys or not: without it OpenSSL would fall back to random keys of its own for this SSL_CTX, so a
       context without keys would issue and accept tickets, and an SNI override's keys would be ignored under a keyless base context
       (OpenSSL takes the callback from the session context). ticket_cb without keys issues no ticket, which RFC 8446 section 4.6.1
       allows, and decrypts none: a full handshake. */
    if (role == KSL_SERVER) SSL_CTX_set_tlsext_ticket_key_evp_cb(c->ctx, ticket_cb);
    if (role == KSL_SERVER) SSL_CTX_set_client_hello_cb(c->ctx, ksl_client_hello_cb, c);   /* QUIC ALPN check, SNI pause (KSL_OPT_SNI_PAUSE) */
    if (role == KSL_SERVER) SSL_CTX_set_tlsext_servername_callback(c->ctx, server_name_cb);
    ksl_live_add(KSL_LIVE_CTX, 1);
    return c;
}
void ksl_ctx_free(ksl_ctx *c) {
    if (!c) return; ksl_live_add(KSL_LIVE_CTX, -1); SSL_CTX_free(c->ctx);
    if (c->ticket_keys) { OPENSSL_cleanse(c->ticket_keys, c->ticket_key_count * 80); free(c->ticket_keys); }
    free(c);
}
static int frozen(ksl_ctx *c) { if (c->frozen) { ksl_ctx_set_error(c, KSL_E_CTX_FROZEN, "ksl: context is frozen"); return 1; } return 0; }

int ksl_ctx_set_alpn(ksl_ctx *c, const uint8_t *wire, size_t len) {
    if (frozen(c)) return KSL_ERROR;
    if (!wire || len == 0 || len > sizeof c->alpn) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: alpn list empty or too long"); return KSL_ERROR; }
    memcpy(c->alpn, wire, len); c->alpn_len = len;
    if (c->role == KSL_CLIENT) { if (SSL_CTX_set_alpn_protos(c->ctx, wire, (unsigned)len) != 0) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: bad alpn list"); return KSL_ERROR; } }
    else SSL_CTX_set_alpn_select_cb(c->ctx, alpn_select_cb, c);
    return KSL_OK;
}
int ksl_parse_chain(const uint8_t *framed, size_t len, STACK_OF(X509) **out) {
    STACK_OF(X509) *sk = sk_X509_new_null(); size_t off = 0;
    while (ksl_span_fits(off, 4, len)) {
        size_t l = ((size_t)framed[off] << 24) | ((size_t)framed[off + 1] << 16) | ((size_t)framed[off + 2] << 8) | framed[off + 3]; off += 4;
        if (!ksl_span_fits(off, l, len) || l > LONG_MAX) break;   /* off != len below then refuses the framing */
        const unsigned char *p = framed + off; X509 *x = d2i_X509(NULL, &p, (long)l); if (!x || !sk_X509_push(sk, x)) { X509_free(x); sk_X509_pop_free(sk, X509_free); return 0; }
        off += l;
    }
    if (off != len) { sk_X509_pop_free(sk, X509_free); return 0; }
    *out = sk; return 1;
}
ksl_pkey *ksl_pkey_new(const uint8_t *der, size_t len) {
    if (!der || len == 0 || len > 0x7fffffff) return NULL;
    ERR_clear_error(); const unsigned char *p = der; EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &p, (long)len);
    if (k && p != der + len) { EVP_PKEY_free(k); k = NULL; }   /* trailing bytes: not exactly one key */
    ERR_clear_error(); if (k) ksl_live_add(KSL_LIVE_PKEY, 1); return (ksl_pkey *)k;
}
void ksl_pkey_free(ksl_pkey *k) { if (k) ksl_live_add(KSL_LIVE_PKEY, -1); EVP_PKEY_free((EVP_PKEY *)k); }   /* the key types free their private part with BN_clear_free / OPENSSL_clear_free */
int ksl_ctx_set_identity_pkey(ksl_ctx *c, const uint8_t *chain, size_t chain_len, ksl_pkey *key) {
    if (frozen(c)) return KSL_ERROR; ERR_clear_error();
    if (!key) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: no private key"); return KSL_ERROR; }
    STACK_OF(X509) *sk = NULL; if (!ksl_parse_chain(chain, chain_len, &sk) || sk_X509_num(sk) == 0) { sk_X509_pop_free(sk, X509_free); ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: bad certificate chain framing"); return KSL_ERROR; }
    /* SSL_CTX_use_PrivateKey takes its own reference to the EVP_PKEY: the caller's handle stays independent */
    int ok = SSL_CTX_use_certificate(c->ctx, sk_X509_value(sk, 0)) == 1 && SSL_CTX_use_PrivateKey(c->ctx, (EVP_PKEY *)key) == 1 && SSL_CTX_check_private_key(c->ctx) == 1;
    for (int i = 1; ok && i < sk_X509_num(sk); i++) ok = SSL_CTX_add1_chain_cert(c->ctx, sk_X509_value(sk, i)) == 1;
    sk_X509_pop_free(sk, X509_free);
    if (!ok) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: identity rejected"); return KSL_ERROR; }
    return KSL_OK;
}
int ksl_ctx_set_identity(ksl_ctx *c, const uint8_t *chain, size_t chain_len, const uint8_t *key_der, size_t key_len) {
    if (frozen(c)) return KSL_ERROR;
    ksl_pkey *k = ksl_pkey_new(key_der, key_len);
    if (!k) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: identity rejected"); return KSL_ERROR; }
    int r = ksl_ctx_set_identity_pkey(c, chain, chain_len, k); ksl_pkey_free(k); return r;
}
/* The system store for TrustConfig.Platform on Linux Native (docs/guide/tls.md, "Linux trust store"). The bundled OpenSSL has
   --openssldir=/nonexistent, so the store is located explicitly. SSL_CERT_FILE / SSL_CERT_DIR, when either is set, replace the
   distribution paths (as Go's crypto/x509 does), so a configured store never silently becomes another one. Otherwise the first
   bundle file that loads wins, then the first directory that yields certificates. The lists are Go's (crypto/x509
   root_linux.go), plus /usr/local/etc/openssl/cert.pem. X509_STORE_load_path accepts any string without looking and finds
   certificates only through subject-hash links (c_rehash), so a directory counts only when it holds such links or, like Go
   reads it, PEM files that load: in a distroless or scratch image, or a directory nobody ran c_rehash on, the failure is
   reported here, with the paths searched, instead of as an unknown issuer at every handshake. */
static const char *const default_files[] = {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem", "/usr/local/etc/openssl/cert.pem", NULL};
static const char *const default_dirs[] = {"/etc/ssl/certs", "/etc/pki/tls/certs", NULL};
static const char *const *trust_files = default_files, *const *trust_dirs = default_dirs;
#ifdef KSL_TEST
void ksl_trust_paths_for_test(const char *const *files, const char *const *dirs) { trust_files = files ? files : default_files; trust_dirs = dirs ? dirs : default_dirs; }
#endif
static int is_dir(const char *path) { struct stat sb; return stat(path, &sb) == 0 && S_ISDIR(sb.st_mode); }
/* A c_rehash link name: 8 hex digits, '.', a decimal suffix (CRLs, ".r<n>", do not count) */
static int is_hash_name(const char *n) {
    for (int i = 0; i < 8; i++) if (!isxdigit((unsigned char)n[i])) return 0;
    if (n[8] != '.' || !isdigit((unsigned char)n[9])) return 0;
    for (const char *p = n + 10; *p; p++) if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}
/* A hashed directory is handed to OpenSSL's lookup; any other one is read like Go does: every regular file, the PEM ones load */
static int load_dir(X509_STORE *st, const char *dir) {
    if (!is_dir(dir)) return 0;
    DIR *d = opendir(dir); if (!d) return 0;
    struct dirent *e; int hashed = 0, loaded = 0;
    while (!hashed && (e = readdir(d)) != NULL) hashed = is_hash_name(e->d_name);
    if (hashed) { closedir(d); return X509_STORE_load_path(st, dir) == 1; }
    rewinddir(d);
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[4096]; struct stat sb;
        if (snprintf(path, sizeof path, "%s/%s", dir, e->d_name) >= (int)sizeof path || stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) continue;
        if (X509_STORE_load_file(st, path) == 1) loaded = 1;
    }
    closedir(d); return loaded;
}
static void append(char *out, size_t cap, const char *text) { size_t n = strlen(out); if (n < cap) snprintf(out + n, cap - n, "%s", text); }
void ksl_trust_paths(const char *const **files, const char *const **dirs) { *files = trust_files; *dirs = trust_dirs; }
int ksl_load_system_roots(ksl_ctx *c, X509_STORE *st) {
    const char *ef = getenv("SSL_CERT_FILE"), *ed = getenv("SSL_CERT_DIR"); int from_env = (ef && *ef) || (ed && *ed), loaded = 0;
    if (from_env) {
        if (ef && *ef && X509_STORE_load_file(st, ef) == 1) loaded = 1;
        if (ed && *ed && load_dir(st, ed)) loaded = 1;
    } else {
        for (int i = 0; !loaded && trust_files[i]; i++) if (X509_STORE_load_file(st, trust_files[i]) == 1) loaded = 1;
        for (int i = 0; !loaded && trust_dirs[i]; i++) if (load_dir(st, trust_dirs[i])) loaded = 1;
    }
    ERR_clear_error();
    if (loaded) return KSL_OK;
    char m[KSL_MSG] = "ksl: no CA certificates for TrustConfig.Platform; searched ";
    if (from_env) {
        if (ef && *ef) { append(m, sizeof m, "SSL_CERT_FILE="); append(m, sizeof m, ef); append(m, sizeof m, ed && *ed ? ", " : ""); }
        if (ed && *ed) { append(m, sizeof m, "SSL_CERT_DIR="); append(m, sizeof m, ed); }
        append(m, sizeof m, " (these replace the system paths); point them at a PEM bundle, or a directory of PEM files or c_rehash links");
    } else {
        for (int i = 0; trust_files[i]; i++) { append(m, sizeof m, trust_files[i]); append(m, sizeof m, ", "); }
        for (int i = 0; trust_dirs[i]; i++) { append(m, sizeof m, trust_dirs[i]); append(m, sizeof m, trust_dirs[i + 1] ? "/, " : "/"); }
        append(m, sizeof m, "; install ca-certificates, set SSL_CERT_FILE or SSL_CERT_DIR, or use AnchoredCa");
    }
    ksl_ctx_set_error(c, KSL_E_BAD_ARG, m); return KSL_ERROR;
}
int ksl_ctx_set_roots(ksl_ctx *c, const uint8_t *roots, size_t roots_len) {
    if (frozen(c)) return KSL_ERROR; ERR_clear_error();
    if (roots_len == 0) return ksl_ctx_use_system_store(c);   /* parsed once, shared (ksl_trust_cache.c) */
    X509_STORE *st = ksl_ctx_private_store(c); if (!st) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: no certificate store"); return KSL_ERROR; }
    STACK_OF(X509) *sk = NULL; if (!ksl_parse_chain(roots, roots_len, &sk)) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: bad roots framing"); return KSL_ERROR; }
    int ok = 1; for (int i = 0; ok && i < sk_X509_num(sk); i++) ok = X509_STORE_add_cert(st, sk_X509_value(sk, i)) == 1;
    sk_X509_pop_free(sk, X509_free);
    /* AnchoredCa: every listed certificate is a trust anchor, also one that is not self-signed (an intermediate), as a JDK TrustAnchor,
       an Apple anchor certificate or Go's root pool; without PARTIAL_CHAIN OpenSSL accepts a chain only up to a self-signed root */
    if (ok) ok = X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(c->ctx), X509_V_FLAG_PARTIAL_CHAIN) == 1;
    if (!ok) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: root rejected"); return KSL_ERROR; }
    return KSL_OK;
}
int ksl_ctx_set_ciphers(ksl_ctx *c, const char *tls13_suites, const char *tls12_list) {
    if (frozen(c)) return KSL_ERROR; ERR_clear_error();
    if (tls13_suites && (strlen(tls13_suites) >= sizeof c->suites13 || SSL_CTX_set_ciphersuites(c->ctx, tls13_suites) != 1)) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: bad TLS 1.3 suites"); return KSL_ERROR; }
    if (tls12_list && (strlen(tls12_list) >= sizeof c->list12 || SSL_CTX_set_cipher_list(c->ctx, tls12_list) != 1)) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: bad TLS 1.2 list"); return KSL_ERROR; }
    if (tls13_suites) snprintf(c->suites13, sizeof c->suites13, "%s", tls13_suites);
    if (tls12_list) snprintf(c->list12, sizeof c->list12, "%s", tls12_list);
    return KSL_OK;
}
int ksl_ctx_set_ticket_keys(ksl_ctx *c, const uint8_t *keys, size_t n) {
    if (frozen(c)) return KSL_ERROR;
    if (!keys || n == 0) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: no ticket keys"); return KSL_ERROR; }
    uint8_t *copy = malloc(n * 80); if (!copy) return KSL_ERROR; memcpy(copy, keys, n * 80);
    if (c->ticket_keys) { OPENSSL_cleanse(c->ticket_keys, c->ticket_key_count * 80); free(c->ticket_keys); }
    c->ticket_keys = copy; c->ticket_key_count = n; return KSL_OK;   /* ticket_cb (installed by ksl_ctx_new) reads them */
}
/* Binds tickets to a server configuration: OpenSSL resumes a session only when its sid_ctx equals the SSL's, otherwise a full handshake
   runs. Kotlin derives it from the trust configuration, so a resumed session proves this configuration's verdict. */
int ksl_ctx_set_session_context(ksl_ctx *c, const uint8_t *sid_ctx, size_t len) {
    if (frozen(c)) return KSL_ERROR; ERR_clear_error();
    if (!sid_ctx || len == 0 || len > SSL_MAX_SID_CTX_LENGTH || SSL_CTX_set_session_id_context(c->ctx, sid_ctx, (unsigned)len) != 1) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: session context is 1..32 bytes"); return KSL_ERROR; }
    memcpy(c->sid_ctx, sid_ctx, len); c->sid_ctx_len = len;
    return KSL_OK;
}
int ksl_ctx_set_option(ksl_ctx *c, int option, int value) {
    if (frozen(c)) return KSL_ERROR;
    switch (option) {
    case KSL_OPT_VERIFY_MODE:
        if (value < KSL_VERIFY_NONE || value > KSL_VERIFY_OPENSSL) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: verify mode is 0..2"); return KSL_ERROR; }
        if (c->role == KSL_SERVER && value == KSL_VERIFY_PAUSE) { ksl_ctx_set_error(c, KSL_E_SERVER_PAUSE_FORBIDDEN, "ksl: verify pause is client-only (OpenSSL would accept silently)"); return KSL_ERROR; }
        c->verify_mode = value;
        if (c->role == KSL_CLIENT) SSL_CTX_set_verify(c->ctx, value == KSL_VERIFY_NONE ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
        return KSL_OK;
    case KSL_OPT_CLIENT_CERT:
        /* on a client this would rewrite SSL_CTX_set_verify and switch server verification off */
        if (c->role != KSL_SERVER || value < KSL_CLIENT_CERT_NONE || value > KSL_CLIENT_CERT_REQUIRED) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: client certificate mode is server-only (0..2)"); return KSL_ERROR; }
        c->client_cert_mode = value;
        SSL_CTX_set_verify(c->ctx, value == KSL_CLIENT_CERT_NONE ? SSL_VERIFY_NONE : value == KSL_CLIENT_CERT_OPTIONAL ? SSL_VERIFY_PEER : SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        return KSL_OK;
    case KSL_OPT_MIN_VERSION: return SSL_CTX_set_min_proto_version(c->ctx, value) == 1 ? KSL_OK : KSL_ERROR;
    case KSL_OPT_MAX_VERSION: return SSL_CTX_set_max_proto_version(c->ctx, value) == 1 ? KSL_OK : KSL_ERROR;
    case KSL_OPT_NUM_TICKETS: c->num_tickets = (size_t)value; return SSL_CTX_set_num_tickets(c->ctx, (size_t)value) == 1 ? KSL_OK : KSL_ERROR;
    case KSL_OPT_KEYLOG: c->keylog = value != 0; return KSL_OK;
    case KSL_OPT_GENERIC_ALERTS: c->generic_alerts = value != 0; return KSL_OK;
    case KSL_OPT_TICKET_LIFETIME: return SSL_CTX_set_timeout(c->ctx, value) >= 0 ? KSL_OK : KSL_ERROR;
    case KSL_OPT_EARLY_DATA:
        if (c->role != KSL_SERVER) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: early data option is server-only"); return KSL_ERROR; }
        c->early_data = value != 0; if (c->early_data) ksl_ctx_enable_early_data(c->ctx); return KSL_OK;
    case KSL_OPT_SNI_PAUSE:
        if (c->role != KSL_SERVER) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: SNI pause is server-only"); return KSL_ERROR; }
        c->sni_pause = value != 0; return KSL_OK;
    default: ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: unknown option"); return KSL_ERROR;
    }
}
int ksl_ctx_freeze(ksl_ctx *c) { c->frozen = 1; return KSL_OK; }
