/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Private structures shared by the ksl translation units. Not part of the ABI. */
#ifndef KSL_INTERNAL_H
#define KSL_INTERNAL_H
#include "ksl.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#define KSL_EVQ 32
#define KSL_NLEVELS 4
#define KSL_MSG 512

typedef struct { uint8_t *buf; size_t len, cap, consumed; } ksl_inbuf;

struct ksl_ctx {
    SSL_CTX *ctx;
    int role, verify_mode, client_cert_mode, frozen, sni_pause, keylog, generic_alerts, early_data;
    size_t num_tickets;
    uint8_t alpn[256]; size_t alpn_len;
    uint8_t *ticket_keys; size_t ticket_key_count;   /* 80-byte entries, first encrypts */
    uint32_t last_err; char last_msg[KSL_MSG];
};

struct ksl_ssl {
    ksl_ctx *owner;
    SSL *ssl;
    int mode, done, fatal, read_level, write_level;
    uint8_t *tp; size_t tp_len;                      /* must outlive the handshake: OpenSSL keeps the pointer */
    uint32_t quic_version; int hs_keys;              /* version whose labels derive Handshake/1-RTT keys; set once Handshake keys exist */
    ksl_inbuf in[KSL_NLEVELS], stash[KSL_NLEVELS];   /* stash receives bytes while a record is outstanding */
    int rcd_level;                                   /* level of the record handed to OpenSSL and not yet released, or -1 */
    ksl_event q[KSL_EVQ]; uint8_t *qbuf[KSL_EVQ]; int qh, qt;
    uint8_t *last_popped;
    /* verification */
    int verify_name_set; char *verify_host; char *verify_ip; unsigned verify_flags;
    int verify_pending, verify_decision, verify_alert;
    STACK_OF(X509) *presented_chain, *validated_chain;
    /* 0-RTT (server): context stamped into tickets, the transport's verdict, whether the resumed ticket's context matched */
    uint8_t early_ctx[64]; size_t early_ctx_len; int early_allow, early_ctx_match;
    /* server SNI pause */
    int sni_pending, sni_decision_alert; ksl_ctx *sni_override;
    /* TCP mode */
    BIO *net;                                        /* our end of the bio pair */
    /* keylog lines */
    char *keylog; size_t keylog_len, keylog_cap;
    /* errors */
    int verify_err;                                  /* X509_V_ERR_* of the last local verification failure */
    uint32_t last_err; int last_alert; char last_msg[KSL_MSG];
};

struct ksl_key {
    int kind;                  /* 0 packet key; KSL_EKEY_TOKEN; KSL_EKEY_RESET (no cipher contexts, secret = HMAC key) */
    EVP_CIPHER_CTX *enc, *dec; EVP_CIPHER_CTX *hp_ctx;
    int aead, hash; uint32_t version;
    uint8_t secret[48]; size_t secret_len;           /* kept for ksl_key_next; zeroed on free */
    uint8_t key[32], iv[12], hp[32]; size_t key_len;
};

/* live-object counters (ksl_lib.c): which = KSL_LIVE_*, relaxed atomic add */
void ksl_live_add(int which, int delta);

/* error helpers (ksl_lib.c) */
uint32_t ksl_pack_openssl_error(unsigned long e);
void ksl_ctx_set_error(ksl_ctx *c, uint32_t fallback, const char *msg);
void ksl_ssl_set_error(ksl_ssl *s, uint32_t fallback, const char *msg);
int ksl_ssl_fail(ksl_ssl *s, uint32_t code, const char *msg);   /* records, marks fatal, returns KSL_ERROR */

/* event queue (ksl_quic.c) */
ksl_event *ksl_push_event(ksl_ssl *s, int type, const uint8_t *copy_from, size_t len);

/* verification (ksl_verify.c) */
int ksl_cert_verify_cb(X509_STORE_CTX *xctx, void *arg);
int ksl_client_hello_cb(SSL *ssl, int *al, void *arg);

/* 0-RTT (ksl_ctx.c) */
void ksl_ctx_enable_early_data(SSL_CTX *ctx);

/* keys (ksl_key.c) */
ksl_key *ksl_key_from_secret(int aead, const uint8_t *secret, size_t slen, uint32_t version);
int ksl_aead_of_cipher(const SSL_CIPHER *c);

/* bounds: n bytes at off fit in a buffer of len (off <= len). Written so nothing can wrap: a 32-bit length field on a 32-bit size_t
   (armeabi-v7a) would wrap off + n past len. */
static inline int ksl_span_fits(size_t off, size_t n, size_t len) { return off <= len && n <= len - off; }

/* shared crypto (ksl_crypto.c) */
int ksl_hkdf_extract(int hash, const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il, uint8_t *out, size_t olen);
int ksl_parse_chain(const uint8_t *framed, size_t len, STACK_OF(X509) **out);
#endif
