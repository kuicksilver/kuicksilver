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

/* System-OpenSSL mode (KSL_SYSTEM_OPENSSL, Linux only): the newest OpenSSL major version a system libssl may have. The one switch of
 * the accepted range: the default is 3 (3.5 and newer 3.x), so a libssl.so.4 is refused with KSL_INIT_VERSION. 4.x is prepared
 * but not supported in 0.3.0; building with -DKSL_SYSTEM_OPENSSL_MAX_MAJOR=4 (tools/ci/system-openssl.sh reads
 * KSL_SYSTEM_OPENSSL_MAX_MAJOR) is how the range is opened once 4.x is supported. */
#define KSL_SYSTEM_OPENSSL_DEFAULT_MAX_MAJOR 3
#ifndef KSL_SYSTEM_OPENSSL_MAX_MAJOR
#define KSL_SYSTEM_OPENSSL_MAX_MAJOR KSL_SYSTEM_OPENSSL_DEFAULT_MAX_MAJOR
#endif
/* Whether a libssl reporting OpenSSL_version_num() == num lies in the accepted range: at least 3.5.0, at most major max_major.
 * Always compiled, so the C tests cover the range without a system libssl. */
int ksl_system_openssl_version_ok(unsigned long num, unsigned max_major);

#define KSL_EVQ 32
#define KSL_NLEVELS 4
#define KSL_QUIC_LEVEL_MAX (256u * 1024u) /* unread CRYPTO bytes ksl holds per level (ksl_quic_provide) */
#define KSL_MSG 512
/* clang-format off */
#define KSL_CLIENT_TICKETS 6 /* tickets a TCP client session keeps until they are handed out (ksl_ctx.c new_session_cb) */
/* clang-format on */

typedef struct {
    uint8_t *buf;
    size_t len, cap, consumed;
} ksl_inbuf;

struct ksl_ctx {
    SSL_CTX *ctx;
    int role, verify_mode, client_cert_mode, frozen, sni_pause, keylog, generic_alerts, early_data, level_after_pause;
    size_t num_tickets;
    uint8_t alpn[256];
    size_t alpn_len;
    /* settings SSL_new copies into each session, kept so an SNI override can apply them (ksl_ctx_apply_to_ssl) */
    char suites13[256], list12[512];
    const char *groups;
    uint8_t sid_ctx[32];
    size_t sid_ctx_len;
    uint8_t *ticket_keys;
    size_t ticket_key_count; /* 80-byte entries, first encrypts */
    uint32_t
        ticket_rotate; /* > 0: the process's generated keys, rotated at this period (ksl_tickets.c), instead of ticket_keys */
    int64_t auth_timeout; /* server: seconds a resumption chain may follow its full handshake (ksl_ctx.c) */
    uint8_t leaf_sha256[32];
    int64_t leaf_not_after;
    int has_leaf;     /* the identity's leaf, digested once when it is set (tickets bind it) */
    int shared_roots; /* the cert store is the process-wide system store: never modified */
    uint32_t last_err;
    char last_msg[KSL_MSG];
};

struct ksl_ssl {
    ksl_ctx *owner;
    SSL *ssl;
    int mode, done, fatal, read_level, write_level;
    uint8_t *tp;
    size_t tp_len; /* must outlive the handshake: OpenSSL keeps the pointer */
    uint32_t quic_version;
    int hs_keys; /* version whose labels derive Handshake/1-RTT keys; set once Handshake keys exist */
    uint32_t
        orig_version; /* server: the client's original version (0 until negotiated); labels of 0-RTT keys (RFC 9369 4.1) */
    ksl_inbuf in[KSL_NLEVELS], stash[KSL_NLEVELS]; /* stash receives bytes while a record is outstanding */
    int rcd_level; /* level of the record handed to OpenSSL and not yet released, or -1 */
    ksl_event q[KSL_EVQ];
    uint8_t *qbuf[KSL_EVQ];
    int qh, qt;
    uint8_t *last_popped;
    /* verification */
    int verify_mode; /* the owner's KSL_VERIFY_* when the session was made (or its SNI override's) */
    int verify_name_set;
    char *verify_host;
    char *verify_ip;
    unsigned verify_flags;
    int verify_pending, verify_decision, verify_alert;
    STACK_OF(X509) * presented_chain, *validated_chain;
    /* 0-RTT (server): context stamped into tickets, the transport's verdict, whether the resumed ticket's context matched */
    uint8_t early_ctx[64];
    size_t early_ctx_len;
    int early_allow, early_ctx_match;
    /* server: digest of the ClientHello's host name, bound into every ticket (RFC 6066 section 3, ksl_client_hello_cb) */
    uint8_t sni_tag[32];
    /* server: when the session being resumed was authenticated (its full handshake, epoch seconds), carried into renewed tickets */
    int64_t auth_time;
    int skip_ticket; /* server: ticket_gen_cb found no time left for a ticket; ticket_cb then issues none */
    /* server SNI pause */
    int sni_pending, sni_decision_alert;
    ksl_ctx *sni_override;
    /* KSL_OPT_NUM_TICKETS 0: set by ksl_ssl_new_session_ticket, the only way such a session gets a ticket (after the pin verdict) */
    int ticket_authorized;
    /* TCP mode */
    BIO *net;        /* our end of the bio pair */
    int abort_alert; /* ksl_tcp_abort: the next ticket (server) or ClientHello (client) fails with internal_error */
    uint8_t *pending_write;
    size_t
        pending_write_len; /* a copy of the bytes of the write ksl_tcp_write left pending in OpenSSL (WANT_READ), for ksl_tcp_abort */
    int pending_write_unkept; /* such a write is pending but its copy could not be made (malloc failed) */
    SSL_SESSION *new_sessions[KSL_CLIENT_TICKETS];
    int new_sessions_n;           /* client: tickets not yet handed out by ksl_ssl_get1_session, oldest first */
    SSL_SESSION *offered_session; /* client: the session set by ksl_ssl_set_session (a reference), for own_alpn */
    uint64_t key_updates_sent,
        key_update_limit; /* KeyUpdates written; the bound (RFC 9846 4.7.3), 0 = KSL_MAX_KEY_UPDATES */
    int key_updates_exhausted,
        update_requested_pending; /* the bound was reached: no more KeyUpdates of ours; our update_requested awaits the peer's KeyUpdate */
    uint64_t fed,
        update_requested_at; /* ciphertext bytes fed (ksl_tcp_feed); how many had been when our update_requested was written */
    int server_hello_ems,
        ems_refused; /* client: the ServerHello carried extended_master_secret; the handshake was refused for its lack (RFC 7627 section 5.2) */
    uint64_t records_sent,
        key_update_records; /* records written under the current key; the bound for a KeyUpdate (ksl_tcp_write) */
    int app_keys_out;       /* our application keys are in use (ksl_msg_cb): records count from here */
    int limit_due;          /* a read reached the record limit: the next call ends the session (ksl_tcp_read) */
    uint64_t record_limit;  /* records the current keys may protect (RFC 9846 5.5), per AEAD; 0 = not yet known */
    /* keylog lines */
    char *keylog;
    size_t keylog_len, keylog_cap;
#ifdef KSL_TEST
    void (*msg_observer)(int, int, int, const void *, size_t, SSL *, void *);
    void *msg_observer_arg;
#endif
    /* errors */
    int verify_err; /* X509_V_ERR_* of the last local verification failure */
    uint32_t last_err;
    int last_alert;
    char last_msg[KSL_MSG];
};

/* Epoch seconds for the ticket checks (ksl_ctx.c); test builds can move it to age tickets without waiting. */
int64_t ksl_ticket_now(void);
#ifdef KSL_TEST
extern int64_t ksl_test_ticket_clock_skew;
#endif

struct ksl_key {
    int kind; /* 0 packet key; KSL_EKEY_TOKEN; KSL_EKEY_RESET (no cipher contexts, secret = HMAC key); KSL_EKEY_LB (key[16], lb_enc/lb_dec templates) */
    EVP_CIPHER_CTX *enc, *dec;
    EVP_CIPHER_CTX *hp_ctx;
    EVP_CIPHER_CTX *lb_enc, *lb_dec; /* KSL_EKEY_LB: expanded once, never used directly; ksl_key_ecb16 runs on a copy */
    int aead, hash;
    uint32_t version;
    uint8_t secret[48];
    size_t secret_len; /* kept for ksl_key_next; zeroed on free */
    uint8_t key[32], iv[12], hp[32];
    size_t key_len;
};

/* live-object counters (ksl_lib.c): which = KSL_LIVE_*, relaxed atomic add */
void ksl_live_add(int which, int delta);

/* error helpers (ksl_lib.c) */
uint32_t ksl_pack_openssl_error(unsigned long e);
void ksl_ctx_set_error(ksl_ctx *c, uint32_t fallback, const char *msg);
void ksl_ssl_set_error(ksl_ssl *s, uint32_t fallback, const char *msg);
int ksl_ssl_fail(ksl_ssl *s, uint32_t code, const char *msg); /* records, marks fatal, returns KSL_ERROR */

/* event queue (ksl_quic.c) */
ksl_event *ksl_push_event(ksl_ssl *s, int type, const uint8_t *copy_from, size_t len);
size_t ksl_quic_pending(const ksl_ssl *s, int level); /* CRYPTO bytes provided at level and not yet read by TLS */

/* verification (ksl_verify.c) */
int ksl_cert_verify_cb(X509_STORE_CTX *xctx, void *arg);
int ksl_chain_security(int level,
                       STACK_OF(X509) *
                           chain); /* ksl_verify.c: X509_V_OK or the X509 error of the first weak key or signature */
int ksl_client_hello_cb(SSL *ssl, int *al, void *arg);
int ksl_client_hello_sni(SSL *ssl, const unsigned char **name,
                         size_t *len); /* during the ClientHello: its host_name, if any */
/* RFC 9846 section 4.7.3: "sending implementations MUST NOT allow the epoch -- and hence the number of key updates -- to exceed 2^48-1" */
#define KSL_MAX_KEY_UPDATES ((UINT64_C(1) << 48) - 1)
void ksl_msg_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl,
                void *arg); /* a TCP client's handshake messages (ksl_ssl.c) */

/* the system CA store (ksl_ctx.c, ksl_trust_cache.c) */
void ksl_trust_paths(const char *const **files, const char *const **dirs);
int ksl_load_system_roots(ksl_ctx *c, X509_STORE *st);
int ksl_ctx_use_system_store(ksl_ctx *c);
X509_STORE *ksl_ctx_private_store(ksl_ctx *c);

/* 0-RTT (ksl_ctx.c) */
void ksl_ctx_enable_early_data(SSL_CTX *ctx);
int ksl_ctx_apply_to_ssl(ksl_ctx *o, SSL *ssl);

/* the process's generated ticket keys (ksl_tickets.c): 1 found, 0 no such key, -1 failure */
int ksl_default_ticket_key(uint32_t rotate_seconds, const uint8_t *name, uint8_t out[80], int *current);

/* Fields one thread writes while another reads them without a lock (ksl_udp: the closed flag a shutdown sets under a blocked
   receiver, the counters ksl_udp_get(STATS) reads): C11 atomics through the GCC/Clang builtins (every toolchain ksl builds with). */
#define KSL_ALOAD(x) __atomic_load_n(&(x), __ATOMIC_ACQUIRE)
#define KSL_COUNT(x) ((void)__atomic_add_fetch(&(x), 1, __ATOMIC_RELAXED))
#define KSL_RELAXED(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)

/* keys (ksl_key.c) */
ksl_key *ksl_key_from_secret(int aead, const uint8_t *secret, size_t slen, uint32_t version);
int ksl_aead_of_cipher(const SSL_CIPHER *c);

/* bounds: n bytes at off fit in a buffer of len (off <= len). Written so nothing can wrap: a 32-bit length field on a 32-bit size_t
   (armeabi-v7a) would wrap off + n past len. */
static inline int ksl_span_fits(size_t off, size_t n, size_t len) {
    return off <= len && n <= len - off;
}

/* shared crypto (ksl_crypto.c) */
/* ciphers fetched once per process (ksl_crypto.c): the fetched one, or `legacy` when the fetch failed */
#define KSL_CIPHER_AES_128_GCM 0
#define KSL_CIPHER_AES_256_GCM 1
#define KSL_CIPHER_CHACHA20_POLY1305 2
#define KSL_CIPHER_AES_128_ECB 3
#define KSL_CIPHER_AES_256_ECB 4
#define KSL_CIPHER_CHACHA20 5
#define KSL_CIPHER_AES_256_CBC 6
#define KSL_CIPHER_COUNT 7
const EVP_CIPHER *ksl_cipher(int which, const EVP_CIPHER *legacy);
int ksl_hkdf_extract(int hash, const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il, uint8_t *out,
                     size_t olen);
int ksl_parse_chain(const uint8_t *framed, size_t len, STACK_OF(X509) * *out);
#endif
