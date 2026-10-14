/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ksl: the C shim between Kuicksilver and OpenSSL 3.5 (ADR-0003).
 *
 * Contract:
 *  - stable C ABI, KSL_ABI_VERSION bumps on any incompatible change;
 *  - no upcalls: OpenSSL callbacks only append to the session's event queue;
 *  - input buffers are copied and owned by ksl; a CRYPTO record handed to OpenSSL is never moved before release;
 *  - packet keys never leave native memory: callers get ksl_key handles;
 *  - errors: every call clears the OpenSSL error queue on entry and copies the error into the object,
 *    read it with ksl_ctx_last_error / ksl_ssl_last_error in the same ownership context;
 *  - one owner at a time per ksl_ssl / ksl_key; ksl_ctx is immutable after ksl_ctx_freeze.
 */
#ifndef KSL_H
#define KSL_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* 2: ksl_ssl_set replaces ksl_ssl_set_sni/ksl_ssl_set_verify_name; QUIC version selector (K2) */
#define KSL_ABI_VERSION 6u
/* 3 (K3): endpoint keys ksl_key_random / ksl_key_mac16 (and ksl_udp_*) */
/* 4: client sessions stay native (the session holds resumption secrets) — ksl_ssl_get1_session / ksl_session_free, ksl_ssl_set_session takes a handle,
   KSL_GET_SESSION (serialized session bytes) removed; ksl_ctx_set_session_context (a ticket resumes only under the trust configuration that issued it) */
/* 5: identity private keys stay native — ksl_pkey_new / ksl_pkey_free / ksl_ctx_set_identity_pkey (a parsed key shared by reference
   between contexts, so the caller keeps no DER copy of it) */
/* 6: 0-RTT — KSL_OPT_EARLY_DATA, KSL_SET_EARLY_CONTEXT, KSL_SET_EARLY_DATA, KSL_GET_EARLY_DATA; the 0-RTT secret arrives as KSL_EV_KEY at KSL_LEVEL_EARLY (ADR-0015) */

/* return codes */
#define KSL_OK 0
#define KSL_WANT_READ 1
#define KSL_WANT_VERIFY 2
#define KSL_WANT_SNI 3
#define KSL_EOF 4
#define KSL_ERROR (-1)

/* roles, modes, options */
#define KSL_CLIENT 0
#define KSL_SERVER 1
#define KSL_MODE_QUIC 0
#define KSL_MODE_TCP 1
#define KSL_VERIFY_NONE 0
#define KSL_VERIFY_PAUSE 1
#define KSL_VERIFY_OPENSSL 2
#define KSL_CLIENT_CERT_NONE 0
#define KSL_CLIENT_CERT_OPTIONAL 1
#define KSL_CLIENT_CERT_REQUIRED 2
#define KSL_TLS1_2 0x0303
#define KSL_TLS1_3 0x0304

/* ksl_ctx_set_option keys */
#define KSL_OPT_VERIFY_MODE 1      /* KSL_VERIFY_* */
#define KSL_OPT_CLIENT_CERT 2      /* KSL_CLIENT_CERT_* (server only: KSL_E_BAD_ARG on a client context) */
#define KSL_OPT_MIN_VERSION 3      /* KSL_TLS1_2 | KSL_TLS1_3; QUIC contexts are always TLS 1.3 */
#define KSL_OPT_MAX_VERSION 4
#define KSL_OPT_NUM_TICKETS 5      /* TLS 1.3 tickets sent automatically after the handshake (server); 0 also suppresses the in-handshake TLS 1.2 ticket (with ticket keys set) */
#define KSL_OPT_KEYLOG 6           /* 1 = collect RFC 9850 lines, drained with KSL_GET_KEYLOG */
#define KSL_OPT_SNI_PAUSE 7        /* 1 = server pauses at ClientHello with KSL_WANT_SNI */
#define KSL_OPT_GENERIC_ALERTS 8   /* 1 = every verification failure is sent as handshake_failure (40) */
#define KSL_OPT_TICKET_LIFETIME 9  /* seconds a server-issued ticket stays valid */
#define KSL_OPT_EARLY_DATA 10      /* server, 1 = QUIC sessions accept 0-RTT: tickets carry early_data, OpenSSL's cache-based anti-replay is off
                                      (SSL_OP_NO_ANTI_REPLAY; the transport keeps the replay register), and each hello needs KSL_SET_EARLY_DATA
                                      plus a matching KSL_SET_EARLY_CONTEXT; KSL_E_BAD_ARG on a client context */

/* ksl_ssl_get keys */
#define KSL_GET_ALPN 1             /* negotiated protocol, bytes */
#define KSL_GET_VERSION 2          /* 2 bytes big-endian: 0x0303 / 0x0304 */
/* 3: was KSL_GET_SESSION (serialized session, ABI <= 3); sessions are ksl_session handles now (ksl_ssl_get1_session) */
#define KSL_GET_CHANNEL_BINDING 4  /* RFC 9266 tls-exporter, 32 bytes */
#define KSL_GET_KEYLOG 5           /* drains collected keylog lines (only with KSL_OPT_KEYLOG) */
#define KSL_GET_SESSION_REUSED 6   /* 1 byte: 1 if the handshake resumed a session */
#define KSL_GET_EMS 7              /* 1 byte: 1 if extended master secret was used (TLS 1.2) */
#define KSL_GET_QUIC_VERSION 8     /* 4 bytes big-endian: negotiated (server, RFC 9368) or set (client) QUIC version */
#define KSL_GET_EARLY_DATA 9       /* 1 byte: 0 not attempted, 1 rejected, 2 accepted (final once EncryptedExtensions is sent / received) */
#define KSL_GET_QUIC_PENDING 10    /* 16 bytes: per level 0..3, 4 bytes big-endian, CRYPTO bytes provided and not yet read by TLS */

/* ksl_ssl_set keys */
#define KSL_SET_SNI 1              /* data = host name, ASCII */
#define KSL_SET_VERIFY_NAME 2      /* data = DNS-ID or IP literal; required for verifying clients */
#define KSL_SET_QUIC_VERSION 3     /* data = 4-byte big-endian QUIC version (0x00000001 | 0x6b3343cf): labels for Handshake/1-RTT keys (RFC 9369 3.3);
                                      unknown -> KSL_E_BAD_ARG, after Handshake keys exist -> KSL_E_TOO_LATE */
#define KSL_SET_EARLY_CONTEXT 4    /* server, 1..64 bytes before the first drive: written into every ticket this session issues; a resumed ticket
                                      whose stored context differs gets no early data (RFC 9001 section 4.6.3). Every server ticket also
                                      carries the QUIC version of its connection (the negotiated one); a ticket of another version than
                                      the client's original one is not resumed (RFC 9369 section 5) */
#define KSL_SET_EARLY_DATA 5       /* 1 byte before the first drive. Client: 1 = send 0-RTT with the session set by ksl_ssl_set_session
                                      (KSL_E_NOT_SUPPORTED when its ticket does not allow early data). Server: 1 = the transport admits early
                                      data for this hello (replay register), 0 = refuse; KSL_E_NOT_SUPPORTED without KSL_OPT_EARLY_DATA */

/* ksl_ssl_get_peer_chain selector */
#define KSL_CHAIN_PRESENTED 0      /* as sent by the peer: leaf first (available during the pause) */
#define KSL_CHAIN_VALIDATED 1      /* as built by the OpenSSL verifier (KSL_VERIFY_OPENSSL only) */

/* AEADs, hashes, signature algorithms */
#define KSL_AEAD_AES_128_GCM 1
#define KSL_AEAD_AES_256_GCM 2
#define KSL_AEAD_CHACHA20_POLY1305 3
#define KSL_HASH_SHA256 1
#define KSL_HASH_SHA384 2
#define KSL_SIG_ECDSA_P256 1
#define KSL_SIG_ED25519 2
#define KSL_DIR_READ 0
#define KSL_DIR_WRITE 1

/* QUIC encryption levels (OSSL_RECORD_PROTECTION_LEVEL_*) and event types */
#define KSL_LEVEL_INITIAL 0
#define KSL_LEVEL_EARLY 1
#define KSL_LEVEL_HANDSHAKE 2
#define KSL_LEVEL_APPLICATION 3
#define KSL_EV_CRYPTO_SEND 1       /* buf/len: CRYPTO bytes for `level` */
#define KSL_EV_KEY 2               /* key: handle for `level`/`direction`, aead set; ownership moves to the caller */
#define KSL_EV_TRANSPORT_PARAMS 3  /* buf/len: peer transport parameters */
#define KSL_EV_HANDSHAKE_DONE 4

/* ksl's own error codes: packed = (lib 0xff << 16) | reason */
#define KSL_E_NO_VERIFY_NAME 0xff0001u
#define KSL_E_SERVER_PAUSE_FORBIDDEN 0xff0002u
#define KSL_E_NOT_PAUSED 0xff0003u
#define KSL_E_CTX_FROZEN 0xff0004u
#define KSL_E_BAD_ARG 0xff0005u
#define KSL_E_HOSTNAME_MISMATCH 0xff0006u
#define KSL_E_EMS_REQUIRED 0xff0007u
#define KSL_E_NOT_SUPPORTED 0xff0008u
#define KSL_E_TRUNCATED 0xff0009u
#define KSL_E_TOO_LATE 0xff000au      /* the setting cannot change at this stage of the handshake */
#define KSL_E_CRYPTO_LEVEL 0xff000bu  /* ksl_quic_provide: a level TLS no longer reads (RFC 9001 4.1.3) or more than
                                         KSL_QUIC_LEVEL_MAX unread bytes at one level */

typedef struct ksl_ctx ksl_ctx;
typedef struct ksl_ssl ksl_ssl;
typedef struct ksl_key ksl_key;
typedef struct ksl_pkey ksl_pkey;         /* a parsed private key (EVP_PKEY, reference counted); the key bytes never leave ksl */
typedef struct ksl_session ksl_session;   /* a client's resumable TLS session (ticket + resumption secret); never serialized out of ksl */

typedef struct ksl_event {
    int32_t type, level, direction, aead;
    const uint8_t *buf;        /* valid until the next ksl_quic_next_event */
    size_t len;
    ksl_key *key;              /* KSL_EV_KEY only */
} ksl_event;

typedef struct ksl_client_hello {
    const uint8_t *sni; size_t sni_len;              /* host name without the type/length prefix, or NULL */
    const uint8_t *alpn; size_t alpn_len;            /* ALPN protocol list in wire format */
    const uint8_t *sig_algs; size_t sig_algs_len;    /* signature_algorithms list in wire format */
} ksl_client_hello;

/* --- library --- */
/* ksl_init return codes beyond KSL_OK (system-OpenSSL builds, Linux only) */
#define KSL_INIT_VERSION (-2)         /* OpenSSL < 3.5 or 4.x */
#define KSL_INIT_MISSING_SYMBOL (-3)  /* no SSL_set_quic_tls_cbs */
#define KSL_INIT_KEYLOG_ENV (-4)      /* SSLKEYLOGFILE set with a system libssl: refused */
int         ksl_init(void);                         /* idempotent */
const char *ksl_version(void);                      /* "ksl abi 6 / OpenSSL 3.5.9 ..." */
uint32_t    ksl_abi_version(void);
/* Live-object counters, process-wide (soak and churn tests; additive in ABI 6, see ADR-0003): objects ksl made and has not
 * freed yet. A handle-reference counter (pkey, session) counts the references ksl handed out and the caller has not dropped;
 * references OpenSSL keeps inside a context or a session are not counted. Relaxed atomics: a snapshot, not a barrier. */
#define KSL_LIVE_CTX 0             /* ksl_ctx */
#define KSL_LIVE_SSL 1             /* ksl_ssl */
#define KSL_LIVE_KEY 2             /* ksl_key: packet keys (KSL_EV_KEY handles included), token and reset keys */
#define KSL_LIVE_PKEY 3            /* ksl_pkey references from ksl_pkey_new not yet dropped with ksl_pkey_free */
#define KSL_LIVE_SESSION 4         /* ksl_session references from ksl_ssl_get1_session not yet dropped with ksl_session_free */
#define KSL_LIVE_UDP 5             /* ksl_udp objects opened and not closed */
#define KSL_LIVE_WAKE 6            /* wake descriptors those ksl_udp objects hold: pipe ends (Linux, Apple) or wake sockets (Windows) */
#define KSL_LIVE_COUNT 7
int         ksl_live_objects(int64_t *out, size_t n);  /* writes the first min(n, KSL_LIVE_COUNT) counters; returns KSL_LIVE_COUNT */

/* --- context (immutable after freeze) --- */
ksl_ctx *ksl_ctx_new(int role);
void     ksl_ctx_free(ksl_ctx *);
int      ksl_ctx_set_alpn(ksl_ctx *, const uint8_t *wire, size_t len);
/* chain: concatenation of (uint32 big-endian length || DER), leaf first; key: PKCS#8 DER */
int      ksl_ctx_set_identity(ksl_ctx *, const uint8_t *chain, size_t chain_len, const uint8_t *key_der, size_t key_len);
/* the same with a parsed key: the context takes its own reference, so the caller may free its handle right after */
int      ksl_ctx_set_identity_pkey(ksl_ctx *, const uint8_t *chain, size_t chain_len, ksl_pkey *key);
ksl_pkey *ksl_pkey_new(const uint8_t *der, size_t len);              /* PKCS#8 (or traditional) DER; NULL if it is not one key with nothing after it */
void     ksl_pkey_free(ksl_pkey *);                                   /* drops one reference; the last one frees and cleanses the key */
int      ksl_ctx_set_roots(ksl_ctx *, const uint8_t *roots, size_t roots_len);  /* same framing; empty = system store */
int      ksl_ctx_set_ciphers(ksl_ctx *, const char *tls13_suites, const char *tls12_list);
int      ksl_ctx_set_ticket_keys(ksl_ctx *, const uint8_t *keys, size_t n);     /* n x 80 bytes: name16 | aes32 | hmac32; first encrypts */
int      ksl_ctx_set_session_context(ksl_ctx *, const uint8_t *sid_ctx, size_t len); /* server, 1..32 bytes: a session (ticket) resumes only under the same context (default "ksl") */
int      ksl_ctx_set_option(ksl_ctx *, int option, int value);
int      ksl_ctx_freeze(ksl_ctx *);
int      ksl_ctx_last_error(ksl_ctx *, uint32_t *packed, char *buf, size_t len);

/* --- session (QUIC or TCP) --- */
ksl_ssl *ksl_ssl_new(ksl_ctx *, int mode);
void     ksl_ssl_free(ksl_ssl *);
int      ksl_ssl_set(ksl_ssl *, int what, const uint8_t *data, size_t len);   /* KSL_SET_* */
int      ksl_ssl_get(ksl_ssl *, int what, uint8_t *out, size_t cap, size_t *len);
int      ksl_ssl_get_peer_chain(ksl_ssl *, int which, int idx, uint8_t *out, size_t cap, size_t *len); /* idx -1 -> count; on a resumed session both selectors yield the peer leaf stored in the session */
int      ksl_ssl_verify_resume(ksl_ssl *, int accept, int alert);   /* after KSL_WANT_VERIFY */
int      ksl_ssl_client_hello(ksl_ssl *, ksl_client_hello *out);     /* during KSL_WANT_SNI */
int      ksl_ssl_sni_resume(ksl_ssl *, ksl_ctx *override_or_null, int alert); /* after KSL_WANT_SNI */
int      ksl_ssl_export_keying_material(ksl_ssl *, uint8_t *out, size_t out_len, const char *label, size_t label_len, const uint8_t *context, size_t context_len);
ksl_session *ksl_ssl_get1_session(ksl_ssl *);                     /* client: the resumable session (a new reference) or NULL; the same pointer until the session changes */
int      ksl_ssl_set_session(ksl_ssl *, ksl_session *);           /* client, before the handshake; the caller keeps its reference */
void     ksl_session_free(ksl_session *);                         /* drops one reference; the last one cleanses the secrets */
int      ksl_ssl_new_session_ticket(ksl_ssl *);                      /* server: queue one ticket now */
int      ksl_ssl_key_update(ksl_ssl *, int request_peer);            /* TCP mode, TLS 1.3 */
/* alert: bits 0-7 alert code, bit 8 set when received from the peer, bits 16-31 the X509_V_ERR_* of a local verification failure */
int      ksl_ssl_last_error(ksl_ssl *, uint32_t *packed, int *alert, char *buf, size_t len);
int      ksl_drive(ksl_ssl *);  /* handshake / post-handshake processing: KSL_OK | KSL_WANT_READ | KSL_WANT_VERIFY | KSL_WANT_SNI | KSL_ERROR */

/* --- QUIC TLS interface --- */
int      ksl_quic_set_transport_params(ksl_ssl *, const uint8_t *tp, size_t len);
int      ksl_quic_provide(ksl_ssl *, int level, const uint8_t *data, size_t len);
int      ksl_quic_next_event(ksl_ssl *, ksl_event *out);  /* 1 = filled, 0 = none */
int      ksl_quic_peek_event(ksl_ssl *, ksl_event *out);  /* same without consuming */

/* --- TLS over TCP through memory --- */
int      ksl_tcp_feed(ksl_ssl *, const uint8_t *ciphertext, size_t len, size_t *consumed);
int      ksl_tcp_drain(ksl_ssl *, uint8_t *out, size_t cap, size_t *written);
int      ksl_tcp_write(ksl_ssl *, const uint8_t *plaintext, size_t len, size_t *consumed);
int      ksl_tcp_read(ksl_ssl *, uint8_t *out, size_t cap, size_t *read);  /* KSL_EOF after close_notify */
int      ksl_tcp_shutdown(ksl_ssl *);                                       /* sends close_notify; KSL_OK when the peer's arrived */

/* --- packet protection keys --- */
ksl_key *ksl_key_initial(const uint8_t *dcid, size_t len, int is_server, int direction, uint32_t version);
ksl_key *ksl_key_next(ksl_key *);                 /* key update generation; header protection key is shared */
#define KSL_EKEY_TOKEN 1                           /* AES-256-GCM key from 32 random bytes made inside ksl: Retry tokens via ksl_seal/ksl_open, pn = 64-bit token nonce */
#define KSL_EKEY_RESET 2                           /* HMAC-SHA256 key from 32 random bytes made inside ksl: stateless reset tokens via ksl_key_mac16 */
ksl_key *ksl_key_random(int kind);                 /* NULL on an unknown kind or RNG failure; the material never leaves ksl; immutable, so ksl_key_mac16 may run concurrently */
int      ksl_key_mac16(ksl_key *, const uint8_t *in, size_t len, uint8_t out[16]);   /* KSL_EKEY_RESET only: first 16 bytes of HMAC-SHA256; KSL_ERROR for any other key */

/* ---- accelerated UDP (Linux; ADR-0006): batched send/receive with GSO, GRO, ECN, DF probe mode and SO_REUSEPORT.
 *  Elsewhere ksl_udp_open answers NULL with KSL_E_NOT_SUPPORTED. Addresses are KSL_UDP_ADDR_LEN bytes: family (4|6), port BE, 16 address bytes
 *  (IPv4 in the first 4), one pad byte. Errors live in the object (ksl_udp_get KSL_UDP_GET_ERROR); nothing here calls back. ---- */
#define KSL_UDP_ECN 1
#define KSL_UDP_GSO 2
#define KSL_UDP_GRO 4
#define KSL_UDP_DF 8                /* IP_PMTUDISC_PROBE + IPV6_DONTFRAG, never _DO (quic-go CVE-2024-53259) */
#define KSL_UDP_REUSEPORT 16
#define KSL_UDP_ADDR_LEN 20
#define KSL_UDP_GET_FD 1            /* 4 bytes BE */
#define KSL_UDP_GET_CAPS 2          /* 8 bytes: granted flags:4 BE | gso max segments:2 BE | batch:2 BE */
#define KSL_UDP_GET_LOCAL 3         /* KSL_UDP_ADDR_LEN bytes */
#define KSL_UDP_GET_ERROR 4         /* errno:4 BE | message */
#define KSL_UDP_GET_STATS 5         /* 12 bytes: send syscalls:4 BE | recv syscalls:4 BE | gso fallbacks:4 BE */
#define KSL_UDP_MAX_BATCH 64        /* slots per ksl_udp_send / ksl_udp_recv call */
typedef struct ksl_udp ksl_udp;
ksl_udp *ksl_udp_open(const uint8_t addr[KSL_UDP_ADDR_LEN], int flags, uint32_t *err, char *msg, size_t msglen);   /* loopback GSO/GRO/ECN probe at open; SO_RCVBUF raised to 7 MB; NULL + err/msg on failure */
int      ksl_udp_send(ksl_udp *, uint8_t *const *bufs, const uint32_t *lens, const uint8_t *addrs, const uint8_t *ecn, uint32_t n, uint32_t *sent);
         /* consecutive slots with equal address, ECN and length (the last may be shorter) leave as one sendmsg + UDP_SEGMENT; EIO on GSO -> GSO off, the
            segments resent one by one; EINVAL on GSO -> the first segment alone decides: GSO goes off only if it then leaves; EINVAL on a marked datagram ->
            resent once without the IP_TOS cmsg, which goes off only if that resend leaves; the first EPERM -> one retry; EMSGSIZE, unreachable and
            destination errors (EINVAL, EAFNOSUPPORT, EADDRNOTAVAIL, EDESTADDRREQ: port 0, a link-local IPv6 peer) on one datagram -> that slot is
            skipped (counted), never an error of the socket; EAGAIN -> KSL_OK with *sent so far. Link-local IPv6 is not supported: the address has no
            scope id, so ksl_udp_recv drops datagrams from fe80::/10 and a send there is a lost slot */
int      ksl_udp_recv(ksl_udp *, uint8_t *const *bufs, const uint32_t *caps, uint32_t *lens, uint8_t *addrs, uint8_t *ecn, uint32_t n, uint32_t *received, int timeout_ms);
         /* recvmsg + UDP_GRO into a scratch buffer, segments split into consecutive slots (leftovers wait for the next call); MSG_TRUNC and oversized segments drop; KSL_WANT_READ on timeout */
int      ksl_udp_get(ksl_udp *, int what, uint8_t *out, size_t cap, size_t *len);
void     ksl_udp_shutdown(ksl_udp *);   /* wakes a blocked ksl_udp_recv and closes the socket; later send/recv answer KSL_ERROR at once; the object stays until ksl_udp_close */
void     ksl_udp_close(ksl_udp *);      /* shutdown (when not done yet), waits for a receiver still inside, frees; never while another thread may still call in */
#ifdef _WIN32
int      ksl_win_sockets_start(int who); /* WSAStartup 2.2 once per process (also run by ksl_init and ksl_udp_open); 1 when Winsock is ready. who: 1 the Kotlin/Native runtime start, 2 ksl_init, 3 ksl_udp_open */
int      ksl_win_sockets_started_by(void); /* the `who` that started Winsock first; 0 not started */
#endif
void     ksl_key_free(ksl_key *);
int      ksl_seal(ksl_key *, uint64_t pn, const uint8_t *hdr, size_t hdr_len, uint8_t *payload, size_t len, size_t cap);
int      ksl_open(ksl_key *, uint64_t pn, const uint8_t *hdr, size_t hdr_len, uint8_t *payload, size_t len);
int      ksl_header_mask(ksl_key *, const uint8_t sample[16], uint8_t mask[5]);
int      ksl_retry_tag(uint32_t version, const uint8_t *odcid, size_t odcid_len, const uint8_t *retry_pseudo, size_t plen, uint8_t tag[16]);

/* --- KslCrypto --- */
int      ksl_rand(uint8_t *out, size_t len);
int      ksl_sha2(int bits, const uint8_t *in, size_t len, uint8_t *out);
int      ksl_hkdf_expand_label(int hash, const uint8_t *secret, size_t slen, const char *label, const uint8_t *ctx, size_t clen, uint8_t *out, size_t olen);
int      ksl_sign(int alg, const uint8_t *key_der, size_t klen, const uint8_t *msg, size_t mlen, uint8_t *sig, size_t *slen);
int      ksl_verify(int alg, const uint8_t *pub_der, size_t plen, const uint8_t *msg, size_t mlen, const uint8_t *sig, size_t slen);
int      ksl_spki_sha256(const uint8_t *cert_der, size_t len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
#endif
