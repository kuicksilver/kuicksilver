/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Encrypted Client Hello (RFC 9849, ADR-0019) through ksl: QUIC (the TLS callbacks) and TCP, accept, HelloRetryRequest,
 * rejection with retry configurations, GREASE, key rotation, the name checked on rejection (also on the paused path), and the
 * ECHConfigList check. The PKI (a CA, leaves for the inner name, the public name and both) and the ECH keys are made per run. */
#include "test_common.h"
#include "ksl_internal.h"
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ECH
#include <openssl/ech.h>
#endif

#if !defined(KSL_SYSTEM_OPENSSL) && OPENSSL_VERSION_MAJOR >= 4 && !defined(OPENSSL_NO_ECH)
#define INNER "inner.test"
#define PUBLIC "public.test"

/* ---------- a PKI of this run ---------- */
typedef struct {
    blob chain; /* framed leaf */
    uint8_t *key;
    size_t key_len;
} ident;
static EVP_PKEY *ca_key;
static X509 *ca_cert;
static blob ca_root;
static ident id_inner, id_public, id_both;

static X509 *make_cert(EVP_PKEY *key, const char *cn, const char *san, int ca, EVP_PKEY *signer, X509 *issuer) {
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), (long)(rand() & 0x7fffffff) + 2);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400L * 30);
    X509_set_pubkey(x, key);
    X509_NAME *n = X509_NAME_new();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, issuer ? X509_get_subject_name(issuer) : n);
    X509_NAME_free(n);
    X509V3_CTX v;
    X509V3_set_ctx(&v, issuer ? issuer : x, x, NULL, NULL, 0);
    const char *exts[][2] = {
        {"basicConstraints", ca ? "critical,CA:TRUE" : "CA:FALSE"},
        {"keyUsage", ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature"},
        {"subjectKeyIdentifier", "hash"},
        {ca ? NULL : "extendedKeyUsage", "serverAuth,clientAuth"}, /* a leaf also serves as a client identity */
        {san ? "subjectAltName" : NULL, san}};
    for (size_t i = 0; i < sizeof exts / sizeof exts[0]; i++) {
        if (!exts[i][0])
            continue;
        X509_EXTENSION *e = X509V3_EXT_conf(NULL, &v, exts[i][0], exts[i][1]);
        X509_add_ext(x, e, -1);
        X509_EXTENSION_free(e);
    }
    X509_sign(x, signer ? signer : key, EVP_sha256());
    return x;
}
static blob framed_der(X509 *x) {
    unsigned char *d = NULL;
    int l = i2d_X509(x, &d);
    blob b = {malloc((size_t)l + 4), (size_t)l + 4};
    b.buf[0] = (uint8_t)(l >> 24), b.buf[1] = (uint8_t)(l >> 16), b.buf[2] = (uint8_t)(l >> 8), b.buf[3] = (uint8_t)l;
    memcpy(b.buf + 4, d, (size_t)l);
    OPENSSL_free(d);
    return b;
}
static ident make_ident(const char *san) {
    ident id;
    EVP_PKEY *k = EVP_EC_gen("P-256");
    X509 *x = make_cert(k, "ech test leaf", san, 0, ca_key, ca_cert);
    id.chain = framed_der(x);
    unsigned char *d = NULL;
    int l = i2d_PrivateKey(k, &d);
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(k);
    OPENSSL_free(d);
    d = NULL;
    l = i2d_PKCS8_PRIV_KEY_INFO(p8, &d);
    id.key = malloc((size_t)l);
    memcpy(id.key, d, (size_t)l);
    id.key_len = (size_t)l;
    OPENSSL_free(d);
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_free(x);
    EVP_PKEY_free(k);
    return id;
}
static void make_pki(void) {
    ca_key = EVP_EC_gen("P-256");
    ca_cert = make_cert(ca_key, "ksl ECH test CA", NULL, 1, NULL, NULL);
    ca_root = framed_der(ca_cert);
    id_inner = make_ident("DNS:" INNER);
    id_public = make_ident("DNS:" PUBLIC);
    id_both = make_ident("DNS:" INNER ",DNS:" PUBLIC);
}
static void free_pki(void) {
    ident *ids[] = {&id_inner, &id_public, &id_both};
    for (size_t i = 0; i < 3; i++) {
        free(ids[i]->chain.buf);
        free(ids[i]->key);
    }
    free(ca_root.buf);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
}

/* ---------- ECH keys of this run ---------- */
typedef struct {
    char *pem;         /* the key and its ECHCONFIG block, as `openssl ech` writes them */
    uint8_t list[512]; /* its ECHConfigList, binary */
    size_t list_len;
} echkey;
static echkey make_echkey_mnl(const char *public_name, uint8_t max_name_length) {
    echkey k;
    memset(&k, 0, sizeof k);
    OSSL_ECHSTORE *es = OSSL_ECHSTORE_new(NULL, NULL);
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT; /* X25519, HKDF-SHA256, AES-128-GCM: RFC 9849's mandatory suite */
    BIO *m = BIO_new(BIO_s_mem());
    if (!es || !m || OSSL_ECHSTORE_new_config(es, OSSL_ECH_RFC9849_VERSION, max_name_length, public_name, suite) != 1 ||
        OSSL_ECHSTORE_write_pem(es, OSSL_ECHSTORE_LAST, m) != 1) {
        printf("ECH key generation failed\n");
        exit(3);
    }
    char *p;
    long l = BIO_get_mem_data(m, &p);
    k.pem = malloc((size_t)l + 1);
    memcpy(k.pem, p, (size_t)l);
    k.pem[l] = 0;
    BIO_free(m);
    m = BIO_new_mem_buf(k.pem, -1);
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long dl = 0;
    while (PEM_read_bio(m, &name, &header, &data, &dl) == 1) {
        if (strcmp(name, "ECHCONFIG") == 0 && dl > 0 && (size_t)dl <= sizeof k.list) {
            memcpy(k.list, data, (size_t)dl);
            k.list_len = (size_t)dl;
        }
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }
    ERR_clear_error();
    BIO_free(m);
    OSSL_ECHSTORE_free(es);
    if (!k.list_len) {
        printf("no ECHCONFIG block\n");
        exit(3);
    }
    return k;
}
static echkey make_echkey(const char *public_name) {
    return make_echkey_mnl(public_name, 0);
}
/* the framing of ksl_ech_keys_new: (uint32 length || flags || PEM)* */
static blob keyset(int n, ...) {
    blob b = {0};
    va_list ap;
    va_start(ap, n);
    for (int i = 0; i < n; i++) {
        const echkey *k = va_arg(ap, const echkey *);
        int retry = va_arg(ap, int);
        size_t l = strlen(k->pem) + 1;
        b.buf = realloc(b.buf, b.len + 4 + l);
        b.buf[b.len] = (uint8_t)(l >> 24), b.buf[b.len + 1] = (uint8_t)(l >> 16), b.buf[b.len + 2] = (uint8_t)(l >> 8);
        b.buf[b.len + 3] = (uint8_t)l;
        b.buf[b.len + 4] = (uint8_t)retry;
        memcpy(b.buf + b.len + 5, k->pem, l - 1);
        b.len += 4 + l;
    }
    va_end(ap);
    return b;
}

/* ksl_ech_keys_new + ksl_ctx_set_ech_keys: KSL_OK, or KSL_ERROR when the set does not read or the context refuses it */
static int set_keys(ksl_ctx *c, const uint8_t *framed, size_t len) {
    char msg[256];
    ksl_ech_keys *k = ksl_ech_keys_new(framed, len, msg, sizeof msg);
    if (!k)
        return KSL_ERROR;
    int r = ksl_ctx_set_ech_keys(c, k);
    ksl_ech_keys_free(k); /* the context keeps its own reference */
    return r;
}

/* ---------- contexts and sessions ---------- */
static ksl_ctx *ech_client(int verify_mode, int grease) {
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT);
    ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    ksl_ctx_set_roots(c, ca_root.buf, ca_root.len);
    ksl_ctx_set_option(c, KSL_OPT_VERIFY_MODE, verify_mode);
    if (grease)
        CHECK(ksl_ctx_set_option(c, KSL_OPT_ECH_GREASE, 1) == KSL_OK, "KSL_OPT_ECH_GREASE taken");
    return c;
}
static ksl_ctx *ech_server(const ident *id, const blob *keys, const char *groups) {
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER);
    ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    CHECK(ksl_ctx_set_identity(c, id->chain.buf, id->chain.len, id->key, id->key_len) == KSL_OK, "server identity");
    if (keys)
        CHECK(set_keys(c, keys->buf, keys->len) == KSL_OK, "server ECH keys");
    if (groups)
        CHECK(ksl_ctx_set_groups(c, groups) == KSL_OK, "server groups");
    return c;
}
static ksl_ssl *ech_session(ksl_ctx *cc, int mode, const echkey *k) {
    ksl_ssl *c = ksl_ssl_new(cc, mode);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)INNER, strlen(INNER));
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)INNER, strlen(INNER));
    if (k)
        CHECK(ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, k->list, k->list_len) == KSL_OK, "KSL_SET_ECH_CONFIG_LIST taken");
    if (mode == KSL_MODE_QUIC)
        ksl_quic_set_transport_params(c, TP, sizeof TP);
    return c;
}

static int hello_ech_kdf, hello_ech_aead;
static size_t hello_ech_payload;
/* the server_name of a ClientHello handshake message, and whether it has encrypted_client_hello (0xfe0d); its outer suite and
   payload length into hello_ech_* */
static int hello_sni(const uint8_t *m, size_t len, char *out, size_t cap, int *has_ech) {
    *has_ech = 0;
    out[0] = 0;
    hello_ech_kdf = hello_ech_aead = -1;
    hello_ech_payload = 0;
    size_t p = 4 + 2 + 32;
    if (len < p + 1 || m[0] != 1)
        return 0;
    p += 1 + m[p];
    if (p + 2 > len)
        return 0;
    p += 2 + (((size_t)m[p] << 8) | m[p + 1]);
    if (p + 1 > len)
        return 0;
    p += 1 + m[p];
    if (p + 2 > len)
        return 0;
    size_t end = p + 2 + (((size_t)m[p] << 8) | m[p + 1]);
    p += 2;
    while (p + 4 <= end && end <= len) {
        unsigned t = ((unsigned)m[p] << 8) | m[p + 1];
        size_t l = ((size_t)m[p + 2] << 8) | m[p + 3];
        if (p + 4 + l > end)
            return 0;
        if (t == 0xfe0d) {
            *has_ech = 1;
            if (l >= 8 && m[p + 4] == 0) { /* outer: type, kdf, aead, config_id, enc<2>, payload<2> */
                hello_ech_kdf = ((int)m[p + 5] << 8) | m[p + 6];
                hello_ech_aead = ((int)m[p + 7] << 8) | m[p + 8];
                size_t el = ((size_t)m[p + 10] << 8) | m[p + 11];
                if (12 + el + 2 <= 4 + l)
                    hello_ech_payload = ((size_t)m[p + 12 + el] << 8) | m[p + 13 + el];
            }
        }
        if (t == 0 && l >= 5) {
            size_t nl = ((size_t)m[p + 7] << 8) | m[p + 8];
            if (nl < cap && 9 + nl <= 4 + l) {
                memcpy(out, m + p + 9, nl);
                out[nl] = 0;
            }
        }
        p += 4 + l;
    }
    return 1;
}

typedef struct {
    int rc, done, alert_c, alert_s, status_c, status_s;
    char wire_sni[256];
    int wire_ech;
    uint8_t retry[4096];
    size_t retry_len;
    char server_sni[256];
    int server_got_cert;             /* the server holds a client certificate */
    int client_resumable;            /* the client holds a session it could resume (a ticket arrived) */
    int wire_ech_kdf, wire_ech_aead; /* the cipher suite of the ClientHello's encrypted_client_hello (outer) */
    size_t wire_ech_payload;         /* its payload length */
    int last_c_type;                 /* TCP: type and length of the last record the client wrote */
    size_t last_c_len;
    int status_c_late; /* the client's KSL_GET_ECH_STATUS after session_hook_late */
    int wire_alert_c;  /* TCP: the alert of the client's last record, read off the wire (-1: none) */
} run;
/* called on each client session right after it is made (test hooks of ksl_internal.h), and before the outcome is read */
static void (*session_hook)(ksl_ssl *c);
static void (*session_hook_late)(ksl_ssl *c);
static void sni_seen(ksl_ssl *s, char *out, size_t cap) {
    out[0] = 0;
    SSL *raw = ksl_ssl_raw_for_test(s);
    const char *n = SSL_get_servername(raw, TLSEXT_NAMETYPE_host_name);
    if (n)
        snprintf(out, cap, "%s", n);
}
static char last_msg_c[256];
static void finish(run *r, ksl_ssl *c, ksl_ssl *s) {
    r->wire_ech_kdf = hello_ech_kdf;
    r->wire_ech_aead = hello_ech_aead;
    r->wire_ech_payload = hello_ech_payload;
    {
        uint32_t code;
        int a;
        ksl_ssl_last_error(c, &code, &a, last_msg_c, sizeof last_msg_c);
    }
    last_code(c, &r->alert_c);
    last_code(s, &r->alert_s);
    uint8_t b;
    size_t n;
    r->status_c = ksl_ssl_get(c, KSL_GET_ECH_STATUS, &b, 1, &n) == KSL_OK && n == 1 ? b : -1;
    r->status_s = ksl_ssl_get(s, KSL_GET_ECH_STATUS, &b, 1, &n) == KSL_OK && n == 1 ? b : -1;
    if (ksl_ssl_get(c, KSL_GET_ECH_RETRY_CONFIGS, r->retry, sizeof r->retry, &r->retry_len) != KSL_OK)
        r->retry_len = (size_t)-1;
    sni_seen(s, r->server_sni, sizeof r->server_sni);
    r->server_got_cert = SSL_get0_peer_certificate(ksl_ssl_raw_for_test(s)) != NULL;
    SSL_SESSION *sess = SSL_get0_session(ksl_ssl_raw_for_test(c));
    r->client_resumable = sess != NULL && SSL_SESSION_is_resumable(sess);
    r->status_c_late = r->status_c;
    if (session_hook_late) {
        session_hook_late(c);
        r->status_c_late = ksl_ssl_get(c, KSL_GET_ECH_STATUS, &b, 1, &n) == KSL_OK && n == 1 ? b : -1;
    }
}
static int accept_verify(ksl_ssl *s, int rc, void *a) {
    char *seen = a;
    if (rc != KSL_WANT_VERIFY)
        return 1;
    size_t n = 0;
    if (seen && ksl_ssl_get(s, KSL_GET_VERIFY_NAME, (uint8_t *)seen, 255, &n) == KSL_OK)
        seen[n] = 0;
    return ksl_ssl_verify_resume(s, 1, 0) == KSL_OK;
}
static uint8_t client_wire[32768]; /* TCP: what the client wrote (move_bytes) */
static size_t client_wire_len;
/* ---------- a server whose flight is rewritten on its way to the client ---------- */
/* Rewrites one handshake message of the server (msg: type, u24 length, body; cap bytes of room): returns the new length, or
   the old one to leave it. Set by the tests below; the TCP and QUIC paths call it on the server's ServerHello and
   EncryptedExtensions, so the client meets what an attacker or a broken server could send. A client that aborts at that
   message never reaches the transcript check that would otherwise catch the change. */
static size_t (*rewrite_msg)(uint8_t *msg, size_t len, size_t cap);
/* the pump of test_common.h, with the server's CRYPTO data rewritten message by message */
static int ech_pump(ksl_ssl *c, ksl_ssl *s, side *cs, side *ss, int max, int (*on_want)(ksl_ssl *, int rc, void *),
                    void *arg) {
    int rc = KSL_OK;
    for (int round = 0; round < max; round++) {
        ksl_ssl *who[2] = {c, s};
        side *me[2] = {cs, ss};
        ksl_ssl *peer[2] = {s, c};
        int progressed = 0;
        for (int k = 0; k < 2; k++) {
            int r = ksl_drive(who[k]);
            if (k == 0)
                rc = r;
            if ((r == KSL_WANT_VERIFY || r == KSL_WANT_SNI) && on_want && !on_want(who[k], r, arg))
                return r;
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                progressed = 1;
                if (ev.type == KSL_EV_CRYPTO_SEND) {
                    static uint8_t out[65536];
                    size_t n = 0;
                    for (size_t off = 0; off + 4 <= ev.len;) { /* each handshake message of the event */
                        size_t l =
                            4 + (((size_t)ev.buf[off + 1] << 16) | ((size_t)ev.buf[off + 2] << 8) | ev.buf[off + 3]);
                        if (off + l > ev.len || n + l + 512 > sizeof out)
                            break;
                        memcpy(out + n, ev.buf + off, l);
                        n += k == 1 && rewrite_msg ? rewrite_msg(out + n, l, l + 512) : l;
                        off += l;
                    }
                    me[k]->crypto_events++;
                    ksl_quic_provide(peer[k], ev.level, out, n);
                } else if (ev.type == KSL_EV_KEY) {
                    me[k]->keys++;
                    ksl_key_free(ev.key);
                } else if (ev.type == KSL_EV_TRANSPORT_PARAMS) {
                    me[k]->tp_len = ev.len < sizeof me[k]->tp ? ev.len : sizeof me[k]->tp;
                    memcpy(me[k]->tp, ev.buf, me[k]->tp_len);
                } else if (ev.type == KSL_EV_HANDSHAKE_DONE)
                    me[k]->done = 1;
            }
            if (r == KSL_ERROR)
                return KSL_ERROR;
        }
        if (cs->done && ss->done && !progressed)
            return rc;
        if (!progressed && round > 3)
            return rc;
    }
    return rc;
}

/* the extensions block of a ServerHello (2) or EncryptedExtensions (8) message: its offset (at the u16 length), else 0 */
static size_t exts_at(const uint8_t *m, size_t len) {
    if (len < 6)
        return 0;
    if (m[0] == 8)
        return 4;
    if (m[0] != 2 || len < 4 + 2 + 32 + 1)
        return 0;
    size_t p = 4 + 2 + 32;
    p += 1 + m[p]; /* legacy_session_id_echo */
    p += 2 + 1;    /* cipher_suite, legacy_compression_method */
    return p + 2 <= len ? p : 0;
}
/* inserts n bytes at `at` of a message of len bytes, fixing the message's and the extensions block's length */
static size_t msg_insert(uint8_t *m, size_t len, size_t cap, size_t ext_len_at, size_t at, const uint8_t *b, size_t n) {
    if (len + n > cap)
        return len;
    memmove(m + at + n, m + at, len - at);
    memcpy(m + at, b, n);
    len += n;
    size_t body = len - 4, el = (((size_t)m[ext_len_at] << 8) | m[ext_len_at + 1]) + n;
    m[1] = (uint8_t)(body >> 16), m[2] = (uint8_t)(body >> 8), m[3] = (uint8_t)body;
    m[ext_len_at] = (uint8_t)(el >> 8), m[ext_len_at + 1] = (uint8_t)el;
    return len;
}
/* EncryptedExtensions: a byte after the ECHConfigList of encrypted_client_hello (RFC 9849 sections 6.1.6, 6.2.1) */
static size_t ee_trailing_byte(uint8_t *m, size_t len, size_t cap) {
    size_t e = exts_at(m, len);
    if (m[0] != 8 || !e)
        return len;
    for (size_t p = e + 2; p + 4 <= len;) {
        unsigned t = ((unsigned)m[p] << 8) | m[p + 1];
        size_t l = ((size_t)m[p + 2] << 8) | m[p + 3];
        if (t == 0xfe0d) {
            static const uint8_t z = 0x5a;
            size_t n = msg_insert(m, len, cap, e, p + 4 + l, &z, 1);
            if (n != len)
                m[p + 2] = (uint8_t)((l + 1) >> 8), m[p + 3] = (uint8_t)(l + 1);
            return n;
        }
        p += 4 + l;
    }
    return len;
}
static const uint8_t *ee_ech_value; /* the retry_configs ee_add_ech adds */
static size_t ee_ech_value_len;
/* EncryptedExtensions: an encrypted_client_hello with ee_ech_value (an ECHConfigList) appended (RFC 9849 section 5) */
static size_t ee_add_ech(uint8_t *m, size_t len, size_t cap) {
    size_t e = exts_at(m, len);
    if (m[0] != 8 || !e || ee_ech_value_len > 1024)
        return len;
    uint8_t ext[1100];
    ext[0] = 0xfe, ext[1] = 0x0d, ext[2] = (uint8_t)(ee_ech_value_len >> 8), ext[3] = (uint8_t)ee_ech_value_len;
    memcpy(ext + 4, ee_ech_value, ee_ech_value_len);
    return msg_insert(m, len, cap, e, len, ext, 4 + ee_ech_value_len);
}
/* ServerHello: a pre_shared_key choosing identity 0 (RFC 9849 section 6.1.2) */
static size_t sh_add_psk(uint8_t *m, size_t len, size_t cap) {
    size_t e = exts_at(m, len);
    if (m[0] != 2 || !e)
        return len;
    static const uint8_t psk[6] = {0, 41, 0, 2, 0, 0};
    return msg_insert(m, len, cap, e, len, psk, sizeof psk);
}

/* TLS 1.3 record protection of the tests' TCP sessions (TLS_AES_128_GCM_SHA256): the key and IV of a traffic secret the
   session's keylog names (`label`), and one record sealed or opened at `seq` */
static int traffic_key(ksl_ssl *s, const char *label, uint8_t key[16], uint8_t iv[12]) {
    const char *l = s->keylog ? strstr(s->keylog, label) : NULL;
    if (!l)
        return 0;
    l = strchr(l + strlen(label) + 1, ' ');
    if (!l)
        return 0;
    uint8_t secret[32];
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(l + 1 + 2 * i, "%2x", &v) != 1)
            return 0;
        secret[i] = (uint8_t)v;
    }
    return ksl_hkdf_expand_label(KSL_HASH_SHA256, secret, 32, "key", NULL, 0, key, 16) == KSL_OK &&
           ksl_hkdf_expand_label(KSL_HASH_SHA256, secret, 32, "iv", NULL, 0, iv, 12) == KSL_OK;
}
/* seals (enc) or opens a record body under key/iv at seq; hdr is the 5-byte record header with the ciphertext length.
   Returns the output length, or 0 when it does not open. */
static size_t record_crypt(int enc, const uint8_t key[16], const uint8_t iv[12], uint64_t seq, const uint8_t hdr[5],
                           const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (uint8_t)(seq >> (56 - 8 * i));
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int ok = 0, l = 0, f = 0;
    size_t body = enc ? n : n - 16;
    if (x && (enc || n >= 16) && EVP_CipherInit_ex(x, EVP_aes_128_gcm(), NULL, key, nonce, enc) == 1 &&
        EVP_CipherUpdate(x, NULL, &l, hdr, 5) == 1 && EVP_CipherUpdate(x, out, &l, in, (int)body) == 1 &&
        (enc || EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, 16, (void *)(in + body)) == 1) &&
        EVP_CipherFinal_ex(x, out + l, &f) == 1 &&
        (!enc || EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, 16, out + body) == 1))
        ok = 1;
    EVP_CIPHER_CTX_free(x);
    return ok ? (enc ? body + 16 : body) : 0;
}
/* the TCP path: the server's records on their way to the client, its first handshake record (ServerHello) and its first
   protected record (EncryptedExtensions) rewritten by rewrite_msg */
static uint8_t srv_buf[65536];
static size_t srv_len;
static uint64_t srv_seq;
static void server_records(ksl_ssl *s, ksl_ssl *c) {
    uint8_t buf[8192];
    size_t n, used;
    while (ksl_tcp_drain(s, buf, sizeof buf, &n) == KSL_OK && n && srv_len + n <= sizeof srv_buf) {
        memcpy(srv_buf + srv_len, buf, n);
        srv_len += n;
    }
    size_t off = 0;
    while (off + 5 <= srv_len) {
        size_t l = ((size_t)srv_buf[off + 3] << 8) | srv_buf[off + 4];
        if (off + 5 + l > srv_len)
            break;
        static uint8_t rec[20000], plain[20000];
        size_t rl = 5 + l;
        memcpy(rec, srv_buf + off, rl);
        if (rewrite_msg && rec[0] == 22 && l >= 4) { /* ServerHello, in the clear */
            rl = 5 + rewrite_msg(rec + 5, l, sizeof rec - 5);
            rec[3] = (uint8_t)((rl - 5) >> 8), rec[4] = (uint8_t)(rl - 5);
        } else if (rewrite_msg && rec[0] == 23) {
            uint8_t key[16], iv[12];
            size_t pl;
            if (srv_seq == 0 && traffic_key(s, "SERVER_HANDSHAKE_TRAFFIC_SECRET", key, iv) &&
                (pl = record_crypt(0, key, iv, 0, rec, rec + 5, l, plain)) > 1 && plain[pl - 1] == 22) {
                size_t ml = rewrite_msg(plain, pl - 1, sizeof plain - 600) /* the record's last byte: its type */;
                plain[ml] = 22;
                uint8_t hdr[5] = {23, 3, 3, (uint8_t)((ml + 1 + 16) >> 8), (uint8_t)(ml + 1 + 16)};
                memcpy(rec, hdr, 5);
                rl = 5 + record_crypt(1, key, iv, 0, hdr, plain, ml + 1, rec + 5);
            }
            srv_seq++;
        }
        for (size_t o = 0; o < rl; o += used)
            if (ksl_tcp_feed(c, rec + o, rl - o, &used) != KSL_OK || !used)
                break;
        off += 5 + l;
    }
    memmove(srv_buf, srv_buf + off, srv_len - off);
    srv_len -= off;
}
/* the alert the client's last record carries (21: in the clear; 23: opened under its handshake key), -1 when none */
static int client_wire_alert(ksl_ssl *c) {
    int type = -1, seq = -1;
    size_t at = 0, len = 0;
    for (size_t off = 0; off + 5 <= client_wire_len;) {
        size_t l = (size_t)client_wire[off + 3] << 8 | client_wire[off + 4];
        if (off + 5 + l > client_wire_len)
            break;
        type = client_wire[off], at = off, len = l;
        if (type == 23)
            seq++;
        off += 5 + l;
    }
    if (type == 21 && len == 2)
        return client_wire[at + 6];
    uint8_t key[16], iv[12], plain[64];
    size_t pl;
    if (type == 23 && seq >= 0 && len <= 64 && traffic_key(c, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", key, iv) &&
        (pl = record_crypt(0, key, iv, (uint64_t)seq, client_wire + at, client_wire + at + 5, len, plain)) == 3 &&
        plain[2] == 21)
        return plain[1];
    return -1;
}

static run quic_run(ksl_ctx *cc, ksl_ctx *sc, const echkey *k, char *paused_name) {
    run r;
    memset(&r, 0, sizeof r);
    ksl_ssl *c = ech_session(cc, KSL_MODE_QUIC, k), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    if (session_hook)
        session_hook(c);
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    ksl_drive(c);
    ksl_event ev;
    if (ksl_quic_peek_event(c, &ev) && ev.type == KSL_EV_CRYPTO_SEND && ev.level == KSL_LEVEL_INITIAL)
        hello_sni(ev.buf, ev.len, r.wire_sni, sizeof r.wire_sni, &r.wire_ech);
    side cs = {0}, ss = {0};
    r.rc = (rewrite_msg ? ech_pump : pump)(c, s, &cs, &ss, 40, accept_verify, paused_name);
    r.done = cs.done && ss.done;
    finish(&r, c, s);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    return r;
}
static size_t move_bytes(ksl_ssl *a, ksl_ssl *b, uint8_t *first, size_t *first_len) {
    uint8_t buf[8192];
    size_t total = 0, n, used;
    while (ksl_tcp_drain(a, buf, sizeof buf, &n) == KSL_OK && n) {
        if (a->owner->role == KSL_CLIENT && client_wire_len + n <= sizeof client_wire) {
            memcpy(client_wire + client_wire_len, buf, n);
            client_wire_len += n;
        }
        if (first && *first_len == 0 && n <= 8192) {
            memcpy(first, buf, n);
            *first_len = n;
        }
        size_t off = 0;
        while (off < n && ksl_tcp_feed(b, buf + off, n - off, &used) == KSL_OK && used)
            off += used;
        total += n;
    }
    return total;
}
static run tcp_run(ksl_ctx *cc, ksl_ctx *sc, const echkey *k) {
    run r;
    memset(&r, 0, sizeof r);
    ksl_ssl *c = ech_session(cc, KSL_MODE_TCP, k), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    if (session_hook)
        session_hook(c);
    client_wire_len = 0;
    srv_len = 0, srv_seq = 0;
    uint8_t first[8192];
    size_t first_len = 0;
    r.rc = KSL_WANT_READ;
    for (int i = 0; i < 60; i++) {
        int a = ksl_drive(c);
        if (a == KSL_WANT_VERIFY)
            ksl_ssl_verify_resume(c, 1, 0), a = ksl_drive(c);
        move_bytes(c, s, first, &first_len);
        int b = ksl_drive(s);
        if (rewrite_msg)
            server_records(s, c);
        else
            move_bytes(s, c, NULL, NULL);
        if (a == KSL_ERROR || b == KSL_ERROR) {
            if (b == KSL_ERROR)
                ksl_drive(c);
            else {
                if (rewrite_msg)
                    ksl_drive(c); /* the client reads what was fed above */
                move_bytes(c, s, NULL, NULL), ksl_drive(s);
            }
            r.rc = KSL_ERROR;
            break;
        }
        if (c->done && s->done) {
            r.rc = KSL_OK;
            r.done = 1;
            break;
        }
    }
    if (first_len > 5 && first[0] == 22)
        hello_sni(first + 5, first_len - 5, r.wire_sni, sizeof r.wire_sni, &r.wire_ech);
    r.last_c_type = -1;
    for (size_t off = 0;
         off + 5 <= client_wire_len;) { /* the client's records, in order: the last one's type and length */
        size_t l = (size_t)client_wire[off + 3] << 8 | client_wire[off + 4];
        r.last_c_type = client_wire[off];
        r.last_c_len = l;
        off += 5 + l;
    }
    r.wire_alert_c = client_wire_alert(c);
    finish(&r, c, s);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    return r;
}

/* ---------- ECHConfigList check ---------- */
/* an ECHConfig (RFC 9849 section 4) of `version` with the KEM of `kem` (X25519 0x0020 with a 32-byte key), one cipher suite
   (HKDF-SHA256, AES-128-GCM) and an extension of type ext (none when 0) */
static size_t ech_config(uint8_t *o, unsigned version, unsigned kem, const char *public_name, unsigned ext) {
    size_t n = 4, pl = strlen(public_name);
    o[n++] = 7; /* config_id */
    o[n++] = (uint8_t)(kem >> 8), o[n++] = (uint8_t)kem;
    o[n++] = 0, o[n++] = 32;
    for (int i = 0; i < 32; i++)
        o[n++] = (uint8_t)(9 + i);
    o[n++] = 0, o[n++] = 4, o[n++] = 0, o[n++] = 1, o[n++] = 0, o[n++] = 1;
    o[n++] = 0; /* maximum_name_length */
    o[n++] = (uint8_t)pl;
    memcpy(o + n, public_name, pl);
    n += pl;
    if (ext) {
        o[n++] = 0, o[n++] = 4, o[n++] = (uint8_t)(ext >> 8), o[n++] = (uint8_t)ext, o[n++] = 0, o[n++] = 0;
    } else
        o[n++] = 0, o[n++] = 0;
    o[0] = (uint8_t)(version >> 8), o[1] = (uint8_t)version, o[2] = (uint8_t)((n - 4) >> 8), o[3] = (uint8_t)(n - 4);
    return n;
}
static size_t ech_list(uint8_t *o, int n, ...) {
    va_list ap;
    va_start(ap, n);
    size_t at = 2;
    for (int i = 0; i < n; i++) {
        const uint8_t *e = va_arg(ap, const uint8_t *);
        size_t l = va_arg(ap, size_t);
        memcpy(o + at, e, l);
        at += l;
    }
    va_end(ap);
    o[0] = (uint8_t)((at - 2) >> 8), o[1] = (uint8_t)(at - 2);
    return at;
}
static void test_list_check(void) {
    SECTION("ech_config_list_check");
    uint8_t good[128], other_version[128], ipv4[128], hex[128], mandatory[128], optional[128], kem[128], dotted[128];
    size_t gl = ech_config(good, 0xfe0d, 0x0020, PUBLIC, 0);
    size_t vl = ech_config(other_version, 0xfe0c, 0x0020, PUBLIC, 0);
    size_t il = ech_config(ipv4, 0xfe0d, 0x0020, "10.0.0.1", 0);
    size_t hl = ech_config(hex, 0xfe0d, 0x0020, "a.0x1f", 0);
    size_t ml = ech_config(mandatory, 0xfe0d, 0x0020, PUBLIC, 0xfa01);
    size_t ol = ech_config(optional, 0xfe0d, 0x0020, PUBLIC, 0x0a01);
    size_t kl = ech_config(kem, 0xfe0d, 0x7777, PUBLIC, 0);
    size_t dl = ech_config(dotted, 0xfe0d, 0x0020, "public.test.", 0);
    uint8_t list[1024], out[1024];
    size_t n = ech_list(list, 1, good, gl), on = 0;
    CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_OK && on == n && !memcmp(out, list, n),
          "a list of one usable ECHConfig comes back unchanged");
    n = ech_list(list, 8, other_version, vl, ipv4, il, hex, hl, mandatory, ml, kem, kl, dotted, dl, good, gl, optional,
                 ol);
    uint8_t want[512];
    size_t wn = ech_list(want, 2, good, gl, optional, ol);
    CHECK(
        ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_OK && on == wn && !memcmp(out, want, wn),
        "negative_ech_unusable_configs_ignored: another version, an IPv4 or 0x hex public_name, a trailing dot, a "
        "mandatory extension and an unknown KEM are dropped one by one (RFC 9849 sections 4, 4.2, 6.1.7), the rest kept");
    n = ech_list(list, 3, other_version, vl, ipv4, il, mandatory, ml);
    CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_OK && on == 0,
          "negative_ech_no_usable_config: a list that parses with nothing usable: KSL_OK, 0 bytes");
    n = ech_list(list, 1, good, gl);
    CHECK(ksl_ech_config_list_check(list, n, out, 3, &on) == KSL_ERROR && on == n, "a small buffer: the size needed");
    list[1] ^= 1;
    CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_ERROR && on == 0,
          "negative_ech_list_length_mismatch");
    list[1] ^= 1;
    CHECK(ksl_ech_config_list_check(list, n - 1, out, sizeof out, &on) == KSL_ERROR, "negative_ech_list_truncated");
    list[5] = 0xff; /* the entry's length past the end */
    CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_ERROR, "negative_ech_entry_overruns_list");
    CHECK(ksl_ech_config_list_check(list, 1, out, sizeof out, &on) == KSL_ERROR, "negative_ech_list_one_byte");
    CHECK(ksl_ech_config_list_check(NULL, 0, out, sizeof out, &on) == KSL_ERROR, "negative_ech_list_null");
    uint8_t empty[2] = {0, 0}; /* ECHConfigList<4..2^16-1> (section 4) */
    CHECK(ksl_ech_config_list_check(empty, 2, out, sizeof out, &on) == KSL_ERROR && on == 0, "negative_ech_list_empty");
    /* RFC 9849 section 4.2: "there MUST NOT be more than one extension of the same type"; and an ECHConfig's contents end with its
       extensions: a trailing byte, a field past the contents or an empty field is no ECHConfig, and the list does not parse */
    uint8_t dup[160], tail[160], bad[160];
    size_t dl2 = ech_config(dup, 0xfe0d, 0x0020, PUBLIC, 0x0a01);
    /* the extension block 00 04 | 0a 01 00 00 becomes 00 08 | 0a 01 00 00 | 0a 01 00 00 */
    dup[dl2 - 5] = 8;
    memcpy(dup + dl2, dup + dl2 - 4, 4);
    dl2 += 4;
    dup[2] = (uint8_t)((dl2 - 4) >> 8), dup[3] = (uint8_t)(dl2 - 4);
    n = ech_list(list, 2, good, gl, dup, dl2);
    CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_ERROR && on == 0,
          "negative_ech_duplicate_extension: an extension type twice in one ECHConfig, the list does not parse");
    memcpy(dup + dl2 - 4, "\x0a\x02\x00\x00", 4); /* two types: a list that parses */
    n = ech_list(list, 2, good, gl, dup, dl2);
    CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_OK && on == n,
          "two extensions of other types are fine");
    size_t tl = ech_config(tail, 0xfe0d, 0x0020, PUBLIC, 0);
    tail[tl++] = 0; /* a byte after the extensions, inside the contents */
    tail[2] = (uint8_t)((tl - 4) >> 8), tail[3] = (uint8_t)(tl - 4);
    n = ech_list(list, 2, good, gl, tail, tl);
    CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_ERROR && on == 0,
          "negative_ech_trailing_bytes_in_contents: the list does not parse");
    tail[0] = 0xfe, tail[1] = 0x0c; /* another version: opaque contents */
    n = ech_list(list, 2, good, gl, tail, tl);
    CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_OK && on == 2 + gl,
          "the contents of another version are not read");
    static const struct {
        size_t at;
        uint8_t v;
        const char *what;
    } breaks[] = {{8, 0, "negative_ech_public_key_empty"},
                  {7, 0xff, "negative_ech_public_key_past_contents"},
                  {42, 3, "negative_ech_suites_not_pairs"},
                  {42, 0, "negative_ech_suites_empty"},
                  {48, 0, "negative_ech_public_name_empty"}};
    for (size_t i = 0; i < sizeof breaks / sizeof breaks[0]; i++) {
        size_t bl = ech_config(bad, 0xfe0d, 0x0020, PUBLIC, 0);
        bad[breaks[i].at] = breaks[i].v;
        n = ech_list(list, 2, good, gl, bad, bl);
        CHECK(ksl_ech_config_list_check(list, n, out, sizeof out, &on) == KSL_ERROR && on == 0, breaks[i].what);
    }
    END();
}

/* ---------- handshakes ---------- */
static echkey key_a, key_b;
#define ACCEPTED(r)                                                                                                    \
    ((r).rc != KSL_ERROR && (r).done && (r).status_c == KSL_ECH_ACCEPTED && (r).status_s == KSL_ECH_ACCEPTED &&        \
     !strcmp((r).server_sni, INNER))
static void report(const char *what, run r) {
    printf(
        "  %s: rc=%d done=%d alert c=%d s=%d status c=%d s=%d wire sni=%s ech=%d server sni=%s retry=%zu (client: %s)\n",
        what, r.rc, r.done, r.alert_c, r.alert_s, r.status_c, r.status_s, r.wire_sni, r.wire_ech, r.server_sni,
        r.retry_len, last_msg_c);
}
static void test_accept(void) {
    SECTION("ech_accept");
    blob ks = keyset(1, &key_a, 1);
    ksl_ctx *sc = ech_server(&id_both, &ks, NULL), *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    run q = quic_run(cc, sc, &key_a, NULL);
    CHECK(
        ACCEPTED(q) && !strcmp(q.wire_sni, PUBLIC) && q.wire_ech && q.retry_len == 0,
        "QUIC: accepted; the wire names the public_name and carries encrypted_client_hello, the server sees the inner name");
    if (!ACCEPTED(q))
        report("quic", q);
    run t = tcp_run(cc, sc, &key_a);
    CHECK(ACCEPTED(t) && !strcmp(t.wire_sni, PUBLIC) && t.wire_ech, "TCP: accepted the same way");
    if (!ACCEPTED(t))
        report("tcp", t);
    /* the inner certificate alone suffices when ECH is accepted */
    ksl_ctx *sc2 = ech_server(&id_inner, &ks, NULL);
    q = quic_run(cc, sc2, &key_a, NULL);
    CHECK(ACCEPTED(q), "accepted with a certificate for the inner name only");
    /* the paused path checks the inner name when accepted */
    ksl_ctx *pc = ech_client(KSL_VERIFY_PAUSE, 0);
    char seen[256] = "";
    q = quic_run(pc, sc, &key_a, seen);
    CHECK(ACCEPTED(q) && !strcmp(seen, INNER), "KSL_GET_VERIFY_NAME at the pause: the inner name after acceptance");
    ksl_ctx_free(pc);
    ksl_ctx_free(sc2);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    free(ks.buf);
    END();
}
static void test_hrr(void) {
    SECTION("ech_hello_retry_request");
    /* the server takes only secp384r1, the client sends no share for it: a HelloRetryRequest. OpenSSL 4.1.0 fails the second ECH
       ClientHello with a custom extension (QUIC's transport parameters always are one); the patch of ADR-0019 fixes it */
    blob ks = keyset(1, &key_a, 1);
    ksl_ctx *sc = ech_server(&id_both, &ks, "secp384r1"), *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    run q = quic_run(cc, sc, &key_a, NULL);
    CHECK(ACCEPTED(q), "QUIC: ECH accepted after a HelloRetryRequest (bug B, the carried patch)");
    if (!ACCEPTED(q))
        report("quic hrr", q);
    run t = tcp_run(cc, sc, &key_a);
    CHECK(ACCEPTED(t), "TCP: ECH accepted after a HelloRetryRequest");
    if (!ACCEPTED(t))
        report("tcp hrr", t);
    /* rejected after a HelloRetryRequest (RFC 9849 sections 6.1.4, 7.1: the rejecting server may answer with an ECH extension
       of 8 random bytes, which is no acceptance): the rejection path, ech_required and the retry configurations, over QUIC and
       TCP, and the retry with them succeeds. OpenSSL 4.1.0 took that extension for an acceptance and ended with
       illegal_parameter (bug C of ADR-0019, the second carried patch) */
    blob kb = keyset(1, &key_b, 1);
    ksl_ctx *sb = ech_server(&id_both, &kb, "secp384r1");
    run qs[2] = {quic_run(cc, sb, &key_a, NULL), tcp_run(cc, sb, &key_a)};
    for (int m = 0; m < 2; m++) {
        run r = qs[m];
        int ok = r.rc == KSL_ERROR && !r.done && r.alert_c == 121 && r.status_c == KSL_ECH_REJECTED &&
                 r.retry_len == key_b.list_len && !memcmp(r.retry, key_b.list, key_b.list_len);
        CHECK(ok, m == 0 ? "ech_rejected_after_hrr: QUIC, ech_required and the retry configurations (bug C)"
                         : "ech_rejected_after_hrr over TCP");
        if (!ok)
            report(m == 0 ? "quic hrr reject" : "tcp hrr reject", r);
    }
    echkey retry = key_b;
    memcpy(retry.list, qs[0].retry, qs[0].retry_len);
    retry.list_len = qs[0].retry_len;
    q = quic_run(cc, sb, &retry, NULL);
    CHECK(ACCEPTED(q), "the retry with them after a HelloRetryRequest is accepted");
    ksl_ctx_free(sb);
    free(kb.buf);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    free(ks.buf);
    END();
}
/* RFC 9849 section 6.1.7: "If the server requests a client certificate, the client MUST respond with an empty Certificate
   message" on a rejection: the server learns no certificate. OpenSSL 4.1 aborts with ech_required once the server's Finished
   is verified (statem_lib.c tls_process_finished, statem_clnt.c tls_process_initial_server_flight), before the client's second
   flight, so no Certificate message, empty or not, goes out; the accepted control shows the server would see one */
static void test_reject_client_certificate(void) {
    SECTION("ech_rejection_sends_no_client_certificate");
    blob ka = keyset(1, &key_a, 1), kb = keyset(1, &key_b, 1);
    ksl_ctx *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    CHECK(ksl_ctx_set_identity(cc, id_inner.chain.buf, id_inner.chain.len, id_inner.key, id_inner.key_len) == KSL_OK,
          "client identity");
    for (int rejected = 0; rejected < 2; rejected++) {
        ksl_ctx *sc = ech_server(&id_both, rejected ? &kb : &ka, NULL);
        ksl_ctx_set_roots(sc, ca_root.buf, ca_root.len);
        CHECK(ksl_ctx_set_option(sc, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_OPTIONAL) == KSL_OK,
              "server asks for a certificate");
        run qs[2] = {quic_run(cc, sc, &key_a, NULL), tcp_run(cc, sc, &key_a)};
        for (int m = 0; m < 2; m++) {
            run r = qs[m];
            /* nor a session ticket ("MUST ignore all session tickets and session IDs presented by the server") */
            int ok = rejected ? (r.alert_c == 121 && r.status_c == KSL_ECH_REJECTED && !r.server_got_cert &&
                                 !r.client_resumable)
                              : (ACCEPTED(r) && r.server_got_cert);
            CHECK(ok, rejected ? (m == 0 ? "negative_ech_rejected_no_client_certificate over QUIC" : "... over TCP")
                               : (m == 0 ? "accepted: the server holds the client certificate (QUIC)" : "... (TCP)"));
            if (!ok)
                report(m == 0 ? "quic client cert" : "tcp client cert", r);
        }
        ksl_ctx_free(sc);
    }
    ksl_ctx_free(cc);
    free(ka.buf);
    free(kb.buf);
    END();
}
static void test_reject(void) {
    SECTION("ech_reject");
    blob kb = keyset(1, &key_b, 1);
    ksl_ctx *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    /* RFC 9849 section 6.1.6: authenticated for the public_name, then ech_required (121), retry_configs reported */
    ksl_ctx *sc = ech_server(&id_both, &kb, NULL);
    run q = quic_run(cc, sc, &key_a, NULL), t = tcp_run(cc, sc, &key_a);
    int okq = q.rc == KSL_ERROR && !q.done && q.alert_c == 121 && q.status_c == KSL_ECH_REJECTED &&
              q.status_s == KSL_ECH_REJECTED && q.retry_len == key_b.list_len &&
              !memcmp(q.retry, key_b.list, q.retry_len) && !strcmp(q.server_sni, PUBLIC);
    CHECK(okq, "negative_ech_rejected: QUIC, ech_required (CRYPTO_ERROR 0x179), the server's retry configurations");
    if (!okq)
        report("quic reject", q);
    int okt = t.rc == KSL_ERROR && t.alert_c == 121 && t.status_c == KSL_ECH_REJECTED && t.retry_len == key_b.list_len;
    CHECK(okt, "negative_ech_rejected over TCP");
    if (!okt)
        report("tcp reject", t);
    /* the certificate is checked against the public_name, on the paused path too */
    ksl_ctx *pc = ech_client(KSL_VERIFY_PAUSE, 0);
    char seen[256] = "";
    q = quic_run(pc, sc, &key_a, seen);
    CHECK(q.status_c == KSL_ECH_REJECTED && !strcmp(seen, PUBLIC),
          "KSL_GET_VERIFY_NAME at the pause: the public_name after a rejection (RFC 9849 section 6.1.7)");
    ksl_ctx_free(pc);
    ksl_ctx_free(sc);
    /* a certificate valid for the public name only: rejection still authenticated */
    sc = ech_server(&id_public, &kb, NULL);
    q = quic_run(cc, sc, &key_a, NULL);
    CHECK(q.alert_c == 121 && q.status_c == KSL_ECH_REJECTED && q.retry_len == key_b.list_len,
          "a certificate for the public name alone authenticates the rejection");
    ksl_ctx *pc2 = ech_client(KSL_VERIFY_PAUSE, 0);
    seen[0] = 0;
    q = quic_run(pc2, sc, &key_a, seen);
    CHECK(q.alert_c == 121 && q.status_c == KSL_ECH_REJECTED && !strcmp(seen, PUBLIC),
          "the paused path with a certificate for the public name alone: the name check after the pause takes it too");
    ksl_ctx_free(pc2);
    ksl_ctx_free(sc);
    /* a certificate for the inner name only: the outer handshake is not authenticated for the public_name */
    sc = ech_server(&id_inner, &kb, NULL);
    q = quic_run(cc, sc, &key_a, NULL);
    CHECK(q.rc == KSL_ERROR && q.alert_c == 42 && q.status_c == KSL_ECH_OFFERED && q.retry_len == 0,
          "negative_ech_rejection_unauthenticated: bad_certificate, no retry configurations (section 6.1.7)");
    if (!(q.alert_c == 42 && q.retry_len == 0))
        report("inner-only cert", q);
    t = tcp_run(cc, sc, &key_a);
    CHECK(t.rc == KSL_ERROR && t.alert_c == 42 && t.retry_len == 0, "negative_ech_rejection_unauthenticated over TCP");
    ksl_ctx_free(sc);
    /* a server without ECH: rejected, no retry configurations ("securely disabled", section 6.1.6) */
    sc = ech_server(&id_both, NULL, NULL);
    q = quic_run(cc, sc, &key_a, NULL);
    CHECK(q.rc == KSL_ERROR && q.alert_c == 121 && q.status_c == KSL_ECH_REJECTED && q.retry_len == 0 &&
              q.status_s == KSL_ECH_NONE,
          "negative_ech_server_without_ech: ech_required, no retry configurations");
    if (q.status_c != KSL_ECH_REJECTED)
        report("no-ech server", q);
    t = tcp_run(cc, sc, &key_a);
    CHECK(t.rc == KSL_ERROR && t.alert_c == 121 && t.retry_len == 0, "negative_ech_server_without_ech over TCP");
    ksl_ctx_free(sc);
    /* a downgrade to TLS 1.2 (a server without TLS 1.3): an ECH client offers TLS 1.3 only, the handshake fails */
    sc = ech_server(&id_both, &kb, NULL);
    ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(sc, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    t = tcp_run(cc, sc, &key_a);
    CHECK(t.rc == KSL_ERROR && !t.done && t.status_c != KSL_ECH_ACCEPTED && t.retry_len == 0,
          "negative_ech_downgrade_to_tls12: no connection, nothing accepted, no retry configurations");
    ksl_ctx_free(sc);
    ksl_ctx_free(cc);
    free(kb.buf);
    END();
}
static void test_grease(void) {
    SECTION("ech_grease");
    ksl_ctx *gc = ech_client(KSL_VERIFY_OPENSSL, 1);
    ksl_ctx *plain = ech_server(&id_inner, NULL, NULL);
    run q = quic_run(gc, plain, NULL, NULL);
    CHECK(
        q.rc != KSL_ERROR && q.done && q.status_c == KSL_ECH_GREASE && q.wire_ech && !strcmp(q.wire_sni, INNER),
        "GREASE (RFC 9849 section 6.2.1): the extension is sent, the real name in the clear, the handshake completes");
    if (q.status_c != KSL_ECH_GREASE)
        report("grease", q);
    run t = tcp_run(gc, plain, NULL);
    CHECK(t.rc != KSL_ERROR && t.done && t.status_c == KSL_ECH_GREASE && t.wire_ech, "GREASE over TCP");
    blob ka = keyset(1, &key_a, 1);
    ksl_ctx *ech = ech_server(&id_inner, &ka, NULL);
    q = quic_run(gc, ech, NULL, NULL);
    CHECK(q.rc != KSL_ERROR && q.done && q.status_c == KSL_ECH_GREASE && q.retry_len == 0 &&
              q.status_s == KSL_ECH_REJECTED,
          "negative_ech_grease_retry_configs_ignored: an ECH server answers GREASE with retry_configs, never reported");
    if (q.retry_len != 0 || q.status_c != KSL_ECH_GREASE)
        report("grease vs ech server", q);
    ksl_ctx *nc = ech_client(KSL_VERIFY_OPENSSL, 0);
    q = quic_run(nc, plain, NULL, NULL);
    CHECK(q.done && q.status_c == KSL_ECH_NONE && !q.wire_ech, "without GREASE nor a configuration: no extension");
    /* a configuration wins over GREASE */
    q = quic_run(gc, ech, &key_a, NULL);
    CHECK(ACCEPTED(q), "a session with a configuration offers it, not GREASE");
    ksl_ctx_free(nc);
    ksl_ctx_free(ech);
    ksl_ctx_free(plain);
    ksl_ctx_free(gc);
    free(ka.buf);
    END();
}
static void test_rotation(void) {
    SECTION("ech_key_rotation");
    blob both = keyset(2, &key_b, 1, &key_a, 0), only_b = keyset(1, &key_b, 1);
    ksl_ctx *sc = ech_server(&id_both, &both, NULL), *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    ksl_ctx_freeze(sc);
    run q = quic_run(cc, sc, &key_a, NULL);
    CHECK(ACCEPTED(q), "the old key (kept, not in retry_configs) still decrypts");
    q = quic_run(cc, sc, &key_b, NULL);
    CHECK(ACCEPTED(q), "the new key decrypts");
    /* a session made before the rotation keeps its keys */
    ksl_ssl *early = ksl_ssl_new(sc, KSL_MODE_QUIC);
    CHECK(set_keys(sc, only_b.buf, only_b.len) == KSL_OK, "rotation on a frozen context");
    ksl_ssl *c = ech_session(cc, KSL_MODE_QUIC, &key_a);
    ksl_quic_set_transport_params(early, TP, sizeof TP);
    side cs = {0}, ss = {0};
    int rc = pump(c, early, &cs, &ss, 40, accept_verify, NULL);
    uint8_t st = 0xee;
    size_t n;
    ksl_ssl_get(c, KSL_GET_ECH_STATUS, &st, 1, &n);
    CHECK(rc != KSL_ERROR && cs.done && st == KSL_ECH_ACCEPTED,
          "a session made before the rotation keeps the old keys");
    ksl_ssl_free(c);
    ksl_ssl_free(early);
    q = quic_run(cc, sc, &key_a, NULL);
    CHECK(q.alert_c == 121 && q.status_c == KSL_ECH_REJECTED && q.retry_len == key_b.list_len &&
              !memcmp(q.retry, key_b.list, key_b.list_len),
          "negative_ech_rotated_out_key: rejected with the new key's retry configuration");
    /* a retry with the retry configuration succeeds (the single retry of RFC 9849 section 6.1.6) */
    echkey retry = key_b;
    memcpy(retry.list, q.retry, q.retry_len);
    retry.list_len = q.retry_len;
    q = quic_run(cc, sc, &retry, NULL);
    CHECK(ACCEPTED(q), "the retry with the server's retry configuration is accepted");
    /* refused sets change nothing */
    blob none_retry = keyset(1, &key_a, 0);
    CHECK(set_keys(sc, none_retry.buf, none_retry.len) == KSL_ERROR,
          "negative_ech_keys_without_retry: a set with no key for retry_configs is refused");
    blob bad = keyset(1, &key_a, 1);
    memcpy(bad.buf + 5, "-----BEGIN NOTHING", 18);
    CHECK(set_keys(sc, bad.buf, bad.len) == KSL_ERROR, "negative_ech_keys_garbage_pem");
    bad.buf[4] = 2;
    CHECK(set_keys(sc, bad.buf, bad.len) == KSL_ERROR, "negative_ech_keys_unknown_flag");
    CHECK(set_keys(sc, bad.buf, 3) == KSL_ERROR, "negative_ech_keys_truncated_framing");
    CHECK(set_keys(sc, NULL, 0) == KSL_ERROR, "negative_ech_keys_empty");
    blob many = {0};
    for (int i = 0; i < 17; i++) {
        many.buf = realloc(many.buf, many.len + only_b.len);
        memcpy(many.buf + many.len, only_b.buf, only_b.len);
        many.len += only_b.len;
    }
    CHECK(set_keys(sc, many.buf, many.len) == KSL_ERROR, "negative_ech_keys_too_many: 17 keys");
    blob pubonly = keyset(1, &key_a, 1);
    echkey public_only = key_a; /* the ECHCONFIG block without the private key before it */
    public_only.pem = strstr(key_a.pem, "-----BEGIN ECHCONFIG-----");
    free(pubonly.buf);
    pubonly = keyset(1, &public_only, 1);
    CHECK(set_keys(sc, pubonly.buf, pubonly.len) == KSL_ERROR,
          "negative_ech_keys_without_private_key: an ECHCONFIG block alone is refused");
    q = quic_run(cc, sc, &retry, NULL);
    CHECK(ACCEPTED(q), "after the refused sets the last good one is in use");
    CHECK(set_keys(cc, only_b.buf, only_b.len) == KSL_ERROR, "negative_ech_keys_on_client");
    /* one parsed set serves two contexts; removing it from one leaves the other */
    ksl_ech_keys *shared = ksl_ech_keys_new(only_b.buf, only_b.len, NULL, 0);
    ksl_ctx *s2 = ech_server(&id_both, NULL, NULL);
    CHECK(shared && ksl_ctx_set_ech_keys(sc, shared) == KSL_OK && ksl_ctx_set_ech_keys(s2, shared) == KSL_OK,
          "one key set on two contexts");
    ksl_ech_keys_free(shared);
    CHECK(ksl_ctx_set_ech_keys(s2, NULL) == KSL_OK, "keys removed from one context");
    q = quic_run(cc, sc, &retry, NULL);
    CHECK(ACCEPTED(q), "the other context still decrypts with the shared set");
    q = quic_run(cc, s2, &retry, NULL);
    CHECK(q.alert_c == 121 && q.status_c == KSL_ECH_REJECTED && q.status_s == KSL_ECH_NONE,
          "without keys the server ignores ECH: rejected, no retry configurations");
    ksl_ctx_free(s2);
    free(many.buf);
    free(pubonly.buf);
    free(bad.buf);
    free(none_retry.buf);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    free(both.buf);
    free(only_b.buf);
    END();
}
static void test_set_rules(void) {
    SECTION("ech_set_rules");
    ksl_ctx *cc = ech_client(KSL_VERIFY_OPENSSL, 0), *sc = ech_server(&id_both, NULL, NULL);
    ksl_ssl *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    CHECK(ksl_ssl_set(s, KSL_SET_ECH_CONFIG_LIST, key_a.list, key_a.list_len) == KSL_ERROR &&
              last_code(s, NULL) == KSL_E_BAD_ARG,
          "negative_ech_config_on_server");
    ksl_ssl_free(s);
    ksl_ssl *c = ech_session(cc, KSL_MODE_QUIC, &key_a);
    CHECK(ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, key_a.list, key_a.list_len) == KSL_ERROR &&
              last_code(c, NULL) == KSL_E_TOO_LATE,
          "negative_ech_config_twice");
    CHECK(ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"127.0.0.1", 9) == KSL_ERROR,
          "negative_ech_ip_verify_name_after_config");
    ksl_ssl_free(c);
    c = ksl_ssl_new(cc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)"127.0.0.1", 9);
    CHECK(ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, key_a.list, key_a.list_len) == KSL_ERROR &&
              last_code(c, NULL) == KSL_E_BAD_ARG,
          "negative_ech_ip_verify_name");
    ksl_ssl_free(c);
    c = ech_session(cc, KSL_MODE_QUIC, NULL);
    ksl_drive(c);
    CHECK(ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, key_a.list, key_a.list_len) == KSL_ERROR &&
              last_code(c, NULL) == KSL_E_TOO_LATE,
          "negative_ech_config_after_start");
    ksl_ssl_free(c);
    c = ech_session(cc, KSL_MODE_QUIC, NULL);
    uint8_t broken[64];
    memcpy(broken, key_a.list, key_a.list_len < sizeof broken ? key_a.list_len : sizeof broken);
    broken[0] ^= 0x40;
    CHECK(ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, broken, sizeof broken) == KSL_ERROR &&
              last_code(c, NULL) == KSL_E_BAD_ARG,
          "negative_ech_config_malformed");
    uint8_t unusable[128], list[160];
    size_t ul = ech_config(unusable, 0xfe0d, 0x7777, PUBLIC, 0), ll = ech_list(list, 1, unusable, ul);
    CHECK(ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, list, ll) == KSL_ERROR && last_code(c, NULL) == KSL_E_NOT_SUPPORTED,
          "negative_ech_config_none_usable");
    CHECK(ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, key_a.list, key_a.list_len) == KSL_OK,
          "a refused list leaves the session open to a good one");
    ksl_ssl_free(c);
    /* bug A of ADR-0019: a context that allows TLS 1.2 has ksl_tcp_abort's extension and takes no ECH configuration */
    ksl_ctx *c12 = ech_client(KSL_VERIFY_OPENSSL, 1);
    ksl_ctx_set_option(c12, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    c = ech_session(c12, KSL_MODE_TCP, NULL);
    CHECK(ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, key_a.list, key_a.list_len) == KSL_ERROR &&
              last_code(c, NULL) == KSL_E_NOT_SUPPORTED,
          "negative_ech_config_on_tls12_context (OpenSSL 4.1.0 bug A)");
    ksl_ssl_free(c);
    /* GREASE is not affected by bug A: a TLS 1.2 context still sends it and completes */
    ksl_ctx *plain = ech_server(&id_inner, NULL, NULL);
    run t = tcp_run(c12, plain, NULL);
    CHECK(t.done && t.status_c == KSL_ECH_GREASE && t.wire_ech, "GREASE on a context that allows TLS 1.2");
    CHECK(ksl_ctx_set_option(sc, KSL_OPT_ECH_GREASE, 1) == KSL_ERROR, "negative_ech_grease_on_server");
    ksl_ctx_free(plain);
    ksl_ctx_free(c12);
    ksl_ctx_free(sc);
    ksl_ctx_free(cc);
    END();
}
static void test_sni_pause(void) {
    SECTION("ech_server_sni_pause");
    /* the server's SNI decision (KSL_OPT_SNI_PAUSE) sees the inner name when it accepts, the public name when it rejects */
    blob ka = keyset(1, &key_a, 1);
    ksl_ctx *sc = ech_server(&id_both, &ka, NULL), *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    ksl_ctx_set_option(sc, KSL_OPT_SNI_PAUSE, 1);
    const echkey *keys[2] = {&key_a, &key_b};
    const char *want[2] = {INNER, PUBLIC};
    for (int i = 0; i < 2; i++) {
        ksl_ssl *c = ech_session(cc, KSL_MODE_QUIC, keys[i]), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
        ksl_quic_set_transport_params(s, TP, sizeof TP);
        char seen[256] = "";
        for (int round = 0; round < 10 && !seen[0]; round++) {
            ksl_drive(c);
            ksl_event ev;
            while (ksl_quic_next_event(c, &ev))
                if (ev.type == KSL_EV_CRYPTO_SEND)
                    ksl_quic_provide(s, ev.level, ev.buf, ev.len);
            if (ksl_drive(s) == KSL_WANT_SNI) {
                ksl_client_hello ch;
                if (ksl_ssl_client_hello(s, &ch) == KSL_OK && ch.sni && ch.sni_len < sizeof seen) {
                    memcpy(seen, ch.sni, ch.sni_len);
                    seen[ch.sni_len] = 0;
                }
            }
        }
        CHECK(!strcmp(seen, want[i]), i == 0 ? "the SNI pause sees the inner name of an accepted ECH"
                                             : "the SNI pause sees the public name of a rejected ECH");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
    }
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    free(ka.buf);
    END();
}
static void test_resumption(void) {
    SECTION("ech_resumption");
    /* a ticket from an accepted ECH connection resumes with ECH (the PSK identity rides in the inner ClientHello, the outer one
       carries a random one: OpenSSL extensions_clnt.c) */
    blob ka = keyset(1, &key_a, 1);
    ksl_ctx *sc = ech_server(&id_both, &ka, NULL), *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    static const uint8_t ticket_key[80] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 2, 3};
    ksl_ctx_set_ticket_keys(sc, ticket_key, 1);
    ksl_ctx_set_option(sc, KSL_OPT_NUM_TICKETS, 2);
    ksl_ssl *c = ech_session(cc, KSL_MODE_QUIC, &key_a), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    side cs = {0}, ss = {0};
    pump(c, s, &cs, &ss, 40, accept_verify, NULL);
    ksl_session *sess = ksl_ssl_get1_session(c);
    CHECK(cs.done && sess != NULL, "a ticket from the ECH connection");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    c = ech_session(cc, KSL_MODE_QUIC, &key_a);
    s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    if (sess)
        ksl_ssl_set_session(c, sess);
    side cs2 = {0}, ss2 = {0};
    int rc = pump(c, s, &cs2, &ss2, 40, accept_verify, NULL);
    uint8_t reused = 0, st = 0xee;
    size_t n;
    ksl_ssl_get(c, KSL_GET_SESSION_REUSED, &reused, 1, &n);
    ksl_ssl_get(c, KSL_GET_ECH_STATUS, &st, 1, &n);
    CHECK(rc != KSL_ERROR && cs2.done && reused == 1 && st == KSL_ECH_ACCEPTED, "resumed with ECH accepted");
    ksl_session_free(sess);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    free(ka.buf);
    END();
}
/* rotation while other threads make sessions: each session copies one whole set under the context's lock (ksl_ech_ssl_init); run
   under ThreadSanitizer by KSL_TSAN=1 tools/c-test.sh */
typedef struct {
    ksl_ctx *sc;
    int stop;
} rot_arg;
static void *make_sessions(void *p) {
    rot_arg *a = p;
    for (int i = 0; i < 200 && !__atomic_load_n(&a->stop, __ATOMIC_ACQUIRE); i++)
        ksl_ssl_free(ksl_ssl_new(a->sc, KSL_MODE_QUIC));
    return NULL;
}
static void test_rotation_threads(void) {
    SECTION("ech_rotation_threads");
    blob one = keyset(1, &key_a, 1), two = keyset(2, &key_b, 1, &key_a, 0);
    ksl_ctx *sc = ech_server(&id_both, &one, NULL);
    ksl_ctx_freeze(sc);
    rot_arg a = {sc, 0};
    pthread_t t[3];
    for (int i = 0; i < 3; i++)
        pthread_create(&t[i], NULL, make_sessions, &a);
    int ok = 1;
    for (int i = 0; i < 100; i++)
        ok &= set_keys(sc, (i & 1 ? &one : &two)->buf, (i & 1 ? &one : &two)->len) == KSL_OK;
    __atomic_store_n(&a.stop, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < 3; i++)
        pthread_join(t[i], NULL);
    CHECK(ok, "100 rotations while three threads make sessions");
    ksl_ctx *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    run q = quic_run(cc, sc, &key_a, NULL);
    CHECK(ACCEPTED(q), "the last set (two keys) decrypts the old key");
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    free(one.buf);
    free(two.buf);
    END();
}
/* a host name of d bytes: labels of up to 40 'a', then ".test" */
static void name_of(char *out, int d) {
    for (int i = 0; i < d - 5; i++)
        out[i] = (i % 41 == 40 && i < d - 6) ? '.' : 'a'; /* never a dot before ".test" */
    memcpy(out + d - 5, ".test", 6);
}
/* ---------- the outcomes of RFC 9849 sections 5, 6.1.2, 6.1.6 and 6.2.1 ---------- */
/* a PEM of k's private key with `list` as its ECHCONFIG block */
static char *pem_with_list(const echkey *k, const uint8_t *list, size_t len) {
    BIO *in = BIO_new_mem_buf(k->pem, -1), *out = BIO_new(BIO_s_mem());
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long dl = 0;
    while (PEM_read_bio(in, &name, &header, &data, &dl) == 1) {
        if (strcmp(name, "ECHCONFIG") == 0)
            PEM_write_bio(out, name, "", list, (long)len);
        else
            PEM_write_bio(out, name, header, data, dl);
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }
    ERR_clear_error();
    char *p;
    long l = BIO_get_mem_data(out, &p);
    char *r = malloc((size_t)l + 1);
    memcpy(r, p, (size_t)l);
    r[l] = 0;
    BIO_free(in);
    BIO_free(out);
    return r;
}
static const uint8_t *hook_retry;
static size_t hook_retry_len;
static int hook_retry_mode, hook_reused;
static void apply_hooks(ksl_ssl *c) {
    c->test_ech_retry_set = hook_retry_mode;
    c->test_ech_retry = hook_retry;
    c->test_ech_retry_len = hook_retry_len;
    c->test_ech_reused = hook_reused;
}
static void set_hooks(int mode, const uint8_t *retry, size_t len, int reused) {
    hook_retry_mode = mode, hook_retry = retry, hook_retry_len = len, hook_reused = reused;
    session_hook = mode || reused ? apply_hooks : NULL;
}
static void forget_alert(ksl_ssl *c) {
    c->last_alert = 0;
}
static void test_outcomes(void) {
    SECTION("ech_outcomes");
    blob ka = keyset(1, &key_a, 1), kb = keyset(1, &key_b, 1);
    ksl_ctx *cc = ech_client(KSL_VERIFY_OPENSSL, 0), *gc = ech_client(KSL_VERIFY_OPENSSL, 1);
    ksl_ctx *sa = ech_server(&id_both, &ka, NULL), *sb = ech_server(&id_both, &kb, NULL),
            *plain = ech_server(&id_inner, NULL, NULL);
    /* the rejection is recorded by itself, not read back from the last alert (which a later one would replace) */
    session_hook_late = forget_alert;
    run q = quic_run(cc, sb, &key_a, NULL);
    session_hook_late = NULL;
    CHECK(q.status_c == KSL_ECH_REJECTED && q.status_c_late == KSL_ECH_REJECTED,
          "negative_ech_rejection_kept_after_the_last_alert_changes");
    /* RFC 9849 section 6.1.6: our ech_required goes out protected under the client handshake key, over TCP too (no middlebox
       compatibility mode: RFC 9846 appendix A.1) */
    run t = tcp_run(cc, sb, &key_a);
    CHECK(t.alert_c == 121 && t.status_c == KSL_ECH_REJECTED && t.last_c_type == 23 && t.last_c_len == 2 + 1 + 16,
          "TCP: the client's ech_required is the last record, application_data of 2+1+16 bytes");
    if (!(t.last_c_type == 23 && t.last_c_len == 19))
        printf("  last client record: type %d length %zu\n", t.last_c_type, t.last_c_len);
    /* section 6.1.2: a server that rejects and still resumes (a pre_shared_key in its ServerHello) is no rejection: the handshake
       fails with illegal_parameter (QUIC; over TCP OpenSSL wrote ech_required first), no retry configurations */
    set_hooks(0, NULL, 0, 1);
    run qs[2] = {quic_run(cc, sb, &key_a, NULL), tcp_run(cc, sb, &key_a)};
    for (int m = 0; m < 2; m++) {
        run r = qs[m];
        int ok = r.rc == KSL_ERROR && !r.done && r.status_c == KSL_ECH_OFFERED && r.retry_len == 0 &&
                 r.alert_c == (m == 0 ? 47 : 121) && strstr(last_msg_c, "6.1.2") != NULL;
        CHECK(ok, m == 0 ? "negative_ech_rejected_with_psk: QUIC, illegal_parameter, no retry configurations"
                         : "negative_ech_rejected_with_psk over TCP");
        if (!ok)
            report(m == 0 ? "quic psk" : "tcp psk", r);
    }
    /* section 6.1.6: retry_configs that do not parse fail the handshake with decode_error, never "securely disabled": bytes that
       do not frame (what OpenSSL refuses), and bytes OpenSSL takes but ksl's syntax check refuses */
    uint8_t dup_list[600];
    size_t dup_len;
    {
        /* key_b's ECHConfig with the extension 0a01 twice (section 4.2) */
        memcpy(dup_list, key_b.list, key_b.list_len);
        dup_len = key_b.list_len;
        dup_list[dup_len - 1] = 8; /* the extension block, empty, becomes 00 08 | 0a 01 00 00 | 0a 01 00 00 */
        static const uint8_t two[8] = {0x0a, 0x01, 0, 0, 0x0a, 0x01, 0, 0};
        memcpy(dup_list + dup_len, two, 8);
        dup_len += 8;
        size_t entry = dup_len - 6;
        dup_list[4] = (uint8_t)(entry >> 8), dup_list[5] = (uint8_t)entry;
        dup_list[0] = (uint8_t)((dup_len - 2) >> 8), dup_list[1] = (uint8_t)(dup_len - 2);
    }
    static const uint8_t unframed[] = {0, 9, 0xfe, 0x0d, 0, 40, 1, 2, 3, 4, 5};
    const uint8_t *bad_lists[2] = {unframed, dup_list};
    size_t bad_lens[2] = {sizeof unframed, dup_len};
    for (int b = 0; b < 2; b++) {
        set_hooks(1, bad_lists[b], bad_lens[b], 0);
        run rs[2] = {quic_run(cc, sb, &key_a, NULL), tcp_run(cc, sb, &key_a)};
        for (int m = 0; m < 2; m++) {
            run r = rs[m];
            int ok = r.rc == KSL_ERROR && r.status_c == KSL_ECH_OFFERED && r.retry_len == 0 &&
                     r.alert_c == (m == 0 ? 50 : 121) && strstr(last_msg_c, "6.1.6") != NULL;
            CHECK(ok, b == 0 ? (m == 0 ? "negative_ech_retry_configs_unframed: QUIC, decode_error" : "... over TCP")
                             : (m == 0 ? "negative_ech_retry_configs_duplicate_extension: QUIC, decode_error"
                                       : "... over TCP"));
            if (!ok)
                report("malformed retry", r);
        }
    }
    set_hooks(2, NULL, 0, 0); /* SSL_ech_get1_retry_config fails */
    q = quic_run(cc, sb, &key_a, NULL);
    CHECK(q.status_c == KSL_ECH_OFFERED && q.alert_c == 50,
          "negative_ech_retry_configs_refused_by_openssl: decode_error");
    /* the same from a real server: an ECH key whose ECHConfig has a trailing byte loads into OpenSSL 4.1, which then sends it
       without that byte under the original length (ech_store.c keeps the parsed bytes); and one with an extension twice */
    for (int b = 0; b < 2; b++) {
        uint8_t l[600];
        size_t n = key_b.list_len;
        memcpy(l, key_b.list, n);
        if (b == 0) {
            l[n++] = 0;
            size_t entry = n - 6;
            l[4] = (uint8_t)(entry >> 8), l[5] = (uint8_t)entry;
            l[0] = (uint8_t)((n - 2) >> 8), l[1] = (uint8_t)(n - 2);
        } else {
            memcpy(l, dup_list, dup_len);
            n = dup_len;
        }
        echkey odd = key_b;
        odd.pem = pem_with_list(&key_b, l, n);
        blob ko = keyset(1, &odd, 1);
        ksl_ctx *so = ech_server(&id_both, &ko, NULL);
        set_hooks(0, NULL, 0, 0);
        run rs[2] = {quic_run(cc, so, &key_a, NULL), tcp_run(cc, so, &key_a)};
        for (int m = 0; m < 2; m++) {
            run r = rs[m];
            int ok = r.rc == KSL_ERROR && r.status_c == KSL_ECH_OFFERED && r.retry_len == 0 && r.alert_c == 50 &&
                     (m == 0 || r.alert_s == (50 | 0x100));
            CHECK(ok, b == 0 ? (m == 0 ? "negative_ech_server_sends_truncated_retry_configs: QUIC, decode_error"
                                       : "... over TCP")
                             : (m == 0 ? "negative_ech_server_sends_duplicate_extension: QUIC, decode_error"
                                       : "... over TCP"));
            if (!ok)
                report("server malformed retry", r);
        }
        ksl_ctx_free(so);
        free(ko.buf);
        free(odd.pem);
    }
    /* M1 (the carried patch): one ECHConfig of the retry list that OpenSSL cannot use no longer takes the others with it; the
       usable one comes back alone and the retry with it is accepted */
    {
        uint8_t mand[160], kem[160], l[800];
        size_t ml = ech_config(mand, 0xfe0d, 0x0020, PUBLIC, 0xfa01), kl = ech_config(kem, 0xfe0d, 0x7777, PUBLIC, 0);
        const uint8_t *firsts[2] = {mand, kem};
        size_t first_lens[2] = {ml, kl};
        for (int b = 0; b < 2; b++) {
            size_t n = ech_list(l, 2, firsts[b], first_lens[b], key_b.list + 2, key_b.list_len - 2);
            set_hooks(1, l, n, 0);
            run r = quic_run(cc, sb, &key_a, NULL);
            int ok = r.status_c == KSL_ECH_REJECTED && r.alert_c == 121 && r.retry_len == key_b.list_len &&
                     !memcmp(r.retry, key_b.list, key_b.list_len);
            CHECK(ok, b == 0 ? "ech_retry_list_with_a_mandatory_extension_entry: the usable entry is kept"
                             : "ech_retry_list_with_an_unknown_kem_entry: the usable entry is kept");
            if (!ok)
                report("retry filter", r);
            set_hooks(0, NULL, 0, 0);
            echkey retry = key_b;
            memcpy(retry.list, r.retry, r.retry_len);
            retry.list_len = r.retry_len;
            run again = quic_run(cc, sb, &retry, NULL);
            CHECK(ACCEPTED(again), "... and the retry with it is accepted");
        }
    }
    /* M1 from a real server: retry_configs of 6 keys with long public names, 1.6 KB in all. OpenSSL 4.1.0 decoded the list
       into a store before handing it out and refused it past 1500 bytes, so a good rejection read as one whose retry_configs do
       not parse; with the patch they come back whole */
    {
        echkey big[6];
        blob kbig = {0};
        size_t want = 2;
        uint8_t all[4096];
        for (int i = 0; i < 6; i++) {
            char pn[256];
            name_of(pn, 230);
            pn[0] = (char)('b' + i);
            big[i] = make_echkey(pn);
            blob one = keyset(1, &big[i], 1);
            kbig.buf = realloc(kbig.buf, kbig.len + one.len);
            memcpy(kbig.buf + kbig.len, one.buf, one.len);
            kbig.len += one.len;
            free(one.buf);
            memcpy(all + want, big[i].list + 2, big[i].list_len - 2);
            want += big[i].list_len - 2;
        }
        ksl_ctx *sbig = ech_server(&id_both, &kbig, NULL);
        set_hooks(0, NULL, 0, 0);
        run r = quic_run(cc, sbig, &key_a, NULL);
        all[0] = (uint8_t)((want - 2) >> 8), all[1] = (uint8_t)(want - 2);
        int ok = r.status_c == KSL_ECH_REJECTED && r.alert_c == 121 && want > 1500 && r.retry_len == want &&
                 !memcmp(r.retry, all, want);
        CHECK(ok, "ech_long_retry_list: 6 retry configurations past 1500 bytes are reported whole (carried patch M1)");
        if (!ok)
            report("long retry list", r);
        ksl_ctx_free(sbig);
        free(kbig.buf);
        for (int i = 0; i < 6; i++)
            free(big[i].pem);
    }
    /* section 5: retry_configs answer only the outer ClientHello; with ECH accepted they fail the session (unsupported_extension) */
    set_hooks(1, key_b.list, key_b.list_len, 0);
    run as[2] = {quic_run(cc, sa, &key_a, NULL), tcp_run(cc, sa, &key_a)};
    for (int m = 0; m < 2; m++) {
        run r = as[m];
        int ok = r.rc == KSL_ERROR && !r.done && r.status_c == KSL_ECH_ACCEPTED && r.retry_len == 0 &&
                 (m == 0 ? r.alert_c == 110 : 1) && strstr(last_msg_c, "section 5") != NULL;
        CHECK(ok, m == 0 ? "negative_ech_accepted_with_retry_configs: QUIC, unsupported_extension"
                         : "negative_ech_accepted_with_retry_configs over TCP: the session fails");
        if (!ok)
            report("accepted with retry", r);
    }
    /* section 6.2.1: GREASE answered with retry_configs that do not parse: decode_error; that parse: ignored */
    set_hooks(1, unframed, sizeof unframed, 0);
    run gs[2] = {quic_run(gc, plain, NULL, NULL), tcp_run(gc, plain, NULL)};
    for (int m = 0; m < 2; m++) {
        run r = gs[m];
        int ok = r.rc == KSL_ERROR && !r.done && (m == 0 ? r.alert_c == 50 : 1) && strstr(last_msg_c, "6.2.1") != NULL;
        CHECK(ok, m == 0 ? "negative_ech_grease_malformed_retry_configs: QUIC, decode_error" : "... over TCP");
        if (!ok)
            report("grease malformed", r);
    }
    set_hooks(1, key_b.list, key_b.list_len, 0);
    q = quic_run(gc, plain, NULL, NULL);
    CHECK(q.done && q.status_c == KSL_ECH_GREASE && q.retry_len == 0,
          "GREASE with well-formed retry_configs completes");
    set_hooks(0, NULL, 0, 0);
    ksl_ctx_free(plain);
    ksl_ctx_free(sb);
    ksl_ctx_free(sa);
    ksl_ctx_free(gc);
    ksl_ctx_free(cc);
    free(ka.buf);
    free(kb.buf);
    END();
}
/* RFC 9849 section 6.2.1: GREASE takes a suite as a real offer would, not OpenSSL's fixed default */
static void test_grease_suites(void) {
    SECTION("ech_grease_suites");
    ksl_ctx *gc = ech_client(KSL_VERIFY_OPENSSL, 1);
    int seen[4] = {0}, other = 0;
    for (int i = 0; i < 60; i++) {
        ksl_ssl *c = ech_session(gc, KSL_MODE_QUIC, NULL);
        ksl_drive(c);
        ksl_event ev;
        char sni[256];
        int has = 0;
        if (ksl_quic_peek_event(c, &ev) && ev.type == KSL_EV_CRYPTO_SEND)
            hello_sni(ev.buf, ev.len, sni, sizeof sni, &has);
        if (has && hello_ech_kdf == 1 && hello_ech_aead >= 1 && hello_ech_aead <= 3)
            seen[hello_ech_aead]++;
        else
            other++;
        ksl_ssl_free(c);
    }
    CHECK(
        !other && seen[1] && seen[2] && seen[3],
        "60 GREASE ClientHellos: HKDF-SHA256 with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 all seen, nothing else");
    if (other || !seen[1] || !seen[2] || !seen[3])
        printf("  aes128 %d aes256 %d chacha %d other %d\n", seen[1], seen[2], seen[3], other);
    ksl_ctx_free(gc);
    END();
}
/* RFC 9849 section 7.1: an accepted inner ClientHello that offers TLS 1.2 or below is refused with illegal_parameter. ksl clients
   never offer it (TLS 1.3 only with ECH), so the client here is OpenSSL's own */
static int raw_client_run(ksl_ctx *sc, int min_version, int *server_alert, int *server_status) {
    SSL_CTX *cx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(cx, min_version);
    SSL_CTX_set_verify(cx, SSL_VERIFY_NONE, NULL);
    SSL *x = SSL_new(cx);
    SSL_set_tlsext_host_name(x, INNER);
    int ok = SSL_set1_ech_config_list(x, key_a.list, key_a.list_len) == 1;
    BIO *rb = BIO_new(BIO_s_mem()), *wb = BIO_new(BIO_s_mem());
    SSL_set_bio(x, rb, wb);
    SSL_set_connect_state(x);
    ksl_ssl *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    int done = 0;
    for (int i = 0; ok && i < 40 && !done; i++) {
        done = SSL_do_handshake(x) == 1;
        uint8_t buf[8192];
        int n;
        while ((n = BIO_read(wb, buf, sizeof buf)) > 0)
            for (size_t off = 0, used = 0; off < (size_t)n; off += used)
                if (ksl_tcp_feed(s, buf + off, (size_t)n - off, &used) != KSL_OK || !used)
                    break;
        if (ksl_drive(s) == KSL_ERROR) {
            size_t m;
            while (ksl_tcp_drain(s, buf, sizeof buf, &m) == KSL_OK && m)
                BIO_write(rb, buf, (int)m);
            SSL_do_handshake(x);
            break;
        }
        size_t m;
        while (ksl_tcp_drain(s, buf, sizeof buf, &m) == KSL_OK && m)
            BIO_write(rb, buf, (int)m);
    }
    ERR_clear_error();
    last_code(s, server_alert);
    uint8_t b = 0xee;
    size_t n;
    *server_status = ksl_ssl_get(s, KSL_GET_ECH_STATUS, &b, 1, &n) == KSL_OK ? b : -1;
    ksl_ssl_free(s);
    SSL_free(x);
    SSL_CTX_free(cx);
    return ok ? done : -1;
}
static void test_inner_tls12(void) {
    SECTION("ech_inner_offers_tls12");
    blob ka = keyset(1, &key_a, 1);
    ksl_ctx *sc = ech_server(&id_both, &ka, NULL);
    ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    int alert = 0, st = -1;
    int r = raw_client_run(sc, TLS1_3_VERSION, &alert, &st);
    CHECK(r == 1 && st == KSL_ECH_ACCEPTED, "an OpenSSL client offering TLS 1.3 only: ECH accepted");
    r = raw_client_run(sc, TLS1_2_VERSION, &alert, &st);
    CHECK(r == 0 && alert == SSL_AD_ILLEGAL_PARAMETER,
          "negative_ech_inner_offers_tls12: the server aborts with illegal_parameter (RFC 9849 section 7.1)");
    if (!(r == 0 && alert == SSL_AD_ILLEGAL_PARAMETER))
        printf("  r=%d server alert=%d status=%d\n", r, alert, st);
    /* without ECH a client may offer TLS 1.2 to this server */
    ksl_ctx *plain = ech_server(&id_inner, NULL, NULL);
    ksl_ctx_set_option(plain, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    r = raw_client_run(plain, TLS1_2_VERSION, &alert, &st);
    CHECK(alert != SSL_AD_ILLEGAL_PARAMETER, "a server without ECH keys does not apply the check");
    ksl_ctx_free(plain);
    ksl_ctx_free(sc);
    free(ka.buf);
    END();
}

/* the payload length of the encrypted_client_hello in the first ClientHello of a session for `name` with k */
static size_t payload_for(ksl_ctx *cc, const echkey *k, const char *name) {
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)name, strlen(name));
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)name, strlen(name));
    ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, k->list, k->list_len);
    ksl_quic_set_transport_params(c, TP, sizeof TP);
    ksl_drive(c);
    ksl_event ev;
    char sni[256];
    int has = 0;
    hello_ech_payload = 0;
    if (ksl_quic_peek_event(c, &ev) && ev.type == KSL_EV_CRYPTO_SEND)
        hello_sni(ev.buf, ev.len, sni, sizeof sni, &has);
    ksl_ssl_free(c);
    return has ? hello_ech_payload : 0;
}
/* RFC 9849 section 6.1.3: with maximum_name_length M, an inner server_name of length D gets max(0, M - D) bytes of padding, then
   the whole is rounded up to 32 bytes: every name up to M bytes gives the same payload length. OpenSSL 4.1.0 padded
   max(0, M - D - 9), so a name of M bytes came out up to 9 bytes longer than a short one, visible whenever that crossed a
   32-byte step (the fourth carried patch of ADR-0019). Every M of one 32-byte cycle above the 128-byte floor is tried. */
static void test_padding(void) {
    SECTION("ech_inner_name_padding");
    ksl_ctx *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
    int same = 1;
    for (int m = 160; m < 192 && same; m++) {
        echkey k = make_echkey_mnl(PUBLIC, (uint8_t)m);
        char shortest[16], longest[256];
        name_of(shortest, 6);
        name_of(longest, m);
        size_t a = payload_for(cc, &k, shortest), b = payload_for(cc, &k, longest);
        if (a == 0 || a != b) {
            printf("  M=%d: payload %zu for 6 bytes, %zu for %d bytes\n", m, a, b, m);
            same = 0;
        }
        free(k.pem);
    }
    CHECK(same, "a name of 6 bytes and one of M bytes give one encrypted payload length, for 32 values of M");
    ksl_ctx_free(cc);
    END();
}
/* RFC 9849 section 4.1: a server SHOULD give its keys distinct config_ids; OpenSSL 4.1 tries only the first key of a
   config_id (section 7.1 has it go on to the next), so a set whose keys share one is refused: a client of the second key
   would be rejected */
static void test_shared_config_id(void) {
    SECTION("ech_keys_sharing_a_config_id");
    uint8_t l[600];
    memcpy(l, key_b.list, key_b.list_len);
    l[6] = key_a.list[6]; /* key_b's ECHConfig with key_a's config_id */
    echkey twin = key_b;
    twin.pem = pem_with_list(&key_b, l, key_b.list_len);
    blob both = keyset(2, &twin, 1, &key_a, 0), alone = keyset(1, &twin, 1);
    char msg[256] = "";
    ksl_ech_keys *k = ksl_ech_keys_new(both.buf, both.len, msg, sizeof msg);
    CHECK(k == NULL && strstr(msg, "config_id") != NULL,
          "negative_ech_keys_sharing_a_config_id: refused, the message says why");
    if (k) { /* what the set would do: the client of the second key is rejected */
        ksl_ctx *sc = ech_server(&id_both, NULL, NULL), *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
        ksl_ctx_set_ech_keys(sc, k);
        run q = quic_run(cc, sc, &key_a, NULL);
        printf("  accepted: the client of key_a gets status %d\n", q.status_c);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
        ksl_ech_keys_free(k);
    }
    k = ksl_ech_keys_new(alone.buf, alone.len, msg, sizeof msg);
    CHECK(k != NULL, "the same key alone is taken");
    ksl_ech_keys_free(k);
    free(both.buf);
    free(alone.buf);
    free(twin.pem);
    END();
}
/* ---------- the alerts on the wire (the carried patches 5 and 6 of ADR-0019) ---------- */
static ksl_session *captured;
static void capture_session(ksl_ssl *c) {
    ksl_drive(c); /* TCP: read the tickets that came with the server's last flight */
    ksl_session_free(captured);
    captured = ksl_ssl_get1_session(c);
}
static void offer_captured(ksl_ssl *c) {
    if (captured)
        ksl_ssl_set_session(c, captured);
}
static ksl_ctx *wire_ctx(ksl_ctx *c) {
    ksl_ctx_set_option(c, KSL_OPT_KEYLOG, 1);
    ksl_ctx_set_ciphers(c, "TLS_AES_128_GCM_SHA256", NULL);
    return c;
}
/* checks one case over QUIC (the alert of the CONNECTION_CLOSE) and TCP (the alert of the client's last record, read off the
   wire, and the server's reading of it) */
static void wire_case(const char *what, ksl_ctx *cc, ksl_ctx *sc, const echkey *k,
                      size_t (*rw)(uint8_t *, size_t, size_t), int alert, int ech_status) {
    char m[300];
    rewrite_msg = rw;
    session_hook = captured ? offer_captured : NULL;
    run q = quic_run(cc, sc, k, NULL);
    snprintf(m, sizeof m, "%s: QUIC, alert %d", what, alert);
    int ok = q.rc == KSL_ERROR && !q.done && q.alert_c == alert && q.status_c == ech_status && q.retry_len == 0;
    CHECK(ok, m);
    if (!ok)
        report(what, q);
    run t = tcp_run(cc, sc, k);
    snprintf(m, sizeof m, "%s: TCP, alert %d on the wire, read by the server", what, alert);
    ok = t.rc == KSL_ERROR && !t.done && t.wire_alert_c == alert && t.alert_s == (alert | 0x100) &&
         t.status_c == ech_status && t.retry_len == 0;
    CHECK(ok, m);
    if (!ok) {
        printf("  wire alert %d\n", t.wire_alert_c);
        report(what, t);
    }
    rewrite_msg = NULL;
    session_hook = NULL;
}
static void test_wire_alerts(void) {
    SECTION("ech_alerts_on_the_wire");
    blob ka = keyset(1, &key_a, 1), kb = keyset(1, &key_b, 1);
    ksl_ctx *cc = wire_ctx(ech_client(KSL_VERIFY_OPENSSL, 0)), *gc = wire_ctx(ech_client(KSL_VERIFY_OPENSSL, 1));
    ksl_ctx *sa = wire_ctx(ech_server(&id_both, &ka, NULL)), *sb = wire_ctx(ech_server(&id_both, &kb, NULL));
    /* RFC 9849 sections 6.1.6 and 6.2.1: a byte after the retry_configs' ECHConfigList is no valid extension */
    wire_case("negative_ech_retry_configs_trailing_byte (rejection)", cc, sb, &key_a, ee_trailing_byte, 50,
              KSL_ECH_OFFERED);
    wire_case("negative_ech_retry_configs_trailing_byte (GREASE)", gc, sa, NULL, ee_trailing_byte, 50, KSL_ECH_GREASE);
    /* section 5: retry_configs on an accepted ECH */
    ee_ech_value = key_b.list, ee_ech_value_len = key_b.list_len;
    wire_case("negative_ech_accepted_with_retry_configs_on_the_wire", cc, sa, &key_a, ee_add_ech, 110,
              KSL_ECH_ACCEPTED);
    /* section 6.1.2: a pre_shared_key in the ServerHello after a rejection; the client holds a ticket of an accepted ECH
       connection, so its inner ClientHello offers it and the outer one a GREASE PSK */
    static const uint8_t ticket_key[80] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 4, 5, 6};
    ksl_ctx_set_ticket_keys(sa, ticket_key, 1);
    ksl_ctx_set_option(sa, KSL_OPT_NUM_TICKETS, 2);
    for (int m = 0; m < 2; m++) {
        session_hook_late = capture_session;
        run r = m == 0 ? quic_run(cc, sa, &key_a, NULL) : tcp_run(cc, sa, &key_a);
        session_hook_late = NULL;
        CHECK(ACCEPTED(r) && captured != NULL,
              m == 0 ? "a ticket from an accepted ECH connection (QUIC)" : "... (TCP)");
        rewrite_msg = sh_add_psk;
        session_hook = offer_captured;
        run x = m == 0 ? quic_run(cc, sb, &key_a, NULL) : tcp_run(cc, sb, &key_a);
        rewrite_msg = NULL;
        session_hook = NULL;
        int ok = x.rc == KSL_ERROR && !x.done && x.retry_len == 0 && x.status_c != KSL_ECH_REJECTED &&
                 (m == 0 ? x.alert_c == 47 : x.wire_alert_c == 47 && x.alert_s == (47 | 0x100));
        CHECK(ok, m == 0 ? "negative_ech_rejected_with_psk_on_the_wire: QUIC, illegal_parameter"
                         : "negative_ech_rejected_with_psk_on_the_wire: TCP, illegal_parameter on the wire");
        if (!ok) {
            printf("  wire alert %d\n", x.wire_alert_c);
            report("psk after rejection", x);
        }
        ksl_session_free(captured);
        captured = NULL;
    }
    /* section 6.2.1 from a real server: GREASE answered with retry_configs that do not frame (a key whose ECHConfig has a
       trailing byte, which OpenSSL sends truncated) */
    {
        uint8_t l[600];
        size_t n = key_b.list_len;
        memcpy(l, key_b.list, n);
        l[n++] = 0;
        l[4] = (uint8_t)((n - 6) >> 8), l[5] = (uint8_t)(n - 6);
        l[0] = (uint8_t)((n - 2) >> 8), l[1] = (uint8_t)(n - 2);
        echkey odd = key_b;
        odd.pem = pem_with_list(&key_b, l, n);
        blob ko = keyset(1, &odd, 1);
        ksl_ctx *so = wire_ctx(ech_server(&id_both, &ko, NULL));
        wire_case("negative_ech_grease_answered_with_unframed_retry_configs", gc, so, NULL, NULL, 50, KSL_ECH_GREASE);
        ksl_ctx_free(so);
        free(ko.buf);
        free(odd.pem);
    }
    ksl_ctx_free(sb);
    ksl_ctx_free(sa);
    ksl_ctx_free(gc);
    ksl_ctx_free(cc);
    free(ka.buf);
    free(kb.buf);
    END();
}
/* RFC 9849 section 6.2.1: a GREASE payload is "a randomly generated string of L+C bytes", L the padded
   EncodedClientHelloInner of a real offer of the same ClientHello: GREASE and a real offer (maximum_name_length 0, the same
   name and ALPN, with and without a ticket to offer) have one payload length (the carried patch 7 of ADR-0019) */
static size_t first_payload(ksl_ctx *cc, const echkey *k, const char *name, int mode) {
    ksl_ssl *c = ksl_ssl_new(cc, mode);
    ksl_ssl_set(c, KSL_SET_SNI, (const uint8_t *)name, strlen(name));
    ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)name, strlen(name));
    if (k)
        ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, k->list, k->list_len);
    if (captured)
        ksl_ssl_set_session(c, captured);
    if (mode == KSL_MODE_QUIC)
        ksl_quic_set_transport_params(c, TP, sizeof TP);
    ksl_drive(c);
    char sni[256];
    int has = 0;
    hello_ech_payload = 0;
    if (mode == KSL_MODE_QUIC) {
        ksl_event ev;
        if (ksl_quic_peek_event(c, &ev) && ev.type == KSL_EV_CRYPTO_SEND)
            hello_sni(ev.buf, ev.len, sni, sizeof sni, &has);
    } else {
        uint8_t b[8192];
        size_t n = 0;
        if (ksl_tcp_drain(c, b, sizeof b, &n) == KSL_OK && n > 5 && b[0] == 22)
            hello_sni(b + 5, n - 5, sni, sizeof sni, &has);
    }
    ksl_ssl_free(c);
    return has ? hello_ech_payload : 0;
}
static void test_grease_length(void) {
    SECTION("ech_grease_payload_length");
    ksl_ctx *gc = ech_client(KSL_VERIFY_OPENSSL, 1), *tc = ech_client(KSL_VERIFY_OPENSSL, 1);
    static const uint8_t alpn_tcp[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    ksl_ctx_set_alpn(tc, alpn_tcp, sizeof alpn_tcp);
    int same = 1, n = 0;
    for (int with_ticket = 0; with_ticket < 2; with_ticket++) {
        if (with_ticket) { /* a ticket of an accepted QUIC ECH connection, offered by both */
            blob ka = keyset(1, &key_a, 1);
            ksl_ctx *sa = ech_server(&id_both, &ka, NULL);
            static const uint8_t tk[80] = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1};
            ksl_ctx_set_ticket_keys(sa, tk, 1);
            ksl_ctx_set_option(sa, KSL_OPT_NUM_TICKETS, 2);
            session_hook_late = capture_session;
            quic_run(gc, sa, &key_a, NULL);
            session_hook_late = NULL;
            ksl_ctx_free(sa);
            free(ka.buf);
            CHECK(captured != NULL, "a ticket to offer");
        }
        for (int mode = 0; mode < 2; mode++)
            for (int d = 6; d < 200; d += 7) {
                char name[256];
                name_of(name, d);
                ksl_ctx *c = mode == 0 ? gc : tc;
                int m = mode == 0 ? KSL_MODE_QUIC : KSL_MODE_TCP;
                if (with_ticket && m == KSL_MODE_TCP)
                    continue; /* the QUIC ticket is for QUIC */
                size_t real = first_payload(c, &key_a, name, m), grease = first_payload(c, NULL, name, m);
                n++;
                if (!real || real != grease) {
                    if (same)
                        printf("  %s, %d-byte name%s: real %zu, GREASE %zu\n", m == KSL_MODE_QUIC ? "QUIC" : "TCP", d,
                               with_ticket ? ", ticket" : "", real, grease);
                    same = 0;
                }
            }
        ksl_session_free(captured);
        captured = NULL;
    }
    CHECK(same && n > 60,
          "GREASE and a real offer have one payload length (QUIC and TCP, 28 name lengths, with a ticket)");
    ksl_ctx_free(tc);
    ksl_ctx_free(gc);
    END();
}

/* the first ksl_ctx_set_ech_keys on a fresh server context, from several threads at once, while others make sessions: the
   key lock exists from ksl_ctx_new (a lock made by the first setter raced the others and ksl_ech_ssl_init); run under
   ThreadSanitizer by KSL_TSAN=1 tools/c-test.sh */
typedef struct {
    ksl_ctx *sc;
    const blob *keys;
    int *go;
    int ok;
} first_arg;
static void *first_set(void *p) {
    first_arg *a = p;
    while (!__atomic_load_n(a->go, __ATOMIC_ACQUIRE))
        ;
    a->ok = set_keys(a->sc, a->keys->buf, a->keys->len) == KSL_OK;
    for (int i = 0; i < 20; i++)
        ksl_ssl_free(ksl_ssl_new(a->sc, KSL_MODE_QUIC));
    return NULL;
}
static void test_first_keys_threads(void) {
    SECTION("ech_first_keys_threads");
    blob one = keyset(1, &key_a, 1);
    int ok = 1;
    for (int round = 0; round < 20; round++) {
        ksl_ctx *sc = ech_server(&id_both, NULL, NULL);
        int go = 0;
        first_arg a[4];
        pthread_t t[4];
        for (int i = 0; i < 4; i++) {
            a[i] = (first_arg){sc, &one, &go, 0};
            pthread_create(&t[i], NULL, first_set, &a[i]);
        }
        __atomic_store_n(&go, 1, __ATOMIC_RELEASE);
        for (int i = 0; i < 4; i++) {
            pthread_join(t[i], NULL);
            ok &= a[i].ok;
        }
        ksl_ctx_free(sc);
    }
    CHECK(ok, "the first key set from four threads at once on fresh contexts, sessions made meanwhile");
    free(one.buf);
    END();
}
/* ---------- review of 2026-11-20 ---------- */
static void test_review_guards(void) {
    SECTION("ech_review_guards");
    /* section 6.1.6: a rejection is acted on only after the outer handshake was authenticated for the public_name, which a
       client that verifies nothing (KSL_VERIFY_NONE) never does: ECH is refused on such a session */
    {
        ksl_ctx *nc = ech_client(KSL_VERIFY_NONE, 0);
        ksl_ssl *c = ksl_ssl_new(nc, KSL_MODE_QUIC);
        uint32_t code = 0;
        int a = 0;
        char msg[200] = "";
        int set = ksl_ssl_set(c, KSL_SET_ECH_CONFIG_LIST, key_a.list, key_a.list_len);
        ksl_ssl_last_error(c, &code, &a, msg, sizeof msg);
        CHECK(set == KSL_ERROR && strstr(msg, "KSL_VERIFY_NONE") != NULL,
              "negative_ech_config_without_verification_refused");
        if (set != KSL_ERROR || strstr(msg, "KSL_VERIFY_NONE") == NULL)
            printf("  set %d code %08x msg %s\n", set, code, msg);
        ksl_ssl_free(c);
        ksl_ctx_free(nc);
    }
    /* the verify name of an ECH session is fixed once the handshake started: after a rejection the outer handshake is checked
       against the public_name, and a new name would put the hidden one back */
    {
        ksl_ctx *cc = ech_client(KSL_VERIFY_OPENSSL, 0);
        ksl_ssl *c = ech_session(cc, KSL_MODE_QUIC, &key_a);
        (void)ksl_drive(c); /* the ClientHello is written: the handshake started */
        CHECK(ksl_ssl_set(c, KSL_SET_VERIFY_NAME, (const uint8_t *)INNER, strlen(INNER)) == KSL_ERROR,
              "negative_ech_verify_name_fixed_after_the_handshake_started");
        ksl_ssl_free(c);
        ksl_ctx_free(cc);
    }
    /* section 6.1.6: retry_configs whose ECHConfigs are all of the supported version but none usable (here an unknown KEM) are
       neither a usable replacement nor "securely disabled" (which needs no entry of a supported version): the handshake fails,
       no rejection is reported, so no caller retries with the name in the clear. Entries of another version only: disabled */
    {
        blob kb = keyset(1, &key_b, 1);
        ksl_ctx *cc = ech_client(KSL_VERIFY_OPENSSL, 0), *sb = ech_server(&id_both, &kb, NULL);
        uint8_t kem[160], other[160], l[400];
        size_t kl = ech_config(kem, 0xfe0d, 0x7777, PUBLIC, 0), ol = ech_config(other, 0xfe0c, 0x0020, PUBLIC, 0);
        size_t n = ech_list(l, 1, kem, kl);
        set_hooks(1, l, n, 0);
        run rs[2] = {quic_run(cc, sb, &key_a, NULL), tcp_run(cc, sb, &key_a)};
        for (int m = 0; m < 2; m++) {
            run r = rs[m];
            int ok = r.rc == KSL_ERROR && r.status_c == KSL_ECH_OFFERED && r.retry_len == 0 && r.alert_c == 121 &&
                     strstr(last_msg_c, "6.1.6") != NULL;
            CHECK(ok, m == 0 ? "negative_ech_retry_configs_supported_but_unusable: QUIC, no rejection reported"
                             : "... over TCP");
            if (!ok)
                report("unusable retry", r);
        }
        n = ech_list(l, 1, other, ol);
        set_hooks(1, l, n, 0);
        run q = quic_run(cc, sb, &key_a, NULL);
        CHECK(q.status_c == KSL_ECH_REJECTED && q.retry_len == 0,
              "ech_retry_configs_of_another_version_only: securely disabled");
        set_hooks(0, NULL, 0, 0);
        ksl_ctx_free(cc);
        ksl_ctx_free(sb);
        free(kb.buf);
    }
    END();
}
void run_ech(void) {
    make_pki();
    key_a = make_echkey(PUBLIC);
    key_b = make_echkey(PUBLIC);
    while (key_b.list[6] == key_a.list[6]) { /* distinct config_ids (OpenSSL tries only the first key of one) */
        free(key_b.pem);
        key_b = make_echkey(PUBLIC);
    }
    test_list_check();
    test_accept();
    test_hrr();
    test_reject();
    test_reject_client_certificate();
    test_grease();
    test_rotation();
    test_set_rules();
    test_sni_pause();
    test_resumption();
    test_rotation_threads();
    test_first_keys_threads();
    test_outcomes();
    test_grease_suites();
    test_inner_tls12();
    test_padding();
    test_shared_config_id();
    test_wire_alerts();
    test_grease_length();
    test_review_guards();
    free(key_a.pem);
    free(key_b.pem);
    free_pki();
}
#else
void run_ech(void) {
    SECTION("ech_unavailable");
    uint8_t list[6] = {0, 4, 0xfe, 0x0d, 0, 0}, out[8];
    size_t n = 9;
    static const uint8_t empty[2] = {0, 0};
    CHECK(ksl_ech_config_list_check(empty, 2, out, sizeof out, &n) == KSL_ERROR && n == 0,
          "no ECH: an empty list does not parse");
    n = 9;
    list[3] = 0x0c; /* one ECHConfig of another version: parses, nothing usable */
    CHECK(ksl_ech_config_list_check(list, 6, out, sizeof out, &n) == KSL_OK && n == 0, "no ECH: nothing usable");
    ksl_ctx *s = ksl_ctx_new(KSL_SERVER);
    char msg[128];
    CHECK(ksl_ech_keys_new(list, 2, msg, sizeof msg) == NULL, "no ECH keys without ECH");
    CHECK(ksl_ctx_set_ech_keys(s, NULL) == KSL_ERROR, "no ECH keys on a context without ECH");
    ksl_ctx_free(s);
    END();
}
#endif
