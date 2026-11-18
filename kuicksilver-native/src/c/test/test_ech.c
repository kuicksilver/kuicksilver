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
    const char *exts[][2] = {{"basicConstraints", ca ? "critical,CA:TRUE" : "CA:FALSE"},
                             {"keyUsage", ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature"},
                             {"subjectKeyIdentifier", "hash"},
                             {ca ? NULL : "extendedKeyUsage", "serverAuth"},
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
static echkey make_echkey(const char *public_name) {
    echkey k;
    memset(&k, 0, sizeof k);
    OSSL_ECHSTORE *es = OSSL_ECHSTORE_new(NULL, NULL);
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT; /* X25519, HKDF-SHA256, AES-128-GCM: RFC 9849's mandatory suite */
    BIO *m = BIO_new(BIO_s_mem());
    if (!es || !m || OSSL_ECHSTORE_new_config(es, OSSL_ECH_RFC9849_VERSION, 0, public_name, suite) != 1 ||
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

/* the server_name of a ClientHello handshake message, and whether it has encrypted_client_hello (0xfe0d) */
static int hello_sni(const uint8_t *m, size_t len, char *out, size_t cap, int *has_ech) {
    *has_ech = 0;
    out[0] = 0;
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
        if (t == 0xfe0d)
            *has_ech = 1;
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
    uint8_t retry[512];
    size_t retry_len;
    char server_sni[256];
} run;
static void sni_seen(ksl_ssl *s, char *out, size_t cap) {
    out[0] = 0;
    SSL *raw = ksl_ssl_raw_for_test(s);
    const char *n = SSL_get_servername(raw, TLSEXT_NAMETYPE_host_name);
    if (n)
        snprintf(out, cap, "%s", n);
}
static char last_msg_c[256];
static void finish(run *r, ksl_ssl *c, ksl_ssl *s) {
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
static run quic_run(ksl_ctx *cc, ksl_ctx *sc, const echkey *k, char *paused_name) {
    run r;
    memset(&r, 0, sizeof r);
    ksl_ssl *c = ech_session(cc, KSL_MODE_QUIC, k), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    ksl_drive(c);
    ksl_event ev;
    if (ksl_quic_peek_event(c, &ev) && ev.type == KSL_EV_CRYPTO_SEND && ev.level == KSL_LEVEL_INITIAL)
        hello_sni(ev.buf, ev.len, r.wire_sni, sizeof r.wire_sni, &r.wire_ech);
    side cs = {0}, ss = {0};
    r.rc = pump(c, s, &cs, &ss, 40, accept_verify, paused_name);
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
    uint8_t first[8192];
    size_t first_len = 0;
    r.rc = KSL_WANT_READ;
    for (int i = 0; i < 60; i++) {
        int a = ksl_drive(c);
        if (a == KSL_WANT_VERIFY)
            ksl_ssl_verify_resume(c, 1, 0), a = ksl_drive(c);
        move_bytes(c, s, first, &first_len);
        int b = ksl_drive(s);
        move_bytes(s, c, NULL, NULL);
        if (a == KSL_ERROR || b == KSL_ERROR) {
            if (b == KSL_ERROR)
                ksl_drive(c);
            else
                move_bytes(c, s, NULL, NULL), ksl_drive(s);
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
    uint8_t empty[2] = {0, 0};
    CHECK(ksl_ech_config_list_check(empty, 2, out, sizeof out, &on) == KSL_OK && on == 0,
          "an empty list: nothing usable");
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
    /* rejected after a HelloRetryRequest. RFC 9849 wants the rejection path (public_name authenticated, ech_required, the
       retry configurations), but OpenSSL 4.1.0's client takes any encrypted_client_hello extension in a HelloRetryRequest for
       acceptance (statem_clnt.c: hrrsignal_p != NULL), and a rejecting server sends one with 8 random bytes (its own does,
       extensions_srvr.c tls_construct_stoc_ech), so the ServerHello ends the handshake with illegal_parameter (bug C of
       ADR-0019, not patched without a decision). It fails closed: no connection, nothing accepted, no retry configurations. */
    blob kb = keyset(1, &key_b, 1);
    ksl_ctx *sb = ech_server(&id_both, &kb, "secp384r1");
    q = quic_run(cc, sb, &key_a, NULL);
    CHECK(
        q.rc == KSL_ERROR && !q.done && q.status_c != KSL_ECH_ACCEPTED && q.retry_len == 0 &&
            (q.alert_c == 47 || (q.alert_c == 121 && q.status_c == KSL_ECH_REJECTED)),
        "negative_ech_rejected_after_hrr: no connection (illegal_parameter on OpenSSL 4.1.0, bug C), nothing accepted");
    if (q.rc != KSL_ERROR || q.done)
        report("quic hrr reject", q);
    ksl_ctx_free(sb);
    free(kb.buf);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    free(ks.buf);
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
void run_ech(void) {
    make_pki();
    key_a = make_echkey(PUBLIC);
    key_b = make_echkey(PUBLIC);
    test_list_check();
    test_accept();
    test_hrr();
    test_reject();
    test_grease();
    test_rotation();
    test_set_rules();
    test_sni_pause();
    test_resumption();
    test_rotation_threads();
    free(key_a.pem);
    free(key_b.pem);
    free_pki();
}
#else
void run_ech(void) {
    SECTION("ech_unavailable");
    uint8_t list[2] = {0, 0}, out[8];
    size_t n = 9;
    CHECK(ksl_ech_config_list_check(list, 2, out, sizeof out, &n) == KSL_OK && n == 0, "no ECH: nothing usable");
    ksl_ctx *s = ksl_ctx_new(KSL_SERVER);
    char msg[128];
    CHECK(ksl_ech_keys_new(list, 2, msg, sizeof msg) == NULL, "no ECH keys without ECH");
    CHECK(ksl_ctx_set_ech_keys(s, NULL) == KSL_ERROR, "no ECH keys on a context without ECH");
    ksl_ctx_free(s);
    END();
}
#endif
