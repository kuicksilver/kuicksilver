/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* TLS certificate compression (RFC 8879, KSL_OPT_CERT_COMPRESSION, KSL_GET_CERT_COMPRESSION): the default over TCP and QUIC, client
   certificates, a peer without it, the server's first flight with and without it (RFC 9000 section 8.1), TLS 1.2 (no certificate and
   no record compression, RFC 9325 section 3.3), and a peer's malformed CompressedCertificate. A QUIC handshake's messages pass through
   the test in the clear (CRYPTO data), so the test rewrites the server's (or client's) Certificate into a CompressedCertificate of its
   own making: valid but for one field each time. */
#include "test_common.h"
#include <openssl/comp.h>
#include <openssl/ssl.h>
#include "ksl_internal.h"

#define ALG_ZLIB 1
#define ALG_BROTLI 2
#define ALG_ZSTD 3
#define CERT_LIST_MAX (100 * 1024) /* OpenSSL's max_cert_list default (SSL_MAX_CERT_LIST_DEFAULT), which ksl keeps */

/* Whether this OpenSSL compresses with brotli: not the decoder-only build of Android and iOS (ADR-0025), which the C tests also run
   on a host (the matrix step "c-tests: macos-arm64 (decoder-only)"). A server then sends zlib, a client its certificate
   uncompressed. */
static int brotli_here(void) {
    return (ksl_cert_compressors() & 2) != 0;
}
#define SERVER_ALG (brotli_here() ? ALG_BROTLI : ALG_ZLIB)
#define CLIENT_ALG (brotli_here() ? ALG_BROTLI : 0)

/* brotli inputs made beforehand, so that a build without the encoder decodes them too: 1 MiB of zeros (14 bytes), and a stream
   whose first meta-block declares 16 MiB and holds 64 bytes (68 bytes: brotli 1.2.1 sizes its ring buffer by the declared length) */
static const uint8_t BROTLI_BOMB[] = {0x59, 0xff, 0xff, 0x8f, 0x7f, 0x02, 0x20,
                                      0x1e, 0x0b, 0x04, 0x72, 0xef, 0x1f, 0x00};
static const uint8_t BROTLI_RING[68] = {0xcf, 0xff, 0xff, 0xff};
/* testdata/certcomp-chain.br: the Certificate body of server-via-intermediate + intermediate in brotli
   (tools/certs/gen-certcomp-fixtures.sh) */
static uint8_t *brotli_chain(size_t *len) {
    static uint8_t *b;
    static size_t l;
    if (!b)
        b = read_file(TESTDATA "certcomp-chain.br", &l);
    *len = l;
    return b;
}

static int set_str(ksl_ssl *s, int what, const char *v) {
    return ksl_ssl_set(s, what, (const uint8_t *)v, strlen(v));
}
static ksl_ssl *qclient(ksl_ctx *c) {
    ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC);
    set_str(s, KSL_SET_SNI, "server.test");
    set_str(s, KSL_SET_VERIFY_NAME, "server.test");
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    return s;
}
static ksl_ssl *qserver(ksl_ctx *c) {
    ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC);
    ksl_quic_set_transport_params(s, TP, sizeof TP);
    return s;
}
#ifdef KSL_TEST_TCP
static ksl_ssl *tclient(ksl_ctx *c) {
    ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_TCP);
    set_str(s, KSL_SET_SNI, "server.test");
    set_str(s, KSL_SET_VERIFY_NAME, "server.test");
    return s;
}
#endif
/* A server context with the identity `leaf` (and `inter` after it when given), certificate compression `comp`, frozen; client
   certificates required (verified against test-ca) when `mtls`. */
static ksl_ctx *srv(const char *leaf, const char *inter, int comp, int mtls) {
    ksl_ctx *c = ksl_ctx_new(KSL_SERVER);
    ksl_ctx_set_alpn(c, ALPN_H3, sizeof ALPN_H3);
    blob ch = inter ? chain_of(2, leaf, inter) : chain_of(1, leaf);
    size_t kl;
    uint8_t *k = key_of(leaf, &kl);
    CHECK(ksl_ctx_set_identity(c, ch.buf, ch.len, k, kl) == KSL_OK, "server identity");
    free(ch.buf);
    free(k);
    CHECK(ksl_ctx_set_option(c, KSL_OPT_CERT_COMPRESSION, comp) == KSL_OK, "server certificate compression option");
    if (mtls) {
        blob r = chain_of(1, "test-ca");
        ksl_ctx_set_roots(c, r.buf, r.len);
        free(r.buf);
        ksl_ctx_set_option(c, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_REQUIRED);
    }
    ksl_ctx_freeze(c);
    return c;
}
/* A client context trusting test-ca, certificate compression `comp`, with the client identity when `mtls`, frozen */
static ksl_ctx *cli(int comp, int mtls) {
    ksl_ctx *c = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
    CHECK(ksl_ctx_set_option(c, KSL_OPT_CERT_COMPRESSION, comp) == KSL_OK, "client certificate compression option");
    if (mtls) {
        blob ch = chain_of(1, "client");
        size_t kl;
        uint8_t *k = key_of("client", &kl);
        CHECK(ksl_ctx_set_identity(c, ch.buf, ch.len, k, kl) == KSL_OK, "client identity");
        free(ch.buf);
        free(k);
    }
    ksl_ctx_freeze(c);
    return c;
}
/* KSL_GET_CERT_COMPRESSION, 0xffff when the getter fails */
static unsigned peer_alg(ksl_ssl *s) {
    uint8_t b[2];
    size_t n = 0;
    if (ksl_ssl_get(s, KSL_GET_CERT_COMPRESSION, b, sizeof b, &n) != KSL_OK || n != 2)
        return 0xffff;
    return (unsigned)(b[0] << 8 | b[1]);
}
/* the alert a session sent (bit 8 clear) or received (bit 8 set), from ksl_ssl_last_error */
static int alert_of(ksl_ssl *s) {
    int a = 0;
    last_code(s, &a);
    return a;
}

/* --- TCP --- */
#ifdef KSL_TEST_TCP /* the TCP tests and their helpers: run from main under KSL_TEST_TCP only */
static size_t tshuttle(ksl_ssl *a, ksl_ssl *b) {
    uint8_t buf[4096];
    size_t total = 0, n, used;
    while (ksl_tcp_drain(a, buf, sizeof buf, &n) == KSL_OK && n) {
        size_t off = 0;
        while (off < n) {
            if (ksl_tcp_feed(b, buf + off, n - off, &used) != KSL_OK || !used)
                break;
            off += used;
        }
        total += n;
    }
    return total;
}
static int tcp_handshake(ksl_ssl *c, ksl_ssl *s) {
    for (int i = 0; i < 40; i++) {
        int r = ksl_drive(c);
        tshuttle(c, s);
        int r2 = ksl_drive(s);
        tshuttle(s, c);
        if (r == KSL_ERROR || r2 == KSL_ERROR)
            return KSL_ERROR;
        if (c->done && s->done) {
            ksl_drive(c);
            tshuttle(c, s);
            ksl_drive(s);
            return KSL_OK;
        }
    }
    return KSL_WANT_READ;
}
static void test_tcp_default(void) {
    SECTION("certcomp_tcp_default_brotli_both_ways");
    ksl_ctx *cc = cli(1, 1), *sc = srv("server", NULL, 1, 1);
    ksl_ssl *c = tclient(cc), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_handshake(c, s) == KSL_OK, "handshake");
    CHECK(peer_alg(c) == SERVER_ALG,
          "the client got the server's chain with brotli, the first of both lists (zlib: decoder only)");
    CHECK(peer_alg(s) == CLIENT_ALG, "the server got the client's certificate with brotli (none: decoder only)");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
/* Peers that also allow TLS 1.2 negotiate 1.3 and compress, each side alone allowing 1.2 or both */
static void test_tls12_capable_peers(void) {
    SECTION("certcomp_tcp_tls12_capable_peers_compress_under_tls13");
    for (int which = 1; which < 4; which++) {
        ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
        if (which & 1)
            ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
        if (which & 2)
            ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
        ksl_ctx_freeze(cc);
        ksl_ctx_freeze(sc);
        ksl_ssl *c = tclient(cc), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
        CHECK(tcp_handshake(c, s) == KSL_OK, "handshake");
        uint8_t v[2];
        size_t n;
        CHECK(ksl_ssl_get(c, KSL_GET_VERSION, v, 2, &n) == KSL_OK && v[1] == 0x04, "TLS 1.3");
        if (peer_alg(c) != SERVER_ALG)
            printf("  client%s server%s: %u\n", which & 1 ? " 1.2+" : "", which & 2 ? " 1.2+" : "", peer_alg(c));
        CHECK(peer_alg(c) == SERVER_ALG, "compressed");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}
/* The default is on: a context that never sets the option compresses (KSL_OPT_CERT_COMPRESSION 1 is the default) */
static void test_default_is_on(void) {
    SECTION("certcomp_default_is_on_without_the_option");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
    ksl_ctx_freeze(cc);
    ksl_ctx_freeze(sc);
    ksl_ssl *c = tclient(cc), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
    CHECK(tcp_handshake(c, s) == KSL_OK, "handshake");
    CHECK(peer_alg(c) == SERVER_ALG, "compressed without any option set");
    CHECK(peer_alg(s) == 0, "no client certificate: 0");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
/* RFC 8879 section 3: only a peer that offered the extension gets a compressed certificate; either side off: plain Certificates */
static void test_peer_without_compression(void) {
    SECTION("negative_certcomp_peer_without_it_gets_plain_certificates");
    for (int which = 0; which < 2; which++) {
        ksl_ctx *cc = cli(which == 0 ? 0 : 1, 1), *sc = srv("server", NULL, which == 1 ? 0 : 1, 1);
        ksl_ssl *c = tclient(cc), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
        CHECK(tcp_handshake(c, s) == KSL_OK, which ? "server off: handshake" : "client off: handshake");
        CHECK(peer_alg(c) == 0 && peer_alg(s) == 0,
              which ? "server off: both certificates plain" : "client off: both plain");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}
#endif /* KSL_TEST_TCP */
static void test_option_values(void) {
    SECTION("negative_certcomp_option_values");
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT);
    CHECK(ksl_ctx_set_option(c, KSL_OPT_CERT_COMPRESSION, 2) == KSL_ERROR, "2 refused");
    CHECK(ksl_ctx_set_option(c, KSL_OPT_CERT_COMPRESSION, -1) == KSL_ERROR, "-1 refused");
    CHECK(c->cert_compression == 1, "a refused value changes nothing");
    CHECK(ksl_ctx_set_option(c, KSL_OPT_CERT_COMPRESSION, 0) == KSL_OK && c->cert_compression == 0, "0 accepted");
    ksl_ctx_freeze(c);
    CHECK(ksl_ctx_set_option(c, KSL_OPT_CERT_COMPRESSION, 1) == KSL_ERROR, "frozen: refused");
    ksl_ctx_free(c);
    END();
}

#ifdef KSL_TEST_TCP /* run from main under KSL_TEST_TCP only: a build without the TCP tests (mingw-x64) would leave it unused */
/* TLS 1.2 (RFC 8879 section 3: the extension is ignored; RFC 9325 section 3.3: no TLS-level compression). A client that clears
   SSL_OP_NO_COMPRESSION and lowers its security level offers DEFLATE (OpenSSL's built-in method list has zlib now); the ksl server
   still chooses null, and a ksl client offers null alone. */
typedef struct {
    int hello_methods_ok; /* the ClientHello written offered only the null method */
    int hello_seen;
    int server_hello_method; /* the compression method of the ServerHello read, -1 none */
} tls12_watch;
static void watch_client(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version;
    (void)ssl;
    tls12_watch *w = arg;
    const uint8_t *m = buf;
    if (content_type != SSL3_RT_HANDSHAKE || len < 4)
        return;
    if (write_p && m[0] == SSL3_MT_CLIENT_HELLO && len > 4 + 2 + 32 + 1) {
        size_t p = 4 + 2 + 32;
        p += 1 + m[p]; /* session id */
        if (p + 2 > len)
            return;
        p += 2 + (size_t)(m[p] << 8 | m[p + 1]); /* cipher suites */
        if (p + 1 > len)
            return;
        w->hello_seen = 1;
        w->hello_methods_ok = m[p] == 1 && p + 1 < len && m[p + 1] == 0;
    }
    if (!write_p && m[0] == SSL3_MT_SERVER_HELLO && len > 4 + 2 + 32 + 1) {
        size_t p = 4 + 2 + 32;
        p += 1 + m[p];
        if (p + 3 <= len)
            w->server_hello_method = m[p + 2];
    }
}
static void test_tls12(void) {
    SECTION("negative_certcomp_tls12_no_certificate_or_record_compression");
    for (int misbehave = 0; misbehave < 2; misbehave++) {
        ksl_ctx *sc = server_ctx("server"), *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
        ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
        ksl_ctx_freeze(sc);
        ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
        ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
        ksl_ctx_freeze(cc);
        ksl_ssl *c = tclient(cc), *s = ksl_ssl_new(sc, KSL_MODE_TCP);
        tls12_watch w = {0, 0, -1};
        ksl_ssl_msg_observer_for_test(c, watch_client, &w);
        if (misbehave) { /* a peer that offers record compression: ksl's client never does. OpenSSL's security level 2 (ksl's)
                            refuses compression by itself (SSL_SECOP_COMPRESSION), so the misbehaving client drops to level 1 too */
            SSL_clear_options(ksl_ssl_raw_for_test(c), SSL_OP_NO_COMPRESSION);
            SSL_set_security_level(ksl_ssl_raw_for_test(c), 1);
        }
        CHECK(tcp_handshake(c, s) == KSL_OK, "TLS 1.2 handshake");
        uint8_t v[2];
        size_t n;
        CHECK(ksl_ssl_get(c, KSL_GET_VERSION, v, 2, &n) == KSL_OK && v[1] == 0x03, "TLS 1.2 negotiated");
        CHECK(w.hello_seen && w.hello_methods_ok == !misbehave,
              misbehave ? "the misbehaving client offered more than null (the control)" : "ksl offers only null");
        CHECK(w.server_hello_method == 0, "the ksl server chose null");
        CHECK(SSL_get_current_compression(ksl_ssl_raw_for_test(c)) == NULL &&
                  SSL_get_current_compression(ksl_ssl_raw_for_test(s)) == NULL,
              "no record compression on either side");
        CHECK(peer_alg(c) == 0, "no certificate compression in TLS 1.2 (the extension is ignored)");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}
#endif /* KSL_TEST_TCP */

/* --- QUIC --- */
/* What the test does with one side's Handshake-level messages: nothing, or rewrite its Certificate into a CompressedCertificate */
enum {
    TM_NONE,
    TM_ZLIB,   /* a valid CompressedCertificate (zlib): the control, refused only at CertificateVerify (transcript) */
    TM_BROTLI, /* the same with brotli */
    TM_LEN_PLUS1,     /* uncompressed_length one more than the output */
    TM_LEN_MINUS1,    /* one less */
    TM_LEN_ZERO,      /* 0 */
    TM_LEN_OVER,      /* max_cert_list + 1 (valid data) */
    TM_LEN_MAX,       /* 2^24 - 1 */
    TM_BOMB_ZLIB,     /* 1 MiB of zeros compressed, uncompressed_length the real one */
    TM_BOMB_BROTLI,   /* the same with brotli */
    TM_BROTLI_RING,   /* brotli declaring a 16 MiB meta-block in 68 bytes */
    TM_BOMB_AT_LIMIT, /* 1 MiB of zeros, uncompressed_length max_cert_list */
    TM_ALG_ZSTD,      /* zlib data labelled zstd (not offered) */
    TM_ALG_UNKNOWN,   /* zlib data labelled 0x4242 */
    TM_EMPTY,         /* compressed_length 0 */
    TM_GARBAGE,       /* 64 bytes that are no zlib stream */
    TM_SHORT_LENGTH,  /* compressed_length one less than the bytes that follow */
};
typedef struct {
    int mode;
    int from_client; /* rewrite the client's Certificate instead of the server's */
    int rewritten;   /* a Certificate was found and rewritten */
    size_t flight
        [2]; /* the server's CRYPTO bytes at Initial and Handshake level until the client's first Handshake bytes */
    int client_spoke;
    const uint8_t *ch_ext; /* when set: the body the client's compress_certificate extension gets in its ClientHello */
    size_t ch_ext_len;
    int ch_rewritten;
    int sent_type; /* the server's certificate message as it sent it: 11 Certificate, 25 CompressedCertificate, 0 none */
    unsigned sent_alg; /* and the algorithm of a CompressedCertificate */
} tamper;
static size_t compress_with(int alg, const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    COMP_CTX *z = COMP_CTX_new(alg == ALG_BROTLI ? COMP_brotli_oneshot() : COMP_zlib_oneshot());
    if (!z)
        return 0;
    int n = COMP_compress_block(z, out, (int)cap, (unsigned char *)(uintptr_t)in, (int)len);
    COMP_CTX_free(z);
    return n > 0 ? (size_t)n : 0;
}
static void put24(uint8_t *p, size_t v) {
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}
/* the CompressedCertificate for the Certificate message body `body` (RFC 8879 section 4: the encoded Certificate message, without
   its handshake header), shaped by `mode`; returns its length with the 4-byte header */
static size_t make_compressed(int mode, const uint8_t *body, size_t blen, uint8_t *out, size_t cap) {
    static uint8_t zeros[1 << 20];
    int alg = mode == TM_BROTLI || mode == TM_BOMB_BROTLI || mode == TM_BROTLI_RING ? ALG_BROTLI : ALG_ZLIB;
    const uint8_t *src = body;
    size_t slen = blen;
    if (mode == TM_BOMB_ZLIB || mode == TM_BOMB_BROTLI || mode == TM_BOMB_AT_LIMIT) {
        src = zeros;
        slen = sizeof zeros;
    }
    uint8_t *data = out + 4 + 2 + 3 + 3;
    size_t dlen = 0;
    if (mode == TM_GARBAGE) {
        for (size_t i = 0; i < 64; i++)
            data[i] = (uint8_t)(0x5a ^ (i * 37));
        dlen = 64;
    } else if (mode == TM_BROTLI) { /* the fixture, made by the brotli command for exactly this chain */
        uint8_t *f = brotli_chain(&dlen);
        memcpy(data, f, dlen);
    } else if (mode == TM_BOMB_BROTLI || mode == TM_BROTLI_RING) {
        dlen = mode == TM_BOMB_BROTLI ? sizeof BROTLI_BOMB : sizeof BROTLI_RING;
        memcpy(data, mode == TM_BOMB_BROTLI ? BROTLI_BOMB : BROTLI_RING, dlen);
    } else if (mode != TM_EMPTY)
        dlen = compress_with(alg, src, slen, data, cap - 12);
    size_t ulen = blen;
    if (mode == TM_LEN_PLUS1)
        ulen = blen + 1;
    else if (mode == TM_LEN_MINUS1)
        ulen = blen - 1;
    else if (mode == TM_LEN_ZERO)
        ulen = 0;
    else if (mode == TM_LEN_OVER)
        ulen = CERT_LIST_MAX + 1;
    else if (mode == TM_LEN_MAX)
        ulen = 0xffffff;
    else if (mode == TM_BOMB_AT_LIMIT)
        ulen = CERT_LIST_MAX;
    uint16_t wire_alg = mode == TM_ALG_ZSTD ? ALG_ZSTD : mode == TM_ALG_UNKNOWN ? 0x4242 : (uint16_t)alg;
    size_t body_len = 2 + 3 + 3 + dlen;
    out[0] = SSL3_MT_COMPRESSED_CERTIFICATE;
    put24(out + 1, body_len);
    out[4] = (uint8_t)(wire_alg >> 8);
    out[5] = (uint8_t)wire_alg;
    put24(out + 6, ulen);
    put24(out + 9, mode == TM_SHORT_LENGTH ? dlen - 1 : dlen);
    return 4 + body_len;
}
/* rewrites the Certificate (type 11) among `len` bytes of whole handshake messages into `out` */
static size_t rewrite(tamper *t, const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    size_t p = 0, o = 0;
    while (p + 4 <= len) {
        size_t ml = (size_t)(in[p + 1] << 16 | in[p + 2] << 8 | in[p + 3]);
        if (p + 4 + ml > len)
            break;
        if (in[p] == SSL3_MT_CERTIFICATE && t->mode != TM_NONE) {
            o += make_compressed(t->mode, in + p + 4, ml, out + o, cap - o);
            t->rewritten = 1;
        } else {
            memcpy(out + o, in + p, 4 + ml);
            o += 4 + ml;
        }
        p += 4 + ml;
    }
    memcpy(out + o, in + p, len - p); /* a partial message stays as it is */
    return o + len - p;
}
/* the ClientHello (one whole message in `in`) with the body of its compress_certificate extension (27) replaced */
static size_t rewrite_hello(tamper *t, const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    memcpy(out, in, len);
    if (len < 4 + 2 + 32 + 1 || in[0] != SSL3_MT_CLIENT_HELLO)
        return len;
    size_t p = 4 + 2 + 32;
    p += 1 + in[p];                            /* legacy_session_id */
    p += 2 + (size_t)(in[p] << 8 | in[p + 1]); /* cipher_suites */
    p += 1 + in[p];                            /* legacy_compression_methods */
    size_t exts = p, end = p + 2 + (size_t)(in[p] << 8 | in[p + 1]);
    for (p += 2; p + 4 <= end;) {
        size_t type = (size_t)(in[p] << 8 | in[p + 1]), el = (size_t)(in[p + 2] << 8 | in[p + 3]);
        if (type == 27) {
            ptrdiff_t delta = (ptrdiff_t)t->ch_ext_len - (ptrdiff_t)el;
            if (len + (size_t)delta > cap)
                return len;
            memcpy(out + p + 4, t->ch_ext, t->ch_ext_len);
            memcpy(out + p + 4 + t->ch_ext_len, in + p + 4 + el, len - (p + 4 + el));
            out[p + 2] = (uint8_t)(t->ch_ext_len >> 8);
            out[p + 3] = (uint8_t)t->ch_ext_len;
            size_t el_all = end - exts - 2 + (size_t)delta;
            out[exts] = (uint8_t)(el_all >> 8);
            out[exts + 1] = (uint8_t)el_all;
            put24(out + 1, len + (size_t)delta - 4);
            t->ch_rewritten = 1;
            return len + (size_t)delta;
        }
        p += 4 + el;
    }
    return len;
}
/* pump() of test_common.h, with each side's Handshake-level bytes of one drive collected and passed through rewrite() (for the side
   the tamper names) before the peer gets them */
static int qpump(ksl_ssl *c, ksl_ssl *s, side *cs, side *ss, tamper *t) {
    static uint8_t hs[1 << 21], out[1 << 21];
    int rc = KSL_OK;
    for (int round = 0; round < 40; round++) {
        ksl_ssl *who[2] = {c, s};
        side *me[2] = {cs, ss};
        ksl_ssl *peer[2] = {s, c};
        int progressed = 0;
        for (int k = 0; k < 2; k++) {
            int r = ksl_drive(who[k]);
            if (k == 0)
                rc = r;
            size_t hl = 0;
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                progressed = 1;
                if (ev.type == KSL_EV_CRYPTO_SEND) {
                    if (k == 0 && ev.level == KSL_LEVEL_HANDSHAKE)
                        t->client_spoke = 1;
                    if (k == 1 && !t->client_spoke &&
                        (ev.level == KSL_LEVEL_INITIAL || ev.level == KSL_LEVEL_HANDSHAKE))
                        t->flight[ev.level == KSL_LEVEL_INITIAL ? 0 : 1] += ev.len;
                    if (k == 0 && ev.level == KSL_LEVEL_INITIAL && t->ch_ext && !t->ch_rewritten) {
                        size_t ol = rewrite_hello(t, ev.buf, ev.len, out, sizeof out);
                        ksl_quic_provide(peer[k], ev.level, out, ol);
                    } else if (ev.level == KSL_LEVEL_HANDSHAKE && hl + ev.len <= sizeof hs) {
                        memcpy(hs + hl, ev.buf, ev.len);
                        hl += ev.len;
                    } else
                        ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len);
                } else if (ev.type == KSL_EV_KEY) {
                    me[k]->keys++;
                    ksl_key_free(ev.key);
                } else if (ev.type == KSL_EV_HANDSHAKE_DONE)
                    me[k]->done = 1;
            }
            if (hl && k == 1)
                for (size_t q = 0; q + 4 <= hl;) {
                    size_t ml = (size_t)(hs[q + 1] << 16 | hs[q + 2] << 8 | hs[q + 3]);
                    if (hs[q] == SSL3_MT_CERTIFICATE || hs[q] == SSL3_MT_COMPRESSED_CERTIFICATE) {
                        t->sent_type = hs[q];
                        t->sent_alg = hs[q] == SSL3_MT_COMPRESSED_CERTIFICATE && ml >= 2
                                          ? (unsigned)(hs[q + 4] << 8 | hs[q + 5])
                                          : 0;
                    }
                    q += 4 + ml;
                }
            if (hl) {
                int mine = (k == 0) == (t->from_client != 0);
                size_t ol = mine ? rewrite(t, hs, hl, out, sizeof out) : hl;
                ksl_quic_provide(peer[k], KSL_LEVEL_HANDSHAKE, mine ? out : hs, ol);
            }
            if (r == KSL_ERROR) {
                ksl_drive(peer[k]); /* the peer reads what it was given */
                return KSL_ERROR;
            }
        }
        if (cs->done && ss->done && !progressed)
            return rc;
        if (!progressed && round > 3)
            return rc;
    }
    return rc;
}
static void test_quic_default(void) {
    SECTION("certcomp_quic_default_and_mtls");
    ksl_ctx *cc = cli(1, 1), *sc = srv("server-via-intermediate", "intermediate", 1, 1);
    ksl_ssl *c = qclient(cc), *s = qserver(sc);
    side cs = {0}, ss = {0};
    tamper t = {TM_NONE, 0, 0, {0, 0}, 0, NULL, 0, 0, 0, 0};
    int rc = qpump(c, s, &cs, &ss, &t);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done && ss.done, "QUIC handshake with compressed certificates");
    CHECK(peer_alg(c) == SERVER_ALG, "the client got the chain with brotli (zlib: decoder only)");
    CHECK(peer_alg(s) == CLIENT_ALG, "a QUIC server that asks for a client certificate notes its compression");
    CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_PRESENTED, -1, NULL, 0, NULL) == 2,
          "the decompressed chain has both certificates");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}
/* RFC 9000 section 8.1: before the client's address is validated, a server sends at most three times what it received; a smaller
   Certificate keeps more of the first flight inside that. The server's CRYPTO bytes until the client answers, per chain. */
static void test_first_flight(void) {
    SECTION("certcomp_quic_first_flight_smaller");
    static const char *const chains[][2] = {
        {"server", NULL}, {"server-via-intermediate", "intermediate"}, {"server-big-chain", "intermediate"}};
    for (size_t i = 0; i < sizeof chains / sizeof chains[0]; i++) {
        size_t bytes[2];
        for (int comp = 0; comp < 2; comp++) {
            ksl_ctx *cc = cli(1, 0), *sc = srv(chains[i][0], chains[i][1], comp, 0);
            ksl_ssl *c = qclient(cc), *s = qserver(sc);
            side cs = {0}, ss = {0};
            tamper t = {TM_NONE, 0, 0, {0, 0}, 0, NULL, 0, 0, 0, 0};
            int rc = qpump(c, s, &cs, &ss, &t);
            CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done, "handshake");
            CHECK(peer_alg(c) == (unsigned)(comp ? SERVER_ALG : 0), comp ? "compressed" : "plain");
            bytes[comp] = t.flight[0] + t.flight[1];
            ksl_ssl_free(c);
            ksl_ssl_free(s);
            ksl_ctx_free(cc);
            ksl_ctx_free(sc);
        }
        printf("  first flight, %s%s%s: %zu bytes plain, %zu compressed\n", chains[i][0], chains[i][1] ? " + " : "",
               chains[i][1] ? chains[i][1] : "", bytes[0], bytes[1]);
        CHECK(bytes[1] < bytes[0], "the compressed first flight is smaller");
        if (i == 2 &&
            brotli_here()) /* zlib (decoder only) needs 3,681 bytes: within the 3x of a two-datagram ClientHello */
            CHECK(
                bytes[0] > 3 * 1200 && bytes[1] < 3 * 1200,
                "the big chain's flight exceeds three 1200-byte datagrams plain, and fits compressed (CRYPTO bytes alone)");
    }
    END();
}
/* RFC 8879 sections 4 and 5: every malformed CompressedCertificate ends the handshake with the alert the RFC (or RFC 8446 section
   6.2, for what RFC 8879 names no alert for) gives; the valid one is refused only by CertificateVerify, as its bytes are not what
   the server signed. */
static void test_tampered(void) {
    SECTION("negative_certcomp_malformed_compressed_certificate");
    static const struct {
        int mode, client_comp, alert;
        const char *what;
    } cases[] = {
        {TM_ZLIB, 1, 51,
         "control: a valid zlib CompressedCertificate decompresses (decrypt_error from CertificateVerify)"},
        {TM_BROTLI, 1, 51,
         "control: a valid brotli one decompresses as well (testdata/certcomp-chain.br; after the test certificates changed, run "
         "tools/certs/gen-certcomp-fixtures.sh)"},
        {TM_LEN_PLUS1, 1, 42, "uncompressed_length one more than the output: bad_certificate"},
        {TM_LEN_MINUS1, 1, 42, "uncompressed_length one less: bad_certificate"},
        {TM_LEN_ZERO, 1, 42, "uncompressed_length 0: bad_certificate"},
        {TM_LEN_OVER, 1, 42, "uncompressed_length above the certificate list bound: bad_certificate"},
        {TM_LEN_MAX, 1, 42, "uncompressed_length 2^24-1: bad_certificate"},
        {TM_BOMB_ZLIB, 1, 42, "zlib bomb (1 MiB of zeros): bad_certificate"},
        {TM_BOMB_BROTLI, 1, 42, "brotli bomb (1 MiB of zeros): bad_certificate"},
        {TM_BROTLI_RING, 1, 42, "brotli declaring a 16 MiB meta-block: bad_certificate"},
        {TM_BOMB_AT_LIMIT, 1, 42, "bomb with uncompressed_length at the bound: bad_certificate"},
        {TM_ALG_ZSTD, 1, 47, "zstd, which was not offered: illegal_parameter"},
        {TM_ALG_UNKNOWN, 1, 47, "an unknown algorithm: illegal_parameter"},
        {TM_EMPTY, 1, 50, "no compressed data: decode_error"},
        {TM_GARBAGE, 1, 42, "data that does not decompress: bad_certificate"},
        {TM_SHORT_LENGTH, 1, 50, "compressed_length short of the message: decode_error"},
        {TM_ZLIB, 0, 10, "a CompressedCertificate to a client that did not offer the extension: unexpected_message"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ksl_ctx *cc = cli(cases[i].client_comp, 0), *sc = srv("server-via-intermediate", "intermediate", 0, 0);
        ksl_ssl *c = qclient(cc), *s = qserver(sc);
        side cs = {0}, ss = {0};
        tamper t = {cases[i].mode, 0, 0, {0, 0}, 0, NULL, 0, 0, 0, 0};
        int rc = qpump(c, s, &cs, &ss, &t);
        int a = alert_of(c);
        if (!(t.rewritten && rc == KSL_ERROR && !cs.done && a == cases[i].alert))
            printf("  case %zu: rewritten %d rc %d alert %d\n", i, t.rewritten, rc, a);
        CHECK(t.rewritten && rc == KSL_ERROR && !cs.done && a == cases[i].alert, cases[i].what);
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}
/* The same checks on the server's side: a client certificate compressed wrongly */
static void test_tampered_client_certificate(void) {
    SECTION("negative_certcomp_malformed_client_certificate");
    static const struct {
        int mode, alert;
        const char *what;
    } cases[] = {
        {TM_LEN_PLUS1, 42, "the client's uncompressed_length one more: bad_certificate"},
        {TM_BOMB_ZLIB, 42, "the client's zlib bomb: bad_certificate"},
        {TM_ALG_ZSTD, 47, "the client's algorithm not offered: illegal_parameter"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        /* the client does not compress (it sends a plain Certificate for the test to rewrite); the server asked for compressed ones */
        ksl_ctx *cc = cli(0, 1), *sc = srv("server", NULL, 1, 1);
        ksl_ssl *c = qclient(cc), *s = qserver(sc);
        side cs = {0}, ss = {0};
        tamper t = {cases[i].mode, 1, 0, {0, 0}, 0, NULL, 0, 0, 0, 0};
        qpump(c, s, &cs, &ss, &t);
        int a = alert_of(s);
        if (!(t.rewritten && !ss.done && a == cases[i].alert))
            printf("  case %zu: rewritten %d alert %d\n", i, t.rewritten, a);
        CHECK(t.rewritten && !ss.done && a == cases[i].alert, cases[i].what);
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}

/* RFC 8879 section 3: "CertificateCompressionAlgorithm algorithms<2..2^8-2>". A list that breaks the syntax is decode_error; values
   the server does not know, or only zstd (not built), leave nothing to compress with: a plain Certificate. */
static void test_client_hello_extension(void) {
    SECTION("negative_certcomp_client_hello_extension");
    static const uint8_t empty[] = {0}, odd[] = {3, 0, 2, 0}, trailing[] = {2, 0, 2, 9},
                         unknown[] = {4, 0x42, 0x42, 0x43, 0x43}, zstd[] = {2, 0, 3}, zlib[] = {2, 0, 1};
    static const struct {
        const uint8_t *ext;
        size_t len;
        int alert;           /* the server's alert, 0 for a completed handshake */
        unsigned client_alg; /* what the client then got */
        const char *what;
    } cases[] = {
        {empty, sizeof empty, 50, 0, "an empty list: decode_error"},
        {odd, sizeof odd, 50, 0, "a list of an odd length: decode_error"},
        {trailing, sizeof trailing, 50, 0, "bytes after the list: decode_error"},
        {unknown, sizeof unknown, 0, 0, "only unknown algorithms: a plain Certificate"},
        {zstd, sizeof zstd, 0, 0, "only zstd (not in this build): a plain Certificate"},
        {zlib, sizeof zlib, 0, ALG_ZLIB,
         "only zlib: the server compresses with zlib (precompressed with both at freeze)"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ksl_ctx *cc = cli(1, 0), *sc = srv("server-via-intermediate", "intermediate", 1, 0);
        ksl_ssl *c = qclient(cc), *s = qserver(sc);
        side cs = {0}, ss = {0};
        tamper t = {TM_NONE, 0, 0, {0, 0}, 0, cases[i].ext, cases[i].len, 0, 0, 0};
        qpump(c, s, &cs, &ss, &t);
        int a = alert_of(s);
        if (cases[i].alert) {
            if (!(t.ch_rewritten && !ss.done && a == cases[i].alert))
                printf("  case %zu: rewritten %d done %d alert %d\n", i, t.ch_rewritten, ss.done, a);
            CHECK(t.ch_rewritten && !ss.done && a == cases[i].alert, cases[i].what);
        } else {
            /* the client's transcript has its own ClientHello, the server's the rewritten one, so the client refuses the server's
               CertificateVerify; what counts here is what the server sent before that */
            int want = cases[i].client_alg ? SSL3_MT_COMPRESSED_CERTIFICATE : SSL3_MT_CERTIFICATE;
            if (!(t.ch_rewritten && t.sent_type == want && t.sent_alg == cases[i].client_alg))
                printf("  case %zu: rewritten %d sent %d/%u\n", i, t.ch_rewritten, t.sent_type, t.sent_alg);
            CHECK(t.ch_rewritten && t.sent_type == want && t.sent_alg == cases[i].client_alg, cases[i].what);
        }
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}

/* A build with brotli's decoder only (Android and iOS, ADR-0025), as the probe answers there: the server's chain is compressed with
   zlib, which a client offering brotli then zlib gets; a client still decompresses brotli (from a full build's server) but sends
   its own certificate uncompressed (OpenSSL would pick brotli for it, fail, and end the handshake). */
static void test_decoder_only(void) {
    SECTION("negative_aDecoderOnlyClientSendsItsCertificateUncompressed");
    ksl_brotli_compresses_for_test(0);
    ksl_ctx *cc = cli(1, 1), *sc = srv("server", NULL, 1, 1), *full = NULL;
    ksl_ssl *c = qclient(cc), *s = qserver(sc);
    side cs = {0}, ss = {0};
    tamper t = {TM_NONE, 0, 0, {0, 0}, 0, NULL, 0, 0, 0, 0};
    int rc = qpump(c, s, &cs, &ss, &t);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done && ss.done, "handshake");
    CHECK(peer_alg(c) == ALG_ZLIB, "the server's chain in zlib");
    CHECK(peer_alg(s) == 0, "the client's certificate uncompressed");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_brotli_compresses_for_test(-1);
    /* a server of this build (brotli where brotli compresses): the decoder-only client takes what it sends */
    full = srv("server", NULL, 1, 1);
    unsigned sent = SERVER_ALG; /* what this build's server sends, before the client is made decoder-only */
    ksl_brotli_compresses_for_test(0);
    cc = cli(1, 1);
    c = qclient(cc);
    s = qserver(full);
    side cs2 = {0}, ss2 = {0};
    rc = qpump(c, s, &cs2, &ss2, &t);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs2.done && ss2.done, "handshake with a full server");
    CHECK(peer_alg(c) == sent, "a decoder-only client decompresses what a server sends");
    CHECK(peer_alg(s) == 0, "and sends its certificate uncompressed");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    ksl_ctx_free(full);
    ksl_brotli_compresses_for_test(-1);
    END();
}

/* RFC 8879 section 5 SHOULD: the one-shot brotli decoder OpenSSL uses holds its allocations to 3 x the output + 256 KiB
   (tools/openssl/brotli/ksl_decompress.c): a stream declaring a 16 MiB meta-block in 68 bytes made brotli 1.2.1 allocate 16.8 MiB */
int BrotliDecoderDecompress(size_t encoded_size, const uint8_t *encoded, size_t *decoded_size, uint8_t *decoded);
size_t ksl_brotli_decode_budget(size_t decoded);
extern _Thread_local size_t ksl_brotli_decode_peak;
static void test_brotli_memory_bound(void) {
    SECTION("negative_certcomp_brotli_memory_bounded");
    static uint8_t out[CERT_LIST_MAX];
    size_t n = sizeof out;
    CHECK(BrotliDecoderDecompress(sizeof BROTLI_RING, BROTLI_RING, &n, out) != 1, "the 68-byte stream fails");
    printf("  68-byte stream: peak %zu bytes, budget %zu\n", ksl_brotli_decode_peak,
           ksl_brotli_decode_budget(sizeof out));
    CHECK(ksl_brotli_decode_peak <= ksl_brotli_decode_budget(sizeof out) && ksl_brotli_decode_peak < 1024 * 1024,
          "its allocations stayed under the budget (not 16.8 MiB)");
    size_t fl;
    uint8_t *f = brotli_chain(&fl);
    blob ch = chain_of(2, "server-via-intermediate", "intermediate");
    size_t body =
        4 + ch.len + 2; /* context and list length, then per entry 3 + DER + 2 against the framing's 4 + DER */
    n = sizeof out;
    CHECK(BrotliDecoderDecompress(fl, f, &n, out) == 1 && n == body,
          "the fixture decodes to the chain's Certificate body (else run tools/certs/gen-certcomp-fixtures.sh)");
    CHECK(ksl_brotli_decode_peak <= ksl_brotli_decode_budget(sizeof out), "inside the budget");
    n = 2;
    CHECK(BrotliDecoderDecompress(fl, f, &n, out) != 1, "an output too small fails, as upstream's");
    CHECK(ksl_brotli_decode_budget((size_t)-1) == (size_t)-1, "the budget saturates");
    free(ch.buf);
    END();
}

void run_certcomp(void) {
    test_brotli_memory_bound();
    test_option_values();
    test_quic_default();
    test_first_flight();
    test_tampered();
    test_tampered_client_certificate();
    test_client_hello_extension();
    test_decoder_only();
#ifdef KSL_TEST_TCP
    test_tcp_default();
    test_default_is_on();
    test_tls12_capable_peers();
    test_peer_without_compression();
    test_tls12();
#endif
}
