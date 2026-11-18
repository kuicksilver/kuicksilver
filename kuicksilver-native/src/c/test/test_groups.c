/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Key-exchange groups (ksl_ctx_set_groups, KSL_GET_GROUP; RFC 9846 sections 4.2.1, 4.2.4, 4.3.7 and 4.3.8, RFC 9001 sections 4.7
   and 4.8): the list's checks, what a client puts on the wire, the server's choice by its own order, HelloRetryRequest, no group in
   common, SNI overrides and resumption, over QUIC and TCP. */
#include "test_common.h"
#include "ksl_internal.h" /* the TCP pump reads whether a session is done */

#define G_X25519MLKEM768 0x11ec
#define G_X25519 0x001d
#define G_X448 0x001e
#define G_P256 0x0017
#define G_P384 0x0018
#define G_P521 0x0019

static int set_str(ksl_ssl *s, int what, const char *v) {
    return ksl_ssl_set(s, what, (const uint8_t *)v, strlen(v));
}
static ksl_ssl *new_client(ksl_ctx *c, int tcp) {
    ksl_ssl *s = ksl_ssl_new(c, tcp ? KSL_MODE_TCP : KSL_MODE_QUIC);
    set_str(s, KSL_SET_SNI, "server.test");
    set_str(s, KSL_SET_VERIFY_NAME, "server.test");
    if (!tcp)
        ksl_quic_set_transport_params(s, TP, sizeof TP);
    return s;
}
static ksl_ssl *new_server(ksl_ctx *c, int tcp) {
    ksl_ssl *s = ksl_ssl_new(c, tcp ? KSL_MODE_TCP : KSL_MODE_QUIC);
    if (!tcp)
        ksl_quic_set_transport_params(s, TP, sizeof TP);
    return s;
}
static void shuttle(ksl_ssl *a, ksl_ssl *b) {
    uint8_t buf[4096];
    size_t n, used;
    while (ksl_tcp_drain(a, buf, sizeof buf, &n) == KSL_OK && n) {
        size_t off = 0;
        while (off < n && ksl_tcp_feed(b, buf + off, n - off, &used) == KSL_OK && used)
            off += used;
    }
}
static int tcp_pump(ksl_ssl *c, ksl_ssl *s, int (*on_want)(ksl_ssl *, int, void *), void *arg) {
    for (int i = 0; i < 60; i++) {
        int r = ksl_drive(c);
        shuttle(c, s);
        int r2 = ksl_drive(s);
        if (r2 == KSL_WANT_SNI && on_want && !on_want(s, r2, arg))
            return r2;
        shuttle(s, c);
        if (r == KSL_ERROR || r2 == KSL_ERROR) {
            if (r2 == KSL_ERROR)
                ksl_drive(c); /* the client reads the server's alert */
            return KSL_ERROR;
        }
        if (c->done && s->done)
            return KSL_OK;
    }
    return KSL_WANT_READ;
}
/* Runs a handshake over QUIC (tcp 0) or TCP; KSL_OK when both sides completed */
static int handshake(ksl_ssl *c, ksl_ssl *s, int tcp, int (*on_want)(ksl_ssl *, int, void *), void *arg) {
    if (tcp)
        return tcp_pump(c, s, on_want, arg);
    side cs = {0}, ss = {0};
    int rc = pump(c, s, &cs, &ss, 60, on_want, arg);
    return rc != KSL_ERROR && cs.done && ss.done ? KSL_OK : KSL_ERROR;
}
static int group_of(ksl_ssl *s) {
    uint8_t b[2];
    size_t n = 0;
    if (ksl_ssl_get(s, KSL_GET_GROUP, b, sizeof b, &n) != KSL_OK)
        return -1;
    return n == 0 ? 0 : n == 2 ? (b[0] << 8 | b[1]) : -2;
}
static ksl_ctx *groups_client(const char *list) {
    ksl_ctx *c = client_ctx("test-ca", KSL_VERIFY_OPENSSL);
    if (list && ksl_ctx_set_groups(c, list) != KSL_OK)
        printf("client groups %s refused\n", list);
    return c;
}
static ksl_ctx *groups_server(const char *list) {
    ksl_ctx *c = server_ctx("server");
    if (list && ksl_ctx_set_groups(c, list) != KSL_OK)
        printf("server groups %s refused\n", list);
    return c;
}

/* What the handshake messages carried: the ClientHellos' supported_groups and key_share groups, the EncryptedExtensions'
   supported_groups (each as code points), and how many ClientHellos there were. */
typedef struct {
    int hellos;
    uint16_t groups[16], shares[8], ee_groups[16];
    size_t ngroups, nshares, nee;
    int ee_seen, bad;
} wire;
static int u16(const uint8_t *p) {
    return p[0] << 8 | p[1];
}
/* the body of extension `type` in an extensions block, or NULL */
static const uint8_t *find_ext(const uint8_t *p, size_t len, int type, size_t *out_len) {
    size_t i = 0;
    while (i + 4 <= len) {
        int t = u16(p + i);
        size_t l = (size_t)u16(p + i + 2);
        if (i + 4 + l > len)
            return NULL;
        if (t == type) {
            *out_len = l;
            return p + i + 4;
        }
        i += 4 + l;
    }
    return NULL;
}
static void read_group_list(const uint8_t *e, size_t l, uint16_t *out, size_t cap, size_t *n, int *bad) {
    *n = 0;
    if (!e || l < 2 || (size_t)u16(e) != l - 2 || (l & 1)) {
        *bad = 1;
        return;
    }
    for (size_t i = 2; i + 1 < l && *n < cap; i += 2)
        out[(*n)++] = (uint16_t)u16(e + i);
}
static void observe(int write_p, int version, int content_type, const void *buf, size_t len, struct ssl_st *ssl,
                    void *arg) {
    (void)version;
    (void)ssl;
    wire *w = arg;
    const uint8_t *m = buf;
    if (content_type != SSL3_RT_HANDSHAKE || len < 4)
        return;
    if (write_p && m[0] == SSL3_MT_CLIENT_HELLO) {
        w->hellos++;
        /* type, length(3), legacy_version(2), random(32), session id, cipher suites, compression methods, extensions */
        size_t i = 4 + 2 + 32;
        if (i >= len)
            return;
        i += 1 + m[i];
        if (i + 2 > len)
            return;
        i += 2 + (size_t)u16(m + i);
        if (i >= len)
            return;
        i += 1 + m[i];
        if (i + 2 > len)
            return;
        size_t el = (size_t)u16(m + i), gl = 0, kl = 0;
        const uint8_t *exts = m + i + 2;
        if (i + 2 + el > len) {
            w->bad = 1;
            return;
        }
        /* found first: C leaves the order of a call's arguments open, and gcc reads gl before find_ext sets it */
        const uint8_t *sg = find_ext(exts, el, 10, &gl);
        read_group_list(sg, gl, w->groups, 16, &w->ngroups, &w->bad);
        const uint8_t *ks = find_ext(exts, el, 51, &kl);
        w->nshares = 0;
        if (!ks || kl < 2 || (size_t)u16(ks) != kl - 2) {
            w->bad = 1;
            return;
        }
        for (size_t k = 2; k + 4 <= kl && w->nshares < 8;) {
            w->shares[w->nshares++] = (uint16_t)u16(ks + k);
            k += 4 + (size_t)u16(ks + k + 2);
        }
    } else if (!write_p && m[0] == SSL3_MT_ENCRYPTED_EXTENSIONS && len >= 6) {
        size_t gl = 0;
        const uint8_t *g = find_ext(m + 6, len - 6, 10, &gl);
        w->ee_seen = 1;
        w->nee = 0;
        if (g)
            read_group_list(g, gl, w->ee_groups, 16, &w->nee, &w->bad);
    }
}
static int list_is(const uint16_t *got, size_t n, const uint16_t *want, size_t wn) {
    return n == wn && (wn == 0 || !memcmp(got, want, wn * sizeof *want));
}

/* The list's checks: every refusal is KSL_E_BAD_ARG (or KSL_E_CTX_FROZEN) and changes nothing */
static int refused(ksl_ctx *c, const char *list, uint32_t want) {
    char before[sizeof c->groups];
    memcpy(before, c->groups, sizeof before);
    uint32_t code = 0;
    char m[256] = {0};
    int rc = ksl_ctx_set_groups(c, list);
    ksl_ctx_last_error(c, &code, m, sizeof m);
    return rc == KSL_ERROR && code == want && m[0] && !memcmp(before, c->groups, sizeof before);
}
static void test_negative_group_list_checks(void) {
    SECTION("negative_group_list_checks");
    ksl_ctx *c = ksl_ctx_new(KSL_CLIENT), *s = ksl_ctx_new(KSL_SERVER);
    static const char *const bad[] = {
        "",
        ":",
        "X25519:",
        ":X25519",
        "X25519::secp256r1",
        "X25519 ",
        " X25519",
        "X25519,secp256r1",
        "nope",
        "P-256", /* an alias OpenSSL takes: ksl takes the IANA names only */
        "brainpoolP256r1tls13",
        "ffdhe2048",
        "X25519:x25519", /* RFC 9846 section 4.3.7: no duplicate entries */
        "secp256r1:SECP256R1",
        "?X25519",
        "-X25519",
        "DEFAULT",
        "X25519/secp256r1",
        "**X25519",
        "*",
        "X25519*",
        "*X25519MLKEM768:*SecP256r1MLKEM768:*X25519:*secp256r1:*secp384r1", /* five key shares */
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char what[160];
        snprintf(what, sizeof what, "negative: client list \"%s\" is refused, nothing changed", bad[i]);
        CHECK(refused(c, bad[i], KSL_E_BAD_ARG), what);
    }
    CHECK(ksl_ctx_set_groups(c, NULL) == KSL_ERROR, "negative: NULL is refused");
    CHECK(refused(s, "*X25519:secp256r1", KSL_E_BAD_ARG), "negative: a server takes no key share mark");
    char longest[600] = {0};
    for (int i = 0; i < 40; i++)
        strcat(longest, "secp256r1:");
    CHECK(refused(c, longest, KSL_E_BAD_ARG), "negative: a list longer than every valid one is refused");
    CHECK(ksl_ctx_set_groups(c, "*x25519:SECP256R1:*secp384r1") == KSL_OK &&
              !strcmp(c->groups, "*X25519:secp256r1:*secp384r1"),
          "names in any case, kept in OpenSSL's spelling");
    CHECK(ksl_ctx_set_groups(
              c, "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:X448:secp256r1:secp384r1:secp521r1") ==
              KSL_OK,
          "every group of the table at once");
    CHECK(ksl_ctx_set_groups(s, "secp384r1:X25519") == KSL_OK && !strcmp(s->groups, "secp384r1:X25519"),
          "a server list");
    ksl_ctx_freeze(s);
    CHECK(refused(s, "X25519", KSL_E_CTX_FROZEN), "negative: a frozen context keeps its groups");
    ksl_ctx_free(c);
    ksl_ctx_free(s);
    END();
}

/* The default is unchanged: the six groups in this order, key shares for X25519MLKEM768 and X25519 (RFC 9846 section 4.3.8: the
   shares a subset of supported_groups, in its order, one per group) */
static void test_default_groups(void) {
    SECTION("groups_default_unchanged");
    for (int tcp = 0; tcp < 2; tcp++) {
        ksl_ctx *cc = groups_client(NULL), *sc = groups_server(NULL);
        ksl_ssl *c = new_client(cc, tcp), *s = new_server(sc, tcp);
        wire w = {0};
        ksl_ssl_msg_observer_for_test(c, observe, &w);
        CHECK(group_of(c) == 0, "no group before the handshake");
        CHECK(handshake(c, s, tcp, NULL, NULL) == KSL_OK, "handshake");
        static const uint16_t groups[] = {G_X25519MLKEM768, G_X25519, G_P256, G_X448, G_P384, G_P521},
                              shares[] = {G_X25519MLKEM768, G_X25519};
        CHECK(!w.bad && list_is(w.groups, w.ngroups, groups, 6), "supported_groups: the default order");
        CHECK(list_is(w.shares, w.nshares, shares, 2), "key shares for X25519MLKEM768 and X25519");
        CHECK(w.hellos == 1 && group_of(c) == G_X25519MLKEM768 && group_of(s) == G_X25519MLKEM768,
              "X25519MLKEM768 in one flight, both sides report it");
        CHECK(w.ee_seen && w.nee == 0,
              "the server's first group was taken: no supported_groups in EncryptedExtensions");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}

/* A configured client list on the wire: supported_groups in its order, key shares for the marked groups only, in that order */
static void test_client_hello_groups(void) {
    SECTION("groups_client_hello_carries_the_list");
    static const struct {
        const char *list;
        uint16_t groups[4], shares[4];
        size_t ng, ns;
    } cases[] = {
        {"secp384r1:*X25519:secp256r1", {G_P384, G_X25519, G_P256}, {G_X25519}, 3, 1},
        {"*secp384r1:x25519:*secp256r1", {G_P384, G_X25519, G_P256}, {G_P384, G_P256}, 3, 2},
        {"secp521r1:X448", {G_P521, G_X448}, {G_P521}, 2, 1}, /* none marked: the first group */
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        ksl_ctx *cc = groups_client(cases[i].list), *sc = groups_server(NULL);
        ksl_ssl *c = new_client(cc, 1), *s = new_server(sc, 1);
        wire w = {0};
        ksl_ssl_msg_observer_for_test(c, observe, &w);
        handshake(c, s, 1, NULL, NULL);
        char what[160];
        snprintf(what, sizeof what, "\"%s\": supported_groups and key_share as configured", cases[i].list);
        CHECK(!w.bad && list_is(w.groups, w.ngroups, cases[i].groups, cases[i].ng) &&
                  list_is(w.shares, w.nshares, cases[i].shares, cases[i].ns),
              what);
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}

/* RFC 9846 section 4.2.1: "If the server selects an asymmetric key exchange group and the client did not offer a compatible
   "key_share" extension in the initial ClientHello, the server MUST respond with a HelloRetryRequest"; section 4.3.8: the second
   ClientHello carries one share, for the group asked for. The lists meet only on the client's second group. */
static void test_hello_retry_on_non_first_group(void) {
    SECTION("groups_hello_retry_request_for_a_non_first_group");
    for (int tcp = 0; tcp < 2; tcp++) {
        ksl_ctx *cc = groups_client("*X25519:secp256r1"), *sc = groups_server("secp384r1:secp256r1");
        ksl_ssl *c = new_client(cc, tcp), *s = new_server(sc, tcp);
        wire w = {0};
        ksl_ssl_msg_observer_for_test(c, observe, &w);
        CHECK(handshake(c, s, tcp, NULL, NULL) == KSL_OK,
              tcp ? "TCP: handshake completes" : "QUIC: handshake completes");
        static const uint16_t second[] = {G_P256};
        CHECK(w.hellos == 2 && list_is(w.shares, w.nshares, second, 1),
              "two ClientHellos, the second with one key share, for secp256r1");
        CHECK(group_of(c) == G_P256 && group_of(s) == G_P256, "secp256r1 on both sides");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}

/* RFC 9846 section 4.2.1: "If there is no overlap between the received "supported_groups" and the groups supported by the server,
   then the server MUST abort the handshake with a "handshake_failure" or an "insufficient_security" alert"; RFC 9001 section 4.8
   makes it CRYPTO_ERROR 0x0128 in QUIC (the transport adds 0x0100). */
static void test_no_common_group(void) {
    SECTION("negative_groups_without_overlap_handshake_failure");
    for (int tcp = 0; tcp < 2; tcp++) {
        ksl_ctx *cc = groups_client("*X25519:X448"), *sc = groups_server("secp384r1:secp256r1");
        ksl_ssl *c = new_client(cc, tcp), *s = new_server(sc, tcp);
        int sent = 0, got = 0;
        CHECK(handshake(c, s, tcp, NULL, NULL) == KSL_ERROR, tcp ? "TCP: refused" : "QUIC: refused");
        last_code(s, &sent);
        last_code(c, &got);
        CHECK(sent == SSL_AD_HANDSHAKE_FAILURE, "the server sends handshake_failure (40)");
        /* QUIC carries no alert record: the transport sends the code in CONNECTION_CLOSE (RFC 9001 section 4.8) */
        CHECK(!tcp || got == (SSL_AD_HANDSHAKE_FAILURE | 0x100), "TCP: the client receives it");
        ksl_ssl_free(c);
        ksl_ssl_free(s);
        ksl_ctx_free(cc);
        ksl_ctx_free(sc);
    }
    END();
}

/* The server's own order decides, a group with a key share first (no HelloRetryRequest when one is usable): among the client's
   shares, the first of the server's list; with none usable, a HelloRetryRequest for the first of the server's list the client
   supports, not the client's first. RFC 9846 section 4.3.7: a server that took another group than its first sends
   supported_groups (its whole list) in EncryptedExtensions (SHOULD). */
static void test_server_preference(void) {
    SECTION("groups_server_chooses_by_its_own_order");
    static const struct {
        const char *client, *server;
        int group, hellos;
        const char *what;
    } cases[] = {
        {"*X25519:*secp256r1", "secp256r1:X25519", G_P256, 1,
         "two shares: the server's first of them, not the client's"},
        {"*secp256r1:*X25519", "X25519:secp256r1", G_X25519, 1, "two shares, the other way round"},
        {"*X25519:secp256r1", "secp256r1:X25519", G_X25519, 1,
         "the only share is taken over a preferred group without one"},
        {"*X448:X25519:secp256r1", "secp256r1:X25519", G_P256, 2,
         "no usable share: HelloRetryRequest for the server's first"},
        {"*X448:secp384r1:secp256r1:X25519", "X25519:secp256r1:secp384r1", G_X25519, 2,
         "no usable share: the server's first the client supports, though the client lists it last"},
    };
    for (int tcp = 0; tcp < 2; tcp++)
        for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
            ksl_ctx *cc = groups_client(cases[i].client), *sc = groups_server(cases[i].server);
            ksl_ssl *c = new_client(cc, tcp), *s = new_server(sc, tcp);
            wire w = {0};
            ksl_ssl_msg_observer_for_test(c, observe, &w);
            char what[200];
            snprintf(what, sizeof what, "%s %s", tcp ? "TCP:" : "QUIC:", cases[i].what);
            CHECK(handshake(c, s, tcp, NULL, NULL) == KSL_OK && group_of(c) == cases[i].group &&
                      group_of(s) == cases[i].group && w.hellos == cases[i].hellos,
                  what);
            /* the server took a group other than its first: EncryptedExtensions name its whole list, in its order */
            uint16_t first = (uint16_t)(strncmp(cases[i].server, "secp256r1", 9) == 0 ? G_P256 : G_X25519);
            CHECK(w.ee_seen && (cases[i].group == first ? w.nee == 0 : w.nee >= 2 && w.ee_groups[0] == first),
                  "supported_groups in EncryptedExtensions exactly when the server took another than its first");
            ksl_ssl_free(c);
            ksl_ssl_free(s);
            ksl_ctx_free(cc);
            ksl_ctx_free(sc);
        }
    END();
}

/* An SNI override's groups, not the base context's, decide once the override is applied (ksl_client_hello_cb,
   ksl_ctx_apply_to_ssl), both ways: an override that takes the client's share completes in one flight under a base that would
   have asked for another, and an override that takes another group asks for it. */
typedef struct {
    ksl_ctx *override;
    int asked;
} sni_answer;
static int on_sni(ksl_ssl *s, int rc, void *arg) {
    sni_answer *a = arg;
    if (rc != KSL_WANT_SNI)
        return 1;
    a->asked++;
    return ksl_ssl_sni_resume(s, a->override, 0) == KSL_OK;
}
static void test_sni_override_groups(void) {
    SECTION("groups_of_the_sni_override_apply");
    for (int tcp = 0; tcp < 2; tcp++)
        for (int way = 0; way < 2; way++) {
            ksl_ctx *cc = groups_client("*X25519:secp384r1"), *sc = groups_server(way ? "X25519" : "secp384r1"),
                    *o = groups_server(way ? "secp384r1" : "X25519");
            ksl_ctx_set_option(sc, KSL_OPT_SNI_PAUSE, 1);
            ksl_ctx_freeze(o);
            ksl_ssl *c = new_client(cc, tcp), *s = new_server(sc, tcp);
            wire w = {0};
            ksl_ssl_msg_observer_for_test(c, observe, &w);
            sni_answer a = {o, 0};
            int rc = handshake(c, s, tcp, on_sni, &a);
            char what[160];
            snprintf(what, sizeof what, "%s override of %s: its own group, %s", tcp ? "TCP" : "QUIC",
                     way ? "secp384r1" : "X25519", way ? "after a HelloRetryRequest" : "in one flight");
            CHECK(rc == KSL_OK && a.asked == 1 && group_of(s) == (way ? G_P384 : G_X25519) && w.hellos == (way ? 2 : 1),
                  what);
            ksl_ssl_free(c);
            ksl_ssl_free(s);
            ksl_ctx_free(cc);
            ksl_ctx_free(sc);
            ksl_ctx_free(o);
        }
    END();
}

/* A ticket does not bind the group (psk_dhe_ke runs a fresh key exchange): it resumes under a client and a server whose groups
   changed since it was issued, also through a HelloRetryRequest; RFC 9846 section 4.2.2 has the second ClientHello carry the PSK
   again. */
static void test_resumption_with_other_groups(void) {
    SECTION("groups_resumption_under_other_groups");
    uint8_t keys[80];
    for (int i = 0; i < 80; i++)
        keys[i] = (uint8_t)(i * 5 + 3);
    ksl_ctx *cc = groups_client("*X25519"), *sc = groups_server("X25519:secp256r1"),
            *cc2 = groups_client("*secp256r1:secp384r1"), *sc2 = groups_server("secp384r1");
    ksl_ctx *servers[2] = {sc, sc2};
    for (int i = 0; i < 2; i++) {
        ksl_ctx_set_option(servers[i], KSL_OPT_NUM_TICKETS, 1);
        ksl_ctx_set_ticket_keys(servers[i], keys, 1);
    }
    ksl_ssl *c = new_client(cc, 1), *s = new_server(sc, 1);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && group_of(c) == G_X25519, "first handshake with X25519");
    /* the ticket arrives after the handshake */
    uint8_t buf[16];
    size_t n;
    ksl_tcp_read(c, buf, sizeof buf, &n);
    ksl_session *sess = ksl_ssl_get1_session(c);
    CHECK(sess != NULL, "a ticket");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    for (int hrr = 0; hrr < 2; hrr++) {
        ksl_ssl *c2 = new_client(cc2, 1), *s2 = new_server(hrr ? sc2 : sc, 1);
        wire w = {0};
        ksl_ssl_msg_observer_for_test(c2, observe, &w);
        ksl_ssl_set_session(c2, sess);
        uint8_t re = 0;
        int rc = tcp_pump(c2, s2, NULL, NULL);
        ksl_ssl_get(c2, KSL_GET_SESSION_REUSED, &re, 1, &n);
        CHECK(rc == KSL_OK && re == 1 && group_of(c2) == (hrr ? G_P384 : G_P256) && w.hellos == (hrr ? 2 : 1),
              hrr ? "resumed with secp384r1 after a HelloRetryRequest"
                  : "resumed with secp256r1, the client's new list");
        ksl_ssl_free(c2);
        ksl_ssl_free(s2);
    }
    ksl_session_free(sess);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    ksl_ctx_free(cc2);
    ksl_ctx_free(sc2);
    END();
}

/* TLS 1.2 (TCP) takes the list's elliptic curves, by the server's order; a list without one leaves TLS 1.2 nothing */
static void test_tls12_groups(void) {
    SECTION("groups_tls12_curves");
    ksl_ctx *cc = groups_client("*X25519:secp256r1:secp384r1"), *sc = groups_server("secp384r1:X25519");
    ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    ksl_ssl *c = new_client(cc, 1), *s = new_server(sc, 1);
    uint8_t v[2];
    size_t n;
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && ksl_ssl_get(c, KSL_GET_VERSION, v, 2, &n) == KSL_OK && v[1] == 0x03 &&
              group_of(c) == G_P384 && group_of(s) == G_P384,
          "TLS 1.2: ECDHE over secp384r1, the server's first");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    cc = groups_client("*X25519MLKEM768");
    sc = groups_server("X25519MLKEM768:X25519");
    ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    c = new_client(cc, 1);
    s = new_server(sc, 1);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_ERROR, "negative: TLS 1.2 with a hybrid group alone has no key exchange");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    /* RFC 8422 section 5.1: in TLS 1.2 supported_groups also names the curves a client accepts in ECDSA certificates, so a list
       without P-256 refuses the server's P-256 certificate (handshake_failure); TLS 1.3 negotiates signatures apart (RFC 9846
       section 4.3.7: "Signature algorithms are now negotiated independently") */
    cc = groups_client("*X25519:secp384r1");
    sc = groups_server("secp384r1:X25519");
    ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    c = new_client(cc, 1);
    s = new_server(sc, 1);
    int sent = 0;
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_ERROR, "negative: TLS 1.2 without P-256 refuses a P-256 ECDSA certificate");
    last_code(s, &sent);
    CHECK(sent == SSL_AD_HANDSHAKE_FAILURE, "with handshake_failure");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    cc = groups_client("*X25519:secp384r1");
    sc = groups_server("secp384r1:X25519");
    c = new_client(cc, 1);
    s = new_server(sc, 1);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK, "control: the same lists in TLS 1.3 accept it");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}

/* ksl_key_share_choice reads the ClientHello's key_share before OpenSSL checks it: every length is bounded, a malformed extension
   (RFC 9846 section 4.3.8) is -2 and left to OpenSSL's decode_error, a share of a group the server does not list is skipped */
static void test_negative_key_share_scan(void) {
    SECTION("negative_key_share_scan_bounds");
    ksl_ctx *sc = groups_server("secp384r1:X25519:secp256r1");
    static const struct {
        uint8_t b[16];
        size_t n;
        int want;
        const char *what;
    } cases[] = {
        {{0}, 0, -2, "empty extension"},
        {{0}, 1, -2, "one byte"},
        {{0, 0}, 2, -1, "an empty list (RFC 9846 section 4.3.8 allows it): no share"},
        {{0, 1, 0}, 3, -2, "list length past the end"},
        {{0, 2, 0, 0x1d}, 4, -2, "an entry without its length"},
        {{0, 4, 0, 0x1d, 0, 0}, 6, -2, "an empty key_exchange"},
        {{0, 5, 0, 0x1d, 0, 2, 9}, 7, -2, "key_exchange past the end"},
        {{0, 5, 0, 0x1d, 0, 1, 9}, 7, 1, "X25519: the server's second"},
        {{0, 10, 0, 0x17, 0, 1, 9, 0, 0x1d, 0, 1, 9}, 12, 1, "secp256r1 and X25519: the server's earlier of them"},
        {{0, 5, 0, 0x1e, 0, 1, 9}, 7, -1, "X448 only: none the server lists"},
        {{0, 6, 0, 0x1d, 0, 1, 9, 0}, 8, -2, "a trailing byte"},
        {{0xff, 0xff, 0, 0x1d, 0, 1, 9}, 7, -2, "list length 0xffff"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        uint8_t *copy = malloc(cases[i].n ? cases[i].n : 1); /* exact size: ASan sees a read past the end */
        memcpy(copy, cases[i].b, cases[i].n);
        CHECK(ksl_key_share_choice(sc, copy, cases[i].n) == cases[i].want, cases[i].what);
        free(copy);
    }
    ksl_ctx_free(sc);
    END();
}

/* The server side of RFC 8422 section 5.1 in TLS 1.2: OpenSSL holds a client's ECDSA certificate to the server's own list too
   (tls12_check_peer_sigalg with check_own_groups), so a server list without P-256 refuses a P-256 client certificate. [max12]
   limits the client to TLS 1.2; returns the alert the server sent, 0 when the handshake completed. */
static int client_cert_alert(const char *server_groups, int max12) {
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = groups_server(server_groups);
    blob ch = chain_of(1, "client");
    size_t kl;
    uint8_t *k = key_of("client", &kl);
    ksl_ctx_set_identity(cc, ch.buf, ch.len, k, kl);
    free(ch.buf);
    free(k);
    blob roots = chain_of(1, "test-ca");
    ksl_ctx_set_roots(sc, roots.buf, roots.len);
    free(roots.buf);
    ksl_ctx_set_option(sc, KSL_OPT_CLIENT_CERT, KSL_CLIENT_CERT_REQUIRED);
    ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    if (max12) {
        ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
        ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    }
    ksl_ssl *c = new_client(cc, 1), *s = new_server(sc, 1);
    int rc = tcp_pump(c, s, NULL, NULL), sent = 0;
    if (rc != KSL_OK)
        last_code(s, &sent);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    return rc == KSL_OK ? 0 : sent ? sent : -1;
}
static void test_tls12_server_groups_and_client_certificates(void) {
    SECTION("groups_tls12_server_list_and_client_certificate_curve");
    CHECK(client_cert_alert("X25519:secp384r1", 1) == SSL_AD_ILLEGAL_PARAMETER,
          "negative: TLS 1.2, a server list without P-256 refuses a P-256 client certificate");
    CHECK(client_cert_alert("X25519:secp384r1:secp256r1", 1) == 0,
          "control: with P-256 in the server's list it is accepted");
    CHECK(client_cert_alert("X25519:secp384r1", 0) == 0, "control: TLS 1.3 accepts it under the same list");
    END();
}

/* A TLS 1.2 abbreviated handshake (a resumption) runs no key exchange: KSL_GET_GROUP reports none on both sides, not the group of
   the full handshake the session came from (OpenSSL keeps that one in the session, SSL_get_negotiated_group) */
static void test_tls12_resumption_reports_no_group(void) {
    SECTION("groups_tls12_resumption_reports_no_group");
    uint8_t keys[80];
    for (int i = 0; i < 80; i++)
        keys[i] = (uint8_t)(i * 3 + 7);
    /* secp256r1 too: in TLS 1.2 the list also names the curves of ECDSA certificates the client accepts (the server's is P-256) */
    ksl_ctx *cc = groups_client("*X25519:secp384r1:secp256r1"), *sc = groups_server("secp384r1:X25519");
    ksl_ctx_set_option(cc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(cc, KSL_OPT_MAX_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(sc, KSL_OPT_MIN_VERSION, KSL_TLS1_2);
    ksl_ctx_set_option(sc, KSL_OPT_NUM_TICKETS, 1);
    ksl_ctx_set_ticket_keys(sc, keys, 1);
    ksl_ssl *c = new_client(cc, 1), *s = new_server(sc, 1);
    CHECK(tcp_pump(c, s, NULL, NULL) == KSL_OK && group_of(c) == G_P384 && group_of(s) == G_P384,
          "TLS 1.2 full handshake: ECDHE over secp384r1");
    ksl_session *sess = ksl_ssl_get1_session(c);
    CHECK(sess != NULL, "a TLS 1.2 session");
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    c = new_client(cc, 1);
    s = new_server(sc, 1);
    ksl_ssl_set_session(c, sess);
    uint8_t re = 0;
    size_t n;
    int rc = tcp_pump(c, s, NULL, NULL);
    ksl_ssl_get(c, KSL_GET_SESSION_REUSED, &re, 1, &n);
    CHECK(rc == KSL_OK && re == 1, "the session resumes (abbreviated handshake)");
    CHECK(group_of(c) == 0 && group_of(s) == 0, "no key exchange ran: no group on either side");
    ksl_session_free(sess);
    ksl_ssl_free(c);
    ksl_ssl_free(s);
    ksl_ctx_free(cc);
    ksl_ctx_free(sc);
    END();
}

void run_groups(void) {
    test_negative_key_share_scan();
    test_negative_group_list_checks();
    test_default_groups();
    test_client_hello_groups();
    test_hello_retry_on_non_first_group();
    test_no_common_group();
    test_server_preference();
    test_sni_override_groups();
    test_resumption_with_other_groups();
    test_tls12_groups();
    test_tls12_server_groups_and_client_certificates();
    test_tls12_resumption_reports_no_group();
}
