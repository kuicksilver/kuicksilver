/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* QUIC TLS interface tests: handshake, split records, pause contract, stable errors, events. */
#include "test_common.h"
#include <openssl/ssl.h>
#include "ksl_internal.h"   /* test_tp_replace inspects the buffer OpenSSL points at */

static int set_str(ksl_ssl *s, int what, const char *v) { return ksl_ssl_set(s, what, (const uint8_t *)v, strlen(v)); }
static ksl_ssl *client(ksl_ctx *c, const char *name) { ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC); set_str(s, KSL_SET_SNI, "server.test"); if (name) set_str(s, KSL_SET_VERIFY_NAME, name); ksl_quic_set_transport_params(s, TP, sizeof TP); return s; }
static ksl_ssl *server(ksl_ctx *c) { ksl_ssl *s = ksl_ssl_new(c, KSL_MODE_QUIC); ksl_quic_set_transport_params(s, TP, sizeof TP); return s; }

static void test_handshake(void) {
    SECTION("quic_handshake_h3");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = client(cc, "server.test"), *s = server(sc);
    side cs = {0}, ss = {0}; int rc = pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done && ss.done, "both HANDSHAKE_DONE (post-handshake drive reports WANT_READ)");
    uint8_t alpn[16]; size_t n; CHECK(ksl_ssl_get(c, KSL_GET_ALPN, alpn, sizeof alpn, &n) == KSL_OK && n == 2 && !memcmp(alpn, "h3", 2), "alpn h3");
    CHECK(cs.keys == 4 && ss.keys == 4, "four KEY events per side: handshake and application, read and write");
    CHECK(cs.tp_len == sizeof TP && !memcmp(cs.tp, TP, sizeof TP) && ss.tp_len == sizeof TP, "transport params exchanged");
    uint8_t v[2]; CHECK(ksl_ssl_get(c, KSL_GET_VERSION, v, 2, &n) == KSL_OK && v[0] == 0x03 && v[1] == 0x04, "TLS 1.3");
    CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_VALIDATED, -1, NULL, 0, NULL) == 2, "validated chain = leaf + CA");
    uint8_t der[2048]; CHECK(ksl_ssl_get_peer_chain(c, KSL_CHAIN_PRESENTED, 0, der, sizeof der, &n) == KSL_OK && n > 300 && der[0] == 0x30, "presented leaf DER");
    uint8_t ekm[2][32]; CHECK(ksl_ssl_export_keying_material(c, ekm[0], 32, "test", 4, (const uint8_t *)"ctx", 3) == KSL_OK && ksl_ssl_export_keying_material(s, ekm[1], 32, "test", 4, (const uint8_t *)"ctx", 3) == KSL_OK && !memcmp(ekm[0], ekm[1], 32), "exporter matches");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static int client_hellos = 0;
static void count_client_hello(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl; (void)arg; if (write_p && content_type == SSL3_RT_HANDSHAKE && len > 0 && ((const uint8_t *)buf)[0] == SSL3_MT_CLIENT_HELLO) client_hellos++;
}
/* A client that supports X25519MLKEM768 but sends a key share only for X25519 (ngtcp2 today) must not be sent a HelloRetryRequest
   for the post-quantum group: the extra round trip doubled the handshake under loss (interop handshakeloss vs ngtcp2: 50 of 50 HRR). */
static void test_no_hrr_for_x25519_only_client(void) {
    SECTION("quic_x25519_only_client_gets_no_hrr");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = client(cc, "server.test"), *s = server(sc);
    SSL *raw = ksl_ssl_raw_for_test(c); CHECK(SSL_set1_groups_list(raw, "*X25519:X25519MLKEM768") == 1, "client supports both groups, sends a key share only for X25519 (what ngtcp2 does)");
    client_hellos = 0; SSL_set_msg_callback(raw, count_client_hello);
    side cs = {0}, ss = {0}; int rc = pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done && ss.done, "handshake completes with X25519");
    CHECK(client_hellos == 1, "one ClientHello: the server took the X25519 share instead of asking for X25519MLKEM768");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_split_server_hello(void) {
    SECTION("quic_split_serverhello_wants_read");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = client(cc, "server.test"), *s = server(sc);
    CHECK(ksl_drive(c) == KSL_WANT_READ, "client hello queued");
    ksl_event ev; while (ksl_quic_next_event(c, &ev)) if (ev.type == KSL_EV_CRYPTO_SEND) ksl_quic_provide(s, ev.level, ev.buf, ev.len);
    ksl_drive(s);
    int split = 0;
    while (ksl_quic_next_event(s, &ev)) {
        if (ev.type == KSL_EV_KEY) ksl_key_free(ev.key);
        if (ev.type != KSL_EV_CRYPTO_SEND) continue;
        if (!split && ev.level == KSL_LEVEL_INITIAL && ev.len > 1) {
            split = 1; ksl_quic_provide(c, ev.level, ev.buf, ev.len - 1);
            CHECK(ksl_drive(c) == KSL_WANT_READ, "truncated ServerHello -> KSL_WANT_READ, not an error");
            ksl_quic_provide(c, ev.level, ev.buf + ev.len - 1, 1);
        } else ksl_quic_provide(c, ev.level, ev.buf, ev.len);
    }
    side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 40, NULL, NULL); CHECK(split && cs.done && ss.done, "handshake completes after the split");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static int resume_with_junk(ksl_ssl *s, int rc, void *a) {
    (void)a; if (rc != KSL_WANT_VERIFY) return 1;
    uint8_t junk[8192]; memset(junk, 0x5a, sizeof junk);
    for (int i = 0; i < 4; i++) ksl_quic_provide(s, KSL_LEVEL_HANDSHAKE, junk, sizeof junk);   /* would realloc the outstanding record without the stash */
    return ksl_ssl_verify_resume(s, 1, 0) == KSL_OK;
}
static void test_provide_during_pause(void) {
    SECTION("quic_provide_during_pause_no_realloc");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_PAUSE), *sc = server_ctx("server"); ksl_ssl *c = client(cc, "server.test"), *s = server(sc);
    side cs = {0}, ss = {0}; int rc = pump(c, s, &cs, &ss, 40, resume_with_junk, NULL);
    CHECK(rc == KSL_ERROR || cs.done, "no crash under ASan; junk yields a clean error or completion");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_corrupt_stable(void) {
    SECTION("quic_corrupt_byte_error_stable");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = client(cc, "server.test"), *s = server(sc);
    ksl_drive(c); ksl_event ev; while (ksl_quic_next_event(c, &ev)) if (ev.type == KSL_EV_CRYPTO_SEND) ksl_quic_provide(s, ev.level, ev.buf, ev.len);
    ksl_drive(s); int first = 1;
    while (ksl_quic_next_event(s, &ev)) {
        if (ev.type == KSL_EV_KEY) ksl_key_free(ev.key);
        if (ev.type != KSL_EV_CRYPTO_SEND) continue;
        uint8_t *copy = malloc(ev.len); memcpy(copy, ev.buf, ev.len); if (first && ev.level == KSL_LEVEL_HANDSHAKE) { copy[ev.len / 2] ^= 0xff; first = 0; }
        ksl_quic_provide(c, ev.level, copy, ev.len); free(copy);
    }
    int r1 = ksl_drive(c); uint32_t e1 = last_code(c, NULL); int r2 = ksl_drive(c), r3 = ksl_drive(c);
    CHECK(r1 == KSL_ERROR && r2 == KSL_ERROR && r3 == KSL_ERROR, "KSL_ERROR on every drive after a fatal error");
    CHECK(e1 != 0 && last_code(c, NULL) == e1, "same error code on repeated drives");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_unknown_ca(void) {
    SECTION("quic_unknown_ca_alert_48");
    ksl_ctx *cc = client_ctx("other-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = client(cc, "server.test"), *s = server(sc);
    side cs = {0}, ss = {0}; int rc = pump(c, s, &cs, &ss, 40, NULL, NULL); int alert = 0; uint32_t code = last_code(c, &alert);
    CHECK(rc == KSL_ERROR && !cs.done && !ss.done, "client fails, server never completes (alerts are not carried in CRYPTO)");
    CHECK(alert == 48, "local alert unknown_ca (48)"); CHECK((code >> 16) != 0xff, "OpenSSL error code packed");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_post_handshake_ticket(void) {
    SECTION("quic_post_handshake_ticket_delivered");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ctx_set_option(sc, KSL_OPT_NUM_TICKETS, 0);
    ksl_ssl *c = client(cc, "server.test"), *s = server(sc); side cs = {0}, ss = {0}; pump(c, s, &cs, &ss, 40, NULL, NULL);
    CHECK(cs.done && ss.done, "handshake done");
    int before = ss.crypto_events; CHECK(ksl_ssl_new_session_ticket(s) == KSL_OK, "queue a ticket");
    pump(c, s, &cs, &ss, 6, NULL, NULL);
    CHECK(ss.crypto_events == before + 1, "exactly one application-level CRYPTO (NewSessionTicket) after the explicit request");
    ksl_session *sess = ksl_ssl_get1_session(c); CHECK(sess != NULL, "client holds a resumable session after the ticket"); ksl_session_free(sess);
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_server_pause_forbidden(void) {
    SECTION("quic_server_pause_forbidden");
    ksl_ctx *sc = ksl_ctx_new(KSL_SERVER); uint32_t e; char m[128];
    CHECK(ksl_ctx_set_option(sc, KSL_OPT_VERIFY_MODE, KSL_VERIFY_PAUSE) == KSL_ERROR, "pause mode rejected on a server context");
    ksl_ctx_last_error(sc, &e, m, sizeof m); CHECK(e == KSL_E_SERVER_PAUSE_FORBIDDEN, "KSL_E_SERVER_PAUSE_FORBIDDEN");
    CHECK(ksl_ctx_freeze(sc) == KSL_OK && ksl_ctx_set_option(sc, KSL_OPT_NUM_TICKETS, 1) == KSL_ERROR, "frozen context rejects mutation");
    ksl_ctx_last_error(sc, &e, m, sizeof m); CHECK(e == KSL_E_CTX_FROZEN, "KSL_E_CTX_FROZEN");
    ksl_ctx_free(sc); END();
}

static void test_resume_without_pause(void) {
    SECTION("quic_resume_without_pause_is_error");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_PAUSE); ksl_ssl *c = client(cc, "server.test");
    CHECK(ksl_ssl_verify_resume(c, 1, 0) == KSL_ERROR && last_code(c, NULL) == KSL_E_NOT_PAUSED, "verify_resume outside a pause -> KSL_E_NOT_PAUSED");
    CHECK(ksl_drive(c) == KSL_WANT_READ, "the session is still usable");
    ksl_ssl_free(c); ksl_ctx_free(cc); END();
}

static void test_peek(void) {
    SECTION("quic_event_peek_keeps_event");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL); ksl_ssl *c = client(cc, "server.test"); ksl_drive(c);
    ksl_event a, b, d; CHECK(ksl_quic_peek_event(c, &a) == 1 && ksl_quic_peek_event(c, &b) == 1 && a.len == b.len && a.buf == b.buf, "peek twice gives the same event");
    CHECK(ksl_quic_next_event(c, &d) == 1 && d.len == a.len, "next returns the peeked event");
    CHECK(ksl_quic_peek_event(c, &a) == 0, "queue empty after next");
    ksl_ssl_free(c); ksl_ctx_free(cc); END();
}

static void test_no_verify_name(void) {
    SECTION("quic_forgot_verify_name_fails");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL); ksl_ssl *c = client(cc, NULL);
    CHECK(ksl_drive(c) == KSL_ERROR && last_code(c, NULL) == KSL_E_NO_VERIFY_NAME, "verifying client without a reference identifier cannot start");
    CHECK(set_str(c, KSL_SET_VERIFY_NAME, "") == KSL_ERROR && ksl_ssl_set(c, KSL_SET_VERIFY_NAME, NULL, 0) == KSL_ERROR && ksl_ssl_set(c, 99, (const uint8_t *)"x", 1) == KSL_ERROR, "empty name and unknown selector rejected");
    ksl_ssl_free(c); ksl_ctx_free(cc); END();
}

static void test_secret_lengths(void) {
    SECTION("quic_aes128_and_aes256_key_events");
    for (int v = 0; v < 2; v++) {
        ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
        ksl_ctx_set_ciphers(cc, v ? "TLS_AES_128_GCM_SHA256" : "TLS_AES_256_GCM_SHA384", NULL);
        ksl_ssl *c = client(cc, "server.test"), *s = server(sc); int aead = 0; int done = 0;
        for (int round = 0; round < 40 && !done; round++) {
            ksl_ssl *who[2] = {c, s}, *peer[2] = {s, c};
            for (int k = 0; k < 2; k++) { ksl_drive(who[k]); ksl_event ev; while (ksl_quic_next_event(who[k], &ev)) { if (ev.type == KSL_EV_CRYPTO_SEND) ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len); else if (ev.type == KSL_EV_KEY) { aead = ev.aead; ksl_key_free(ev.key); } else if (ev.type == KSL_EV_HANDSHAKE_DONE && k == 1) done = 1; } }
        }
        CHECK(done && aead == (v ? KSL_AEAD_AES_128_GCM : KSL_AEAD_AES_256_GCM), v ? "AES-128-GCM negotiated" : "AES-256-GCM negotiated");
        ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc);
    }
    END();
}


/* ---- QUIC v2 and RFC 9368 version choice (K2) ---- */
#include <openssl/evp.h>
ksl_key *ksl_key_from_secret_for_test(int aead, const uint8_t *secret, size_t slen, uint32_t version);
#define V2 0x6b3343cfu
static void be32(uint8_t *o, uint32_t v) { o[0] = (uint8_t)(v >> 24); o[1] = (uint8_t)(v >> 16); o[2] = (uint8_t)(v >> 8); o[3] = (uint8_t)v; }
static int set_version(ksl_ssl *s, uint32_t v) { uint8_t b[4]; be32(b, v); return ksl_ssl_set(s, KSL_SET_QUIC_VERSION, b, 4); }
static uint32_t get_version(ksl_ssl *s) { uint8_t b[4]; size_t n; if (ksl_ssl_get(s, KSL_GET_QUIC_VERSION, b, 4, &n) != KSL_OK || n != 4) return 0; return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3]; }
/* TP blob: max_idle_timeout + version_information(chosen, available...) */
static size_t tp_with_versions(uint8_t *out, uint32_t chosen, const uint32_t *avail, int n) {
    size_t p = 0; out[p++] = 0x01; out[p++] = 0x02; out[p++] = 0x67; out[p++] = 0x10;
    if (chosen) { out[p++] = 0x11; out[p++] = (uint8_t)(4 + 4 * n); be32(out + p, chosen); p += 4; for (int i = 0; i < n; i++) { be32(out + p, avail[i]); p += 4; } }
    return p;
}
static uint32_t chosen_in(const uint8_t *tp, size_t len) {   /* Chosen Version of version_information in a TP blob, 0 when absent */
    size_t p = 0; while (p + 2 <= len) { uint8_t id = tp[p++]; uint8_t l = tp[p++]; if (id == 0x11 && l >= 4 && p + 4 <= len) return ((uint32_t)tp[p] << 24) | ((uint32_t)tp[p + 1] << 16) | ((uint32_t)tp[p + 2] << 8) | tp[p + 3]; p += l; }
    return 0;
}
/* seals with EVP directly: nonce = iv ^ pn, AAD = header; returns the ciphertext+tag in out */
static void ref_seal(const uint8_t *key, const uint8_t *iv, uint64_t pn, const uint8_t *hdr, size_t hl, const uint8_t *pt, size_t pl, uint8_t *out) {
    uint8_t nonce[12]; memcpy(nonce, iv, 12); for (int i = 0; i < 8; i++) nonce[11 - i] ^= (uint8_t)(pn >> (8 * i));
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, t = 0;
    EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, key, nonce); EVP_EncryptUpdate(c, NULL, &l, hdr, (int)hl); EVP_EncryptUpdate(c, out, &l, pt, (int)pl); t = l;
    EVP_EncryptFinal_ex(c, out + t, &l); EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out + pl); EVP_CIPHER_CTX_free(c);
}
static void test_v2_key_from_fixed_secret(void) {
    SECTION("quic_v2_key_from_fixed_secret");
    uint8_t secret[32]; for (int i = 0; i < 32; i++) secret[i] = (uint8_t)(i + 1);
    uint8_t key[16], iv[12], hp[16], hdr[5] = {0x40, 1, 2, 3, 4}, pt[20] = {0}, ref[36], got[36], mask[5], refmask[16], sample[16] = {0};
    CHECK(ksl_hkdf_expand_label(KSL_HASH_SHA256, secret, 32, "quicv2 key", NULL, 0, key, 16) == KSL_OK && ksl_hkdf_expand_label(KSL_HASH_SHA256, secret, 32, "quicv2 iv", NULL, 0, iv, 12) == KSL_OK
          && ksl_hkdf_expand_label(KSL_HASH_SHA256, secret, 32, "quicv2 hp", NULL, 0, hp, 16) == KSL_OK, "reference v2 labels");
    ref_seal(key, iv, 7, hdr, 5, pt, 20, ref);
    ksl_key *k2 = ksl_key_from_secret_for_test(KSL_AEAD_AES_128_GCM, secret, 32, V2), *k1 = ksl_key_from_secret_for_test(KSL_AEAD_AES_128_GCM, secret, 32, 1u);
    memcpy(got, pt, 20); CHECK(ksl_seal(k2, 7, hdr, 5, got, 20, sizeof got) == 36 && !memcmp(got, ref, 36), "v2 key seals like the reference built from quicv2 labels");
    memcpy(got, pt, 20); CHECK(ksl_seal(k1, 7, hdr, 5, got, 20, sizeof got) == 36 && memcmp(got, ref, 36) != 0, "v1 key differs");
    EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new(); int l; EVP_EncryptInit_ex(e, EVP_aes_128_ecb(), NULL, hp, NULL); EVP_CIPHER_CTX_set_padding(e, 0); EVP_EncryptUpdate(e, refmask, &l, sample, 16); EVP_CIPHER_CTX_free(e);
    CHECK(ksl_header_mask(k2, sample, mask) == KSL_OK && !memcmp(mask, refmask, 5), "v2 hp key masks like the reference");
    ksl_key_free(k1); ksl_key_free(k2); END();
}
/* pump that flips the client to the server's version before the ServerHello is provided, and keeps the APPLICATION keys */
typedef struct { ksl_key *c_app_read, *s_app_write; uint32_t client_switch; } v2pump;
static int pump_v2(ksl_ssl *c, ksl_ssl *s, side *cs, side *ss, v2pump *vp) {
    int rc = KSL_OK;
    for (int round = 0; round < 40; round++) {
        ksl_ssl *who[2] = {c, s}; side *me[2] = {cs, ss}; ksl_ssl *peer[2] = {s, c}; int progressed = 0;
        for (int k = 0; k < 2; k++) {
            int r = ksl_drive(who[k]); if (k == 0) rc = r;
            ksl_event ev;
            while (ksl_quic_next_event(who[k], &ev)) {
                progressed = 1;
                if (ev.type == KSL_EV_CRYPTO_SEND) {
                    if (k == 1 && ev.level == KSL_LEVEL_INITIAL && vp->client_switch) { set_version(c, vp->client_switch); vp->client_switch = 0; }   /* the server Initial header carries the negotiated version */
                    ksl_quic_provide(peer[k], ev.level, ev.buf, ev.len);
                } else if (ev.type == KSL_EV_KEY) {
                    me[k]->keys++;
                    if (ev.level == KSL_LEVEL_APPLICATION && k == 0 && ev.direction == KSL_DIR_READ) vp->c_app_read = ev.key;
                    else if (ev.level == KSL_LEVEL_APPLICATION && k == 1 && ev.direction == KSL_DIR_WRITE) vp->s_app_write = ev.key;
                    else ksl_key_free(ev.key);
                } else if (ev.type == KSL_EV_TRANSPORT_PARAMS) { me[k]->tp_len = ev.len < sizeof me[k]->tp ? ev.len : sizeof me[k]->tp; memcpy(me[k]->tp, ev.buf, me[k]->tp_len); }
                else if (ev.type == KSL_EV_HANDSHAKE_DONE) me[k]->done = 1;
            }
            if (r == KSL_ERROR) return KSL_ERROR;
        }
        if (cs->done && ss->done && !progressed) return rc;
    }
    return rc;
}
static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c - 'A' + 10; }
static void test_server_picks_v2(void) {
    SECTION("quic_server_picks_v2_from_tp_blobs");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ctx_set_option(sc, KSL_OPT_KEYLOG, 1);
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    set_str(c, KSL_SET_SNI, "server.test"); set_str(c, KSL_SET_VERIFY_NAME, "server.test");
    uint8_t ctp[64], stp[64]; uint32_t cav[2] = {1u, V2}, sav[2] = {V2, 1u};
    size_t cl = tp_with_versions(ctp, 1u, cav, 2), sl = tp_with_versions(stp, V2, sav, 2);
    ksl_quic_set_transport_params(c, ctp, cl); ksl_quic_set_transport_params(s, stp, sl);
    CHECK(set_version(c, 1u) == KSL_OK, "client starts in v1");
    side cs = {0}, ss = {0}; v2pump vp = {NULL, NULL, V2}; int rc = pump_v2(c, s, &cs, &ss, &vp);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done && ss.done, "handshake completes");
    CHECK(get_version(s) == V2 && get_version(c) == V2, "server negotiated v2; client switched to v2");
    CHECK(chosen_in(cs.tp, cs.tp_len) == V2, "server Chosen Version rewritten to the negotiated version (RFC 9368 section 4)");
    /* the server's 1-RTT write key equals a key built from the keylog secret with v2 labels, and opens on the client */
    uint8_t log[4096]; size_t n = 0; CHECK(ksl_ssl_get(s, KSL_GET_KEYLOG, log, sizeof log, &n) == KSL_OK && n > 0, "keylog available"); log[n < sizeof log ? n : sizeof log - 1] = 0;
    const char *line = strstr((const char *)log, "SERVER_TRAFFIC_SECRET_0 "); uint8_t secret[48]; size_t slen = 0;
    if (line) { const char *h = strchr(line + 24, ' '); if (h) { h++; while (h[0] && h[1] && h[0] != '\n' && slen < 48) { secret[slen++] = (uint8_t)(hexval(h[0]) * 16 + hexval(h[1])); h += 2; } } }
    CHECK(line && (slen == 32 || slen == 48) && vp.s_app_write && vp.c_app_read, "server 1-RTT secret parsed and keys captured");
    if (line && vp.s_app_write && vp.c_app_read) {
        int aead = slen == 48 ? KSL_AEAD_AES_256_GCM : KSL_AEAD_AES_128_GCM;
        ksl_key *ref2 = ksl_key_from_secret_for_test(aead, secret, slen, V2), *ref1 = ksl_key_from_secret_for_test(aead, secret, slen, 1u);
        uint8_t hdr[3] = {0x41, 1, 2}, a[40] = {9}, b[40] = {9}, d[40] = {9};
        CHECK(ksl_seal(vp.s_app_write, 5, hdr, 3, a, 20, 40) == 36 && ksl_seal(ref2, 5, hdr, 3, b, 20, 40) == 36 && !memcmp(a, b, 36), "server 1-RTT key derived with v2 labels");
        CHECK(ksl_seal(ref1, 5, hdr, 3, d, 20, 40) == 36 && memcmp(a, d, 36) != 0, "and not with v1 labels");
        CHECK(ksl_open(vp.c_app_read, 5, hdr, 3, a, 36) == 20, "client opens the server's 1-RTT packet");
        ksl_key_free(ref1); ksl_key_free(ref2);
    }
    CHECK(set_version(c, 1u) == KSL_ERROR && last_code(c, NULL) == KSL_E_TOO_LATE, "version cannot change once handshake keys exist");
    if (vp.c_app_read) ksl_key_free(vp.c_app_read); if (vp.s_app_write) ksl_key_free(vp.s_app_write);
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_server_falls_back_to_original(void) {
    SECTION("quic_server_falls_back_to_original");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server");
    ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC), *s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    set_str(c, KSL_SET_SNI, "server.test"); set_str(c, KSL_SET_VERIFY_NAME, "server.test");
    uint8_t ctp[64], stp[64]; uint32_t cav[1] = {1u}, sav[2] = {V2, 1u};
    ksl_quic_set_transport_params(c, ctp, tp_with_versions(ctp, 1u, cav, 1)); ksl_quic_set_transport_params(s, stp, tp_with_versions(stp, V2, sav, 2));
    side cs = {0}, ss = {0}; v2pump vp = {NULL, NULL, 0}; int rc = pump_v2(c, s, &cs, &ss, &vp);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done && ss.done && get_version(s) == 1u && get_version(c) == 1u, "client offers v1 only: server keeps the Original Version");
    CHECK(chosen_in(cs.tp, cs.tp_len) == 1u, "server Chosen Version rewritten to v1");
    ksl_ssl_free(c); ksl_ssl_free(s); c = ksl_ssl_new(cc, KSL_MODE_QUIC); s = ksl_ssl_new(sc, KSL_MODE_QUIC);
    set_str(c, KSL_SET_SNI, "server.test"); set_str(c, KSL_SET_VERIFY_NAME, "server.test");
    ksl_quic_set_transport_params(c, TP, sizeof TP); ksl_quic_set_transport_params(s, stp, tp_with_versions(stp, V2, sav, 2));   /* client without version_information */
    side cs2 = {0}, ss2 = {0}; v2pump vp2 = {NULL, NULL, 0}; rc = pump_v2(c, s, &cs2, &ss2, &vp2);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs2.done && ss2.done && get_version(s) == 1u, "client without version_information: v1");
    CHECK(chosen_in(cs2.tp, cs2.tp_len) == 1u, "server Chosen Version rewritten to v1 even when the client sent no version_information (RFC 9368 section 4)");
    if (vp2.c_app_read) ksl_key_free(vp2.c_app_read); if (vp2.s_app_write) ksl_key_free(vp2.s_app_write);
    uint8_t x[8] = {0x0a, 0x0a, 0x0a, 0x0a}; CHECK(ksl_ssl_set(c, KSL_SET_QUIC_VERSION, x, 4) == KSL_ERROR && last_code(c, NULL) == KSL_E_BAD_ARG && ksl_ssl_set(c, KSL_SET_QUIC_VERSION, x, 3) == KSL_ERROR, "unknown version / bad length rejected");
    if (vp.c_app_read) ksl_key_free(vp.c_app_read); if (vp.s_app_write) ksl_key_free(vp.s_app_write);
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_no_version_information(void) {
    SECTION("quic_no_version_information_uses_set_version");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = client(cc, "server.test"), *s = server(sc);
    CHECK(get_version(c) == 1u && get_version(s) == 1u, "default version is 1");
    set_version(c, V2); set_version(s, V2);
    side cs = {0}, ss = {0}; v2pump vp = {NULL, NULL, 0}; int rc = pump_v2(c, s, &cs, &ss, &vp);
    CHECK((rc == KSL_OK || rc == KSL_WANT_READ) && cs.done && ss.done && get_version(s) == V2 && get_version(c) == V2, "without version_information both sides keep the set version");
    uint8_t hdr[3] = {0x41, 1, 2}, a[40] = {3}; CHECK(ksl_seal(vp.s_app_write, 1, hdr, 3, a, 10, 40) == 26 && ksl_open(vp.c_app_read, 1, hdr, 3, a, 26) == 10, "v2 1-RTT keys match");
    if (vp.c_app_read) ksl_key_free(vp.c_app_read); if (vp.s_app_write) ksl_key_free(vp.s_app_write);
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}

static void test_tp_replace(void) {
    SECTION("quic_transport_params_replace_keeps_buffer");
    /* a rejected replacement must not free the buffer OpenSSL still points at; an empty set must not memcpy from NULL */
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL); ksl_ssl *c = ksl_ssl_new(cc, KSL_MODE_QUIC); set_str(c, KSL_SET_VERIFY_NAME, "server.test");
    CHECK(ksl_quic_set_transport_params(c, NULL, 0) == KSL_OK, "empty transport parameters accepted");
    CHECK(ksl_quic_set_transport_params(c, TP, sizeof TP) == KSL_OK, "replaced before the ClientHello");
    ksl_drive(c);   /* the ClientHello consumes the parameters: OpenSSL keeps the pointer for a second ClientHello after HelloRetryRequest */
    const uint8_t other[] = {0x01, 0x02, 0x40, 0x10, 0x04, 0x01, 0x00};
    CHECK(ksl_quic_set_transport_params(c, other, sizeof other) == KSL_ERROR, "a replacement after the ClientHello is rejected");
    CHECK(c->tp != NULL && c->tp_len == sizeof TP && !memcmp(c->tp, TP, sizeof TP), "the rejected call left the buffer OpenSSL points at untouched");
    ksl_ssl_free(c); ksl_ctx_free(cc); END();
}

/* RFC 9001 section 4.1.3: CRYPTO data at a level below the one TLS reads now is never handed to TLS; ksl refuses it instead of
   buffering it until the level is discarded (a pre-authentication memory sink), and caps what one level may hold unread. */
static size_t pending_at(ksl_ssl *s, int level) {
    uint8_t b[16]; size_t n = 0; if (ksl_ssl_get(s, KSL_GET_QUIC_PENDING, b, sizeof b, &n) != KSL_OK || n != 16) return (size_t)-1;
    const uint8_t *p = b + 4 * level; return ((size_t)p[0] << 24) | ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
}
static void test_previous_level_refused(void) {
    SECTION("quic_crypto_at_previous_level_refused");
    ksl_ctx *cc = client_ctx("test-ca", KSL_VERIFY_OPENSSL), *sc = server_ctx("server"); ksl_ssl *c = client(cc, "server.test"), *s = server(sc);
    ksl_drive(c); ksl_event ev; while (ksl_quic_next_event(c, &ev)) if (ev.type == KSL_EV_CRYPTO_SEND) ksl_quic_provide(s, ev.level, ev.buf, ev.len);
    ksl_drive(s); while (ksl_quic_next_event(s, &ev)) if (ev.type == KSL_EV_KEY) ksl_key_free(ev.key);
    CHECK(pending_at(s, KSL_LEVEL_INITIAL) == 0, "the ClientHello was consumed whole");
    uint8_t junk[1024]; memset(junk, 0x16, sizeof junk);
    CHECK(ksl_quic_provide(s, KSL_LEVEL_INITIAL, junk, sizeof junk) == KSL_ERROR, "Initial data after the server reads Handshake is refused");
    CHECK(last_code(s, NULL) == KSL_E_CRYPTO_LEVEL, "KSL_E_CRYPTO_LEVEL");
    CHECK(pending_at(s, KSL_LEVEL_INITIAL) == 0, "and nothing was buffered");
    ksl_ssl_free(c); ksl_ssl_free(s); ksl_ctx_free(cc); ksl_ctx_free(sc); END();
}
static void test_level_cap(void) {
    SECTION("quic_crypto_level_buffer_capped");
    ksl_ctx *sc = server_ctx("server"); ksl_ssl *s = server(sc);
    uint8_t *junk = calloc(1, 65536); int rc = KSL_OK, i = 0;
    for (; i < 8 && rc == KSL_OK; i++) rc = ksl_quic_provide(s, KSL_LEVEL_HANDSHAKE, junk, 65536);
    CHECK(rc == KSL_ERROR && i == 5, "the fifth 64 KiB block passes the 256 KiB cap of unread data at one level");
    CHECK(last_code(s, NULL) == KSL_E_CRYPTO_LEVEL, "KSL_E_CRYPTO_LEVEL");
    CHECK(pending_at(s, KSL_LEVEL_HANDSHAKE) == 4 * 65536, "the refused block was not appended");
    free(junk); ksl_ssl_free(s); ksl_ctx_free(sc); END();
}

void run_quic(void) {
    test_handshake(); test_no_hrr_for_x25519_only_client(); test_split_server_hello(); test_provide_during_pause(); test_corrupt_stable(); test_unknown_ca();
    test_post_handshake_ticket(); test_server_pause_forbidden(); test_resume_without_pause(); test_peek(); test_no_verify_name(); test_secret_lengths();
    test_v2_key_from_fixed_secret(); test_server_picks_v2(); test_server_falls_back_to_original(); test_no_version_information(); test_tp_replace();
    test_previous_level_refused(); test_level_cap();
}
