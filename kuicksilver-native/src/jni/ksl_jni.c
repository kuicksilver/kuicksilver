/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* JNI glue for io.kuicksilver.native.KslNative: RegisterNatives in JNI_OnLoad, no cached JNIEnv, handles as jlong,
 * byte[] for control-plane data (copied in the same call), direct ByteBuffer addresses for the packet hot path. */
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "ksl.h"

#define H(x) ((jlong)(intptr_t)(x))
#define P(t, x) ((t *)(intptr_t)(x))
#define CTX(h) P(ksl_ctx, h)
#define SSLP(h) P(ksl_ssl, h)

typedef struct { uint8_t *p; size_t n; } bytes;
static bytes get_bytes(JNIEnv *e, jbyteArray a) {
    bytes b = {NULL, 0}; if (!a) return b;
    b.n = (size_t)(*e)->GetArrayLength(e, a); b.p = malloc(b.n ? b.n : 1); if (b.p) (*e)->GetByteArrayRegion(e, a, 0, (jsize)b.n, (jbyte *)b.p); return b;
}
/* zeroes scratch that held secrets (session state, keylog, exporter output, plaintext); volatile so the store before free/return stays */
static void wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }
static void drop(bytes *b) { if (b->p) { wipe(b->p, b->n); free(b->p); } b->p = NULL; }
static jbyteArray new_bytes(JNIEnv *e, const uint8_t *p, size_t n) { jbyteArray a = (*e)->NewByteArray(e, (jsize)n); if (a && n) (*e)->SetByteArrayRegion(e, a, 0, (jsize)n, (const jbyte *)p); return a; }
static uint8_t *dbuf(JNIEnv *e, jobject b) { return b ? (uint8_t *)(*e)->GetDirectBufferAddress(e, b) : NULL; }
static const char *cstr(JNIEnv *e, jstring s) { return s ? (*e)->GetStringUTFChars(e, s, NULL) : NULL; }
static void cstr_free(JNIEnv *e, jstring s, const char *p) { if (s && p) (*e)->ReleaseStringUTFChars(e, s, p); }

static jint j_abi(JNIEnv *e, jclass c) { (void)e; (void)c; return (jint)ksl_abi_version(); }
static jint j_init(JNIEnv *e, jclass c) { (void)e; (void)c; return ksl_init(); }
static jstring j_version(JNIEnv *e, jclass c) { (void)c; return (*e)->NewStringUTF(e, ksl_version()); }

static jlong j_ctx_new(JNIEnv *e, jclass c, jint role) { (void)e; (void)c; return H(ksl_ctx_new(role)); }
static void j_ctx_free(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; ksl_ctx_free(CTX(h)); }
static jint j_ctx_set_alpn(JNIEnv *e, jclass c, jlong h, jbyteArray a) { (void)c; bytes b = get_bytes(e, a); int r = ksl_ctx_set_alpn(CTX(h), b.p, b.n); drop(&b); return r; }
static jint j_ctx_set_identity(JNIEnv *e, jclass c, jlong h, jbyteArray ch, jbyteArray k) { (void)c; bytes b = get_bytes(e, ch), kb = get_bytes(e, k); int r = ksl_ctx_set_identity(CTX(h), b.p, b.n, kb.p, kb.n); drop(&b); drop(&kb); return r; }
static jint j_ctx_set_identity_pkey(JNIEnv *e, jclass c, jlong h, jbyteArray ch, jlong k) { (void)c; bytes b = get_bytes(e, ch); int r = ksl_ctx_set_identity_pkey(CTX(h), b.p, b.n, P(ksl_pkey, k)); drop(&b); return r; }
static jlong j_pkey_new(JNIEnv *e, jclass c, jbyteArray k) { (void)c; bytes b = get_bytes(e, k); jlong h = H(ksl_pkey_new(b.p, b.n)); drop(&b); return h; }   /* drop wipes the key copy */
static void j_pkey_free(JNIEnv *e, jclass c, jlong k) { (void)e; (void)c; ksl_pkey_free(P(ksl_pkey, k)); }
static jint j_ctx_set_roots(JNIEnv *e, jclass c, jlong h, jbyteArray a) { (void)c; bytes b = get_bytes(e, a); int r = ksl_ctx_set_roots(CTX(h), b.p, b.n); drop(&b); return r; }
static jint j_ctx_set_ciphers(JNIEnv *e, jclass c, jlong h, jstring s13, jstring s12) { (void)c; const char *a = cstr(e, s13), *b = cstr(e, s12); int r = ksl_ctx_set_ciphers(CTX(h), a, b); cstr_free(e, s13, a); cstr_free(e, s12, b); return r; }
static jint j_ctx_use_default_ticket_keys(JNIEnv *e, jclass c, jlong h, jint rotate) { (void)e; (void)c; return rotate <= 0 ? KSL_ERROR : ksl_ctx_use_default_ticket_keys(CTX(h), (uint32_t)rotate); }
/* the keys: copied by get_bytes, wiped by drop; the caller zeroes its array */
static jint j_ticket_keys_register(JNIEnv *e, jclass c, jbyteArray a) { (void)c; bytes b = get_bytes(e, a); int r = b.n == 0 || b.n % 80 ? KSL_ERROR : ksl_ticket_keys_register(b.p, b.n / 80); drop(&b); return r; }
static jint j_ctx_use_ticket_keys(JNIEnv *e, jclass c, jlong h, jint id) { (void)e; (void)c; return ksl_ctx_use_ticket_keys(CTX(h), id); }
static jint j_ctx_set_session_context(JNIEnv *e, jclass c, jlong h, jbyteArray a) { (void)c; bytes b = get_bytes(e, a); int r = ksl_ctx_set_session_context(CTX(h), b.p, b.n); drop(&b); return r; }
static jint j_ctx_set_option(JNIEnv *e, jclass c, jlong h, jint o, jint v) { (void)e; (void)c; return ksl_ctx_set_option(CTX(h), o, v); }
static jint j_ctx_freeze(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; return ksl_ctx_freeze(CTX(h)); }
static jint j_ctx_verify_chain(JNIEnv *e, jclass c, jlong h, jbyteArray a, jstring name, jlong at) {
    (void)c; bytes b = get_bytes(e, a); const char *n = cstr(e, name); int err = 0;
    int r = ksl_ctx_verify_chain(CTX(h), b.p, b.n, n, (int64_t)at, &err); cstr_free(e, name, n); drop(&b);
    return r == KSL_OK ? 0 : err ? err : -1;
}
static jstring j_ctx_last_error(JNIEnv *e, jclass c, jlong h, jintArray out) { (void)c; uint32_t code; char m[512]; ksl_ctx_last_error(CTX(h), &code, m, sizeof m); jint v = (jint)code; (*e)->SetIntArrayRegion(e, out, 0, 1, &v); return (*e)->NewStringUTF(e, m); }

static jlong j_ssl_new(JNIEnv *e, jclass c, jlong h, jint mode) { (void)e; (void)c; return H(ksl_ssl_new(CTX(h), mode)); }
static void j_ssl_free(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; ksl_ssl_free(SSLP(h)); }
static jint j_ssl_set(JNIEnv *e, jclass c, jlong h, jint what, jbyteArray data) { (void)c; jsize n = (*e)->GetArrayLength(e, data); jbyte *p = (*e)->GetByteArrayElements(e, data, NULL); if (!p) return -1; int r = ksl_ssl_set(SSLP(h), what, (const uint8_t *)p, (size_t)n); (*e)->ReleaseByteArrayElements(e, data, p, JNI_ABORT); return r; }
static jbyteArray j_ssl_get(JNIEnv *e, jclass c, jlong h, jint what) {
    (void)c; uint8_t small[512]; size_t n = 0; int r = ksl_ssl_get(SSLP(h), what, small, sizeof small, &n);
    if (r == KSL_OK) { jbyteArray a = new_bytes(e, small, n); wipe(small, sizeof small); return a; }   /* the keylog passes through here */
    if (n <= sizeof small) return NULL;
    uint8_t *big = malloc(n); if (!big) return NULL; size_t cap = n; r = ksl_ssl_get(SSLP(h), what, big, cap, &n); jbyteArray a = r == KSL_OK ? new_bytes(e, big, n) : NULL; wipe(big, cap); free(big); return a;
}
static jint j_ssl_peer_chain_count(JNIEnv *e, jclass c, jlong h, jint which) { (void)e; (void)c; return ksl_ssl_get_peer_chain(SSLP(h), which, -1, NULL, 0, NULL); }
static jbyteArray j_ssl_peer_chain_item(JNIEnv *e, jclass c, jlong h, jint which, jint idx) {
    (void)c; size_t n = 0; if (ksl_ssl_get_peer_chain(SSLP(h), which, idx, NULL, 0, &n) == KSL_OK && n == 0) return new_bytes(e, NULL, 0);
    if (!n) return NULL; uint8_t *b = malloc(n); if (!b) return NULL; int r = ksl_ssl_get_peer_chain(SSLP(h), which, idx, b, n, &n); jbyteArray a = r == KSL_OK ? new_bytes(e, b, n) : NULL; free(b); return a;
}
static jint j_ssl_verify_resume(JNIEnv *e, jclass c, jlong h, jint accept, jint alert) { (void)e; (void)c; return ksl_ssl_verify_resume(SSLP(h), accept, alert); }
static jbyteArray j_ssl_client_hello(JNIEnv *e, jclass c, jlong h) {
    (void)c; ksl_client_hello ch; if (ksl_ssl_client_hello(SSLP(h), &ch) != KSL_OK) return NULL;
    size_t n = 6 + (ch.sni ? ch.sni_len : 0) + ch.alpn_len + ch.sig_algs_len; uint8_t *b = malloc(n); if (!b) return NULL; size_t o = 0;
#define U16(v) do { b[o++] = (uint8_t)((v) >> 8); b[o++] = (uint8_t)(v); } while (0)
    if (ch.sni) { U16(ch.sni_len); memcpy(b + o, ch.sni, ch.sni_len); o += ch.sni_len; } else U16(0xffff);
    U16(ch.alpn_len); if (ch.alpn_len) memcpy(b + o, ch.alpn, ch.alpn_len); o += ch.alpn_len;
    U16(ch.sig_algs_len); if (ch.sig_algs_len) memcpy(b + o, ch.sig_algs, ch.sig_algs_len); o += ch.sig_algs_len;
#undef U16
    jbyteArray a = new_bytes(e, b, o); free(b); return a;
}
static jint j_ssl_sni_resume(JNIEnv *e, jclass c, jlong h, jlong o, jint alert) { (void)e; (void)c; return ksl_ssl_sni_resume(SSLP(h), CTX(o), alert); }
static jbyteArray j_ssl_export(JNIEnv *e, jclass c, jlong h, jstring label, jbyteArray ctxa, jint len) {
    (void)c; if (len <= 0 || len > 65535) return NULL; const char *l = cstr(e, label); bytes cb = get_bytes(e, ctxa); uint8_t *out = malloc((size_t)len);
    int r = out && l ? ksl_ssl_export_keying_material(SSLP(h), out, (size_t)len, l, strlen(l), ctxa ? cb.p : NULL, cb.n) : KSL_ERROR;
    jbyteArray a = r == KSL_OK ? new_bytes(e, out, (size_t)len) : NULL; if (out) { wipe(out, (size_t)len); free(out); } drop(&cb); cstr_free(e, label, l); return a;
}
static jlong j_ssl_get1_session(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; return H(ksl_ssl_get1_session(SSLP(h))); }
static jint j_ssl_set_session(JNIEnv *e, jclass c, jlong h, jlong sess) { (void)e; (void)c; return ksl_ssl_set_session(SSLP(h), P(ksl_session, sess)); }
static void j_session_free(JNIEnv *e, jclass c, jlong sess) { (void)e; (void)c; ksl_session_free(P(ksl_session, sess)); }
static jint j_ssl_new_ticket(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; return ksl_ssl_new_session_ticket(SSLP(h)); }
static jint j_ssl_key_update(JNIEnv *e, jclass c, jlong h, jint req) { (void)e; (void)c; return ksl_ssl_key_update(SSLP(h), req); }
static jstring j_ssl_last_error(JNIEnv *e, jclass c, jlong h, jintArray out) { (void)c; uint32_t code; int alert; char m[512]; ksl_ssl_last_error(SSLP(h), &code, &alert, m, sizeof m); jint v[2] = {(jint)code, alert}; (*e)->SetIntArrayRegion(e, out, 0, 2, v); return (*e)->NewStringUTF(e, m); }
static jint j_drive(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; return ksl_drive(SSLP(h)); }

static jint j_quic_set_tp(JNIEnv *e, jclass c, jlong h, jbyteArray a) { (void)c; bytes b = get_bytes(e, a); int r = ksl_quic_set_transport_params(SSLP(h), b.p, b.n); drop(&b); return r; }
static jint j_quic_provide(JNIEnv *e, jclass c, jlong h, jint level, jbyteArray a, jint off, jint len) {
    (void)c; if (off < 0 || len < 0 || off > (*e)->GetArrayLength(e, a) - len) return KSL_ERROR;
    uint8_t *b = malloc(len ? (size_t)len : 1); if (!b) return KSL_ERROR; (*e)->GetByteArrayRegion(e, a, off, len, (jbyte *)b); int r = ksl_quic_provide(SSLP(h), level, b, (size_t)len); free(b); return r;
}
/* event: int32 type, level, direction, aead, len, pad | int64 key | payload */
static jint j_quic_next_event(JNIEnv *e, jclass c, jlong h, jobject out, jint cap) {
    (void)c; ksl_event ev; if (!ksl_quic_peek_event(SSLP(h), &ev)) return 0;
    size_t need = 32 + ev.len; if (need > (size_t)cap) return -(jint)need;
    uint8_t *o = dbuf(e, out); if (!o) return -1;
    (void)ksl_quic_next_event(SSLP(h), &ev);
    int32_t hdr[6] = {ev.type, ev.level, ev.direction, ev.aead, (int32_t)ev.len, 0}; memcpy(o, hdr, 24); int64_t key = (int64_t)(intptr_t)ev.key; memcpy(o + 24, &key, 8);
    if (ev.len) memcpy(o + 32, ev.buf, ev.len); return 1;
}

static jint j_tcp_feed(JNIEnv *e, jclass c, jlong h, jbyteArray a, jint off, jint len) {
    (void)c; if (off < 0 || len < 0 || off > (*e)->GetArrayLength(e, a) - len) return -1;
    uint8_t *b = malloc(len ? (size_t)len : 1); if (!b) return -1; (*e)->GetByteArrayRegion(e, a, off, len, (jbyte *)b); size_t used = 0; int r = ksl_tcp_feed(SSLP(h), b, (size_t)len, &used); free(b); return r == KSL_OK ? (jint)used : -1;
}
static jint j_tcp_drain(JNIEnv *e, jclass c, jlong h, jbyteArray a, jint off, jint cap) {
    (void)c; if (off < 0 || cap < 0 || off > (*e)->GetArrayLength(e, a) - cap) return -1;
    uint8_t *b = malloc(cap ? (size_t)cap : 1); if (!b) return -1; size_t n = 0; int r = ksl_tcp_drain(SSLP(h), b, (size_t)cap, &n); if (r == KSL_OK && n) (*e)->SetByteArrayRegion(e, a, off, (jsize)n, (const jbyte *)b); free(b); return r == KSL_OK ? (jint)n : -1;
}
static jint map_rw(int r, size_t n) { return r == KSL_OK ? (jint)n : r == KSL_WANT_READ ? -2 : r == KSL_EOF ? -3 : -1; }
static jint j_tcp_write(JNIEnv *e, jclass c, jlong h, jbyteArray a, jint off, jint len) {
    (void)c; if (off < 0 || len < 0 || off > (*e)->GetArrayLength(e, a) - len) return -1;
    uint8_t *b = malloc(len ? (size_t)len : 1); if (!b) return -1; (*e)->GetByteArrayRegion(e, a, off, len, (jbyte *)b); size_t n = 0; int r = ksl_tcp_write(SSLP(h), b, (size_t)len, &n); wipe(b, (size_t)len); free(b); return map_rw(r, n);
}
static jint j_tcp_read(JNIEnv *e, jclass c, jlong h, jbyteArray a, jint off, jint cap) {
    (void)c; if (off < 0 || cap < 0 || off > (*e)->GetArrayLength(e, a) - cap) return -1;
    uint8_t *b = malloc(cap ? (size_t)cap : 1); if (!b) return -1; size_t n = 0; int r = ksl_tcp_read(SSLP(h), b, (size_t)cap, &n); if (r == KSL_OK && n) (*e)->SetByteArrayRegion(e, a, off, (jsize)n, (const jbyte *)b); wipe(b, (size_t)cap); free(b); return map_rw(r, n);
}
static jint j_tcp_shutdown(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; return ksl_tcp_shutdown(SSLP(h)); }
static jint j_tcp_abort(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; return ksl_tcp_abort(SSLP(h)); }

static jlong j_key_initial(JNIEnv *e, jclass c, jbyteArray dcid, jint is_server, jint dir, jint version) { (void)c; bytes b = get_bytes(e, dcid); ksl_key *k = ksl_key_initial(b.p, b.n, is_server, dir, (uint32_t)version); drop(&b); return H(k); }
static jlong j_key_next(JNIEnv *e, jclass c, jlong k) { (void)e; (void)c; return H(ksl_key_next(P(ksl_key, k))); }
static void j_key_free(JNIEnv *e, jclass c, jlong k) { (void)e; (void)c; ksl_key_free(P(ksl_key, k)); }
static jlong j_key_random(JNIEnv *e, jclass c, jint kind) { (void)e; (void)c; return H(ksl_key_random(kind)); }
static jint j_key_mac16(JNIEnv *e, jclass c, jlong k, jobject in, jint off, jint len, jbyteArray out, jint outOff) {
    (void)c; uint8_t *p = dbuf(e, in); if (!p || len < 0 || off < 0 || outOff < 0) return -1; uint8_t mac[16]; int r = ksl_key_mac16(P(ksl_key, k), p + off, (size_t)len, mac);
    if (r == KSL_OK) (*e)->SetByteArrayRegion(e, out, outOff, 16, (const jbyte *)mac); return r;
}
static jint j_seal(JNIEnv *e, jclass c, jlong k, jlong pn, jobject hdr, jint ho, jint hl, jobject pl, jint po, jint len, jint cap) { (void)c; uint8_t *h = dbuf(e, hdr), *p = dbuf(e, pl); if (!h || !p) return -1; return ksl_seal(P(ksl_key, k), (uint64_t)pn, h + ho, (size_t)hl, p + po, (size_t)len, (size_t)cap); }
static jint j_open(JNIEnv *e, jclass c, jlong k, jlong pn, jobject hdr, jint ho, jint hl, jobject pl, jint po, jint len) { (void)c; uint8_t *h = dbuf(e, hdr), *p = dbuf(e, pl); if (!h || !p) return -1; return ksl_open(P(ksl_key, k), (uint64_t)pn, h + ho, (size_t)hl, p + po, (size_t)len); }
static jint j_header_mask(JNIEnv *e, jclass c, jlong k, jobject sample, jint off, jbyteArray mask) { (void)c; uint8_t *s = dbuf(e, sample); if (!s) return -1; uint8_t m[5]; int r = ksl_header_mask(P(ksl_key, k), s + off, m); if (r == KSL_OK) (*e)->SetByteArrayRegion(e, mask, 0, 5, (const jbyte *)m); return r; }
static jbyteArray j_retry_tag(JNIEnv *e, jclass c, jint version, jbyteArray odcid, jbyteArray pseudo) { (void)c; bytes o = get_bytes(e, odcid), p = get_bytes(e, pseudo); uint8_t tag[16]; int r = ksl_retry_tag((uint32_t)version, o.p, o.n, p.p, p.n, tag); drop(&o); drop(&p); return r == KSL_OK ? new_bytes(e, tag, 16) : NULL; }

static jbyteArray j_rand(JNIEnv *e, jclass c, jint n) { (void)c; if (n < 0) return NULL; uint8_t *b = malloc(n ? (size_t)n : 1); if (!b) return NULL; int r = ksl_rand(b, (size_t)n); jbyteArray a = r == KSL_OK ? new_bytes(e, b, (size_t)n) : NULL; free(b); return a; }
static jbyteArray j_sha2(JNIEnv *e, jclass c, jint bits, jbyteArray data) { (void)c; bytes d = get_bytes(e, data); uint8_t out[48]; int r = ksl_sha2(bits, d.p, d.n, out); drop(&d); return r == KSL_OK ? new_bytes(e, out, bits / 8) : NULL; }
static jbyteArray j_hkdf(JNIEnv *e, jclass c, jint hash, jbyteArray secret, jstring label, jbyteArray ctxa, jint len) {
    (void)c; if (len <= 0 || len > 65535) return NULL; bytes s = get_bytes(e, secret), x = get_bytes(e, ctxa); const char *l = cstr(e, label); uint8_t *out = malloc((size_t)len);
    int r = out && l ? ksl_hkdf_expand_label(hash, s.p, s.n, l, x.p, x.n, out, (size_t)len) : KSL_ERROR; jbyteArray a = r == KSL_OK ? new_bytes(e, out, (size_t)len) : NULL;
    if (out) { wipe(out, (size_t)len); free(out); } drop(&s); drop(&x); cstr_free(e, label, l); return a;
}
static jbyteArray j_sign(JNIEnv *e, jclass c, jint alg, jbyteArray key, jbyteArray msg) { (void)c; bytes k = get_bytes(e, key), m = get_bytes(e, msg); uint8_t sig[512]; size_t sl = sizeof sig; int r = ksl_sign(alg, k.p, k.n, m.p, m.n, sig, &sl); drop(&k); drop(&m); return r == KSL_OK ? new_bytes(e, sig, sl) : NULL; }
static jint j_verify(JNIEnv *e, jclass c, jint alg, jbyteArray pub, jbyteArray msg, jbyteArray sig) { (void)c; bytes p = get_bytes(e, pub), m = get_bytes(e, msg), s = get_bytes(e, sig); int r = ksl_verify(alg, p.p, p.n, m.p, m.n, s.p, s.n); drop(&p); drop(&m); drop(&s); return r; }
static jbyteArray j_spki(JNIEnv *e, jclass c, jbyteArray cert) { (void)c; bytes d = get_bytes(e, cert); uint8_t out[32]; int r = ksl_spki_sha256(d.p, d.n, out); drop(&d); return r == KSL_OK ? new_bytes(e, out, 32) : NULL; }

/* ---- accelerated UDP: slots are PacketBuffer objects; their direct ByteBuffer is read through a field id cached at load (no JNIEnv cached) ---- */
static jfieldID pb_buffer_field;
static jint udp_slots(JNIEnv *e, jobjectArray bufs, jint n, uint8_t **ptrs, uint32_t *caps) {
    if (n < 0 || n > KSL_UDP_MAX_BATCH || !bufs || (*e)->GetArrayLength(e, bufs) < n) return -1;
    for (jint i = 0; i < n; i++) {
        jobject pb = (*e)->GetObjectArrayElement(e, bufs, i); if (!pb) return -1;
        jobject bb = (*e)->GetObjectField(e, pb, pb_buffer_field); (*e)->DeleteLocalRef(e, pb); if (!bb) return -1;
        ptrs[i] = (uint8_t *)(*e)->GetDirectBufferAddress(e, bb); jlong cap = (*e)->GetDirectBufferCapacity(e, bb); (*e)->DeleteLocalRef(e, bb);
        if (!ptrs[i] || cap < 0) return -1; caps[i] = (uint32_t)cap;
    }
    return 0;
}
static jlong j_udp_open(JNIEnv *e, jclass c, jbyteArray addr, jint flags, jintArray err, jobjectArray msg) {
    (void)c; uint8_t a[KSL_UDP_ADDR_LEN]; if (!addr || (*e)->GetArrayLength(e, addr) != KSL_UDP_ADDR_LEN) return 0; (*e)->GetByteArrayRegion(e, addr, 0, KSL_UDP_ADDR_LEN, (jbyte *)a);
    uint32_t code = 0; char m[256] = {0}; ksl_udp *u = ksl_udp_open(a, flags, &code, m, sizeof m);
    if (!u) { jint ec = (jint)code; (*e)->SetIntArrayRegion(e, err, 0, 1, &ec); jstring js = (*e)->NewStringUTF(e, m); if (js) (*e)->SetObjectArrayElement(e, msg, 0, js); }
    return H(u);
}
static jint j_udp_send(JNIEnv *e, jclass c, jlong h, jobjectArray bufs, jintArray lens, jbyteArray addrs, jbyteArray ecn, jint n) {
    (void)c; uint8_t *ptrs[KSL_UDP_MAX_BATCH]; uint32_t caps[KSL_UDP_MAX_BATCH]; jint l[KSL_UDP_MAX_BATCH]; uint8_t a[KSL_UDP_MAX_BATCH * KSL_UDP_ADDR_LEN]; uint8_t m[KSL_UDP_MAX_BATCH]; uint32_t sent = 0;
    if (udp_slots(e, bufs, n, ptrs, caps) != 0 || !lens || !addrs || !ecn || (*e)->GetArrayLength(e, lens) < n || (*e)->GetArrayLength(e, addrs) < n * KSL_UDP_ADDR_LEN || (*e)->GetArrayLength(e, ecn) < n) return -1;
    (*e)->GetIntArrayRegion(e, lens, 0, n, l); (*e)->GetByteArrayRegion(e, addrs, 0, n * KSL_UDP_ADDR_LEN, (jbyte *)a); (*e)->GetByteArrayRegion(e, ecn, 0, n, (jbyte *)m);
    uint32_t ul[KSL_UDP_MAX_BATCH]; for (jint i = 0; i < n; i++) { if (l[i] < 0 || (uint32_t)l[i] > caps[i]) return -1; ul[i] = (uint32_t)l[i]; }
    int r = ksl_udp_send(P(ksl_udp, h), ptrs, ul, a, m, (uint32_t)n, &sent); return r == KSL_OK ? (jint)sent : -1;
}
static jint j_udp_recv(JNIEnv *e, jclass c, jlong h, jobjectArray bufs, jintArray lens, jbyteArray addrs, jbyteArray ecn, jint n, jint timeout) {
    (void)c; uint8_t *ptrs[KSL_UDP_MAX_BATCH]; uint32_t caps[KSL_UDP_MAX_BATCH]; uint32_t ul[KSL_UDP_MAX_BATCH]; uint8_t a[KSL_UDP_MAX_BATCH * KSL_UDP_ADDR_LEN]; uint8_t m[KSL_UDP_MAX_BATCH]; uint32_t got = 0;
    if (udp_slots(e, bufs, n, ptrs, caps) != 0 || !lens || !addrs || !ecn || (*e)->GetArrayLength(e, lens) < n || (*e)->GetArrayLength(e, addrs) < n * KSL_UDP_ADDR_LEN || (*e)->GetArrayLength(e, ecn) < n) return -1;
    int r = ksl_udp_recv(P(ksl_udp, h), ptrs, caps, ul, a, m, (uint32_t)n, &got, timeout);
    if (r == KSL_WANT_READ) return -2; if (r != KSL_OK) return -1;
    jint l[KSL_UDP_MAX_BATCH]; for (uint32_t i = 0; i < got; i++) l[i] = (jint)ul[i];
    if (got) { (*e)->SetIntArrayRegion(e, lens, 0, (jsize)got, l); (*e)->SetByteArrayRegion(e, addrs, 0, (jsize)(got * KSL_UDP_ADDR_LEN), (const jbyte *)a); (*e)->SetByteArrayRegion(e, ecn, 0, (jsize)got, (const jbyte *)m); }
    return (jint)got;
}
static jbyteArray j_udp_get(JNIEnv *e, jclass c, jlong h, jint what) { (void)c; uint8_t out[300]; size_t n = 0; if (ksl_udp_get(P(ksl_udp, h), what, out, sizeof out, &n) != KSL_OK) return NULL; return new_bytes(e, out, n); }
/* quote (at least KSL_UDP_PTB_QUOTE bytes), meta[0] = quote length, meta[1] = MTU, dst (KSL_UDP_ADDR_LEN bytes) */
static jboolean j_udp_take_ptb(JNIEnv *e, jclass c, jlong h, jbyteArray quote, jintArray meta, jbyteArray dst) {
    (void)c; if (!quote || !meta || !dst || (*e)->GetArrayLength(e, quote) < KSL_UDP_PTB_QUOTE || (*e)->GetArrayLength(e, meta) < 2 || (*e)->GetArrayLength(e, dst) < KSL_UDP_ADDR_LEN) return JNI_FALSE;
    uint8_t q[KSL_UDP_PTB_QUOTE], d[KSL_UDP_ADDR_LEN]; uint32_t ql = 0, mtu = 0;
    if (!ksl_udp_take_ptb(P(ksl_udp, h), q, sizeof q, &ql, d, &mtu)) return JNI_FALSE;
    jint m[2] = { (jint)ql, (jint)mtu };
    (*e)->SetByteArrayRegion(e, quote, 0, (jsize)ql, (const jbyte *)q); (*e)->SetIntArrayRegion(e, meta, 0, 2, m); (*e)->SetByteArrayRegion(e, dst, 0, KSL_UDP_ADDR_LEN, (const jbyte *)d);
    return JNI_TRUE;
}
static jlong j_udp_emsgsize(JNIEnv *e, jclass c, jlong h, jintArray last) {
    (void)c; uint32_t l = 0; uint64_t n = ksl_udp_emsgsize(P(ksl_udp, h), &l);
    if (last && (*e)->GetArrayLength(e, last) >= 1) { jint v = (jint)l; (*e)->SetIntArrayRegion(e, last, 0, 1, &v); }
    return (jlong)n;
}
static void j_udp_shutdown(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; ksl_udp_shutdown(P(ksl_udp, h)); }
static void j_udp_close(JNIEnv *e, jclass c, jlong h) { (void)e; (void)c; ksl_udp_close(P(ksl_udp, h)); }
static jint j_live_objects(JNIEnv *e, jclass c, jlongArray out) {
    (void)c; int64_t v[KSL_LIVE_COUNT]; int n = ksl_live_objects(v, KSL_LIVE_COUNT); jlong j[KSL_LIVE_COUNT];
    jsize len = out ? (*e)->GetArrayLength(e, out) : 0; if (len > KSL_LIVE_COUNT) len = KSL_LIVE_COUNT;
    for (jsize i = 0; i < len; i++) j[i] = (jlong)v[i];
    if (len) (*e)->SetLongArrayRegion(e, out, 0, len, j);
    return n;
}

#define S_BB "Ljava/nio/ByteBuffer;"
#define S_STR "Ljava/lang/String;"
static const JNINativeMethod methods[] = {
    {"abiVersion", "()I", (void *)j_abi}, {"init", "()I", (void *)j_init}, {"version", "()" S_STR, (void *)j_version},
    {"ctxNew", "(I)J", (void *)j_ctx_new}, {"ctxFree", "(J)V", (void *)j_ctx_free}, {"ctxSetAlpn", "(J[B)I", (void *)j_ctx_set_alpn},
    {"ctxSetIdentity", "(J[B[B)I", (void *)j_ctx_set_identity}, {"ctxSetIdentityPkey", "(J[BJ)I", (void *)j_ctx_set_identity_pkey}, {"pkeyNew", "([B)J", (void *)j_pkey_new}, {"pkeyFree", "(J)V", (void *)j_pkey_free},
    {"ctxSetRoots", "(J[B)I", (void *)j_ctx_set_roots}, {"ctxSetCiphers", "(J" S_STR S_STR ")I", (void *)j_ctx_set_ciphers},
    {"ctxUseDefaultTicketKeys", "(JI)I", (void *)j_ctx_use_default_ticket_keys}, {"ticketKeysRegister", "([B)I", (void *)j_ticket_keys_register}, {"ctxUseTicketKeys", "(JI)I", (void *)j_ctx_use_ticket_keys}, {"ctxSetSessionContext", "(J[B)I", (void *)j_ctx_set_session_context}, {"ctxSetOption", "(JII)I", (void *)j_ctx_set_option}, {"ctxFreeze", "(J)I", (void *)j_ctx_freeze}, {"ctxVerifyChain", "(J[B" S_STR "J)I", (void *)j_ctx_verify_chain}, {"ctxLastError", "(J[I)" S_STR, (void *)j_ctx_last_error},
    {"sslNew", "(JI)J", (void *)j_ssl_new}, {"sslFree", "(J)V", (void *)j_ssl_free}, {"sslSet", "(JI[B)I", (void *)j_ssl_set},
    {"sslGet", "(JI)[B", (void *)j_ssl_get}, {"sslPeerChainCount", "(JI)I", (void *)j_ssl_peer_chain_count}, {"sslPeerChainItem", "(JII)[B", (void *)j_ssl_peer_chain_item},
    {"sslVerifyResume", "(JII)I", (void *)j_ssl_verify_resume}, {"sslClientHello", "(J)[B", (void *)j_ssl_client_hello}, {"sslSniResume", "(JJI)I", (void *)j_ssl_sni_resume},
    {"sslExportKeyingMaterial", "(J" S_STR "[BI)[B", (void *)j_ssl_export}, {"sslGet1Session", "(J)J", (void *)j_ssl_get1_session}, {"sslSetSession", "(JJ)I", (void *)j_ssl_set_session}, {"sessionFree", "(J)V", (void *)j_session_free}, {"sslNewSessionTicket", "(J)I", (void *)j_ssl_new_ticket},
    {"sslKeyUpdate", "(JI)I", (void *)j_ssl_key_update}, {"sslLastError", "(J[I)" S_STR, (void *)j_ssl_last_error}, {"drive", "(J)I", (void *)j_drive},
    {"quicSetTransportParams", "(J[B)I", (void *)j_quic_set_tp}, {"quicProvide", "(JI[BII)I", (void *)j_quic_provide}, {"quicNextEvent", "(J" S_BB "I)I", (void *)j_quic_next_event},
    {"tcpFeed", "(J[BII)I", (void *)j_tcp_feed}, {"tcpDrain", "(J[BII)I", (void *)j_tcp_drain}, {"tcpWrite", "(J[BII)I", (void *)j_tcp_write}, {"tcpRead", "(J[BII)I", (void *)j_tcp_read}, {"tcpShutdown", "(J)I", (void *)j_tcp_shutdown}, {"tcpAbort", "(J)I", (void *)j_tcp_abort},
    {"keyInitial", "([BIII)J", (void *)j_key_initial}, {"keyNext", "(J)J", (void *)j_key_next}, {"keyFree", "(J)V", (void *)j_key_free}, {"keyRandom", "(I)J", (void *)j_key_random}, {"keyMac16", "(J" S_BB "II[BI)I", (void *)j_key_mac16},
    {"seal", "(JJ" S_BB "II" S_BB "III)I", (void *)j_seal}, {"open", "(JJ" S_BB "II" S_BB "II)I", (void *)j_open}, {"headerMask", "(J" S_BB "I[B)I", (void *)j_header_mask}, {"retryTag", "(I[B[B)[B", (void *)j_retry_tag},
    {"rand", "(I)[B", (void *)j_rand}, {"sha2", "(I[B)[B", (void *)j_sha2}, {"hkdfExpandLabel", "(I[B" S_STR "[BI)[B", (void *)j_hkdf}, {"sign", "(I[B[B)[B", (void *)j_sign}, {"verify", "(I[B[B[B)I", (void *)j_verify}, {"spkiSha256", "([B)[B", (void *)j_spki},
    {"udpOpen", "([BI[I[Ljava/lang/String;)J", (void *)j_udp_open}, {"udpSend", "(J[Lio/kuicksilver/native/PacketBuffer;[I[B[BI)I", (void *)j_udp_send}, {"udpRecv", "(J[Lio/kuicksilver/native/PacketBuffer;[I[B[BII)I", (void *)j_udp_recv},
    {"udpGet", "(JI)[B", (void *)j_udp_get}, {"udpShutdown", "(J)V", (void *)j_udp_shutdown}, {"udpClose", "(J)V", (void *)j_udp_close},
    {"udpTakePtb", "(J[B[I[B)Z", (void *)j_udp_take_ptb}, {"udpEmsgsize", "(J[I)J", (void *)j_udp_emsgsize},
    {"liveObjects", "([J)I", (void *)j_live_objects},
};

static jint on_load(JavaVM *vm, jint version) {
    JNIEnv *env; if ((*vm)->GetEnv(vm, (void **)&env, version) != JNI_OK) return JNI_ERR;
    jclass cls = (*env)->FindClass(env, "io/kuicksilver/native/KslNative"); if (!cls) return JNI_ERR;
    if ((*env)->RegisterNatives(env, cls, methods, sizeof methods / sizeof methods[0]) != JNI_OK) return JNI_ERR;
    jclass pb = (*env)->FindClass(env, "io/kuicksilver/native/PacketBuffer"); if (!pb) return JNI_ERR;
    pb_buffer_field = (*env)->GetFieldID(env, pb, "buffer", "Ljava/nio/ByteBuffer;"); if (!pb_buffer_field) return JNI_ERR;
    return version;
}
#ifdef __ANDROID__
#define KSL_JNI_VERSION JNI_VERSION_1_6
#else
#define KSL_JNI_VERSION JNI_VERSION_1_8
#endif
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) { (void)reserved; return on_load(vm, KSL_JNI_VERSION); }
/* static JNI (java -Djava.library.path / GraalVM): the library name is "ksl" */
JNIEXPORT jint JNICALL JNI_OnLoad_ksl(JavaVM *vm, void *reserved) { (void)reserved; return on_load(vm, KSL_JNI_VERSION); }
