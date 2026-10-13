/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Certificate verification: OpenSSL verifier, client-side pause/resume (ADR-0012), the reference-identifier
 * matcher that runs on every path (ADR-0011), and the ClientHello pause for SNI selection. */
#include "ksl_internal.h"

static STACK_OF(X509) *capture_presented(X509_STORE_CTX *xctx) {
    STACK_OF(X509) *out = sk_X509_new_null(); X509 *leaf = X509_STORE_CTX_get0_cert(xctx);
    if (leaf && X509_up_ref(leaf)) sk_X509_push(out, leaf);
    STACK_OF(X509) *un = X509_STORE_CTX_get0_untrusted(xctx);
    for (int i = 0; un && i < sk_X509_num(un); i++) { X509 *x = sk_X509_value(un, i); if (X509_cmp(x, leaf) != 0 && X509_up_ref(x)) sk_X509_push(out, x); }
    return out;
}
/* Name and purpose checks that the platform verifier may have skipped (JDK/Android never check the name). */
static int ksl_match_leaf(ksl_ssl *s, X509 *leaf, int role_of_peer_is_server) {
    int ok = 1;
    if (role_of_peer_is_server) {
        if (s->verify_ip) ok = X509_check_ip_asc(leaf, s->verify_ip, 0) == 1;
        else ok = s->verify_host && X509_check_host(leaf, s->verify_host, 0, s->verify_flags, NULL) == 1;
        if (!ok) return X509_V_ERR_HOSTNAME_MISMATCH;
    }
    if (X509_check_purpose(leaf, role_of_peer_is_server ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT, 0) != 1) return X509_V_ERR_INVALID_PURPOSE;
    return X509_V_OK;
}
/* The X509 error whose libssl alert mapping (statem_lib.c x509table) yields the requested alert. */
static int alert_to_x509_error(int alert) {
    switch (alert) {
    case 40: return X509_V_ERR_APPLICATION_VERIFICATION;   /* handshake_failure */
    case 43: return X509_V_ERR_INVALID_PURPOSE;            /* unsupported_certificate */
    case 44: return X509_V_ERR_CERT_REVOKED;
    case 45: return X509_V_ERR_CERT_HAS_EXPIRED;
    case 46: return X509_V_OK;                             /* certificate_unknown: libssl's default for a failed callback without an error code */
    case 48: return X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    default: return X509_V_ERR_CERT_REJECTED;              /* bad_certificate (42) */
    }
}
static int fail_with(ksl_ssl *s, X509_STORE_CTX *xctx, int x509_err) {
    s->verify_err = x509_err;
    X509_STORE_CTX_set_error(xctx, s->owner->generic_alerts ? X509_V_ERR_APPLICATION_VERIFICATION : x509_err);
    return 0;
}
int ksl_cert_verify_cb(X509_STORE_CTX *xctx, void *arg) {
    (void)arg;
    SSL *ssl = X509_STORE_CTX_get_ex_data(xctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    ksl_ssl *s = SSL_get_ex_data(ssl, 1); ksl_ctx *c = s->owner;
    int peer_is_server = c->role == KSL_CLIENT;
    sk_X509_pop_free(s->presented_chain, X509_free); s->presented_chain = capture_presented(xctx);
    if (c->role == KSL_CLIENT && c->verify_mode == KSL_VERIFY_PAUSE) {
        /* statem_clnt.c: the pause happens only when the callback returns 1 AND retry_verify is set; 0 is a plain failure. */
        if (s->verify_pending == 0) { s->verify_pending = 1; (void)SSL_set_retry_verify(ssl); return 1; }
        if (s->verify_pending == 1) { (void)SSL_set_retry_verify(ssl); return 1; }
        s->verify_pending = 3;
        if (s->verify_decision) {
            int e = ksl_match_leaf(s, X509_STORE_CTX_get0_cert(xctx), 1);
            if (e == X509_V_OK) return 1;
            return fail_with(s, xctx, e);
        }
        /* a Kotlin-side rejection: the requested alert decides the wire error; verify_err keeps it for the caller */
        s->verify_err = alert_to_x509_error(s->verify_alert);
        X509_STORE_CTX_set_error(xctx, s->owner->generic_alerts ? X509_V_ERR_APPLICATION_VERIFICATION : s->verify_err); return 0;
    }
    /* OpenSSL verifier: trust store + purpose + name (the SSL object carries the verify params) */
    if (X509_verify_cert(xctx) != 1) {
        int e = X509_STORE_CTX_get_error(xctx); s->verify_err = e;
        if (e == X509_V_ERR_CERT_NOT_YET_VALID) e = X509_V_ERR_CERT_HAS_EXPIRED;   /* both map to certificate_expired (45), RFC 8446 section 6.2 */
        X509_STORE_CTX_set_error(xctx, s->owner->generic_alerts ? X509_V_ERR_APPLICATION_VERIFICATION : e);
        return 0;
    }
    int e = ksl_match_leaf(s, X509_STORE_CTX_get0_cert(xctx), peer_is_server);
    if (e != X509_V_OK) return fail_with(s, xctx, e);
    sk_X509_pop_free(s->validated_chain, X509_free); s->validated_chain = X509_STORE_CTX_get1_chain(xctx);
    return 1;
}
/* Every server's ClientHello: QUIC needs ALPN (RFC 9001 section 8.1: "endpoints MUST immediately close a connection ... with a
   no_application_protocol TLS alert (QUIC error code 0x0178)"); OpenSSL calls the ALPN select callback only when the extension is
   present, so a ClientHello without it is refused here, as OpenSSL's own QUIC stack and BoringSSL do. Then the pause for SNI selection
   (KSL_OPT_SNI_PAUSE): Kotlin reads ksl_ssl_client_hello and answers with ksl_ssl_sni_resume; the override is applied once (a second
   ClientHello after HelloRetryRequest keeps it). */
int ksl_client_hello_cb(SSL *ssl, int *al, void *arg) {
    (void)arg; ksl_ssl *s = SSL_get_ex_data(ssl, 1); const unsigned char *ext; size_t ext_len;
    if (s->mode == KSL_MODE_QUIC && SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &ext, &ext_len) != 1) {
        *al = SSL_AD_NO_APPLICATION_PROTOCOL; return SSL_CLIENT_HELLO_ERROR;
    }
    if (!s->owner->sni_pause || s->sni_pending == 3) return SSL_CLIENT_HELLO_SUCCESS;
    if (s->sni_pending == 0) { s->sni_pending = 1; return SSL_CLIENT_HELLO_RETRY; }
    if (s->sni_pending == 1) return SSL_CLIENT_HELLO_RETRY;
    s->sni_pending = 3;
    if (s->sni_decision_alert) { *al = s->sni_decision_alert; return SSL_CLIENT_HELLO_ERROR; }
    if (s->sni_override) {
        ksl_ctx *o = s->sni_override;
        if (!SSL_set_SSL_CTX(ssl, o->ctx) || !ksl_ctx_apply_to_ssl(o, ssl)) { *al = SSL_AD_INTERNAL_ERROR; return SSL_CLIENT_HELLO_ERROR; }
        /* ALPN: the override's SSL_CTX carries its own select callback (arg = o); the frozen base context, shared by other sessions, is never written */
        s->owner = o;   /* ownership of the session's settings moves to the override context */
        SSL_set_ex_data(ssl, 1, s);
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}
