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
    /* RFC 7627, RFC 9325 section 3.6: a TLS 1.2 server without extended master secret is refused here, the first callback after its
       ServerHello, so that OpenSSL sends handshake_failure (X509_V_ERR_APPLICATION_VERIFICATION) before our Finished (RFC 8446
       section 6.1); the check after the handshake (ksl_drive) could only drop the connection without an alert */
    if (c->role == KSL_CLIENT && s->mode == KSL_MODE_TCP && SSL_version(ssl) < TLS1_3_VERSION && !s->server_hello_ems) {
        s->ems_refused = 1; X509_STORE_CTX_set_error(xctx, X509_V_ERR_APPLICATION_VERIFICATION); return 0;
    }
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
int ksl_client_hello_sni(SSL *ssl, const unsigned char **name, size_t *len) {
    const unsigned char *p; size_t l; *name = NULL; *len = 0;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &p, &l) == 1 && l >= 5 && p[2] == 0) {   /* list len(2) type(1) name len(2) name */
        size_t nl = ((size_t)p[3] << 8) | p[4]; if (5 + nl <= l) { *name = p + 5; *len = nl; return 1; }
    }
    return 0;   /* none; OpenSSL refuses a malformed extension itself (decode_error) */
}
/* The tag a ticket carries for its server name: SHA-256 of a presence byte and the host name in ASCII lower case (DNS names
   compare case-insensitively, RFC 4343 section 3), so that no name and every distinct name have distinct tags. */
static int sni_tag(SSL *ssl, uint8_t out[32]) {
    const unsigned char *name; size_t len; uint8_t has = (uint8_t)ksl_client_hello_sni(ssl, &name, &len); unsigned int ol = 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new(); int ok = m && EVP_DigestInit_ex(m, EVP_sha256(), NULL) == 1 && EVP_DigestUpdate(m, &has, 1) == 1;
    for (size_t i = 0; ok && i < len; i += 64) {
        uint8_t low[64]; size_t k = len - i < sizeof low ? len - i : sizeof low;
        for (size_t j = 0; j < k; j++) { uint8_t ch = name[i + j]; low[j] = ch >= 'A' && ch <= 'Z' ? (uint8_t)(ch + 32) : ch; }
        ok = EVP_DigestUpdate(m, low, k) == 1;
    }
    ok = ok && EVP_DigestFinal_ex(m, out, &ol) == 1 && ol == 32; EVP_MD_CTX_free(m); return ok;
}
int ksl_client_hello_cb(SSL *ssl, int *al, void *arg) {
    (void)arg; ksl_ssl *s = SSL_get_ex_data(ssl, 1); const unsigned char *ext; size_t ext_len;
    if (s->mode == KSL_MODE_QUIC && SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &ext, &ext_len) != 1) {
        *al = SSL_AD_NO_APPLICATION_PROTOCOL; return SSL_CLIENT_HELLO_ERROR;
    }
    /* RFC 6066 section 3: a server "MUST NOT accept the request to resume the session if the server_name extension contains a
       different name". OpenSSL compares no name on a TLS 1.3 resumption, and virtual hosts of one server (SNI overrides with the
       same trust, hence the same session context, and the process-wide ticket keys) would accept each other's tickets: every
       ticket carries this tag (ticket_gen_cb), and a ticket of another name runs a full handshake (ticket_dec_cb). Taken from the
       ClientHello itself: OpenSSL decrypts the ticket before it parses server_name, so SSL_get_servername is not yet set then. */
    if (!sni_tag(ssl, s->sni_tag)) { *al = SSL_AD_INTERNAL_ERROR; return SSL_CLIENT_HELLO_ERROR; }
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
/* Resumption (ADR-0011): a resumed handshake carries no Certificate, so the chain cached from the full handshake is verified again with
   the current trust store, time, name and purpose; X509_STORE is safe to share between threads for verification. */
int ksl_ctx_verify_chain(ksl_ctx *c, const uint8_t *chain, size_t chain_len, const char *name, int64_t at, int *x509_err) {
    ERR_clear_error(); if (x509_err) *x509_err = 0;
    if (c->role == KSL_CLIENT && (!name || !*name)) return KSL_ERROR;   /* no error is written into the shared context: *x509_err says it all */
    STACK_OF(X509) *sk = NULL;
    if (!ksl_parse_chain(chain, chain_len, &sk) || sk_X509_num(sk) == 0) { sk_X509_pop_free(sk, X509_free); return KSL_ERROR; }
    X509_STORE_CTX *x = X509_STORE_CTX_new(); int ok = 0, err = 0;
    if (x && X509_STORE_CTX_init(x, SSL_CTX_get_cert_store(c->ctx), sk_X509_value(sk, 0), sk) == 1
        && X509_STORE_CTX_set_default(x, c->role == KSL_CLIENT ? "ssl_server" : "ssl_client") == 1) {
        X509_VERIFY_PARAM *p = X509_STORE_CTX_get0_param(x); int named = 1;
        X509_VERIFY_PARAM_set1(p, SSL_CTX_get0_param(c->ctx));   /* the context's flags (PARTIAL_CHAIN for AnchoredCa) and depth */
        if (at > 0) X509_VERIFY_PARAM_set_time(p, (time_t)at);
        if (c->role == KSL_CLIENT) {
            X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (X509_VERIFY_PARAM_set1_ip_asc(p, name) != 1) { ERR_clear_error(); named = X509_VERIFY_PARAM_set1_host(p, name, 0) == 1; }
        }
        if (named) { ok = X509_verify_cert(x) == 1; err = ok ? X509_V_OK : X509_STORE_CTX_get_error(x); }
    }
    X509_STORE_CTX_free(x); sk_X509_pop_free(sk, X509_free); ERR_clear_error();
    if (ok) return KSL_OK;
    if (x509_err) *x509_err = err;
    return KSL_ERROR;
}
