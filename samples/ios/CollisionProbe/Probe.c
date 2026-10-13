// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
#include "Probe.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>

static X509 *self_signed(EVP_PKEY *key) {
    X509 *x = X509_new();
    if (x == NULL) return NULL;
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"probe.test", -1, -1, 0);
    X509_set_issuer_name(x, name);
    if (X509_sign(x, key, EVP_sha256()) == 0) { X509_free(x); return NULL; }
    return x;
}

int probe_unprefixed_openssl_handshake(char *out, int out_len) {
    int rc = 1;
    EVP_PKEY *key = EVP_EC_gen("P-256");
    X509 *cert = key ? self_signed(key) : NULL;
    SSL_CTX *sctx = SSL_CTX_new(TLS_server_method()), *cctx = SSL_CTX_new(TLS_client_method());
    SSL *server = NULL, *client = NULL;
    BIO *sbio = NULL, *cbio = NULL;
    if (cert == NULL || sctx == NULL || cctx == NULL) goto done;
    SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate(sctx, cert) != 1 || SSL_CTX_use_PrivateKey(sctx, key) != 1) goto done;
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);   // the probe proves the stack works, not a PKI
    server = SSL_new(sctx); client = SSL_new(cctx);
    if (server == NULL || client == NULL || BIO_new_bio_pair(&sbio, 0, &cbio, 0) != 1) goto done;
    SSL_set_bio(server, sbio, sbio); SSL_set_bio(client, cbio, cbio);
    SSL_set_accept_state(server); SSL_set_connect_state(client);
    for (int i = 0; i < 20 && !(SSL_is_init_finished(server) && SSL_is_init_finished(client)); i++) {
        int c = SSL_do_handshake(client), s = SSL_do_handshake(server);
        if (c <= 0 && SSL_get_error(client, c) != SSL_ERROR_WANT_READ) goto done;
        if (s <= 0 && SSL_get_error(server, s) != SSL_ERROR_WANT_READ) goto done;
    }
    if (!(SSL_is_init_finished(server) && SSL_is_init_finished(client))) goto done;
    snprintf(out, (size_t)out_len, "%s %s %s", OpenSSL_version(OPENSSL_VERSION), SSL_get_version(client),
             SSL_CIPHER_get_name(SSL_get_current_cipher(client)));
    rc = 0;
done:
    if (rc != 0) {
        unsigned long e = ERR_get_error();
        snprintf(out, (size_t)out_len, "handshake failed: %s", e ? ERR_error_string(e, NULL) : "no OpenSSL error");
    }
    SSL_free(client); SSL_free(server);   // each SSL owns its end of the BIO pair
    SSL_CTX_free(cctx); SSL_CTX_free(sctx);
    X509_free(cert); EVP_PKEY_free(key);
    return rc;
}
