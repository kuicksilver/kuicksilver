/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* TLS Encrypted Client Hello (RFC 9849; ADR-0019): a client's ECHConfigList (checked entry by entry), GREASE, the outcome and the
 * server's retry configurations; a server's ECH keys, replaced whole for rotation. OpenSSL 4 does the protocol; ksl decides what
 * reaches it and what is reported. Built only with the bundled OpenSSL 4 (KSL_HAS_ECH); a system-OpenSSL build (Linux, 3.5 to
 * 3.x) answers KSL_E_NOT_SUPPORTED. */
#include "ksl_internal.h"
#include <limits.h>
#if KSL_HAS_ECH
#include <openssl/ech.h>
#endif

#define ECH_VERSION 0xfe0d       /* RFC 9849 section 4: the version of the ECHConfig this document defines */
#define ECH_LIST_MAX 65537       /* an ECHConfigList: a 2-byte length and at most 65535 bytes (RFC 9849 section 4) */
#define ECH_KEYS_MAX 16          /* ECH keys a server context holds at once (rotation keeps a few) */
#define ECH_KEY_PEM_MAX (16384u) /* one key's PEM: a PKCS#8 private key and its ECHCONFIG block */

/* The checked list into out: the ECHConfigs of `list` this OpenSSL can use, in their order. RFC 9849 section 4 has the client ignore an
   ECHConfig of another version, one with an unsupported mandatory extension (section 4.2), one without a KEM and cipher suite it
   supports, and one whose public_name is not a valid DNS name or could be read as an IPv4 address (section 6.1.7). OpenSSL checks all of
   that per ECHConfig (ech_store.c ech_final_config_checks), but refuses the whole list for one bad entry, where the RFC ignores that
   entry alone: so each entry goes to OpenSSL on its own, as a list of one, and only those it takes are kept. Bounds: the list's own
   length must match `len` exactly, every entry must fit, and an entry OpenSSL would not read (longer than OSSL_ECH_MAX_ECHCONFIG_LEN)
   is dropped. KSL_OK with at least one entry kept; else KSL_ERROR with *code KSL_E_NOT_SUPPORTED (no entry usable, or no ECH in
   this build) or KSL_E_BAD_ARG (the framing does not parse, *out_len 0; or the result does not fit `cap`, *out_len the size it
   needs). */
static int check_list(const uint8_t *list, size_t len, uint8_t *out, size_t cap, size_t *out_len, uint32_t *code) {
    *out_len = 0;
    *code = KSL_E_BAD_ARG;
    if (list == NULL || len < 2 || len > ECH_LIST_MAX || (((size_t)list[0] << 8) | list[1]) != len - 2)
        return KSL_ERROR;
#if KSL_HAS_ECH
    size_t kept = 2, off = 2;
    int bad = 0;
    while (off < len) {
        if (!ksl_span_fits(off, 4, len))
            return KSL_ERROR;
        size_t version = ((size_t)list[off] << 8) | list[off + 1], n = ((size_t)list[off + 2] << 8) | list[off + 3];
        if (!ksl_span_fits(off + 4, n, len))
            return KSL_ERROR;
        size_t entry = 4 + n;
        int usable = version == ECH_VERSION && entry + 2 < OSSL_ECH_MAX_ECHCONFIG_LEN;
        if (usable) {
            uint8_t one[OSSL_ECH_MAX_ECHCONFIG_LEN];
            one[0] = (uint8_t)(entry >> 8);
            one[1] = (uint8_t)entry;
            memcpy(one + 2, list + off, entry);
            OSSL_ECHSTORE *es = OSSL_ECHSTORE_new(NULL, NULL);
            BIO *in = BIO_new_mem_buf(one, (int)(entry + 2));
            int entries = 0;
            usable = es != NULL && in != NULL && OSSL_ECHSTORE_read_echconfiglist(es, in) == 1 &&
                     OSSL_ECHSTORE_num_entries(es, &entries) == 1 && entries == 1;
            BIO_free(in);
            OSSL_ECHSTORE_free(es);
            ERR_clear_error();
        }
        if (usable) {
            if (out != NULL && kept + entry <= cap)
                memcpy(out + kept, list + off, entry);
            else
                bad = 1;
            kept += entry;
        }
        off += entry;
    }
    *out_len = kept;
    if (kept == 2) {
        *out_len = 0;
        *code = KSL_E_NOT_SUPPORTED;
        return KSL_ERROR;
    }
    if (bad || out == NULL || cap < kept)
        return KSL_ERROR; /* KSL_E_BAD_ARG: too small, *out_len says the size */
    out[0] = (uint8_t)((kept - 2) >> 8);
    out[1] = (uint8_t)(kept - 2);
    return KSL_OK;
#else
    (void)out;
    (void)cap;
    *code = KSL_E_NOT_SUPPORTED;
    return KSL_ERROR;
#endif
}
int ksl_ech_config_list_check(const uint8_t *list, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    uint32_t code;
    size_t n = 0;
    int r = check_list(list, len, out, cap, &n, &code);
    ERR_clear_error();
    if (out_len)
        *out_len = n;
    if (r != KSL_OK && code == KSL_E_NOT_SUPPORTED) {
        if (out_len)
            *out_len = 0;
        return KSL_OK; /* parses, nothing usable */
    }
    return r;
}

int ksl_ech_set_config_list(ksl_ssl *s, const uint8_t *data, size_t len) {
#if KSL_HAS_ECH
    if (s->owner->role != KSL_CLIENT) {
        ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: an ECH configuration list is for clients");
        return KSL_ERROR;
    }
    if (!SSL_in_before(s->ssl) || s->ech_set) {
        ksl_ssl_set_error(s, KSL_E_TOO_LATE, "ksl: ECH is set once, before the handshake starts");
        return KSL_ERROR;
    }
    /* OpenSSL 4.1.0 bug A (ADR-0019): a client custom extension that declines to be sent breaks the ECH ClientHello; the only one
       ksl registers (ksl_tcp_abort's) is on contexts that allow TLS 1.2, which ECH never needs */
    if (s->owner->abort_ext) {
        ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED,
                          "ksl: ECH needs a client context that allows TLS 1.3 only (KSL_OPT_MIN_VERSION KSL_TLS1_2 was set)");
        return KSL_ERROR;
    }
    if (s->verify_ip) {
        ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: ECH needs a host name, not an IP literal, as the verify name");
        return KSL_ERROR;
    }
    uint8_t *checked = malloc(len > 2 ? len : 2);
    size_t n = 0;
    uint32_t code = KSL_E_NO_MEMORY;
    int r = checked ? check_list(data, len, checked, len, &n, &code) : KSL_ERROR;
    if (r != KSL_OK) {
        free(checked);
        ksl_ssl_set_error(s, code,
                          code == KSL_E_NOT_SUPPORTED ? "ksl: no ECHConfig of the list is usable (version, suite, mandatory "
                                                        "extension or public_name)"
                          : code == KSL_E_NO_MEMORY ? "ksl: out of memory"
                                                    : "ksl: the ECHConfigList does not parse");
        return KSL_ERROR;
    }
    r = SSL_set1_ech_config_list(s->ssl, checked, n);
    free(checked);
    if (r != 1) {
        ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: OpenSSL refused the ECHConfigList");
        return KSL_ERROR;
    }
    s->ech_set = 1;
    return KSL_OK;
#else
    (void)data;
    (void)len;
    ksl_ssl_set_error(s, KSL_E_NOT_SUPPORTED, "ksl: this build has no ECH (OpenSSL 4 bundled only)");
    return KSL_ERROR;
#endif
}

int ksl_ech_status(ksl_ssl *s) {
#if KSL_HAS_ECH
    char *inner = NULL, *outer = NULL;
    int st = SSL_ech_get1_status(s->ssl, &inner, &outer);
    OPENSSL_free(inner);
    OPENSSL_free(outer);
    ERR_clear_error();
    if (s->owner->role == KSL_SERVER) {
        if (st == SSL_ECH_STATUS_SUCCESS)
            return KSL_ECH_ACCEPTED;
        /* an encrypted_client_hello extension this server did not decrypt (another key, or GREASE): it answered with retry_configs */
        if (st == SSL_ECH_STATUS_GREASE || st == SSL_ECH_STATUS_GREASE_ECH || st == SSL_ECH_STATUS_FAILED_ECH ||
            st == SSL_ECH_STATUS_FAILED || st == SSL_ECH_STATUS_FAILED_ECH_BAD_NAME)
            return KSL_ECH_REJECTED;
        return KSL_ECH_NONE;
    }
    if (!s->ech_set)
        return (st == SSL_ECH_STATUS_GREASE || st == SSL_ECH_STATUS_GREASE_ECH) ? KSL_ECH_GREASE : KSL_ECH_NONE;
    /* rejected: OpenSSL authenticated the outer handshake for public_name and then sent ech_required (statem_clnt.c
       tls_process_initial_server_flight), with or without retry_configs; the alert is ours, not the peer's */
    if (s->last_alert == SSL_AD_ECH_REQUIRED)
        return KSL_ECH_REJECTED;
    /* BAD_NAME: accepted, and OpenSSL's verifier refused the certificate (a separate failure of the handshake) */
    if (st == SSL_ECH_STATUS_SUCCESS || st == SSL_ECH_STATUS_BAD_NAME)
        return KSL_ECH_ACCEPTED;
    return KSL_ECH_OFFERED;
#else
    (void)s;
    return KSL_ECH_NONE;
#endif
}

/* RFC 9849 section 6.1.6: retry_configs only from a rejection whose outer handshake was authenticated for public_name (OpenSSL keeps
   them otherwise: retry_configs_ok), never after GREASE (section 6.2.1: "It MUST NOT save the retry_configs value"); checked like a
   list from DNS, so only usable ECHConfigs reach the caller. Zero bytes when there are none. */
int ksl_ech_retry_configs(ksl_ssl *s, uint8_t *out, size_t cap, size_t *len) {
    *len = 0;
#if KSL_HAS_ECH
    if (s->owner->role != KSL_CLIENT || ksl_ech_status(s) != KSL_ECH_REJECTED)
        return KSL_OK;
    unsigned char *ec = NULL;
    size_t n = 0;
    if (SSL_ech_get1_retry_config(s->ssl, &ec, &n) != 1 || ec == NULL || n == 0) {
        OPENSSL_free(ec);
        ERR_clear_error();
        return KSL_OK;
    }
    uint8_t *checked = malloc(n);
    size_t k = 0;
    uint32_t code = KSL_E_NO_MEMORY;
    int r = checked ? check_list(ec, n, checked, n, &k, &code) : KSL_ERROR;
    OPENSSL_free(ec);
    ERR_clear_error();
    if (r != KSL_OK) {
        free(checked);
        if (code == KSL_E_NO_MEMORY) {
            ksl_ssl_set_error(s, KSL_E_NO_MEMORY, "ksl: out of memory");
            return KSL_ERROR;
        }
        return KSL_OK; /* nothing usable in them: none */
    }
    *len = k;
    if (out == NULL || cap < k) {
        free(checked);
        ksl_ssl_set_error(s, KSL_E_BAD_ARG, "ksl: buffer too small");
        return KSL_ERROR;
    }
    memcpy(out, checked, k);
    free(checked);
    return KSL_OK;
#else
    (void)out;
    (void)cap;
    (void)s;
    return KSL_OK;
#endif
}

/* The name a server certificate is checked against: the session's verify name, or once a server rejected this session's ECH, the
   public_name of the ECHConfig it used (RFC 9849 section 6.1.7), which OpenSSL then makes the verify host (statem_clnt.c,
   SSL_set1_dnsname). Accepted or not yet answered, the host is still the verify name. */
const char *ksl_verify_host(ksl_ssl *s) {
#if KSL_HAS_ECH
    if (s->ech_set) {
        const char *h = X509_VERIFY_PARAM_get0_host(SSL_get0_param(s->ssl), 0);
        if (h != NULL)
            return h;
    }
#endif
    return s->verify_host;
}

int ksl_ech_ssl_init(ksl_ssl *s) {
#if KSL_HAS_ECH
    ksl_ctx *c = s->owner;
    if (c->role == KSL_CLIENT && c->ech_grease)
        SSL_set_options(s->ssl, SSL_OP_ECH_GREASE);
    if (c->role == KSL_SERVER && c->ech_lock != NULL) {
        int ok = 1;
        if (!CRYPTO_THREAD_read_lock(c->ech_lock))
            return 0;
        if (c->ech_store != NULL)
            ok = SSL_set1_echstore(s->ssl, (OSSL_ECHSTORE *)c->ech_store) == 1; /* the session's own copy */
        CRYPTO_THREAD_unlock(c->ech_lock);
        ERR_clear_error();
        return ok;
    }
#else
    (void)s;
#endif
    return 1;
}

void ksl_ech_ctx_free(ksl_ctx *c) {
#if KSL_HAS_ECH
    OSSL_ECHSTORE_free((OSSL_ECHSTORE *)c->ech_store);
    c->ech_store = NULL;
    CRYPTO_THREAD_lock_free(c->ech_lock);
    c->ech_lock = NULL;
#else
    (void)c;
#endif
}

int ksl_ctx_set_ech_keys(ksl_ctx *c, const uint8_t *keys, size_t len) {
    ERR_clear_error();
    if (c->role != KSL_SERVER) {
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: ECH keys are for servers");
        return KSL_ERROR;
    }
#if KSL_HAS_ECH
    if (keys == NULL || len == 0) {
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: no ECH keys");
        return KSL_ERROR;
    }
    /* the whole set is read into a new store first: a set that does not read changes nothing */
    OSSL_ECHSTORE *es = OSSL_ECHSTORE_new(NULL, NULL);
    size_t off = 0;
    int count = 0, retry = 0, ok = es != NULL;
    const char *why = "ksl: out of memory";
    while (ok && off < len) {
        ok = ksl_span_fits(off, 4, len);
        size_t l = ok ? ((size_t)keys[off] << 24) | ((size_t)keys[off + 1] << 16) | ((size_t)keys[off + 2] << 8) | keys[off + 3]
                      : 0;
        off += 4;
        ok = ok && l >= 2 && l - 1 <= ECH_KEY_PEM_MAX && ksl_span_fits(off, l, len) && count < ECH_KEYS_MAX &&
             (keys[off] & ~1u) == 0;
        why = "ksl: bad ECH key framing: (uint32 length || flags || PEM)*, 1 to 16 keys, flags 0 or 1";
        if (!ok)
            break;
        int for_retry = keys[off] & 1, before = 0, after = 0;
        BIO *in = BIO_new_mem_buf(keys + off + 1, (int)(l - 1));
        ok = in != NULL && OSSL_ECHSTORE_num_keys(es, &before) == 1 &&
             OSSL_ECHSTORE_read_pem(es, in, for_retry ? OSSL_ECH_FOR_RETRY : OSSL_ECH_NO_RETRY) == 1 &&
             OSSL_ECHSTORE_num_keys(es, &after) == 1 && after == before + 1;
        BIO_free(in);
        why = "ksl: an ECH key does not read: a PKCS#8 private key and an ECHCONFIG block of RFC 9849 version 0xfe0d that "
              "it opens";
        count++;
        retry |= for_retry;
        off += l;
    }
    if (ok && !retry) {
        ok = 0;
        why = "ksl: no ECH key is marked for retry_configs (RFC 9849 section 7.1: a server that rejects ECH sends them)";
    }
    if (ok && c->ech_lock == NULL && (c->ech_lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ok = 0;
        why = "ksl: out of memory";
    }
    if (!ok) {
        OSSL_ECHSTORE_free(es);
        ERR_clear_error();
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, why);
        return KSL_ERROR;
    }
    /* rotation: sessions made from now on get the new set, sessions already made keep their copy (ksl_ech_ssl_init) */
    if (!CRYPTO_THREAD_write_lock(c->ech_lock)) {
        OSSL_ECHSTORE_free(es);
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: lock failed");
        return KSL_ERROR;
    }
    OSSL_ECHSTORE *old = (OSSL_ECHSTORE *)c->ech_store;
    c->ech_store = es;
    CRYPTO_THREAD_unlock(c->ech_lock);
    OSSL_ECHSTORE_free(old);
    return KSL_OK;
#else
    (void)keys;
    (void)len;
    ksl_ctx_set_error(c, KSL_E_NOT_SUPPORTED, "ksl: this build has no ECH (OpenSSL 4 bundled only)");
    return KSL_ERROR;
#endif
}
