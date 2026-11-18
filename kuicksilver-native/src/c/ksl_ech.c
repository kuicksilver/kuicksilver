/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* TLS Encrypted Client Hello (RFC 9849; ADR-0019): a client's ECHConfigList (checked entry by entry), GREASE, the outcome and the
 * server's retry configurations; a server's ECH keys, replaced whole for rotation. OpenSSL 4 does the protocol; ksl decides what
 * reaches it and what is reported. Built only with the bundled OpenSSL 4 (KSL_HAS_ECH); a system-OpenSSL build (Linux, 3.5 to
 * 3.x) answers KSL_E_NOT_SUPPORTED. */
#include "ksl_internal.h"
#include <limits.h>
#include <stdio.h>
#if KSL_HAS_ECH
#include <openssl/ech.h>
#include <openssl/pem.h>
#endif

#define ECH_VERSION 0xfe0d       /* RFC 9849 section 4: the version of the ECHConfig this document defines */
#define ECH_LIST_MAX 65537       /* an ECHConfigList: a 2-byte length and at most 65535 bytes (RFC 9849 section 4) */
#define ECH_KEYS_MAX 16          /* ECH keys a server context holds at once (rotation keeps a few) */
#define ECH_KEY_PEM_MAX (16384u) /* one key's PEM: a PKCS#8 private key and its ECHCONFIG block */
#if KSL_HAS_ECH
/* a server's keys: immutable once made, shared by reference between contexts (ksl_ctx_set_ech_keys) */
struct ksl_ech_keys {
    int refs; /* atomic */
    OSSL_ECHSTORE *es;
};
#endif

#define ECH_GREASE(v) (((v) & 0x0f0f) == 0x0a0a)
/* The syntax of an ECHConfigList (RFC 9849 section 4): its length exact, every ECHConfig framed inside it, and the contents of each
   ECHConfig of version 0xfe0d well formed to their last byte: config_id, kem_id, public_key<1..2^16-1>, cipher_suites<4..2^16-4> of
   4-byte pairs, maximum_name_length, public_name<1..255>, extensions<0..2^16-1> each framed, no trailing byte, and no extension type
   twice (section 4.2: "there MUST NOT be more than one extension of the same type"). The contents of another version are opaque
   (section 4: ignored). 1 when it holds. What the server sends in retry_configs MUST pass this (section 6.1.6, 6.2.1: decode_error). */
static int list_syntax_ok(const uint8_t *list, size_t len) {
    if (list == NULL || len < 2 || len > ECH_LIST_MAX || (((size_t)list[0] << 8) | list[1]) != len - 2)
        return 0;
    size_t off = 2;
    while (off < len) {
        if (!ksl_span_fits(off, 4, len))
            return 0;
        size_t version = ((size_t)list[off] << 8) | list[off + 1], n = ((size_t)list[off + 2] << 8) | list[off + 3];
        off += 4;
        if (!ksl_span_fits(off, n, len))
            return 0;
        if (version == ECH_VERSION) {
            const uint8_t *c = list + off;
            size_t p = 3; /* config_id, kem_id */
            if (n < p + 2)
                return 0;
            size_t pk = ((size_t)c[p] << 8) | c[p + 1];
            p += 2;
            if (pk == 0 || !ksl_span_fits(p, pk, n))
                return 0;
            p += pk;
            if (!ksl_span_fits(p, 2, n))
                return 0;
            size_t cs = ((size_t)c[p] << 8) | c[p + 1];
            p += 2;
            if (cs < 4 || cs % 4 != 0 || !ksl_span_fits(p, cs, n))
                return 0;
            p += cs;
            if (!ksl_span_fits(p, 2, n)) /* maximum_name_length, public_name length */
                return 0;
            size_t pn = c[p + 1];
            p += 2;
            if (pn == 0 || !ksl_span_fits(p, pn, n))
                return 0;
            p += pn;
            if (!ksl_span_fits(p, 2, n))
                return 0;
            size_t el = ((size_t)c[p] << 8) | c[p + 1];
            p += 2;
            if (p + el != n) /* the extensions end the contents: a trailing byte is no ECHConfig */
                return 0;
            for (size_t e = p; e < n;) {
                if (!ksl_span_fits(e, 4, n))
                    return 0;
                unsigned t = ((unsigned)c[e] << 8) | c[e + 1];
                size_t l = ((size_t)c[e + 2] << 8) | c[e + 3];
                if (!ksl_span_fits(e + 4, l, n))
                    return 0;
                for (size_t f = p; f < e;) { /* types before this one: quadratic, bounded by the 64 KiB list */
                    if ((((unsigned)c[f] << 8) | c[f + 1]) == t)
                        return 0;
                    f += 4 + (((size_t)c[f + 2] << 8) | c[f + 3]);
                }
                e += 4 + l;
            }
        }
        off += n;
    }
    return 1;
}

/* The checked list into out: the ECHConfigs of `list` this OpenSSL can use, in their order. RFC 9849 section 4 has the client ignore an
   ECHConfig of another version, one with an unsupported mandatory extension (section 4.2), one without a KEM and cipher suite it
   supports, and one whose public_name is not a valid DNS name or could be read as an IPv4 address (section 6.1.7). OpenSSL checks all of
   that per ECHConfig (ech_store.c ech_final_config_checks), but refuses the whole list for one bad entry, where the RFC ignores that
   entry alone: so each entry goes to OpenSSL on its own, as a list of one, and only those it takes are kept. Bounds: the list's own
   length must match `len` exactly, every entry must fit, and an entry OpenSSL would not read (longer than OSSL_ECH_MAX_ECHCONFIG_LEN)
   is dropped. The whole list must pass list_syntax_ok first (a malformed ECHConfig of version 0xfe0d, or an extension type twice,
   is a list that does not parse). KSL_OK with at least one entry kept; else KSL_ERROR with *code KSL_E_NOT_SUPPORTED (no entry usable, or no ECH in
   this build) or KSL_E_BAD_ARG (the framing does not parse, *out_len 0; or the result does not fit `cap`, *out_len the size it
   needs). */
static int check_list(const uint8_t *list, size_t len, uint8_t *out, size_t cap, size_t *out_len, uint32_t *code) {
    *out_len = 0;
    *code = KSL_E_BAD_ARG;
    if (!list_syntax_ok(list, len))
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
        ksl_ssl_set_error(
            s, KSL_E_NOT_SUPPORTED,
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
                          code == KSL_E_NOT_SUPPORTED
                              ? "ksl: no ECHConfig of the list is usable (version, suite, mandatory "
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

#if KSL_HAS_ECH
/* What OpenSSL holds of the server's retry_configs (EncryptedExtensions): 0 none, 1 present in *raw (OPENSSL_free), -1 present and
   malformed. SSL_ech_get1_retry_config answers once the outer handshake is authenticated (RFC 9849 section 6.1.6; OpenSSL:
   retry_configs_ok) or the handshake is complete (an accepted ECH, GREASE); with the carried patch of ADR-0019 (M1) it checks only
   the list's framing and hands the bytes over as the server sent them, so one ECHConfig OpenSSL cannot use no longer takes the
   others with it, and a failure means bytes that do not frame (or no memory: the handshake fails either way). ksl then checks the
   syntax itself (list_syntax_ok). */
static int retry_raw(ksl_ssl *s, unsigned char **raw, size_t *n) {
    *raw = NULL;
    *n = 0;
    int r;
#ifdef KSL_TEST
    if (s->test_ech_retry_set) {
        if (s->test_ech_retry_set == 2)
            return -1;
        if (s->test_ech_retry == NULL)
            return 0;
        *raw = OPENSSL_memdup(s->test_ech_retry, s->test_ech_retry_len);
        *n = s->test_ech_retry_len;
        return *raw ? (list_syntax_ok(*raw, *n) ? 1 : -1) : -1;
    }
#endif
    r = SSL_ech_get1_retry_config(s->ssl, raw, n);
    ERR_clear_error();
    if (r != 1) {
        OPENSSL_free(*raw);
        *raw = NULL;
        *n = 0;
        return -1;
    }
    if (*raw == NULL || *n == 0) {
        OPENSSL_free(*raw);
        *raw = NULL;
        *n = 0;
        return 0;
    }
    return list_syntax_ok(*raw, *n) ? 1 : -1;
}
static int retry_state(ksl_ssl *s) {
    unsigned char *raw;
    size_t n;
    int r = retry_raw(s, &raw, &n);
    OPENSSL_free(raw);
    return r;
}
static int session_reused(ksl_ssl *s) {
#ifdef KSL_TEST
    if (s->test_ech_reused)
        return 1;
#endif
    return SSL_session_reused(s->ssl) == 1;
}
#endif

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
       tls_process_initial_server_flight), with or without retry_configs; the alert is ours (info_cb), not the peer's. Not a
       rejection the caller may act on (no retry configurations, never "securely disabled"; the handshake failed, ksl_ech_check_failed
       says why) when the server resumed a session in the outer handshake (section 6.1.2: illegal_parameter), or when its
       retry_configs are malformed (section 6.1.6: decode_error) */
    if (s->ech_required_sent)
        return session_reused(s) || retry_state(s) < 0 ? KSL_ECH_OFFERED : KSL_ECH_REJECTED;
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
   list from DNS, entry by entry, so only usable ECHConfigs reach the caller. Zero bytes when there are none. */
int ksl_ech_retry_configs(ksl_ssl *s, uint8_t *out, size_t cap, size_t *len) {
    *len = 0;
#if KSL_HAS_ECH
    if (s->owner->role != KSL_CLIENT || ksl_ech_status(s) != KSL_ECH_REJECTED)
        return KSL_OK;
    unsigned char *ec = NULL;
    size_t n = 0;
    if (retry_raw(s, &ec, &n) != 1) {
        OPENSSL_free(ec);
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
        return KSL_ERROR; /* *len says the size; the session's error (the handshake's) stays as it is, as copy_out leaves it */
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

/* A client handshake that completed (ksl_drive). RFC 9849 section 5: an encrypted_client_hello extension in EncryptedExtensions
   answers only the outer ClientHello; "If the server sent this extension in response to the inner variant, then the client MUST
   abort with an unsupported_extension alert". Section 6.2.1: after GREASE "the client MUST check the extension syntactically and
   abort the connection with a decode_error alert if it is invalid". The fifth carried patch of ADR-0019 has OpenSSL abort at the
   EncryptedExtensions with those alerts, over TCP and QUIC; this is the second line, for an OpenSSL without it: the session
   fails before it is reported established, over QUIC with that alert (the CONNECTION_CLOSE takes it from last_alert), over TCP
   without one (the client's Finished is written, and OpenSSL 4.1 has no call to send an alert afterwards). */
int ksl_ech_check_done(ksl_ssl *s) {
#if KSL_HAS_ECH
    if (s->owner->role != KSL_CLIENT)
        return KSL_OK;
    int st = s->ech_set ? ksl_ech_status(s) : KSL_ECH_NONE, rs = retry_state(s);
    if (s->ech_set && st == KSL_ECH_ACCEPTED && rs != 0) {
        s->last_alert = s->mode == KSL_MODE_QUIC ? SSL_AD_UNSUPPORTED_EXTENSION : 0;
        return ksl_ssl_fail(
            s, KSL_E_NOT_SUPPORTED,
            "ksl: the server accepted ECH and sent retry_configs (RFC 9849 section 5: unsupported_extension)");
    }
    if (!s->ech_set && rs < 0) {
        s->last_alert = s->mode == KSL_MODE_QUIC ? SSL_AD_DECODE_ERROR : 0;
        return ksl_ssl_fail(
            s, KSL_E_NOT_SUPPORTED,
            "ksl: the server's retry_configs to a GREASE ECH do not parse (RFC 9849 section 6.2.1: decode_error)");
    }
#else
    (void)s;
#endif
    return KSL_OK;
}

/* A client handshake that failed (ksl_drive): after our ech_required, the ECH errors RFC 9849 has the client report instead of a
   rejection. The fifth and sixth carried patches of ADR-0019 have OpenSSL abort before ech_required with the alert the section names
   (over TCP and QUIC), and this never runs then; it is the second line, for an OpenSSL without them: over QUIC the alert is the one
   the section names (the CONNECTION_CLOSE takes it from last_alert), over TCP OpenSSL wrote ech_required already, and the message
   names the error. */
void ksl_ech_check_failed(ksl_ssl *s) {
#if KSL_HAS_ECH
    if (s->owner->role != KSL_CLIENT || !s->ech_set || !s->ech_required_sent)
        return;
    const char *why = NULL;
    int alert = 0;
    if (session_reused(s)) {
        why = "ksl: ECH rejected, and the server resumed a session in the outer handshake (RFC 9849 section 6.1.2: "
              "illegal_parameter)";
        alert = SSL_AD_ILLEGAL_PARAMETER;
    } else if (retry_state(s) < 0) {
        why = "ksl: ECH rejected with retry_configs that do not parse (RFC 9849 section 6.1.6: decode_error)";
        alert = SSL_AD_DECODE_ERROR;
    }
    if (why == NULL)
        return;
    if (s->mode == KSL_MODE_QUIC)
        s->last_alert = alert;
    ksl_ssl_fail(s, KSL_E_NOT_SUPPORTED, why);
#else
    (void)s;
#endif
}

/* RFC 9849 section 7.1: the client-facing server "checks that [the ClientHelloInner] includes a well-formed encrypted_client_hello
   extension of type inner and that it does not offer TLS 1.2 or below. If either of these checks fails, the client-facing server
   MUST abort with an illegal_parameter alert." OpenSSL 4.1 checks the first (ech_internal.c) and not the second; the ClientHello
   callback sees the inner ClientHello of an accepted ECH (statem_srvr.c decrypts it before), so the check is ksl's: a
   supported_versions with a version below TLS 1.3 other than a GREASE value, or none at all (TLS 1.2 and below only). 1 when it
   holds or no ECH was accepted. */
int ksl_ech_inner_versions_ok(SSL *ssl) {
#if KSL_HAS_ECH
    char *inner = NULL, *outer = NULL;
    int st = SSL_ech_get1_status(ssl, &inner, &outer);
    OPENSSL_free(inner);
    OPENSSL_free(outer);
    ERR_clear_error();
    if (st != SSL_ECH_STATUS_SUCCESS)
        return 1;
    const unsigned char *v;
    size_t vl;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_versions, &v, &vl) != 1 || vl < 1 || v[0] + 1u != vl ||
        v[0] % 2 != 0)
        return 0;
    for (size_t i = 1; i + 1 < vl; i += 2) {
        unsigned ver = ((unsigned)v[i] << 8) | v[i + 1];
        if (ver <= TLS1_2_VERSION && !ECH_GREASE(ver))
            return 0;
    }
#else
    (void)ssl;
#endif
    return 1;
}

/* RFC 9849 section 6.2.1: a GREASE ECH extension sets "the cipher_suite field to a supported HpkeSymmetricCipherSuite. The
   selection SHOULD vary, so that all plausible configurations are exercised"; OpenSSL 4.1.0 sends its default suite
   (HKDF-SHA256, AES-128-GCM) every time, a fixed mark among clients that vary it. Each GREASE handshake takes one of the suites a
   Kuicksilver client uses with a real ECHConfig (HKDF-SHA256 with AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305; X25519, the KEM
   of RFC 9849's mandatory suite), at random. Set when the handshake starts, not at ksl_ssl_new: SSL_ech_set1_grease_suite marks
   the session as GREASE, and a list given after ksl_ssl_new (KSL_SET_ECH_CONFIG_LIST) must not run under that mark. */
void ksl_ech_before_handshake(ksl_ssl *s) {
#if KSL_HAS_ECH
    if (s->owner->role != KSL_CLIENT || !s->owner->ech_grease || s->ech_set || s->ech_grease_ready ||
        !SSL_in_before(s->ssl))
        return;
    static const char *const suites[] = {"x25519,hkdf-sha256,aes-128-gcm", "x25519,hkdf-sha256,aes-256-gcm",
                                         "x25519,hkdf-sha256,chacha20-poly1305"};
    uint8_t r = 0;
    for (int i = 0; i < 8 && ksl_rand(&r, 1) == KSL_OK && r >= 255; i++)
        ; /* 255 is not a multiple of 3: redrawn, so the three are equally likely; on failure the first suite */
    if (r >= 255)
        r = 0;
    s->ech_grease_ready = 1;
    (void)SSL_ech_set1_grease_suite(s->ssl, suites[r % 3]); /* on failure OpenSSL's default suite */
    ERR_clear_error();
#else
    (void)s;
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
    /* the lock is made with the context (ksl_ctx_new) and never changes: reading the pointer needs no lock */
    if (c->role == KSL_SERVER && c->ech_lock != NULL) {
        int ok = 1;
        if (!CRYPTO_THREAD_read_lock(c->ech_lock))
            return 0;
        if (c->ech_keys != NULL)
            ok = SSL_set1_echstore(s->ssl, c->ech_keys->es) == 1; /* the session's own copy */
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
    ksl_ech_keys_free(c->ech_keys);
    c->ech_keys = NULL;
    CRYPTO_THREAD_lock_free(c->ech_lock);
    c->ech_lock = NULL;
#else
    (void)c;
#endif
}

static void ech_msg(char *msg, size_t msglen, const char *m) {
    if (msg && msglen)
        snprintf(msg, msglen, "%s", m);
}
#if KSL_HAS_ECH
/* The config_id of the ECHConfig in one key's PEM (its ECHCONFIG block: an ECHConfigList of one entry), -1 when there is none */
static int pem_config_id(const uint8_t *pem, size_t len) {
    BIO *in = BIO_new_mem_buf(pem, (int)len);
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long dl = 0;
    int id = -1;
    while (id < 0 && in != NULL && PEM_read_bio(in, &name, &header, &data, &dl) == 1) {
        if (strcmp(name, "ECHCONFIG") == 0 && dl >= 7)
            id = data[6]; /* list length 2, version 2, length 2, then config_id */
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }
    BIO_free(in);
    ERR_clear_error();
    return id;
}
#endif
/* Keys are loaded from their PEM only (OSSL_ECHSTORE_read_pem), never handed over as a store OSSL_ECHSTORE_new_config made:
   OpenSSL 4.1 builds the HPKE info of such a store from other bytes than the same key read back from PEM or published in
   DNS, so a server using it directly would decrypt no client that took the configuration from its HTTPS record (bug L of
   ADR-0019). C test ech_accept pins the PEM path. A set whose keys share a config_id is refused: OpenSSL 4.1's server tries
   only the first key of a config_id and does not go on to the next when it does not decrypt (RFC 9849 section 7.1 has it go
   on), so a client of the second key would be rejected; section 4.1 has a server allocate distinct ones. */
ksl_ech_keys *ksl_ech_keys_new(const uint8_t *keys, size_t len, char *msg, size_t msglen) {
    ERR_clear_error();
#if KSL_HAS_ECH
    if (keys == NULL || len == 0) {
        ech_msg(msg, msglen, "ksl: no ECH keys");
        return NULL;
    }
    OSSL_ECHSTORE *es = OSSL_ECHSTORE_new(NULL, NULL);
    size_t off = 0;
    int count = 0, retry = 0, ok = es != NULL, ids[ECH_KEYS_MAX];
    const char *why = "ksl: out of memory";
    while (ok && off < len) {
        ok = ksl_span_fits(off, 4, len);
        size_t l = ok ? ((size_t)keys[off] << 24) | ((size_t)keys[off + 1] << 16) | ((size_t)keys[off + 2] << 8) |
                            keys[off + 3]
                      : 0;
        off += 4;
        ok = ok && l >= 2 && l - 1 <= ECH_KEY_PEM_MAX && ksl_span_fits(off, l, len) && count < ECH_KEYS_MAX &&
             (keys[off] & ~1u) == 0;
        why = "ksl: bad ECH key framing: (uint32 length || flags || PEM)*, 1 to 16 keys, flags 0 or 1";
        if (!ok)
            break;
        int for_retry = keys[off] & 1, before = 0, after = 0, id = pem_config_id(keys + off + 1, l - 1);
        for (int i = 0; ok && id >= 0 && i < count; i++)
            ok = ids[i] != id;
        why =
            "ksl: two ECH keys share a config_id (RFC 9849 section 4.1: distinct ones; OpenSSL tries only the first): make "
            "one of them again";
        if (!ok)
            break;
        ids[count] = id;
        BIO *in = BIO_new_mem_buf(keys + off + 1, (int)(l - 1));
        ok = in != NULL && OSSL_ECHSTORE_num_keys(es, &before) == 1 &&
             OSSL_ECHSTORE_read_pem(es, in, for_retry ? OSSL_ECH_FOR_RETRY : OSSL_ECH_NO_RETRY) == 1 &&
             OSSL_ECHSTORE_num_keys(es, &after) == 1 && after == before + 1;
        BIO_free(in);
        why =
            "ksl: an ECH key does not read: a PKCS#8 private key and an ECHCONFIG block of RFC 9849 version 0xfe0d that "
            "it opens";
        count++;
        retry |= for_retry;
        off += l;
    }
    if (ok && !retry) {
        ok = 0;
        why =
            "ksl: no ECH key is marked for retry_configs (RFC 9849 section 7.1: a server that rejects ECH sends them)";
    }
    ksl_ech_keys *k = ok ? calloc(1, sizeof *k) : NULL;
    ERR_clear_error();
    if (k == NULL) {
        OSSL_ECHSTORE_free(es);
        ech_msg(msg, msglen, ok ? "ksl: out of memory" : why);
        return NULL;
    }
    k->refs = 1;
    k->es = es;
    return k;
#else
    (void)keys;
    (void)len;
    ech_msg(msg, msglen, "ksl: this build has no ECH (OpenSSL 4 bundled only)");
    return NULL;
#endif
}
void ksl_ech_keys_free(ksl_ech_keys *k) {
#if KSL_HAS_ECH
    if (k == NULL || __atomic_sub_fetch(&k->refs, 1, __ATOMIC_ACQ_REL) != 0)
        return;
    OSSL_ECHSTORE_free(k->es);
    free(k);
#else
    (void)k;
#endif
}
int ksl_ctx_set_ech_keys(ksl_ctx *c, ksl_ech_keys *keys) {
    ERR_clear_error();
    if (c->role != KSL_SERVER) {
        ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: ECH keys are for servers");
        return KSL_ERROR;
    }
#if KSL_HAS_ECH
    if (c->ech_lock == NULL) { /* made by ksl_ctx_new, which ran out of memory */
        ksl_ctx_set_error(c, KSL_E_NO_MEMORY, "ksl: out of memory (no ECH key lock)");
        return KSL_ERROR;
    }
    if (keys)
        __atomic_add_fetch(&keys->refs, 1, __ATOMIC_RELAXED);
    /* rotation: sessions made from now on get the new set, sessions already made keep their copy (ksl_ech_ssl_init) */
    if (!CRYPTO_THREAD_write_lock(c->ech_lock)) {
        ksl_ech_keys_free(keys);
        ksl_ctx_set_error(c, KSL_E_NO_MEMORY, "ksl: the ECH key lock is unavailable (a system resource)");
        return KSL_ERROR;
    }
    ksl_ech_keys *old = c->ech_keys;
    c->ech_keys = keys;
    CRYPTO_THREAD_unlock(c->ech_lock);
    ksl_ech_keys_free(old);
    return KSL_OK;
#else
    (void)keys;
    ksl_ctx_set_error(c, KSL_E_NOT_SUPPORTED, "ksl: this build has no ECH (OpenSSL 4 bundled only)");
    return KSL_ERROR;
#endif
}
