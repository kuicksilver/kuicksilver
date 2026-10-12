/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Library lifecycle and the error model: errors are copied into the owning object inside the same call. */
#include "ksl_internal.h"
#include <stdio.h>

#define KSL_VERSION_STRING "ksl 0.1.0"

#ifdef KSL_SYSTEM_OPENSSL
#include <dlfcn.h>
/* System libssl (Linux only): version floor 3.5, the QUIC TLS API must exist, and a keylog environment is refused outright
 * because a distribution libssl may have been built with enable-sslkeylog, and key logging goes only through the explicit KeylogSink. */
static int check_system_openssl(void) {
    if (OPENSSL_version_major() != 3 || OpenSSL_version_num() < 0x30500000UL) return KSL_INIT_VERSION;
    if (!dlsym(RTLD_DEFAULT, "SSL_set_quic_tls_cbs")) return KSL_INIT_MISSING_SYMBOL;
    const char *k = getenv("SSLKEYLOGFILE"); if (k && *k) return KSL_INIT_KEYLOG_ENV;
    return KSL_OK;
}
#endif
#ifdef _WIN32
int ksl_win_sockets_init(void);   /* ksl_udp_win.c: WSAStartup once */
#endif
int ksl_init(void) {
#ifdef _WIN32
    ksl_win_sockets_init();   /* address lookups (getaddrinfo) need Winsock before any socket exists */
#endif
#ifdef KSL_SYSTEM_OPENSSL
    int rc = check_system_openssl(); if (rc != KSL_OK) return rc;
#endif
    return OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG | OPENSSL_INIT_NO_ATEXIT, NULL) ? KSL_OK : KSL_ERROR;
}
const char *ksl_version(void) {
    static char buf[128];
    snprintf(buf, sizeof buf, "%s / %s", KSL_VERSION_STRING, OpenSSL_version(OPENSSL_VERSION));
    return buf;
}
uint32_t ksl_abi_version(void) { return KSL_ABI_VERSION; }

uint32_t ksl_pack_openssl_error(unsigned long e) {
    return ((uint32_t)ERR_GET_LIB(e) << 16) | (uint32_t)(ERR_GET_REASON(e) & 0xffff);
}
static void capture(uint32_t *code, char *msg, uint32_t fallback, const char *text) {
    unsigned long e = ERR_peek_last_error();
    if (e) { *code = ksl_pack_openssl_error(e); ERR_error_string_n(e, msg, KSL_MSG); }
    else { *code = fallback; snprintf(msg, KSL_MSG, "%s", text ? text : "ksl error"); }
    ERR_clear_error();
}
void ksl_ctx_set_error(ksl_ctx *c, uint32_t fallback, const char *msg) { capture(&c->last_err, c->last_msg, fallback, msg); }
void ksl_ssl_set_error(ksl_ssl *s, uint32_t fallback, const char *msg) {
    capture(&s->last_err, s->last_msg, fallback, msg);
}
int ksl_ssl_fail(ksl_ssl *s, uint32_t code, const char *msg) {
    s->fatal = 1; ERR_clear_error(); s->last_err = code; snprintf(s->last_msg, KSL_MSG, "%s", msg); return KSL_ERROR;
}
int ksl_ctx_last_error(ksl_ctx *c, uint32_t *packed, char *buf, size_t len) {
    if (packed) *packed = c->last_err; if (buf && len) snprintf(buf, len, "%s", c->last_msg); return KSL_OK;
}
int ksl_ssl_last_error(ksl_ssl *s, uint32_t *packed, int *alert, char *buf, size_t len) {
    if (packed) *packed = s->last_err; if (alert) *alert = (s->last_alert & 0x1ff) | ((s->verify_err & 0x7fff) << 16); if (buf && len) snprintf(buf, len, "%s", s->last_msg); return KSL_OK;
}
