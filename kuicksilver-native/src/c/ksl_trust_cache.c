/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* The system CA store (TrustConfig.Platform through OpenSSL, Linux Native), parsed once per process and shared by every client
 * context (security review 2026-10-14, finding 12): loading the bundle cost milliseconds per connection, ten times a QUIC
 * handshake (tools/bench/ksl-ctx-bench.sh, threat model 3.2). The cached store is reloaded when SSL_CERT_FILE / SSL_CERT_DIR
 * or any searched file or directory changes (path, size, mtime, inode), so a CA bundle update reaches new connections. A
 * shared store is never modified: ksl_ctx_private_store gives a context its own store before roots are added to it. */
#include "ksl_internal.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <sys/stat.h>

static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *lock;
static int lock_ok;
static X509_STORE *cached;           /* one reference held here */
static char cached_sig[4096];

static void init_lock(void) { lock = CRYPTO_THREAD_lock_new(); lock_ok = lock != NULL; }

static void add_path(char *sig, size_t cap, const char *path) {
    struct stat sb; size_t n = strlen(sig); if (n >= cap) return;
    if (path && stat(path, &sb) == 0)
        snprintf(sig + n, cap - n, "%s|%lld|%lld|%llu|%llu;", path, (long long)sb.st_size, (long long)sb.st_mtime, (unsigned long long)sb.st_ino, (unsigned long long)sb.st_dev);
    else snprintf(sig + n, cap - n, "%s|-;", path ? path : "");
}
/* What the store would be loaded from now: the variables and every searched path with its file identity. */
static void signature(char *sig, size_t cap) {
    const char *ef = getenv("SSL_CERT_FILE"), *ed = getenv("SSL_CERT_DIR");
    const char *const *files, *const *dirs; ksl_trust_paths(&files, &dirs);
    sig[0] = 0; add_path(sig, cap, ef && *ef ? ef : NULL); add_path(sig, cap, ed && *ed ? ed : NULL);
    for (int i = 0; files[i]; i++) add_path(sig, cap, files[i]);
    for (int i = 0; dirs[i]; i++) add_path(sig, cap, dirs[i]);
}

int ksl_ctx_use_system_store(ksl_ctx *c) {
    if (!CRYPTO_THREAD_run_once(&once, init_lock) || !lock_ok) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: trust cache lock unavailable"); return KSL_ERROR; }
    char sig[sizeof cached_sig]; signature(sig, sizeof sig);
    if (!CRYPTO_THREAD_write_lock(lock)) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: trust cache lock unavailable"); return KSL_ERROR; }
    int rc = KSL_OK;
    if (!cached || strcmp(sig, cached_sig) != 0) {
        X509_STORE *fresh = X509_STORE_new();
        if (!fresh) rc = KSL_ERROR;
        else if ((rc = ksl_load_system_roots(c, fresh)) != KSL_OK) X509_STORE_free(fresh);   /* the error names the paths; nothing cached */
        else { X509_STORE_free(cached); cached = fresh; memcpy(cached_sig, sig, sizeof sig); }
    }
    if (rc == KSL_OK) { SSL_CTX_set1_cert_store(c->ctx, cached); c->shared_roots = 1; }   /* the context takes its own reference */
    CRYPTO_THREAD_unlock(lock);
    return rc;
}

X509_STORE *ksl_ctx_private_store(ksl_ctx *c) {
    if (c->shared_roots) {
        X509_STORE *own = X509_STORE_new(); if (!own) return NULL;
        SSL_CTX_set_cert_store(c->ctx, own); c->shared_roots = 0;   /* drops the context's reference to the shared one */
    }
    return SSL_CTX_get_cert_store(c->ctx);
}

#ifdef KSL_TEST
X509_STORE *ksl_system_store_for_test(void) { return cached; }
#endif
