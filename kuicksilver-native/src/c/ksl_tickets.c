/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Session ticket keys (RFC 9846 section 4.7.1) that never leave native memory (threat model 1, 3.7):
 *  - the process-wide generated keys: a current key that encrypts and the previous one that still decrypts, rotated here;
 *  - explicit keys a deployment shares between processes: copied in once, registered under an id, never handed back.
 * A context takes a copy of the keys it needs (ksl_ctx_set_ticket_keys), which ksl_ctx_free cleanses. Every temporary is
 * cleansed before it goes out of scope. */
#include "ksl_internal.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <time.h>

#define KEY 80                       /* name 16 | AES-256 32 | HMAC-SHA256 32 */
#define MAX_SETS 1024                /* distinct explicit key sets per process: each SessionTicketConfig with new keys adds one */
#define MAX_KEYS_PER_SET 64

static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *lock;
static int lock_ok;

/* generated keys */
static uint8_t gen[2 * KEY];          /* current, previous */
static int gen_count;                 /* 0 before first use, 1 before the first rotation, then 2 */
static int64_t gen_rotated_at;

/* explicit keys: id = index + 1 */
typedef struct { uint8_t *keys; size_t n; } key_set;
static key_set sets[MAX_SETS];
static int set_count;

static int64_t wall_seconds(void) { return (int64_t)time(NULL); }
int64_t (*ksl_ticket_clock)(void) = wall_seconds;   /* the C tests move time; nothing else writes it */

static void init_lock(void) { lock = CRYPTO_THREAD_lock_new(); lock_ok = lock != NULL; }
static int locked(void) { return CRYPTO_THREAD_run_once(&once, init_lock) && lock_ok && CRYPTO_THREAD_write_lock(lock); }

int ksl_ctx_use_default_ticket_keys(ksl_ctx *c, uint32_t rotate_seconds) {
    if (c->frozen) { ksl_ctx_set_error(c, KSL_E_CTX_FROZEN, "ksl: context is frozen"); return KSL_ERROR; }
    if (rotate_seconds == 0) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: rotation period must be positive"); return KSL_ERROR; }
    if (!locked()) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: ticket key lock unavailable"); return KSL_ERROR; }
    /* Wall clock, as OpenSSL's ticket ages: a step forward rotates early (the previous key still decrypts), a step back by more
       than a period rotates too, so a clock reset cannot freeze the current key. Servers that start together see one snapshot:
       rotation happens under the lock. */
    int64_t now = ksl_ticket_clock();
    int ok = 1;
    if (gen_count == 0 || now - gen_rotated_at >= (int64_t)rotate_seconds || now < gen_rotated_at - (int64_t)rotate_seconds) {
        uint8_t fresh[KEY];
        if (RAND_priv_bytes(fresh, KEY) != 1) ok = 0;
        else {
            if (gen_count > 0) { memcpy(gen + KEY, gen, KEY); gen_count = 2; } else gen_count = 1;
            memcpy(gen, fresh, KEY); gen_rotated_at = now;
        }
        OPENSSL_cleanse(fresh, sizeof fresh);
    }
    uint8_t snap[2 * KEY]; int n = gen_count; memcpy(snap, gen, (size_t)n * KEY);
    CRYPTO_THREAD_unlock(lock);
    int rc = ok ? ksl_ctx_set_ticket_keys(c, snap, (size_t)n) : KSL_ERROR;
    if (!ok) ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: no randomness for ticket keys");
    OPENSSL_cleanse(snap, sizeof snap);
    return rc;
}

int ksl_ticket_keys_register(const uint8_t *keys, size_t n) {
    if (!keys || n == 0 || n > MAX_KEYS_PER_SET) return KSL_ERROR;
    if (!locked()) return KSL_ERROR;
    int id = KSL_ERROR;
    for (int i = 0; i < set_count; i++)
        if (sets[i].n == n && CRYPTO_memcmp(sets[i].keys, keys, n * KEY) == 0) { id = i + 1; break; }   /* the same keys: one entry */
    if (id == KSL_ERROR && set_count < MAX_SETS) {
        uint8_t *copy = malloc(n * KEY);
        if (copy) { memcpy(copy, keys, n * KEY); sets[set_count].keys = copy; sets[set_count].n = n; id = ++set_count; }
    }
    CRYPTO_THREAD_unlock(lock);
    return id;
}

int ksl_ctx_use_ticket_keys(ksl_ctx *c, int id) {
    if (c->frozen) { ksl_ctx_set_error(c, KSL_E_CTX_FROZEN, "ksl: context is frozen"); return KSL_ERROR; }
    if (!locked()) { ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: ticket key lock unavailable"); return KSL_ERROR; }
    int rc;
    if (id < 1 || id > set_count) { CRYPTO_THREAD_unlock(lock); ksl_ctx_set_error(c, KSL_E_BAD_ARG, "ksl: unknown ticket key set"); return KSL_ERROR; }
    rc = ksl_ctx_set_ticket_keys(c, sets[id - 1].keys, sets[id - 1].n);   /* copies; the context cleanses its copy when freed */
    CRYPTO_THREAD_unlock(lock);
    return rc;
}
