/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* FNV-1a 64 (Fowler, Noll, Vo; draft-eastlake-fnv): the name of a ksl.parsers corpus input or artifact is this hash of its
   bytes in 16 lowercase hex digits. Offset basis 14695981039346656037 (0xcbf29ce484222325), prime 1099511628211
   (0x100000001b3). Reference values: "" -> cbf29ce484222325, "a" -> af63dc4c8601ec8c, "abc" -> e71fa2190541574b
   (corpus-names.c checks them before it checks a name). */
#ifndef KSL_FUZZ_FNV_H
#define KSL_FUZZ_FNV_H
#include <stddef.h>
#include <stdint.h>

#define KSL_FNV1A64_BASIS 14695981039346656037ull
#define KSL_FNV1A64_PRIME 1099511628211ull

static inline uint64_t ksl_fnv1a64(const uint8_t *d, size_t n) {
    uint64_t h = KSL_FNV1A64_BASIS;
    for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= KSL_FNV1A64_PRIME; }
    return h;
}
#endif
