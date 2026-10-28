/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Test hooks for the Kotlin tests (tools/build-test-hooks.sh): a library of their own, linked or loaded by test code only, never part
   of libksl or of anything published. */
#ifndef KSL_TEST_HOOKS_H
#define KSL_TEST_HOOKS_H
#include <stdint.h>
/* The records the session's current sending keys may protect, as the C tests' ksl_tcp_set_record_limit_for_test: ksl_tcp_write ends
   the session one record before it (RFC 9846 section 5.5). ssl is a ksl_ssl handle. */
void ksl_test_hooks_set_record_limit(void *ssl, uint64_t records);
#endif
