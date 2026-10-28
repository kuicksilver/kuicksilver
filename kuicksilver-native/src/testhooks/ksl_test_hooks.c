/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Test hooks for the Kotlin tests, built into a library of their own by tools/build-test-hooks.sh with KSL_TEST_HOOKS, never into
   libksl: the release libraries carry none of them. They write a field of a session the release libksl created, so this file is
   compiled from the same ksl_internal.h without KSL_TEST (which adds fields to struct ksl_ssl), as libksl is. */
#ifndef KSL_TEST_HOOKS
#error "ksl_test_hooks.c is built only by tools/build-test-hooks.sh"
#endif
#ifdef KSL_TEST
#error "KSL_TEST changes struct ksl_ssl: the hooks must see the release layout"
#endif
#include "ksl_internal.h"
#include "ksl_test_hooks.h"

__attribute__((visibility("default"))) void ksl_test_hooks_set_record_limit(void *ssl, uint64_t records) { ((ksl_ssl *)ssl)->record_limit = records; }

#ifdef KSL_TEST_HOOKS_JNI
#include <jni.h>
/* io.kuicksilver.tls.KslTestHooks.setRecordLimit (kuicksilver-tls jvmTest) */
JNIEXPORT void JNICALL Java_io_kuicksilver_tls_KslTestHooks_setRecordLimit(JNIEnv *e, jclass c, jlong ssl, jlong records) {
    (void)e; (void)c; ksl_test_hooks_set_record_limit((void *)(intptr_t)ssl, (uint64_t)records);
}
#endif
