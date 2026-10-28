// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertNotNull

/** The JVM's native test hooks: libksl_test_hooks next to the release libksl, built by tools/build-test-hooks.sh for this test only. */
internal object KslTestHooks {
    val path: String? = System.getProperty("ksl.testhooks.lib")?.takeIf { java.io.File(it).isFile }

    init {
        path?.let { System.load(it) }
    }

    @JvmStatic external fun setRecordLimit(
        ssl: Long,
        records: Long,
    )
}

class RecordLimitAlertJvmTest {
    /** Skipped only on Windows, where buildTestHooksJni builds nothing; a missing library fails the test everywhere else. */
    @Test fun negative_aSessionAtItsRecordLimitEndsWithInternalError() {
        assumeTrue(!System.getProperty("os.name").lowercase().contains("win"), "no native test hooks on Windows hosts")
        val lib = System.getProperty("ksl.testhooks.lib")
        assertNotNull(KslTestHooks.path, "native test hooks missing: $lib (tools/build-test-hooks.sh)")
        recordLimitEndsWithInternalError(KslTestHooks::setRecordLimit)
    }
}
