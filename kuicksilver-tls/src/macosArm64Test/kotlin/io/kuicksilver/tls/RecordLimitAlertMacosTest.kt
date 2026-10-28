// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.tls.testhooks.ksl_test_hooks_set_record_limit
import kotlinx.cinterop.COpaque
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.interpretCPointer
import kotlinx.cinterop.nativeNullPtr
import kotlin.test.Test

class RecordLimitAlertMacosTest {
    @OptIn(ExperimentalForeignApi::class)
    @Test
    fun negative_aSessionAtItsRecordLimitEndsWithInternalError() =
        recordLimitEndsWithInternalError { ssl, records ->
            ksl_test_hooks_set_record_limit(interpretCPointer<COpaque>(nativeNullPtr + ssl), records.toULong())
        }
}
