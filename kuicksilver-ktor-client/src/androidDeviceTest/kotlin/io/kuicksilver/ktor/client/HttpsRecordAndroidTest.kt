// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.os.Build
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** `HttpsRecordSource.System` on a device: `DnsResolver.rawQuery` from API 29, no lookups below it. */
class HttpsRecordAndroidTest {
    @Test fun rawQueryOnApi29(): Unit =
        runBlocking {
            assumeTrue(Build.VERSION.SDK_INT >= 29)
            // localhost has no HTTPS records: a failed lookup (null) or none (empty), never an exception
            val answer = platformHttpsQuery("localhost", 5.seconds)
            assertTrue(answer == null || answer.records.isEmpty(), "localhost answered ${answer?.records}")
        }

    @Test fun nullBelowApi29(): Unit =
        runBlocking {
            assumeTrue(Build.VERSION.SDK_INT < 29)
            assertNull(platformHttpsQuery("example.com", 5.seconds))
        }
}
