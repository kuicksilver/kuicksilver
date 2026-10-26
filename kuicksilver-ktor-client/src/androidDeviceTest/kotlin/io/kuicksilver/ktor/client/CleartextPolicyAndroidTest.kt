// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.security.NetworkSecurityPolicy
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** On a device the engine asks the app's Network Security Configuration before an `http://` request (as OkHttp does). */
class CleartextPolicyAndroidTest {
    @Test fun cleartextRefusedByTheNetworkSecurityConfigurationNeverConnects(): Unit =
        runBlocking {
            // the test APK's network security config allows cleartext to the loopback and .test names only (androidDeviceTest/res/xml)
            val policy = NetworkSecurityPolicy.getInstance()
            assertTrue(policy.isCleartextTrafficPermitted("127.0.0.1"))
            assertFalse(policy.isCleartextTrafficPermitted("192.0.2.1"))
            HttpClient(Kuicksilver).use { client ->
                // 192.0.2.1 (TEST-NET-1) is never reached: the refusal comes before any connection attempt
                val e = assertFailsWith<java.io.IOException> { client.get("http://192.0.2.1:9/") }
                assertEquals("CLEARTEXT communication to 192.0.2.1 not permitted by network security policy", e.message)
            }
        }
}
