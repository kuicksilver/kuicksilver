// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The callback-to-flow adapter behind Android's `followDefaultNetwork` (ConnectivityManager's default-network callback). */
class DefaultNetworkUpdatesTest {
    private class FakeCallbacks {
        var available: ((String) -> Unit)? = null
        var lost: ((String) -> Unit)? = null
        var unregistered = false

        fun register(
            onAvailable: (String) -> Unit,
            onLost: (String) -> Unit,
        ): () -> Unit {
            available = onAvailable
            lost = onLost
            onAvailable("wifi") // the system reports the current default network at once
            return { unregistered = true }
        }
    }

    @Test fun availableAndLostBecomeNetworksAndNull() =
        runTest {
            val cb = FakeCallbacks()
            val got =
                defaultNetworkUpdates<String> { a, l ->
                    cb.register(a, l).also {
                        cb.lost!!("cell") // a network that is not the default any more: ignored
                        cb.available!!("cell")
                        cb.lost!!("cell")
                    }
                }.take(3).toList()
            assertEquals(listOf("wifi", "cell", null), got)
            assertTrue(cb.unregistered, "the callback is unregistered when collection ends")
        }

    @Test fun lostOfAnOldNetworkAfterTheSwitchIsIgnored() =
        runTest {
            val cb = FakeCallbacks()
            val got =
                defaultNetworkUpdates<String> { a, l ->
                    cb.register(a, l).also {
                        cb.available!!("cell") // the new default arrives before the old one is lost
                        cb.lost!!("wifi")
                        cb.lost!!("cell")
                    }
                }.take(3).toList()
            assertEquals(listOf("wifi", "cell", null), got)
        }
}
