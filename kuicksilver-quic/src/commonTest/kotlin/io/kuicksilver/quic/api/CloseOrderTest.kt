// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.runtime.ConnectionRuntime
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A local close puts CONNECTION_CLOSE on the wire before the runtime turns to the application side of the end (failing the
 * streams, waking the waiters, the listener's onClosed): none of that delays the frame (re-review 2026-10-28, a 4-10 ms gap
 * between close() and the frame on the JVM client).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class CloseOrderTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun connectionCloseIsSentBeforeTheApplicationHearsOfTheClose() =
        runBlocking {
            val sentFirst = CompletableDeferred<Boolean>()
            val listener =
                object : ConnectionListener {
                    override fun onClosed(
                        connection: ConnectionInfo,
                        reason: QuicException.ConnectionLost,
                    ) {
                        // on the loop, inside the flush that handles the close
                        sentFirst.complete((connection.connection as ConnectionRuntime).core.closeSent)
                    }
                }
            ApiPair.open(clientListener = listener).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    c.close(0x42, "done")
                    assertTrue(sentFirst.await(), "CONNECTION_CLOSE was built and handed to the socket before onClosed ran")
                    s.close()
                }
            }
        }
}
