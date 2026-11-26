// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.awaitSendCredit
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.sendCredit
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * `QuicStream.awaitSendCredit` returns 0 once the stream takes no more writes, also while it waits: the peer's STOP_SENDING
 * and a local reset end the wait. It waited on a tick that only StreamWritable moved, and the core sends none for a reset
 * stream (review of 2026-11-26).
 */
class AwaitSendCreditTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun waitThenEnd(stop: Boolean): Long? =
        runBlocking {
            withTimeout(30.seconds) {
                ApiPair
                    .open(serverQuic = quicConfig { flowControl { initialStreamWindow = 16_384 } })
                    .use { p ->
                        val (c, s) = p.connect()
                        val st = c.openBidi()
                        st.output.writeFully(ByteArray(16_384), 0, 16_384)
                        st.output.flush()
                        while (st.sendCredit() > 0) yield()
                        val waiter = async { st.awaitSendCredit() }
                        repeat(100) { yield() } // the waiter goes on to wait
                        val peer = s.acceptStream()
                        if (stop) peer.stopSending(7) else st.reset(3)
                        val r = withTimeoutOrNull(5.seconds) { waiter.await() }
                        waiter.cancel()
                        c.close()
                        s.close()
                        r
                    }
            }
        }

    @Test fun negative_peerStopEndsTheWait() = assertEquals(0L, waitThenEnd(stop = true))

    @Test fun negative_localResetEndsTheWait() = assertEquals(0L, waitThenEnd(stop = false))
}
