// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.ApiPair
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.lang.management.ManagementFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** `trySendDatagram` never suspends and allocates little more than the copy of the payload. */
@OptIn(ExperimentalKuicksilverApi::class)
class DatagramApiAllocationTest {
    @Test fun trySendNeverSuspendsOrAllocatesPerCall() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    KslLoader.ensureLoaded()
                    val (c, s) = p.connect()
                    val data = ByteArray(100)
                    val mx = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
                    repeat(1000) { c.trySendDatagram(data) } // warm up
                    val before = mx.getThreadAllocatedBytes(Thread.currentThread().threadId())
                    repeat(10_000) { assertEquals(DatagramSendResult.Sent, c.trySendDatagram(data)) }
                    val perCall = (mx.getThreadAllocatedBytes(Thread.currentThread().threadId()) - before) / 10_000.0
                    assertTrue(
                        perCall <= data.size + 256,
                        "allocated $perCall bytes per call: the payload copy plus a bounded wrapper (command object and channel slot)",
                    )
                    c.close()
                    s.close()
                }
            }
        }
}
