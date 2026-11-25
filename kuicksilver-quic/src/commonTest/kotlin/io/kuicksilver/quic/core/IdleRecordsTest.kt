// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.recovery.POOL_IDLE_KEEP
import io.kuicksilver.quic.recovery.SpaceId
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.microseconds

/**
 * The connection's timer gives back the sent-packet records of an idle space (LossDetection.settleIdle): the settle deadline is
 * the connection's next timeout once a burst is acknowledged, each firing halves the spare records, and none is armed again
 * once the space keeps [POOL_IDLE_KEEP].
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class IdleRecordsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** The server sends 64 KB on a stream of its own; returns once the client has it all and the server's space went empty. */
    private fun CorePair.answer64k() {
        val s = server!!
        val id = s.openStream(bidi = false, StreamPriority.Default)
        s.writeStream(id, ByteArray(65536), 0, 65536, fin = true)
        val b = ByteArray(65536)
        var got = 0
        assertTrue(
            runUntil {
                while (true) {
                    val n = client.readStream(id, b, 0, b.size)
                    if (n <= 0) break
                    got += n
                }
                got == 65536 && s.loss.settleDeadline() != TimeMark.NEVER
            },
            "64 KB delivered ($got) and the server's space empty",
        )
    }

    @Test fun theSettleDeadlineIsTheConnectionsNextTimeoutUntilTheSpaceKeepsTwo() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.answer64k()
            val s = p.server!!
            val app = s.loss.space(SpaceId.Application)
            val peak = app.pooledForTest
            assertTrue(peak > 2 * POOL_IDLE_KEEP, "the answer had $peak records in flight at once")
            var fired = 0
            while (true) {
                val d = s.loss.settleDeadline()
                if (d == TimeMark.NEVER) break
                assertEquals(d, s.nextTimeoutOrNever(), "the settle deadline is the earliest timer of an idle connection")
                val before = app.pooledForTest
                s.onTimeout(d)
                assertEquals(maxOf(POOL_IDLE_KEEP, before / 2), app.pooledForTest)
                fired++
            }
            assertTrue(fired >= 2, "halved $fired times from $peak")
            assertEquals(POOL_IDLE_KEEP, app.pooledForTest)
            assertEquals(intArrayOf(0, 0, POOL_IDLE_KEEP).toList(), s.idleSentRecords().toList())
            assertEquals(s.idleDeadline(), s.nextTimeoutOrNever(), "nothing armed again: the idle timeout is next")
        } finally {
            p.close()
        }
    }

    /**
     * A closing connection runs only its close timer (RFC 9000 section 10.2): while it is closing no settle deadline is its next
     * timeout and its timers give nothing back, and once closed (three PTOs on, before the 1 s idle period ends) nothing either.
     */
    @Test fun aClosingConnectionArmsNoSettleDeadline() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.answer64k()
            val s = p.server!!
            val app = s.loss.space(SpaceId.Application)
            val d = s.loss.settleDeadline()
            assertNotEquals(TimeMark.NEVER, d)
            val pooled = app.pooledForTest
            s.close(0, "done", p.now)
            assertEquals(ConnectionState.Closing, s.state)
            val close = s.timers.closeDeadline!!
            assertTrue(close < d, "the close deadline ($close) comes before the settle deadline ($d)")
            assertEquals(close, s.nextTimeoutOrNever())
            s.onTimeout(close - 1.microseconds)
            assertEquals(ConnectionState.Closing, s.state, "still closing just before its close deadline")
            assertEquals(close, s.nextTimeoutOrNever(), "no settle deadline armed while closing")
            assertEquals(pooled, app.pooledForTest, "nothing given back while closing")
            s.onTimeout(close)
            assertEquals(ConnectionState.Closed, s.state)
            assertEquals(TimeMark.NEVER, s.nextTimeoutOrNever())
            s.onTimeout(d)
            assertEquals(pooled, app.pooledForTest, "a closed connection runs no timer at its settle deadline either")
        } finally {
            p.close()
        }
    }
}
