// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.crypto.NullPacketProtector
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.PacketProtector
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds

/**
 * Randomized check of [KeyPhase] against a model written from RFC 9001 section 6 alone. The model keeps the whole history (every
 * packet number opened with every generation, every packet we sent and when the peer acknowledged it) and decides each step from it:
 *
 * - which generation's key a packet is tried with (section 6.5: the Key Phase bit, then the packet number against the current phase;
 *   the previous key only while kept, 3 x PTO from the first packet opened with the new one, section 6.5);
 * - KEY_UPDATE_ERROR when an opened packet and any earlier opened packet invert the order of keys and packet numbers (section 6.4,
 *   searched over the history, either order of arrival), for a second peer update before we acknowledged a packet of the current phase
 *   (section 6.2), and for an acknowledgment of a newer-key packet carried with older keys (section 6.2);
 * - whether we may initiate (section 6.1: the first update once confirmed; later ones after an acknowledgment of a packet of the
 *   current phase, and section 6.5: 3 x PTO after it).
 *
 * The peer is mostly honest (it numbers its packets in order, updates when we do, and the network reorders and duplicates them) with
 * forged and misordered packets mixed in, so both accepted and rejected sequences are frequent.
 */
class KeyPhasePropertyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val pto = 100.milliseconds

    /** A packet protection key standing for one generation: it "authenticates" exactly the packets of that generation. */
    private class GenKey(
        val gen: Int,
    ) : PacketProtector by NullPacketProtector {
        override fun next(): PacketProtector = GenKey(gen + 1)

        override fun close() {}
    }

    private class Model(
        val ptoNanos: Long,
    ) {
        var now = 0L
        var cur = 0
        val openedPn = ArrayList<Long>()
        val openedGen = ArrayList<Int>()
        val openedAt = ArrayList<Long>()
        val sentGen = HashMap<Long, Int>()
        val firstAckOfGen = HashMap<Int, Long>()
        val ackSentAt = ArrayList<Long>() // times (as an event counter) we sent an ACK frame
        var clock = 0L // event counter: orders ACKs sent against packets opened at the same time

        val openedEvent = ArrayList<Long>()

        private fun firstOpen(gen: Int): Int = openedGen.indexOfFirst { it == gen }

        fun previousKept(): Boolean {
            if (cur == 0) return false
            val i = firstOpen(cur)
            return i < 0 || now < openedAt[i] + 3 * ptoNanos
        }

        fun select(
            bit: Boolean,
            pn: Long,
        ): Int {
            if (bit == (cur % 2 == 1)) return cur
            var min = Long.MAX_VALUE
            for (i in openedPn.indices) if (openedGen[i] == cur && openedPn[i] < min) min = openedPn[i]
            return if (previousKept() && pn < min) cur - 1 else cur + 1
        }

        fun inverts(
            pn: Long,
            gen: Int,
        ): Boolean {
            for (i in openedPn.indices) {
                if (openedGen[i] < gen && openedPn[i] >= pn) return true
                if (openedGen[i] > gen && openedPn[i] <= pn) return true
            }
            return false
        }

        fun ackedCurrentPhaseBeforeNow(): Boolean {
            val i = firstOpen(cur)
            if (i < 0) return false
            return ackSentAt.any { it > openedEvent[i] }
        }

        fun mayInitiate(): Boolean {
            if (cur == 0) return true
            val t = firstAckOfGen[cur] ?: return false
            return now >= t + 3 * ptoNanos
        }

        fun open(
            pn: Long,
            gen: Int,
        ) {
            openedPn += pn
            openedGen += gen
            openedAt += now
            openedEvent += ++clock
        }
    }

    private class Stats {
        var opened = 0
        var honestOpened = 0
        var lastError = ""
        var previous = 0
        var peerUpdates = 0
        var ownUpdates = 0
        var refused = 0
        var errors = 0
        var inversions = 0
        var consecutive = 0
        var ackErrors = 0
        var dropped = 0
    }

    private fun run(
        seed: Int,
        steps: Int,
        st: Stats,
    ) {
        val r = Random(seed)
        val ptoNanos = pto.inWholeNanoseconds
        val m = Model(ptoNanos)
        val kp = KeyPhase(GenKey(0), GenKey(0)) { _, _ -> }
        var peerPn = 0L
        var peerGen = 0
        var ourPn = 0L
        val inFlight = ArrayList<Pair<Long, Int>>() // the peer's packets on the way: (pn, generation)
        val ours = ArrayList<Long>()
        // even seeds: an honest peer, whose runs must never end in an error; odd seeds: a misbehaving one, at a rate of its own
        val honest = seed % 2 == 0
        val hostile = if (honest) 0.0 else r.nextInt(1, 4) * 0.03
        val ctx = { "seed $seed, generation ${m.cur}, now ${m.now}" }
        val openedBefore = st.opened
        repeat(steps) {
            when (r.nextInt(100)) {
                in 0..29 -> { // the peer sends a packet
                    // an honest peer follows our update (section 6.2) and updates itself now and then once allowed
                    if (peerGen < m.cur && r.nextInt(3) == 0) peerGen = m.cur
                    if (r.nextDouble() < hostile) peerGen = maxOf(0, peerGen + r.nextInt(3) - 1)
                    inFlight += (peerPn++ to peerGen)
                    if (r.nextInt(8) == 0) peerPn += r.nextInt(1, 5) // lost packets
                }

                in 30..54 -> { // one arrives: the oldest mostly, any one (reordering) or a copy (duplication) otherwise
                    if (inFlight.isEmpty()) return@repeat
                    val i = if (r.nextInt(3) == 0) r.nextInt(inFlight.size) else 0
                    val (pn, gen) = if (r.nextInt(10) == 0) inFlight[i] else inFlight.removeAt(i)
                    if (receive(m, kp, pn, gen, ours, r, st, honest, ctx)) {
                        assertTrue(!honest, "an honest peer ended in an error (${st.lastError}): ${ctx()}")
                        return
                    }
                }

                in 55..59 -> { // a forged or misordered packet: any nearby number, any nearby generation
                    if (honest) return@repeat
                    val pn = maxOf(0L, peerPn + r.nextInt(-20, 5))
                    val gen = maxOf(0, m.cur + r.nextInt(-2, 3))
                    if (receive(m, kp, pn, gen, ours, r, st, honest, ctx)) return
                }

                in 60..64 -> { // the peer starts an update of its own: an honest one once we acknowledged its current phase
                    if (honest) {
                        if (peerGen == m.cur && m.ackedCurrentPhaseBeforeNow()) peerGen++
                    } else if (r.nextInt(2) == 0 || r.nextDouble() < hostile * 5) {
                        peerGen = maxOf(peerGen, m.cur) + 1
                    }
                }

                in 65..74 -> { // we send an ACK frame
                    kp.onAckSent()
                    m.ackSentAt += ++m.clock
                }

                in 75..84 -> { // we send a packet
                    kp.onPacketSent(ourPn)
                    m.sentGen[ourPn] = m.cur
                    ours += ourPn
                    ourPn++
                }

                in 85..89 -> { // the peer acknowledges one of them
                    if (ours.isEmpty()) return@repeat
                    val pn = ours[r.nextInt(ours.size)]
                    kp.onPacketAcked(pn, TimeMark(m.now))
                    val g = m.sentGen.getValue(pn)
                    if (g == m.cur && m.cur !in m.firstAckOfGen) m.firstAckOfGen[m.cur] = m.now
                }

                in 90..93 -> { // we try a key update
                    val allowed = m.mayInitiate()
                    assertEquals(allowed, kp.canInitiate(true, TimeMark(m.now), pto), ctx())
                    assertEquals(allowed, kp.initiate(TimeMark(m.now), pto), ctx())
                    if (allowed) {
                        m.cur++
                        st.ownUpdates++
                    } else {
                        st.refused++
                    }
                }

                else -> { // time passes; due timers run
                    m.now += r.nextLong(0, 2 * ptoNanos)
                    kp.onTimeout(TimeMark(m.now))
                }
            }
            assertEquals(m.cur.toLong(), kp.generation, ctx())
            assertEquals(m.cur % 2 == 1, kp.phase, ctx())
        }
        if (honest) st.honestOpened += st.opened - openedBefore
    }

    /** One received packet; true when the connection ended (KEY_UPDATE_ERROR, matched against the model). */
    private fun receive(
        m: Model,
        kp: KeyPhase,
        pn: Long,
        gen: Int,
        ours: List<Long>,
        r: Random,
        st: Stats,
        honest: Boolean,
        ctx: () -> String,
    ): Boolean {
        val bit = gen % 2 == 1
        val chosen = m.select(bit, pn)
        val key = kp.readKey(bit, pn) as GenKey
        assertEquals(chosen, key.gen, "key for pn $pn of generation $gen: ${ctx()}")
        if (chosen != gen) {
            st.dropped++
            return false // fails to authenticate
        }
        val inverts = m.inverts(pn, gen)
        val consecutive = gen == m.cur + 1 && m.cur > 0 && !m.ackedCurrentPhaseBeforeNow()
        val expectError = inverts || consecutive
        val error =
            try {
                kp.onAuthenticated(bit, pn, TimeMark(m.now), pto)
                null
            } catch (e: QuicWireException) {
                e
            }
        assertEquals(expectError, error != null, "pn $pn of generation $gen (${error?.message}): ${ctx()}")
        if (error != null) {
            assertEquals(TransportError.KEY_UPDATE_ERROR, error.code)
            st.lastError = "pn $pn of generation $gen: ${error.message}"
            st.errors++
            if (inverts) st.inversions++ else st.consecutive++
            return true
        }
        if (gen == m.cur - 1) st.previous++
        if (gen == m.cur + 1) {
            m.cur++
            st.peerUpdates++
        }
        m.open(pn, gen)
        st.opened++
        // an ACK frame in it now and then: of a packet of ours protected with a newer generation than this packet's, it is an error
        if (ours.isNotEmpty() && r.nextInt(4) == 0) {
            // an honest peer acknowledges a packet of a newer generation only once it updated itself (section 6.2)
            val candidates = if (honest) ours.filter { m.sentGen.getValue(it) <= gen } else ours
            if (candidates.isEmpty()) return false
            val largest = candidates[r.nextInt(candidates.size)]
            val ackError = m.sentGen.getValue(largest) > gen
            val e =
                try {
                    kp.checkAckInPacket(largest, 0x02)
                    null
                } catch (e: QuicWireException) {
                    e
                }
            assertEquals(ackError, e != null, "ACK of $largest in pn $pn of generation $gen: ${ctx()}")
            if (e != null) {
                assertEquals(TransportError.KEY_UPDATE_ERROR, e.code)
                st.lastError = "ACK of $largest in pn $pn of generation $gen: ${e.message}"
                st.ackErrors++
                return true
            }
        }
        return false
    }

    @Test fun keyPhaseMatchesTheModel() {
        val st = Stats()
        for (seed in 0 until 3000) {
            try {
                run(seed, 300, st)
            } catch (e: AssertionError) {
                fail("seed $seed: ${e.message}", e)
            }
        }
        // the runs reached every part of the state machine
        assertTrue(st.honestOpened > 50_000, "honest runs opened ${st.honestOpened}")
        val all =
            "opened ${st.opened}, previous ${st.previous}, updates ${st.peerUpdates}/${st.ownUpdates}, refused ${st.refused}, " +
                "dropped ${st.dropped}, errors ${st.errors}, ACK errors ${st.ackErrors}"
        assertTrue(st.opened > 80_000 && st.previous > 10_000, all)
        assertTrue(st.peerUpdates > 2000 && st.ownUpdates > 2000 && st.refused > 5000 && st.dropped > 5000, all)
        assertTrue(
            st.inversions > 200 && st.consecutive > 50 && st.ackErrors > 50,
            "$all, inversions ${st.inversions}, consecutive ${st.consecutive}",
        )
    }
}
