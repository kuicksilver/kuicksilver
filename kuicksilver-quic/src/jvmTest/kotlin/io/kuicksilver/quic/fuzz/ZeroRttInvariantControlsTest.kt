// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.fuzz.ZeroRttProgram.ACCEPT
import io.kuicksilver.quic.fuzz.ZeroRttProgram.REJECT_APPLICATION
import io.kuicksilver.quic.recovery.SpaceId
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Negative controls of the 0-RTT invariant ([ZeroRttConnectionFuzz]): each corrupts one thing the invariant covers, the way a
 * bug would leave it, in an otherwise clean run, and the checks must catch it. Without these a check that silently stopped
 * looking (a renamed event, a hook that always answers 0) would let the fuzzer pass everything.
 */
class ZeroRttInvariantControlsTest {
    /** A rejected 0-RTT run whose client opened two streams and wrote before the answer. */
    private val rejected =
        ZeroRttProgram
            .Builder(REJECT_APPLICATION, 0)
            .open(0, 2000, fin = false)
            .open(0, 300, fin = true, uni = true)
            .settle()
            .step()
            .step()
            .build()

    private val accepted =
        ZeroRttProgram
            .Builder(ACCEPT, 0)
            .open(0, 2000, fin = true)
            .open(0, 300, fin = true, uni = true)
            .settle()
            .build()

    private fun caught(
        program: ByteArray,
        expected: String,
        tamper: (CorePair, Boolean) -> Unit,
    ) {
        // the same run without the corruption passes
        ZeroRttConnectionFuzz(program).run()
        val e = assertFailsWith<IllegalStateException> { ZeroRttConnectionFuzz(program, tamper = tamper).run() }
        assertContains(e.message ?: "", expected)
    }

    @Test fun negative_eventForAStreamTheRejectionDroppedIsCaught() {
        var rejectedSeen = false
        caught(rejected, "which the rejected 0-RTT dropped") { p, now ->
            // a round after the rejection, the application is handed an event for the dropped stream 0
            if (rejectedSeen && p.clientEvents.isEmpty()) p.clientEvents += ConnectionEvent.StreamReadable(0)
            if (now && p.client.earlyAccepted == false) rejectedSeen = true
        }
    }

    @Test fun negative_eventAfterStreamFinishedIsCaught() {
        var finished = -1L
        caught(accepted, "after its StreamFinished") { p, _ ->
            if (finished >= 0) {
                p.clientEvents += ConnectionEvent.StreamWritable(finished)
                finished = -2
            }
            if (finished ==
                -1L
            ) {
                p.clientEvents.firstOrNull { it is ConnectionEvent.StreamFinished }?.let {
                    finished =
                        (it as ConnectionEvent.StreamFinished).id
                }
            }
        }
    }

    @Test fun negative_residueOfADroppedStreamIsCaught() {
        caught(rejected, "for dropped stream 0") { p, now ->
            if (now && p.client.earlyAccepted == false) p.client.streams.events += ConnectionEvent.StreamWritable(0)
        }
    }

    @Test fun negative_creditOfDroppedStreamsIsCaught() {
        caught(rejected, "connection credit still charged") { p, now ->
            if (now && p.client.earlyAccepted == false) p.client.connSend.consume(10)
        }
    }

    @Test fun negative_rejectedZeroRttPacketLeftInTheHistoryIsCaught() {
        caught(rejected, "rejected 0-RTT packets still in the sent history") { p, now ->
            if (now && p.client.earlyAccepted == false) {
                // as if the rejection forgot one: in flight, charged to the controller, consistent otherwise
                val c = p.client
                val pkt = c.loss.space(SpaceId.Application).newSentPacket()
                pkt.pn = c.loss.space(SpaceId.Application).nextPn - 1
                pkt.size = 100
                pkt.inFlight = true
                pkt.zeroRtt = true
                pkt.cc = c.cc
                pkt.timeSent = p.now
                c.cc.onPacketSent(p.now, 100)
                c.loss.onPacketSent(SpaceId.Application, pkt, p.now)
            }
        }
    }

    @Test fun negative_bytesInFlightDriftIsCaught() {
        caught(accepted, "bytesInFlight") { p, now ->
            if (now) {
                // a packet in the history that loss detection never counted
                val sp = p.client.loss.space(SpaceId.Application)
                val pkt = sp.newSentPacket()
                pkt.pn = sp.largestSent + 1_000
                pkt.size = 77
                pkt.inFlight = true
                sp.sent.add(pkt)
            }
        }
    }

    @Test fun negative_controllerDriftIsCaught() {
        caught(accepted, "congestion controller") { p, now -> if (now) p.client.cc.onPacketSent(p.now, 50) }
    }

    @Test fun negative_itemHeldAfterTheAnswerIsCaught() {
        // held after the answer, as a hold that missed the settlement would leave it
        caught(accepted, "zeroRttHeld") { p, now -> if (now) p.client.streams.heldUntilAnswer += ConnectionEvent.StreamWritable(0) }
    }

    /**
     * The queue the invariant counts is the one the answer settles: held before it, delivered at an acceptance, dropped at a
     * rejection or close. The held event is one no rejection purges for its own reasons (not a stream's), so a rejection
     * that delivered it instead of dropping it would show.
     */
    @Test fun heldEventsAreSettledByTheAnswerOrTheEnd() {
        for ((program, delivered) in listOf(accepted to true, rejected to false, closedEarly to false)) {
            var held = false
            var seen = 0
            ZeroRttConnectionFuzz(program, tamper = { p, _ ->
                seen += p.clientEvents.count { it === ConnectionEvent.DatagramsReadable }
                if (!held && p.client.earlyAccepted == null && p.client.isStreamOpenForTest(0)) {
                    held = true
                    p.client.streams.heldUntilAnswer += ConnectionEvent.DatagramsReadable
                }
            }).run()
            assertTrue(held, "an event was held before the answer")
            assertEquals(if (delivered) 1 else 0, seen, "the held event ${if (delivered) "delivered once" else "dropped"}")
        }
    }

    private val closedEarly =
        ZeroRttProgram
            .Builder(ACCEPT, 0)
            .open(0, 500, fin = false)
            .step()
            .close(0, 4)
            .settle()
            .build()

    @Test fun negative_limitAboveTheRememberedOneBeforeTheAnswerIsCaught() {
        caught(accepted, "above the remembered") { p, _ ->
            val r = p.client.remembered
            if (r != null && p.client.earlyAccepted == null) p.client.connSend.onMaxUpdate(r.initialMaxData + 1)
        }
    }

    /** The server's higher limits taken when its parameters arrive, in the round that also settles the answer. */
    @Test fun negative_limitsAppliedOnReceiptAreCaught() {
        val higher =
            ZeroRttProgram
                .Builder(ACCEPT, ZeroRttProgram.HIGHER)
                .open(0, 300, fin = true)
                .settle()
                .build()
        caught(higher, "as 1-RTT began") { p, _ -> p.client.testApplyPeerLimitsOnReceipt = true }
    }

    @Test fun negative_zeroRttAfterTheOneRttKeyIsCaught() {
        caught(accepted, "sealed after the 1-RTT key arrived") { p, _ ->
            val c = p.client
            if (c.zeroRttSealedAtOneRttKey >= 0 && c.zeroRttPacketsSealed == c.zeroRttSealedAtOneRttKey) c.zeroRttPacketsSealed++
        }
    }

    @Test fun negative_zeroRttNumberedAfterOneRttIsCaught() {
        caught(accepted, "sealed after the first 1-RTT packet") { p, _ ->
            val c = p.client
            if (c.oneRttFirstPn >= 0 && c.zeroRttLastPn in 0 until c.oneRttFirstPn) c.zeroRttLastPn = c.oneRttFirstPn + 1
        }
    }

    @Test fun negative_streamTheApplicationCannotReachIsCaught() {
        caught(accepted, "its application cannot reach it") { p, now -> if (now) p.client.openStream(bidi = true) }
    }

    @Test fun negative_serverProcessingRejectedZeroRttIsCaught() {
        var done = false
        caught(rejected, "a rejected 0-RTT was processed") { p, _ ->
            val s = p.server
            if (!done && s != null && s.earlyDataAccepted == false) {
                done = true
                p.serverEvents += ConnectionEvent.StreamOpened(0)
            }
        }
    }
}
