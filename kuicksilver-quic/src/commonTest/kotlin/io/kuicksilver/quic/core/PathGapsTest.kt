// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.of
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.NewReno
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.endpoint.EndpointPair
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/** [Paths] bookkeeping and path selection edges (RFC 9000 sections 8.2, 9) the connection-level tests leave open. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class PathGapsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun paths(): Paths = Paths(Path(PathId.Initial, InetSocketAddress("10.0.0.1", 1), PathId.Initial, NewReno(), 333.milliseconds))

    private fun Paths.addAt(i: Int): Path = add(PathId.Initial, InetSocketAddress("10.0.1.$i", 1), NewReno(), 333.milliseconds)!!

    /**
     * A fifth address evicts neither the active path nor the last validated one (the fallback of RFC 9000 section 9.3.2), and the
     * eviction is reported (the connection gives the path's peer ID back, section 9.5).
     */
    @Test fun negative_evictionSparesTheActiveAndTheLastValidatedPath() {
        val ps = paths()
        val first = ps.active
        val a = ps.addAt(1)
        val b = ps.addAt(2)
        ps.addAt(3)
        ps.lastValidated = a
        val evicted = ArrayList<Path>()
        ps.onEvicted = { evicted += it }
        assertNotNull(ps.add(PathId.Initial, InetSocketAddress("10.0.2.1", 1), NewReno(), 333.milliseconds))
        assertEquals(listOf(b), evicted, "the oldest path that is neither active nor the last validated one")
        assertTrue(first in ps.all && a in ps.all)
    }

    /**
     * RFC 9000 section 8.2.4 (abandoning validation): a probe may evict a path under validation only when that path has been silent
     * since the given time; validations still heard from stay, and the new address is ignored.
     */
    @Test fun negative_aProbeDoesNotEvictAValidationStillHeardFrom() {
        val ps = paths()
        val others = (1..3).map { ps.addAt(it) }
        for (p in others) {
            p.state = PathState.Validating
            p.lastReceivedAt = TimeMark(2_000)
        }
        val added =
            ps.add(
                PathId.Initial,
                InetSocketAddress("10.0.2.1", 1),
                NewReno(),
                333.milliseconds,
                abandonValidatingHeardBefore = TimeMark(1_000),
            )
        assertNull(added, "every validation was heard from after the cut-off")
        assertEquals(4, ps.all.size)
    }

    /** RFC 9000 section 9.3.2: a failed active path falls back only to a validated path, never to itself or to an unvalidated one. */
    @Test fun negative_fallbackIsOnlyAnotherValidatedPath() {
        val ps = paths()
        val except = ps.active
        except.state = PathState.Validated
        ps.addAt(1).state = PathState.Validating
        ps.addAt(2)
        assertNull(ps.fallback(except))
    }

    /** Removing a path updates the remote addresses the endpoint routes stateless resets by (RFC 9000 section 10.3.1). */
    @Test fun negative_removingAPathReportsTheRemotesChanged() {
        val ps = paths()
        val p = ps.addAt(1)
        var changes = 0
        ps.onRemotesChanged = { changes++ }
        ps.remove(p)
        assertEquals(1, changes)
    }

    /**
     * RFC 9000 section 8.2.2: "An endpoint MUST NOT send more than one PATH_RESPONSE frame in response to one PATH_CHALLENGE frame"
     * and sends it on the path the challenge arrived on: a queued response is taken by its own path only, and dropping the
     * responses owed to one source drops every one of them.
     */
    @Test fun negative_pathResponsesStayWithTheirPath() {
        val ps = paths()
        val a = ps.addAt(1)
        val b = ps.addAt(2)
        ps.queueResponse(1, a)
        ps.queueResponse(2, b)
        assertEquals(2L, ps.takeResponseFor(b))
        assertEquals(1L, ps.takeResponseFor(a))
        val from = InetSocketAddress("10.0.9.9", 1)
        ps.queueResponse(3, a, from)
        ps.queueResponse(4, a, from)
        ps.dropResponsesFrom(a, from)
        assertEquals(-1, ps.nextStrayResponse(), "both responses owed to $from are gone")
        assertEquals(0, ps.responses)
    }

    private val df =
        io.kuicksilver.quic.IoCapabilities(ecnSend = false, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = true, batch = 1)

    private fun connected(
        caps: io.kuicksilver.quic.IoCapabilities? = null,
        clientQuic: io.kuicksilver.quic.QuicConfig = io.kuicksilver.quic.QuicConfig.Default,
    ): Pair<EndpointPair, ConnectionCore> {
        val p = EndpointPair()
        val c = p.connect(clientQuic)
        if (caps != null) c.setPathCapabilities(PathId.Initial, caps)
        assertTrue(p.confirmed(c))
        repeat(30) { p.step() }
        return p to c
    }

    /**
     * RFC 9000 section 14.2.1: "Endpoints SHOULD ignore all ICMP messages that fail validation"; the quote must be the start of one of
     * our packets on the active path (RFC 8899 section 4.6.1). Every field of the check, at its edges: short headers need the whole
     * peer ID plus one byte, long headers the peer's ID as destination and ours as source, complete; the destination must be the
     * path's and the reported size below one we sent there. Short or malformed quotes are refused without reading past their end.
     */
    @Test fun negative_packetTooBigQuoteValidation() {
        val (p, c) = connected(caps = df)
        try {
            val to = p.serverAddr
            val payload = c.path.largestSent - 1
            val d = c.remoteCid.toByteArray()

            fun accept(
                q: ByteArray,
                len: Int = q.size,
                dest: InetSocketAddress = to,
                size: Int = payload,
            ) = c.acceptPacketTooBig(q, len, dest, size, PathId.Initial)
            val short = byteArrayOf(0x43) + d + byteArrayOf(0x11)
            assertTrue(accept(short), "the peer ID and one more byte")
            assertFalse(accept(byteArrayOf(0x43) + d), "the peer ID alone")
            assertFalse(accept(short, dest = InetSocketAddress("10.9.9.9", 443)), "another destination")
            assertFalse(accept(short, size = c.path.largestSent), "a size no larger than anything we sent")
            val l = c.localCid.toByteArray()
            val long = byteArrayOf(0xc3.toByte(), 0, 0, 0, 1, d.size.toByte()) + d + byteArrayOf(l.size.toByte()) + l
            assertTrue(accept(long), "a long header from us to the peer, exactly complete")
            assertFalse(accept(long, len = long.size - 3), "cut inside our ID")
            val wrongDcid = long.copyOf().also { it[6] = (it[6] + 1).toByte() }
            assertFalse(accept(wrongDcid), "another destination ID")
            val wrongScid = long.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
            assertFalse(accept(wrongScid), "another source ID")
            val shortScid =
                byteArrayOf(0xc3.toByte(), 0, 0, 0, 1, d.size.toByte()) + d + byteArrayOf((l.size - 1).toByte()) + l.copyOf(l.size - 1)
            assertFalse(accept(shortScid), "a source ID of another length")
            assertFalse(accept(byteArrayOf(0xc3.toByte(), 0, 0, 0, 1)), "no room for the ID lengths")
            assertFalse(accept(byteArrayOf(0xc3.toByte(), 0, 0, 0, 1, d.size.toByte(), 0)), "the destination ID length points past the end")
        } finally {
            p.close()
        }
        val (q, plain) = connected()
        try {
            assertNull(plain.path.pmtud)
            val quote = byteArrayOf(0x43) + plain.remoteCid.toByteArray() + byteArrayOf(0x11)
            val payload = plain.path.largestSent - 1
            assertFalse(plain.acceptPacketTooBig(quote, quote.size, q.serverAddr, payload, PathId.Initial), "no DPLPMTUD")
        } finally {
            q.close()
        }
    }

    /** Only packets above the 1200-byte base can vanish in an MTU black hole: full 1200-byte packets in flight say nothing about it. */
    @Test fun negative_fullBasePacketsAreNotLargePackets() {
        val (p, c) = connected()
        try {
            p.filterToServer = { _, _ -> false }
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(6000) { 1 }, 0, 6000, false)
            repeat(3) { p.step() }
            assertTrue(p.clientDatagramSizes.any { it == 1200 }, "full-size packets went out")
            assertFalse(c.largePacketUnanswered(c.path))
        } finally {
            p.close()
        }
    }

    /** A RETIRE_CONNECTION_ID for one of our live IDs is no glitch: only repeats or retirements faster than we replace cost a token. */
    @Test fun negative_validRetirementCostsNoGlitchToken() {
        val (p, c) = connected()
        try {
            val before = c.stats.glitchTokensSpent
            c.onRetireConnectionId(1)
            assertEquals(before, c.stats.glitchTokensSpent)
        } finally {
            p.close()
        }
    }

    /** `allowMigrationToLoopback` lets a peer move to a loopback address (the configuration's exception to the loopback rule). */
    @Test fun negative_loopbackMigrationAllowedWhenConfigured() {
        val (p, c) = connected(clientQuic = io.kuicksilver.quic.quicConfig { allowMigrationToLoopback = true })
        try {
            assertTrue(c.migrationAllowedFrom(InetSocketAddress("127.0.0.1", 4433)))
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 8.2.4: a path validation keeps its timeout and its challenges while it runs. A NEW_CONNECTION_ID (here a
     * repeat) resumes only paths that waited for an ID; a validating path that has one is not started over.
     */
    @Test fun negative_newConnectionIdDoesNotRestartARunningValidation() {
        val (p, c) = connected()
        try {
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = InetSocketAddress("10.0.0.7", 40000)
            p.filterToServer = { _, _ -> false } // the probes never arrive: the validation runs on
            c.probePath(id, p.now)
            repeat(3) { p.step() }
            val path = c.paths.byId(id)!!
            assertEquals(PathState.Validating, path.state)
            val deadline = path.challengeDeadline
            val retries = path.challengeRetries
            p.now += 50.milliseconds
            val seqs = c.cids.peerSeqsForTest()
            val (cid, token) = c.cids.peerTokensForTest()[seqs.indexOf(seqs.first { it > 0 })]
            val b =
                io.kuicksilver.native.PacketBuffer
                    .of(cid.toByteArray() + token!!)
            try {
                c.onNewConnectionId(seqs.first { it > 0 }, 0, b, 0, cid.length, cid.length)
            } finally {
                b.close()
            }
            assertEquals(deadline, path.challengeDeadline, "the validation was not started over")
            assertEquals(retries, path.challengeRetries)
        } finally {
            p.close()
        }
    }

    /** A client path to [addr] probed now; answered only when [heard] (the client then listens there). */
    private fun probed(
        p: EndpointPair,
        c: ConnectionCore,
        heard: Boolean,
        addr: InetSocketAddress = InetSocketAddress("10.0.0.7", 40000),
    ): Path {
        val id = c.addPath(p.serverAddr, p.now)
        p.clientSocketSources[id] = addr
        if (heard) p.clientListens += addr else p.filterToServer = { _, _ -> false }
        c.probePath(id, p.now)
        repeat(if (heard) 10 else 3) { p.step() }
        return c.paths.byId(id)!!
    }

    /**
     * RFC 9000 section 8.2.3: "Path validation succeeds when a PATH_RESPONSE frame is received that contains the data that was sent
     * in a previous PATH_CHALLENGE frame" of this validation: a validation started over (a new address, a revalidation) is not
     * completed by the answer to a challenge of the one before.
     */
    @Test fun negative_aRestartedValidationIgnoresTheEarlierChallengesAnswer() {
        val (p, c) = connected()
        try {
            val path = probed(p, c, heard = false)
            assertEquals(PathState.Validating, path.state)
            val earlier = path.challenge
            assertTrue(earlier != 0L, "a PATH_CHALLENGE went out")
            c.startValidation(path)
            assertFalse(path.awaitingCid, "the path holds a peer ID: nothing to wait for")
            c.onPathResponse(earlier)
            assertEquals(PathState.Validating, path.state, "the answer belongs to the earlier validation")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.5: a client with no spare peer ID does not probe a new path with the active path's ID: the path waits for a
     * NEW_CONNECTION_ID instead of sending a PATH_CHALLENGE.
     */
    @Test fun negative_clientWithoutSpareIdWaitsInsteadOfProbing() {
        val (p, c) = connected()
        try {
            for (seq in c.cids.peerSeqsForTest()) c.cids.markUsedForTest(seq)
            val id = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[id] = InetSocketAddress("10.0.0.7", 40000)
            c.probePath(id, p.now)
            val path = c.paths.byId(id)!!
            assertTrue(path.awaitingCid)
            assertFalse(path.challengePending)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.3.3: "endpoints MUST validate the previously active path using a PATH_CHALLENGE frame"; section 8.2.1 keeps
     * that challenge one PTO after the last one there. The deferred revalidation is due a PTO after that challenge, and when it is
     * due a validated path is validated again, while a path that is neither validated nor validating gives its peer ID back.
     */
    @Test fun negative_previousPathRevalidation() {
        val (p, c) = connected()
        try {
            val target = probed(p, c, heard = true)
            assertEquals(PathState.Validated, target.state)
            val old = c.paths.active
            assertEquals(PathState.Validated, old.state)
            old.lastChallengeAt = c.now
            c.switchPath(target, io.kuicksilver.quic.PathChangeReason.ActiveMigration, challengeOld = true)
            assertEquals(c.now + c.pto(), old.revalidateAt, "deferred one PTO after the last challenge there")
            val held = assertNotNull(old.peerCid, "the old path keeps its peer ID for the revalidation (RFC 9000 section 9.5)")
            assertTrue(held.heldByPath, "held by that path: never picked for the active path")
            assertTrue(held !== c.cids.currentPeer)
            assertTrue(c.cids.isActive(held), "not retired while the revalidation needs it")
            assertEquals(PathState.Validated, old.state)
            c.onRevalidateDue(old)
            assertEquals(PathState.Validating, old.state, "validated again when due")
            assertTrue(old.challengePending)
        } finally {
            p.close()
        }
        val (r, e) = connected()
        try {
            val target = probed(r, e, heard = true)
            val old = e.paths.active
            e.switchPath(target.id, r.now) // no revalidation of the old path: its peer ID is retired at once
            assertNull(old.peerCid)
            assertTrue(e.cids.takeRetireFrames().isNotEmpty(), "the old path's ID is retired")
        } finally {
            r.close()
        }
        val (q, d) = connected()
        try {
            val stale = probed(q, d, heard = false)
            assertNotNull(stale.peerCid)
            stale.state = PathState.Failed
            d.onRevalidateDue(stale)
            assertNull(stale.peerCid, "a failed path gives its peer ID back")
        } finally {
            q.close()
        }
    }
}
