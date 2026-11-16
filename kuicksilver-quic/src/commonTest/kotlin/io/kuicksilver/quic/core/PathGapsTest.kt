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
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

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
        val atCut =
            ps.add(
                PathId.Initial,
                InetSocketAddress("10.0.2.2", 1),
                NewReno(),
                333.milliseconds,
                abandonValidatingHeardBefore = TimeMark(2_000),
            )
        assertNull(atCut, "heard from at the cut-off itself: not silent since")
        others[1].lastReceivedAt = TimeMark(1_500)
        val evicting =
            ps.add(
                PathId.Initial,
                InetSocketAddress("10.0.2.3", 1),
                NewReno(),
                333.milliseconds,
                abandonValidatingHeardBefore = TimeMark(2_000),
            )
        assertNotNull(evicting)
        assertFalse(others[1] in ps.all, "the validation silent since before the cut-off gave its slot")
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
     * in a previous PATH_CHALLENGE frame." The RFC does not say whether a challenge of a validation that was started over still counts;
     * we take the stricter reading, a choice the RFC does not require: only the current validation's challenges are answered, so the
     * answer to one sent before the restart (a new address, a revalidation) does not complete it.
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

    /** The server of a confirmed pair, a few steps on. */
    private fun serverOf(p: EndpointPair): ConnectionCore {
        val c = p.connect()
        assertTrue(p.confirmed(c))
        repeat(5) { p.step() }
        return p.server.connections().single()
    }

    private fun addValidated(
        s: ConnectionCore,
        socket: PathId,
        a: InetSocketAddress,
    ): Path {
        val q = s.paths.add(socket, a, s.config.congestionController(), s.config.newPathInitialRtt, evict = false)!!
        q.state = PathState.Validated
        q.validatedAt = s.now
        q.lastReceivedAt = s.now
        s.paths.lastValidated = q
        return q
    }

    /** Retires spare peer IDs of [s] until [keep] are left. */
    private fun leaveSpares(
        s: ConnectionCore,
        keep: Int,
    ) {
        fun spares() = s.cids.peerStateForTest().count { it.substringAfterLast(':').isEmpty() }
        while (spares() > keep) s.cids.releasePathPeer(s.cids.takePathPeer()!!)
    }

    /**
     * A re-validation under way on the path a revert goes back to, which has no ID it may send with: it cannot run while nothing can
     * leave, so it is postponed and starts once the client gives a new ID (RFC 9000 sections 9.3.3 and 9.5).
     */
    @Test fun negative_aRevalidationOnARevertWaitingForAnIdStartsWithTheId() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val failed = s.paths.active
            val a = InetSocketAddress("10.0.0.8", 40008)
            addValidated(s, io.kuicksilver.quic.PREFERRED_SOCKET, a)
            val k = s.paths.add(failed.socket, a, s.config.congestionController(), s.config.newPathInitialRtt, evict = false)!!
            k.local = failed.local
            s.startValidation(k)
            k.validatedAt = s.now - 1.seconds
            k.lastReceivedAt = s.now
            leaveSpares(s, 0)
            s.onPathFailed(failed)
            assertSame(k, s.paths.active)
            assertTrue(k.waitsForPeerCid)
            assertEquals(PathState.Validated, k.state, "postponed: nothing can be sent")
            assertFalse(k.challengePending)
            val frame =
                io.kuicksilver.native.PacketBuffer
                    .of(ByteArray(8) { 0x66 } + ByteArray(16) { 0x44 })
            try {
                s.onNewConnectionId(40, 0, frame, 0, 8, 8)
            } finally {
                frame.close()
            }
            assertFalse(k.waitsForPeerCid)
            assertEquals(PathState.Validating, k.state, "the postponed validation starts with the ID")
            assertTrue(k.challengePending)
            assertFalse(k.revalidateOnceSending, "started once: not again at the next switch there")
        } finally {
            p.close()
        }
    }

    /**
     * A failed active path on the server reverts to the last validated peer address (RFC 9000 section 9.3.2) through the path already
     * there for that pair; a re-validation of it under way goes on when it can send (a spare ID is left).
     */
    @Test fun negative_aRevalidationUnderWayGoesOnAfterARevert() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val failed = s.paths.active
            val a = InetSocketAddress("10.0.0.8", 40008)
            addValidated(s, io.kuicksilver.quic.PREFERRED_SOCKET, a)
            val k = s.paths.add(failed.socket, a, s.config.congestionController(), s.config.newPathInitialRtt, evict = false)!!
            k.local = failed.local
            s.startValidation(k)
            k.lastReceivedAt = s.now
            k.validatedAt = s.now - 1.seconds
            leaveSpares(s, 1)
            s.onPathFailed(failed)
            assertSame(k, s.paths.active)
            assertFalse(k.waitsForPeerCid, "a spare ID was left")
            assertEquals(PathState.Validating, k.state, "the re-validation under way goes on")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.5: "An endpoint MUST NOT reuse a connection ID when sending from more than one local address." The only
     * validated path left after the active one failed is on another local address of the server, the client changed nothing there, and
     * no spare ID is left: it may become the active path only once it has an ID of its own, so it waits for the client's next one
     * rather than sending with the current ID.
     */
    @Test fun negative_aFallbackOnAnotherLocalAddressNeverTakesTheCurrentId() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val failed = s.paths.active
            val q = addValidated(s, failed.socket, InetSocketAddress("10.0.0.8", 40008))
            q.local = InetSocketAddress("10.0.0.99", 443)
            leaveSpares(s, 0)
            val id = s.remoteCid
            s.onPathFailed(failed)
            assertSame(q, s.paths.active)
            assertTrue(q.waitsForPeerCid, "no ID it may send with from that local address")
            val sid = s.openStream(true)
            s.writeStream(sid, ByteArray(500), 0, 500, false)
            p.batch.clear()
            assertEquals(0, s.poll(p.batch, p.now), "nothing leaves with $id from another local address")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.3: "An endpoint only changes the address to which it sends packets in response to the highest-numbered
     * non-probing packet." A probing packet on the active path, however high its number, does not hold back a migration by a
     * non-probing packet numbered below it.
     */
    @Test fun negative_aProbingPacketDoesNotRaiseTheMigrationThreshold() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val a = s.paths.active
            val moved = InetSocketAddress(a.remote.hostname, a.remote.port + 7)
            s.largestNonProbingPn = 100
            s.onPathPacket(a.socket, a.remote, 3000, nonProbing = false, datagramBytes = 1200)
            assertEquals(100, s.largestNonProbingPn, "a probing packet")
            s.rxDcidSeq = 0
            s.activeDcidSeq = 3
            s.onPathPacket(a.socket, moved, 2000, nonProbing = true, datagramBytes = 1200)
            assertTrue(s.paths.active.isRemote(moved), "the highest-numbered non-probing packet moves the connection")
            assertEquals(0, s.activeDcidSeq, "the ID of ours that packet carried (sequence 0) is the one in use on the new path")
        } finally {
            p.close()
        }
    }

    /**
     * A failed path is retried once its standby period ended and a packet arrives there; a path validated since (or never failed) is
     * not validated again on every packet (RFC 9000 section 8.2: validation is for a new or failed address).
     */
    @Test fun negative_onlyAFailedPathIsValidatedAgainAfterItsStandby() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val a = s.paths.active
            val b = InetSocketAddress("10.0.0.8", 40008)
            s.onPathPacket(a.socket, b, 10, nonProbing = false, datagramBytes = 1200) // a probe: path under validation
            val q = assertNotNull(s.paths.byRemote(a.socket, b))
            s.onPathFailed(q)
            assertEquals(PathState.Failed, q.state)
            s.now = q.standbyUntil + 1.seconds
            q.state = PathState.Validated // validated again meanwhile
            q.validatedAt = s.now
            s.onPathPacket(a.socket, b, 11, nonProbing = false, datagramBytes = 1200)
            assertEquals(PathState.Validated, q.state, "a validated path is not validated again on its next packet")
            q.state = PathState.Failed
            s.onPathPacket(a.socket, b, 12, nonProbing = false, datagramBytes = 1200)
            assertEquals(PathState.Validating, q.state, "a failed one after its standby is")
        } finally {
            p.close()
        }
    }

    /**
     * Server: the client's packets on a new path carried the ID of ours it uses on the active path: noted as known and unchanged, the
     * condition under which the current ID may follow the client there (RFC 9000 section 9.5: "it MAY continue to use the current
     * connection ID").
     */
    @Test fun negative_theIdTheClientUsedOnANewPathIsNoted() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val a = s.paths.active
            val b = InetSocketAddress("10.0.0.8", 40008)
            s.activeDcidSeq = 0
            s.rxDcidSeq = 0
            s.onPathPacket(a.socket, b, 10, nonProbing = false, datagramBytes = 1200)
            val q = assertNotNull(s.paths.byRemote(a.socket, b))
            assertTrue(q.peerDcidKnown)
            assertFalse(q.peerChangedDcid)
            s.rxDcidSeq = 1
            s.onPathPacket(a.socket, b, 11, nonProbing = false, datagramBytes = 1200)
            assertTrue(q.peerChangedDcid, "another ID of ours this time")
            val c2 = InetSocketAddress("10.0.0.8", 40010)
            s.rxDcidSeq = -1 // a packet whose ID of ours is not known
            s.onPathPacket(a.socket, c2, 12, nonProbing = false, datagramBytes = 1200)
            val q2 = assertNotNull(s.paths.byRemote(a.socket, c2))
            assertFalse(q2.peerDcidKnown, "nothing shown")
        } finally {
            p.close()
        }
    }

    /**
     * Server: the preferred-address socket went down. With the active path there the connection closes (nothing can leave the
     * address); otherwise the paths there are given up and their peer IDs retired (RFC 9000 section 9.5), the connection staying where
     * it is.
     */
    @Test fun negative_preferredSocketDown() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val q = addValidated(s, io.kuicksilver.quic.PREFERRED_SOCKET, InetSocketAddress("10.0.0.8", 40008))
            val held = assertNotNull(s.cids.takePathPeer())
            q.peerCid = held
            s.cids.takeRetireFrames()
            assertTrue(s.preferredSocketDown())
            assertFalse(q in s.paths.all)
            assertNull(q.peerCid)
            assertEquals(listOf(held.seq), s.cids.takeRetireFrames(), "the path's peer ID is retired")
            p.drain(s)
            assertTrue(
                p.events[s]!!.any { it is io.kuicksilver.quic.ConnectionEvent.PathFailed && it.path == q.id },
                "the path given up is reported",
            )
            assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, s.state)
        } finally {
            p.close()
        }
        val r = EndpointPair()
        try {
            val s = serverOf(r)
            val q = addValidated(s, io.kuicksilver.quic.PREFERRED_SOCKET, InetSocketAddress("10.0.0.8", 40008))
            s.paths.active = q
            assertTrue(s.preferredSocketDown())
            assertTrue(
                s.state == io.kuicksilver.quic.ConnectionState.Closing || s.state == io.kuicksilver.quic.ConnectionState.Closed,
                "the active path's socket is gone: ${s.state}",
            )
        } finally {
            r.close()
        }
    }

    /**
     * The failed active path is a new one (never validated for amplification), and its peer address was validated just now on the
     * preferred-address socket: the connection stays there with the address validated, the anti-amplification limit lifted with it
     * (RFC 9000 section 8: a validated address is no longer limited).
     */
    @Test fun negative_keepingAnAddressValidatedElsewhereLiftsTheAmplificationLimit() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val b = InetSocketAddress("10.0.0.8", 40008)
            s.onPathPacket(s.paths.active.socket, b, 10, nonProbing = false, datagramBytes = 1200)
            val n = assertNotNull(s.paths.byRemote(s.paths.active.socket, b))
            s.paths.active = n
            assertFalse(n.amplification.validated)
            addValidated(s, io.kuicksilver.quic.PREFERRED_SOCKET, b).peerProbed = true
            s.onPathFailed(n)
            assertSame(n, s.paths.active)
            assertEquals(PathState.Validated, n.state)
            assertTrue(n.amplification.validated)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 8.2.1: when the PATH_CHALLENGE went in a datagram smaller than 1200 bytes, its answer validates the address but
     * "the endpoint MUST perform a second path validation by sending a PATH_CHALLENGE frame in a datagram of at least 1200 bytes".
     */
    @Test fun negative_anUndersizedChallengesAnswerStartsASecondValidation() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val b = InetSocketAddress("10.0.0.8", 40008)
            s.onPathPacket(s.paths.active.socket, b, 10, nonProbing = false, datagramBytes = 1200)
            val q = assertNotNull(s.paths.byRemote(s.paths.active.socket, b))
            assertEquals(PathState.Validating, q.state)
            val d = s.newChallengeData(q)
            q.markLastChallengeUndersized()
            q.challengePending = false
            s.onPathResponse(d)
            assertTrue(q.amplification.validated, "the address is validated")
            assertEquals(PathState.Validating, q.state, "the path MTU is not")
            assertTrue(q.challengePending, "a second, full-size PATH_CHALLENGE")
            assertFalse(q.answers(d), "a new validation: the answered data is spent")
        } finally {
            p.close()
        }
    }

    /** RFC 8899 section 3 item 7 and RFC 9002 section 7.2: a new path MTU reaches the congestion controller (its initial window and burst follow the datagram size) and is reported. */
    @Test fun negative_anMtuChangeReachesTheCongestionController() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val a = s.paths.active
            val cc = NewReno()
            a.cc = cc
            a.mtu = 1200
            assertEquals(12_000, cc.sendQuantum)
            s.setMtu(a, 1452)
            assertEquals(1452, a.mtu)
            assertEquals(14_520, cc.sendQuantum, "the initial window of 1452-byte datagrams")
            p.drain(s)
            assertTrue(p.events[s]!!.any { it is io.kuicksilver.quic.ConnectionEvent.MtuUpdated && it.path == a.id })
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 8.2.4 lets a migration abandon an older validation; a probe from a fifth address may take only the slot of a
     * validation silent for the idle period. With three validations heard from just now, a probe with the highest packet number yet is
     * ignored.
     */
    @Test fun negative_aProbeWithAHighPacketNumberDoesNotAbandonLiveValidations() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val a = s.paths.active
            s.largestNonProbingPn = 100
            for (i in 1..3) {
                s.onPathPacket(
                    a.socket,
                    InetSocketAddress("10.0.1.$i", 5000),
                    50L + i,
                    nonProbing = false,
                    datagramBytes = 1200,
                )
            }
            assertEquals(4, s.paths.all.size)
            assertTrue(s.paths.all.count { it.state == PathState.Validating } == 3)
            val fifth = InetSocketAddress("10.0.2.1", 5000)
            s.onPathPacket(a.socket, fifth, 200, nonProbing = false, datagramBytes = 1200)
            assertEquals(4, s.paths.all.size)
            assertNull(s.paths.byRemote(a.socket, fifth), "a probe: the live validations keep their slots")
        } finally {
            p.close()
        }
    }

    /**
     * A switch of the active path (RFC 9000 section 9.3): a handshake-time candidate still open is dropped; the new path no longer
     * waits to validate a stale address once it starts that validation; and whether the client's packets carried another ID of ours on
     * the path left than on this one is known only when both showed one (section 9.5).
     */
    @Test fun negative_switchPathBookkeeping() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)

            fun fresh(i: Int): Path {
                val q = s.paths.add(s.paths.active.socket, InetSocketAddress("10.0.3.$i", 6000), NewReno(), 333.milliseconds, now = s.now)!!
                q.state = PathState.Validated
                q.validatedAt = s.now
                return q
            }
            val k = fresh(9)
            k.handshakeCandidate = true
            s.handshakeCandidate = k
            for ((oldSeq, newSeq, known, changed) in listOf(
                listOf(0L, 0L, 1L, 0L),
                listOf(0L, 1L, 1L, 1L),
                listOf(-1L, 0L, 0L, 0L),
                listOf(0L, -1L, 0L, 0L),
            )) {
                val old = s.paths.active
                val q = fresh(oldSeq.toInt() + 3 * newSeq.toInt() + 5)
                old.lastRxDcidSeq = oldSeq
                old.peerDcidKnown = !(known == 1L)
                q.lastRxDcidSeq = newSeq
                q.revalidateOnceSending = true
                s.switchPath(q, io.kuicksilver.quic.PathChangeReason.PeerMigration, challengeOld = false)
                assertSame(q, s.paths.active)
                assertEquals(known == 1L, old.peerDcidKnown, "known for ($oldSeq, $newSeq)")
                if (known == 1L) assertEquals(changed == 1L, old.peerChangedDcid, "changed for ($oldSeq, $newSeq)")
                assertFalse(q.revalidateOnceSending, "the postponed validation started")
                assertEquals(PathState.Validating, q.state)
                s.paths.remove(old)
            }
            assertNull(s.handshakeCandidate, "the first switch dropped the handshake-time candidate")
            assertFalse(k in s.paths.all)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.3.3: the previously active path is validated again after a migration; its first challenge waits a PTO after
     * the last one there (section 8.2.1), and meanwhile the path keeps its peer ID for it (section 9.5), not retired, the new path taking
     * a spare one.
     */
    @Test fun negative_theOldPathKeepsItsIdForADeferredRevalidation() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val old = s.paths.active
            old.lastChallengeAt = s.now
            val oldPeer = assertNotNull(s.cids.currentPeer)
            val q = s.paths.add(old.socket, InetSocketAddress("10.0.0.1", 40009), NewReno(), 333.milliseconds, now = s.now)!!
            s.switchPath(q, io.kuicksilver.quic.PathChangeReason.PeerMigration, challengeOld = true)
            assertTrue(old.revalidateAt != TimeMark.NEVER, "deferred")
            assertSame(oldPeer, old.peerCid)
            assertTrue(s.cids.isActive(oldPeer), "not retired while the revalidation needs it")
            assertTrue(s.cids.currentPeer !== oldPeer)
        } finally {
            p.close()
        }
    }

    /** A path that failed its validation (not the active one) sends no further PATH_CHALLENGE (RFC 9000 section 8.2.4). */
    @Test fun negative_aFailedPathHasNoChallengePending() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val b = InetSocketAddress("10.0.0.8", 40008)
            s.onPathPacket(s.paths.active.socket, b, 10, nonProbing = false, datagramBytes = 1200)
            val q = assertNotNull(s.paths.byRemote(s.paths.active.socket, b))
            assertTrue(q.challengePending)
            s.onPathFailed(q)
            assertEquals(PathState.Failed, q.state)
            assertFalse(q.challengePending)
            assertTrue(s.paths.nextProbe() !== q)
        } finally {
            p.close()
        }
    }

    /**
     * A revert with every path slot taken gives way a path that is neither the failed one, the last validated one nor validated, and
     * retires its peer ID (RFC 9000 section 9.5); when all are validated, one other than those two.
     */
    @Test fun negative_aRevertWithEverySlotTakenEvictsTheRightPath() {
        for (allValidated in listOf(false, true)) {
            val p = EndpointPair()
            try {
                val s = serverOf(p)
                val failed = s.paths.active
                val last = addValidated(s, io.kuicksilver.quic.PREFERRED_SOCKET, InetSocketAddress("10.0.0.8", 40008))
                val x1 = addValidated(s, failed.socket, InetSocketAddress("10.0.1.1", 50000))
                x1.local = InetSocketAddress("10.0.0.99", 443)
                val x2 = s.paths.add(failed.socket, InetSocketAddress("10.0.1.2", 50000), NewReno(), 333.milliseconds, evict = false)!!
                x2.local = InetSocketAddress("10.0.0.99", 443)
                if (allValidated) {
                    x2.state = PathState.Validated
                    x2.validatedAt = s.now - 1.seconds
                    x1.validatedAt = s.now - 2.seconds
                } else {
                    s.startValidation(x2)
                }
                s.paths.lastValidated = last
                val victim = if (allValidated) x1 else x2
                // a validated path with an ID of its own could take over as it is; only the validating victim holds one
                val id = if (allValidated) null else assertNotNull(s.cids.takePathPeer())
                if (id != null) victim.peerCid = id
                s.cids.takeRetireFrames()
                leaveSpares(s, 0)
                s.cids.takeRetireFrames()
                s.onPathFailed(failed)
                assertEquals(io.kuicksilver.quic.ConnectionState.Confirmed, s.state)
                assertFalse(victim in s.paths.all, "evicted (all validated: $allValidated)")
                assertTrue(last in s.paths.all, "the last validated path stays")
                assertTrue((if (allValidated) x2 else x1) in s.paths.all)
                if (id != null) assertTrue(id.seq in s.cids.takeRetireFrames(), "the evicted path's peer ID is retired")
            } finally {
                p.close()
            }
        }
    }

    /**
     * Server, RFC 9000 section 9.3: the failed active path's address is validated on another path but was not seen within a validation
     * period: the path validates it again (a fresh validation), once; when the address is seen recently again, a later staleness earns
     * its own re-validation, and keeping the path is reported.
     */
    @Test fun negative_aStaleAddressIsValidatedAfreshOncePerStaleness() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val failed = s.paths.active
            val q = addValidated(s, io.kuicksilver.quic.PREFERRED_SOCKET, failed.remote)
            q.peerProbed = true
            q.validatedAt = s.now - 60.seconds
            q.lastReceivedAt = s.now - 60.seconds
            failed.state = PathState.Validating
            failed.challengePending = false
            failed.challengeDeadline = s.now
            s.onPathFailed(failed)
            assertSame(failed, s.paths.active)
            assertEquals(PathState.Validating, failed.state)
            assertTrue(failed.challengePending, "a fresh validation")
            assertTrue(failed.challengeDeadline > s.now)
            q.lastReceivedAt = s.now // seen again
            p.drain(s)
            p.events[s]!!.clear()
            s.onPathFailed(failed)
            assertEquals(PathState.Validated, failed.state)
            p.drain(s)
            assertTrue(p.events[s]!!.any { it is io.kuicksilver.quic.ConnectionEvent.PathValidated && it.path == failed.id })
            q.lastReceivedAt = s.now - 60.seconds // stale again
            q.validatedAt = s.now - 60.seconds
            s.startValidation(failed)
            s.onPathFailed(failed)
            assertSame(failed, s.paths.active)
            assertEquals(PathState.Validating, failed.state, "a new staleness: validated again once more")
        } finally {
            p.close()
        }
    }

    /**
     * PATH_CHALLENGE from a new address (RFC 9000 section 8.2.2): the path made for it counts the datagram toward its
     * anti-amplification budget (section 8.1) and notes the ID of ours the client used there (section 9.5); a queue of owed responses
     * at its hard bound closes the connection rather than leaving a challenge unanswered.
     */
    @Test fun negative_aPathChallengeFromANewAddress() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val b = InetSocketAddress("10.0.0.8", 40008)
            s.activeDcidSeq = 0
            s.rxDcidSeq = 0
            s.onPathChallenge(7, s.paths.active.socket, b, 1200)
            val q = assertNotNull(s.paths.byRemote(s.paths.active.socket, b))
            assertEquals(1200L, q.amplification.received)
            assertTrue(q.peerDcidKnown)
            assertFalse(q.peerChangedDcid)
            assertTrue(q.peerProbed)
        } finally {
            p.close()
        }
        val r = EndpointPair()
        try {
            val s = serverOf(r)
            while (s.paths.responses < Paths.MAX_RESPONSES) s.paths.queueResponse(1, s.paths.active)
            val e =
                kotlin.test.assertFailsWith<io.kuicksilver.quic.wire.QuicWireException> {
                    s.onPathChallenge(8, s.paths.active.socket, s.paths.active.remote, 100)
                }
            assertEquals(io.kuicksilver.quic.TransportError.PROTOCOL_VIOLATION, e.code)
        } finally {
            r.close()
        }
        val f = EndpointPair()
        try {
            val s = serverOf(f)
            for (i in 1..3) {
                s.onPathPacket(
                    s.paths.active.socket,
                    InetSocketAddress("10.0.1.$i", 5000),
                    10L + i,
                    nonProbing = false,
                    datagramBytes = 1200,
                )
            }
            assertEquals(4, s.paths.all.size)
            val before = s.stats.glitchTokensSpent
            s.onPathChallenge(9, s.paths.active.socket, InetSocketAddress("10.0.2.1", 5000), 1200)
            assertNull(s.paths.byRemote(s.paths.active.socket, InetSocketAddress("10.0.2.1", 5000)), "no slot: no path")
            assertEquals(before + 1, s.stats.glitchTokensSpent, "a challenge that cannot be answered costs a glitch token")
        } finally {
            f.close()
        }
    }

    /**
     * The fallback after a failed validation (RFC 9000 section 9.3.2) takes a validated path as it is when it can send there without an
     * ID used from another local address (section 9.5): one that holds an ID of its own, or one on the failed path's own local address
     * where the client showed no other ID (the current one may follow, "MAY continue to use the current connection ID").
     */
    @Test fun negative_aFallbackTakesAValidatedPathThatCanSendThere() {
        for (ownId in listOf(true, false)) {
            val p = EndpointPair()
            try {
                val s = serverOf(p)
                val failed = s.paths.active
                val q = addValidated(s, failed.socket, InetSocketAddress("10.0.0.8", 40008))
                val id = s.remoteCid
                if (ownId) {
                    q.local = InetSocketAddress("10.0.0.99", 443)
                    q.peerCid = assertNotNull(s.cids.takePathPeer())
                } else {
                    q.local = failed.local
                    q.peerDcidKnown = true // the client's packets there carried the ID of ours it uses on the active path
                }
                leaveSpares(s, 0)
                s.onPathFailed(failed)
                assertSame(q, s.paths.active, "switched to (own ID: $ownId)")
                assertFalse(q.waitsForPeerCid, "it can send at once")
                if (!ownId) assertEquals(id, s.remoteCid, "the current ID follows to the same local address")
            } finally {
                p.close()
            }
        }
    }

    /**
     * RFC 9000 section 9.5: "Due to network changes outside the control of its peer, an endpoint might receive packets from a new
     * source address with the same Destination Connection ID field value, in which case it MAY continue to use the current connection
     * ID with the new remote address while still sending from the same local address." The permission rests on having seen the
     * client use that ID from the new address: a validated path on the failed path's local address whose packets showed no ID of ours
     * (unknown, not "unchanged") does not take the current ID; with no spare one it waits for the client's next ID.
     */
    @Test fun negative_aFallbackNeverTakesTheCurrentIdWithoutSeeingTheClientUseIt() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val failed = s.paths.active
            val q = addValidated(s, failed.socket, InetSocketAddress("10.0.0.8", 40008))
            q.local = failed.local
            assertFalse(q.peerDcidKnown)
            assertFalse(q.peerChangedDcid)
            leaveSpares(s, 0)
            val id = s.remoteCid
            s.onPathFailed(failed)
            assertSame(q, s.paths.active)
            assertTrue(q.waitsForPeerCid, "no ID it may use there: the client never showed $id from that address")
            val sid = s.openStream(true)
            s.writeStream(sid, ByteArray(500), 0, 500, false)
            p.batch.clear()
            assertEquals(0, s.poll(p.batch, p.now), "nothing leaves with $id toward that address")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.5 for a path that is not the active one: with no spare ID, the server answers a new client address from the
     * same local address with the current ID only when the client's packets from there carried the ID of ours it uses on the active
     * path; a path whose packets showed no ID gets none.
     */
    @Test fun negative_theCurrentIdGoesToANewAddressOnlyWhenTheClientUsedItThere() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val a = s.paths.active
            leaveSpares(s, 0)
            s.activeDcidSeq = 0
            s.rxDcidSeq = -1
            val unknown = InetSocketAddress("10.0.0.8", 40008)
            s.onPathChallenge(1, a.socket, unknown, 1200)
            val q = assertNotNull(s.paths.byRemote(a.socket, unknown))
            assertNull(s.dcidFor(q), "nothing shown from there: no ID to send with")
            s.rxDcidSeq = 0
            val same = InetSocketAddress("10.0.0.8", 40010)
            s.onPathChallenge(2, a.socket, same, 1200)
            val r = assertNotNull(s.paths.byRemote(a.socket, same))
            assertEquals(s.remoteCid, s.dcidFor(r), "the client used the current ID from there: it may follow")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 9.3.2: the fallback is "the last validated peer address": a validated path whose validation time is unknown
     * ([TimeMark.NEVER]) is not the most recent one.
     */
    @Test fun negative_aValidationOfUnknownTimeIsNotTheMostRecent() {
        val ps = paths()
        val except = ps.active
        val timed = ps.addAt(1)
        timed.state = PathState.Validated
        timed.validatedAt = TimeMark(1_000)
        val unknown = ps.addAt(2)
        unknown.state = PathState.Validated
        assertEquals(TimeMark.NEVER, unknown.validatedAt)
        assertSame(timed, ps.fallback(except))
        timed.state = PathState.Failed
        assertSame(unknown, ps.fallback(except), "still validated: taken when no other is")
    }
}
