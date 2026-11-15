// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.CollectingHandler
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EcnState
import io.kuicksilver.quic.PREFERRED_SOCKET
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.core.Path
import io.kuicksilver.quic.wire.FrameDecoder
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.WireReader
import io.kuicksilver.tls.TlsRole
import java.util.IdentityHashMap

/**
 * The path, ECN, address, version and Stateless Reset invariants of the connection fuzzer, checked on every datagram an
 * [EndpointNet] carries and after every round ([round]). Each names the rule it enforces:
 *
 * - PMTU (RFC 8899 section 3, RFC 9000 section 14): no datagram but a PMTU probe is larger than its path's MTU, so datagrams above it
 *   never outnumber the probes sent; no datagram exceeds the peer's `max_udp_payload_size`; every path's MTU stays within 1200 and
 *   the configured and peer limits, and never above the largest datagram the network delivered from that side ("PMTU never above
 *   what the path delivers": an ICMP message must not raise it, section 14.2.1) unless the receiving side's program injected ACK
 *   frames (a peer acknowledging what never arrived); a client datagram carrying an Initial is at least 1200 bytes (section 14.1).
 *   The window check of section 3 is in [MtuCheckedCc].
 * - ECN (RFC 9000 section 13.4): no datagram is ECT-marked from a socket that does not mark or on a path whose validation failed
 *   or was disabled ("If validation fails, then the endpoint MUST disable ECN"); the counts a receiver reports never decrease and
 *   never exceed what the network delivered with each codepoint; no path is validated as capable when no marked datagram of its
 *   side arrived marked (a bleaching, remarking or ECT-dropping path), barring injected ACK frames.
 * - Stateless Reset (RFC 9000 section 10.3): a connection is reset only after a datagram ending in the token of a connection ID
 *   it used, not retired, towards the address the datagram came from; such a datagram of at least 21 bytes to an open connection
 *   always ends it (draining); a draining connection sends nothing; an endpoint never answers a reset of one of its connections
 *   with a reset, and every reset it sends is smaller than its trigger, one byte smaller for a trigger of 43 bytes or less
 *   (sections 10.3 and 10.3.3).
 * - Addresses (RFC 9000 sections 8.1, 9.3, 9.5, 9.6): the server sends at most three times the bytes it received to an address
 *   it has not validated; no connection ID goes out from two local sockets, and a client's to two server addresses; the client
 *   talks to the preferred address only once the handshake is confirmed, sends it non-probing packets only after validating it,
 *   moves there only validated and never to an address it was not offered; the server sends non-probing packets from its
 *   preferred address only once it moved there, on a validated path.
 * - Retry and Version Negotiation (RFC 9000 sections 6.2, 17.2.5; RFC 9368 section 4): the client acts on at most one Retry and
 *   one Version Negotiation, on neither after any other server packet, carries the Retry token in every later Initial, and never
 *   completes a handshake after acting on a forged Version Negotiation when the server supports its original version.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ConnectionInvariants(
    /** The packets are NullCryptoProvider's (plaintext): frames can be read. */
    private val plaintext: Boolean,
    private val serverVersions: List<VersionProfile>,
) : EndpointNet.Observer {
    lateinit var net: EndpointNet

    private companion object {
        /** `KUICKSILVER_FUZZ_TRACE=1`: every datagram on standard output (debugging one input). */
        val TRACE = System.getenv("KUICKSILVER_FUZZ_TRACE") == "1"
    }

    /** HandshakeCompleted seen per side. */
    val completed = BooleanArray(2)

    /** The program injected frames sealed by this side that may acknowledge anything (ACK frames, raw bytes). */
    val fakeFrames = BooleanArray(2)

    private val confirmed = BooleanArray(2)
    private val maxDelivered = IntArray(2)
    private val markedArrived = BooleanArray(2)
    private val ecnDelivered = Array(2) { LongArray(4) }
    private val lastEcnCounts = Array(2) { LongArray(3) }
    private val over = IdentityHashMap<ConnectionCore, Int>()

    /** Per side: connection ID (hex) -> local sockets it went out from; the client's -> server addresses it went to. */
    private val dcidSockets = Array(2) { HashMap<String, HashSet<Int>>() }
    private val dcidDestinations = HashMap<String, HashSet<InetSocketAddress>>()

    /** Per side: (connection ID hex, remote address, local address) of every datagram sent. */
    private val used = Array(2) { LinkedHashSet<Triple<String, InetSocketAddress, InetSocketAddress>>() }

    /** Per side: every reset token of the peer it ever held, by the hex of its connection ID. */
    private val seenTokens = Array(2) { LinkedHashMap<String, ByteArray>() }

    /** A valid reset reached the side in the current round ([beginRound] clears it): only then may the side close for one. */
    private val validResetSeen = BooleanArray(2)

    /** A reset with a token the side used, but from an address it never sent that ID to, reached it in the current datagram. */
    private var pendingStranger = -1
    private var pendingValidReset = -1
    private var stateBefore: ConnectionState? = null

    private val sentTo = HashMap<InetSocketAddress, Long>()
    private val receivedFrom = HashMap<InetSocketAddress, Long>()
    private val trusted = HashSet<InetSocketAddress>()

    private var serverMoved = false
    private var retryLocked = false
    private var lockedRetryScid: String? = null
    private var vnLocked = false
    private var lockedVn: List<Int>? = null
    private var firstVn: List<Int>? = null
    private val forgedVnLists = ArrayList<List<Int>>()
    private var forgedRetries = 0

    private val hv = PacketHeaderView()

    private fun fail(msg: String): Nothing = throw IllegalStateException(msg)

    private fun name(side: Int) = if (side == 0) "client" else "server"

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun pathFor(
        c: ConnectionCore,
        socket: PathId,
        remote: InetSocketAddress,
    ): Path? = c.paths.all.firstOrNull { it.socket == socket && it.isRemote(remote) }

    /** The local address of [side] on [socket]. */
    private fun local(
        side: Int,
        socket: PathId,
    ): InetSocketAddress =
        if (side == 0) {
            net.clientAddress(socket)
        } else if (socket == PREFERRED_SOCKET) {
            EndpointNet.PREFERRED
        } else {
            EndpointNet.SERVER
        }

    // ---- datagrams ----

    override fun sent(
        side: Int,
        c: ConnectionCore,
        f: Flight,
        socket: PathId,
    ) {
        val size = f.bytes.size
        if (c.state == ConnectionState.Draining) fail("${name(side)} sent a $size-byte datagram while draining (RFC 9000 section 10.2.2)")
        if (c.state == ConnectionState.Confirmed) confirmed[side] = true
        val path = pathFor(c, socket, f.to)
        // ECN marks only from a marking socket, on a path still testing or capable (RFC 9000 section 13.4.2.2)
        if (f.ecn != Ecn.NotEct) {
            if (!net.capsOf(side, socket).ecnSend) fail("${name(side)} marked a datagram ${f.ecn} on a socket that does not mark")
            if (path != null && (path.ecn.state == EcnState.Failed || path.ecn.state == EcnState.Disabled)) {
                fail(
                    "${name(
                        side,
                    )} marked a datagram ${f.ecn} on path ${path.id.value} whose ECN is ${path.ecn.state} (RFC 9000 section 13.4.2.2)",
                )
            }
        }
        // RFC 8899 section 3: "A PL MUST NOT send a datagram (other than a probe packet) with a size at the PL that is larger than the
        // current PLPMTU"
        if (path != null && size > path.mtu) {
            val n = (over[c] ?: 0) + 1
            over[c] = n
            if (n > c.pmtudProbesSentForTest) {
                fail(
                    "${name(
                        side,
                    )} sent $n datagrams above their path's MTU (this one $size > ${path.mtu}) but only ${c.pmtudProbesSentForTest} probes",
                )
            }
        }
        c.peerTp?.let {
            if (size >
                it.maxUdpPayloadSize
            ) {
                fail("${name(side)} sent $size bytes, above the peer's max_udp_payload_size ${it.maxUdpPayloadSize}")
            }
        }
        val b = PacketBuffer.of(f.bytes)
        try {
            if (!PacketHeaderCodec.parse(b, 0, size, c.remoteCid.length, hv)) return
            val dcid = ByteArray(hv.dcidLen) { b[hv.dcidOff + it] }
            if (side == 0 && hv.type == PacketType.Initial) {
                if (size < 1200) fail("client Initial datagram of $size bytes (RFC 9000 section 14.1: at least 1200)")
                if (c.retryReceivedForTest && hv.tokenLen == 0) fail("client Initial without the Retry token (RFC 9000 section 8.1.2)")
            }
            val key = hex(dcid)
            if (TRACE) {
                println(
                    "t=${net.now} ${name(
                        side,
                    )} sends ${hv.type} ${f.from}->${f.to} sock ${socket.value} ${size}B ${f.ecn} dcid $key${frames(b, size)}" +
                        " paths ${c.paths.all.map {
                            "${it.id.value}:${it.socket.value}:${it.remote}:${it.state}:${it.mtu}"
                        }} active ${c.path.id.value}" +
                        " peers ${c.cids.peerStateForTest()}",
                )
            }
            used[side] += Triple(key, f.to, f.from)
            noteTowards(side, key, f.to)
            if (hv.type == PacketType.OneRtt) {
                try {
                    cidReuse(side, key, socket, f.to)
                } catch (e: IllegalStateException) {
                    fail(
                        "${e.message}; this one to ${f.to}${frames(
                            b,
                            size,
                        )}, paths ${c.paths.all.map { "${it.id.value}:${it.socket.value}:${it.remote}:${it.state}" }}",
                    )
                }
            }
            if (side == 1) amplification(c, f)
            if (plaintext && hv.type == PacketType.OneRtt) preferredRules(side, c, f, socket, b)
        } finally {
            b.close()
        }
    }

    /** RFC 9000 section 9.5: "An endpoint MUST NOT reuse a connection ID when sending from more than one local address", nor a client to more than one destination. */
    private fun cidReuse(
        side: Int,
        dcid: String,
        socket: PathId,
        to: InetSocketAddress,
    ) {
        val sockets = dcidSockets[side].getOrPut(dcid) { HashSet() }
        sockets += socket.value
        if (sockets.size > 1) fail("${name(side)} sent connection ID $dcid from sockets $sockets (RFC 9000 section 9.5)")
        if (side == 0) {
            val dests = dcidDestinations.getOrPut(dcid) { HashSet() }
            dests += to
            if (dests.size > 1) fail("client sent connection ID $dcid to $dests (RFC 9000 section 9.5)")
        }
    }

    /** RFC 9000 sections 8.1 and 9.3: three times what an unvalidated address sent, at most. */
    private fun amplification(
        c: ConnectionCore,
        f: Flight,
    ) {
        val a = f.to
        if (a in trusted) return
        if (c.paths.all.any { it.isRemote(a) && it.amplification.validated }) {
            trusted += a
            return
        }
        val sent = (sentTo[a] ?: 0L) + f.bytes.size
        sentTo[a] = sent
        val received = receivedFrom[a] ?: 0L
        if (sent > 3 * received) fail("server sent $sent bytes to unvalidated $a, which sent $received (RFC 9000 section 8.1)")
    }

    /** RFC 9000 section 9.6: probing only towards an unvalidated preferred address, non-probing from it only after the move. */
    private fun preferredRules(
        side: Int,
        c: ConnectionCore,
        f: Flight,
        socket: PathId,
        b: PacketBuffer,
    ) {
        val toPreferred = side == 0 && f.to == EndpointNet.PREFERRED
        val fromPreferred = side == 1 && socket == PREFERRED_SOCKET
        if (!toPreferred && !fromPreferred) return
        if (toPreferred &&
            !confirmed[0]
        ) {
            fail("client sent to the preferred address before the handshake was confirmed (RFC 9000 section 9.6.1)")
        }
        val pnLen = (f.bytes[0].toInt() and 3) + 1
        val start = hv.pnOffset + pnLen
        val end = f.bytes.size - 16
        if (end <= start) return
        val r = WireReader(b, start, end)
        val h = CollectingHandler()
        try {
            FrameDecoder.decode(r, PacketType.OneRtt, h)
        } catch (_: Exception) {
            return // frames the receiver would refuse (an injection): no verdict on them
        }
        if (r.probingOnly) return
        if (toPreferred) {
            val p = pathFor(c, socket, f.to)
            if (p == null || p.state != PathState.Validated) {
                fail(
                    "client sent a non-probing packet ${frameNames(
                        h,
                    )} to the preferred address before validating it (RFC 9000 section 9.6.2)",
                )
            }
        } else if (!c.leftOriginalAddress) {
            fail(
                "server sent a non-probing packet ${frameNames(
                    h,
                )} from its preferred address to ${f.to} before moving there (active path " +
                    "${c.path.id.value} on socket ${c.path.socket.value}, ${c.path.state}; RFC 9000 section 9.6.2)",
            )
        }
    }

    /** The frames of the 1-RTT packet in [b] (header in [hv]) when the packets are plaintext, for failure messages. */
    private fun frames(
        b: PacketBuffer,
        size: Int,
    ): String {
        if (!plaintext || hv.type != PacketType.OneRtt) return ""
        val start = hv.pnOffset + (b[0].toInt() and 3) + 1
        val h = CollectingHandler()
        try {
            FrameDecoder.decode(WireReader(b, start, size - 16), PacketType.OneRtt, h)
        } catch (_: Exception) {
            return " (undecodable)"
        }
        return " " + h.frames.joinToString(",", "[", "]") { it.toString().take(60) }
    }

    private fun frameNames(h: CollectingHandler): String = h.frames.joinToString(",", "[", "]") { it::class.simpleName ?: "?" }

    override fun delivered(
        side: Int,
        f: Flight,
    ) {
        val size = f.bytes.size
        if (TRACE) println("t=${net.now} ${name(side)} gets ${f.from}->${f.to} ${size}B ${f.ecn}")
        if (side == 1) receivedFrom[f.from] = (receivedFrom[f.from] ?: 0L) + size
        if (size > maxDelivered[1 - side]) maxDelivered[1 - side] = size
        ecnDelivered[side][f.ecn.ordinal]++
        if (f.ecn == Ecn.Ect0 || f.ecn == Ecn.Ce) markedArrived[1 - side] = true
        val c = net.core(side)
        pendingValidReset = -1
        stateBefore = c?.state
        pendingStranger = if (c != null && strangerReset(side, c, f)) side else -1
        if (c != null && validReset(side, c, f)) {
            validResetSeen[side] = true
            pendingValidReset = side
        } else if (c != null && size >= 21 && resetShaped(side, c, f)) {
            QuicReach.hit("reset.invalidIgnored")
        }
    }

    override fun handled(
        side: Int,
        f: Flight,
    ) {
        if (pendingStranger == side) {
            pendingStranger = -1
            val c = net.core(side)
            if (c != null && c.state != ConnectionState.Draining &&
                c.state != ConnectionState.Closed
            ) {
                QuicReach.hit("reset.strangerIgnored")
            }
        }
        if (pendingValidReset != side) return
        pendingValidReset = -1
        val c = net.core(side) ?: return
        val registered = c in net.endpoint(side).connections() || c.state == ConnectionState.Closed
        val open =
            stateBefore == ConnectionState.Handshaking || stateBefore == ConnectionState.Established ||
                stateBefore == ConnectionState.Confirmed || stateBefore == ConnectionState.Closing
        // the tokens of an address the connection still has a path to: an address it left is no longer one it "recently sent" to
        // (section 10.3.1), and the endpoint routes a reset by the paths' addresses
        val onPath = c.paths.all.any { it.isRemote(f.from) }
        if (!registered || !open || !onPath || f.bytes.size < 21) return
        if (c.state != ConnectionState.Draining && c.state != ConnectionState.Closed) {
            fail(
                "${name(
                    side,
                )} in $stateBefore did not take a valid ${f.bytes.size}-byte Stateless Reset from ${f.from} (RFC 9000 section 10.3.1)" +
                    " [examined ${net.endpoint(
                        side,
                    ).resetCandidatesExaminedForTest}, invalid ${c.invalidResets}, remotes ${c.registeredRemotes}]",
            )
        }
    }

    override fun stateless(
        side: Int,
        trigger: Flight,
        answer: ByteArray,
    ) {
        if (answer[0].toInt() and 0x80 != 0) return // Retry, Version Negotiation, an Initial close
        QuicReach.hit("reset.sent")
        val n = trigger.bytes.size
        if (answer.size >=
            n
        ) {
            fail("${name(side)} answered a $n-byte datagram with a ${answer.size}-byte Stateless Reset (RFC 9000 section 10.3.3)")
        }
        if (n <= 43 && answer.size != n - 1) {
            fail(
                "${name(
                    side,
                )} answered a $n-byte datagram with a ${answer.size}-byte Stateless Reset (RFC 9000 section 10.3: one byte shorter)",
            )
        }
        val c = net.core(side)
        if (c != null &&
            validReset(side, c, trigger)
        ) {
            fail("${name(side)} answered a Stateless Reset of its own connection with one (RFC 9000 section 10.3)")
        }
    }

    /** The datagram ends with the token of a connection ID [side] holds, used towards the address the datagram came from. */
    private fun validReset(
        side: Int,
        c: ConnectionCore,
        f: Flight,
    ): Boolean {
        if (f.bytes.size < 17) return false
        val tail = f.bytes.copyOfRange(f.bytes.size - 16, f.bytes.size)
        for ((cid, token) in c.cids.peerTokensForTest()) {
            if (token == null || !token.contentEquals(tail)) continue
            if (f.from in towards(side, hex(cid.toByteArray()))) return true
        }
        return false
    }

    /**
     * The remote addresses [side] sent the peer's ID [key] to, as the engine remembers them for its token (RFC 9000 section 10.3.1,
     * "recently sent"; ConnectionIdManager's ring of SENT_TOWARDS addresses: a known one stays, a new one evicts the oldest).
     */
    private fun towards(
        side: Int,
        key: String,
    ): List<InetSocketAddress> = rings[side][key] ?: emptyList()

    private val rings = Array(2) { HashMap<String, ArrayDeque<InetSocketAddress>>() }

    private fun noteTowards(
        side: Int,
        key: String,
        to: InetSocketAddress,
    ) {
        val r = rings[side].getOrPut(key) { ArrayDeque() }
        if (to in r) return
        r.addLast(to)
        if (r.size > 4) r.removeFirst()
    }

    /** The datagram ends with the token of an ID [side] used, but towards other addresses than its source. */
    private fun strangerReset(
        side: Int,
        c: ConnectionCore,
        f: Flight,
    ): Boolean {
        if (f.bytes.size < 21) return false
        val tail = f.bytes.copyOfRange(f.bytes.size - 16, f.bytes.size)
        for ((cid, token) in c.cids.peerTokensForTest()) {
            if (token == null || !token.contentEquals(tail)) continue
            val t = towards(side, hex(cid.toByteArray()))
            if (t.isNotEmpty() && f.from !in t) return true
        }
        return false
    }

    /** The datagram ends with any token [side] holds or held. */
    private fun resetShaped(
        side: Int,
        c: ConnectionCore,
        f: Flight,
    ): Boolean {
        val tail = f.bytes.copyOfRange(f.bytes.size - 16, f.bytes.size)
        return seenTokens[side].values.any { it.contentEquals(tail) } ||
            c.cids.peerTokensForTest().any { it.second?.contentEquals(tail) == true }
    }

    /** A forged reset's token and its source and destination: [variant] as [ConnProgram.E_RESET] lists them. */
    fun resetToken(
        side: Int,
        c: ConnectionCore,
        variant: Int,
    ): Triple<ByteArray, InetSocketAddress, InetSocketAddress>? {
        val held = c.cids.peerTokensForTest().mapNotNull { (cid, t) -> t?.let { hex(cid.toByteArray()) to it } }
        val activeRemote = c.path.remote
        val activeLocal = local(side, c.path.socket)
        return when (variant) {
            1 -> {
                val heldKeys = held.map { it.first }.toSet()
                seenTokens[side].entries.firstOrNull { it.key !in heldKeys }?.let { Triple(it.value, activeRemote, activeLocal) }
            }

            2 -> {
                held.firstOrNull { (k, _) -> used[side].none { it.first == k } }?.let { Triple(it.second, activeRemote, activeLocal) }
            }

            3 -> {
                Triple(ByteArray(16) { (it * 7 + 1).toByte() }, activeRemote, activeLocal)
            }

            else -> {
                for ((k, t) in held) {
                    val u = used[side].lastOrNull { it.first == k } ?: continue
                    return Triple(t, u.second, u.third)
                }
                null
            }
        }
    }

    /** An address that [side] never talked to, on the peer's side of the network. */
    fun stranger(side: Int): InetSocketAddress = if (side == 0) EndpointNet.STRANGER else InetSocketAddress("10.0.9.9", 50000)

    fun forgedRetry(bytes: ByteArray) {
        forgedRetries++
        bytes.size
    }

    fun forgedVn(
        bytes: ByteArray,
        variant: Int,
    ) {
        if (variant == 0) return // the server's own, again
        val list = ArrayList<Int>()
        var i = 1 + 4 + 1 + (bytes[5].toInt() and 0xff)
        i += 1 + (bytes[i].toInt() and 0xff)
        while (i + 4 <= bytes.size) {
            list += ((bytes[i].toInt() and 0xff) shl 24) or ((bytes[i + 1].toInt() and 0xff) shl 16) or
                ((bytes[i + 2].toInt() and 0xff) shl 8) or (bytes[i + 3].toInt() and 0xff)
            i += 4
        }
        forgedVnLists += list
    }

    // ---- events and rounds ----

    fun event(
        side: Int,
        c: ConnectionCore,
        e: ConnectionEvent,
    ) {
        if (TRACE) println("t=${net.now} ${name(side)} event $e active ${c.path.id.value} peers ${c.cids.peerStateForTest()}")
        when (e) {
            is ConnectionEvent.HandshakeCompleted -> {
                completed[side] = true
                if (side == 0) {
                    val acted = c.receivedVnVersions?.toList()
                    if (acted != null && acted in forgedVnLists && c.config.firstVersion in serverVersions) {
                        fail("client completed the handshake after acting on a forged Version Negotiation $acted (RFC 9368 section 4)")
                    }
                }
            }

            is ConnectionEvent.Closed -> {
                if (e.reason is QuicException.ConnectionLost.NoViablePath) QuicReach.hit("migration.noViablePath")
                if (e.reason is QuicException.ConnectionLost.StatelessReset) {
                    if (!validResetSeen[side]) {
                        fail(
                            "${name(side)} was reset without a valid Stateless Reset in that round (RFC 9000 section 10.3.1)",
                        )
                    }
                    QuicReach.hit("reset.recognised")
                }
                val r = e.reason
                if (side == 0 && r is QuicException.ConnectionLost.TransportClosed && r.code == TransportError.VERSION_NEGOTIATION_ERROR) {
                    QuicReach.hit("vn.downgradeRefused")
                }
            }

            is ConnectionEvent.PathFailed -> {
                if (side == 0 && c.peerTp?.preferredAddressPresent == true) QuicReach.hit("preferred.failed")
            }

            is ConnectionEvent.PathValidated -> {
                if (side == 0) QuicReach.hit("migration.validated")
            }

            else -> {}
        }
    }

    /** Before every round. */
    fun beginRound() {
        validResetSeen.fill(false)
    }

    /** After every round. */
    fun round() {
        for (side in 0..1) {
            val c = net.core(side) ?: continue
            if (c.state == ConnectionState.Confirmed) confirmed[side] = true
            for ((cid, t) in c.cids.peerTokensForTest()) if (t != null) seenTokens[side].getOrPut(hex(cid.toByteArray())) { t }
            pathRules(side, c)
            ecnCounts(side, c)
        }
        clientRules(net.client)
        net.serverCore?.let { s ->
            // the move itself needs a validated path at the preferred address (section 9.6.2); later paths there (a NAT rebinding of the
            // client) may be unvalidated, as any migration's (section 9.3)
            if (!serverMoved && s.leftOriginalAddress) {
                serverMoved = true
                if (s.paths.all.none { it.socket == PREFERRED_SOCKET && it.state == PathState.Validated }) {
                    fail("server moved to its preferred address without a validated path there (RFC 9000 section 9.6.2)")
                }
            }
        }
        val ptb = net.server.ptbAccepted + net.clientEp.ptbAccepted
        if (ptb > 0) QuicReach.hit("pmtud.ptbAccepted")
        if (net.server.ptbIgnored + net.clientEp.ptbIgnored > 0) QuicReach.hit("pmtud.ptbIgnored")
        if (forgedRetries > 0 && net.client.retryReceivedForTest.not() && net.client.anyPeerPacket) QuicReach.hit("retry.forgedIgnored")
    }

    private fun pathRules(
        side: Int,
        c: ConnectionCore,
    ) {
        val peerMax = c.peerTp?.maxUdpPayloadSize
        // one path per local socket and peer address (the handshake-time candidate aside, which holds an address the active path left)
        val pairs = HashSet<Triple<Int, io.kuicksilver.quic.core.AddressClass.IpKey, Int>>()
        for (p in c.paths.all) {
            if (p.handshakeCandidate) continue
            if (!pairs.add(Triple(p.socket.value, p.remoteKey, p.remote.port))) {
                fail(
                    "${name(
                        side,
                    )} has two paths from socket ${p.socket.value} to ${p.remote}: ${c.paths.all.map {
                        "${it.id.value}:${it.socket.value}:${it.remote}:${it.state}"
                    }}",
                )
            }
        }
        for (p in c.paths.all) {
            if (p.mtu < 1200) fail("${name(side)} path ${p.id.value} has MTU ${p.mtu} < 1200 (RFC 9000 section 14)")
            if (p.mtu > c.config.maxUdpPayloadSize) fail("${name(side)} path ${p.id.value} MTU ${p.mtu} above our own limit")
            if (peerMax != null &&
                p.mtu > peerMax
            ) {
                fail("${name(side)} path ${p.id.value} MTU ${p.mtu} above the peer's max_udp_payload_size $peerMax")
            }
            if (!fakeFrames[1 - side] && p.mtu > maxOf(1200, maxDelivered[side])) {
                fail(
                    "${name(
                        side,
                    )} path ${p.id.value} MTU ${p.mtu} above the largest datagram the network delivered from it (${maxDelivered[side]})",
                )
            }
            // every path of a socket that sets DF runs DPLPMTUD (RFC 9000 section 14.2: "An endpoint SHOULD use DPLPMTUD"; section
            // 14.3: an MPS "for each combination of local and remote IP addresses"), and every path of a marking socket validates ECN
            // (section 13.4.2: "for each new connection, when switching to a server's preferred address, and on active connection
            // migration to a new path")
            val caps = net.capsOf(side, p.socket)
            if (caps.df && c.config.pmtud && p.pmtud == null && p.state != PathState.Closed) {
                fail("${name(side)} path ${p.id.value} (socket ${p.socket.value}, to ${p.remote}) runs no DPLPMTUD on a socket with DF")
            }
            if (caps.ecnSend && p.ecn.state == EcnState.Disabled && p.state != PathState.Closed) {
                fail("${name(side)} path ${p.id.value} (socket ${p.socket.value}, to ${p.remote}) does not use ECN on a marking socket")
            }
            if (p.ecn.state == EcnState.Capable && !markedArrived[side] && !fakeFrames[1 - side]) {
                fail(
                    "${name(
                        side,
                    )} path ${p.id.value} validated ECN though no marked datagram of it arrived marked (RFC 9000 section 13.4.2.1)",
                )
            }
        }
    }

    private fun ecnCounts(
        side: Int,
        c: ConnectionCore,
    ) {
        val counts = c.ecnReceivedForTest()
        val last = lastEcnCounts[side]
        val delivered = ecnDelivered[side]
        val codepoints = arrayOf(Ecn.Ect0, Ecn.Ect1, Ecn.Ce)
        for (i in 0 until 3) {
            if (counts[i] < last[i]) fail("${name(side)}'s ECN count $i went down from ${last[i]} to ${counts[i]}")
            if (counts[i] > 2 * delivered[codepoints[i].ordinal]) {
                fail(
                    "${name(
                        side,
                    )} counts ${counts[i]} ${codepoints[i]} packets, more than the network delivered (${delivered[codepoints[i].ordinal]} datagrams)",
                )
            }
            last[i] = counts[i]
        }
    }

    private fun clientRules(c: ConnectionCore) {
        if (c.role != TlsRole.Client) return
        for (p in c.paths.all) {
            if (p.remote != EndpointNet.SERVER && p.remote != EndpointNet.PREFERRED) {
                fail("client has a path to ${p.remote}, an address it neither dialled nor was offered (RFC 9000 section 9.6)")
            }
        }
        if (c.path.remote == EndpointNet.PREFERRED && c.path.state != PathState.Validated) {
            fail("client moved to the preferred address before validating it (RFC 9000 section 9.6.2)")
        }
        // section 17.2.5.2: at most one Retry, none after another server packet; section 6.2: likewise for Version Negotiation
        val retry = c.retryScid?.toByteArray()?.let { hex(it) }
        if (retryLocked && retry != lockedRetryScid) fail("client acted on a Retry after it had processed one or another server packet")
        if (!retryLocked && (c.anyPeerPacket || retry != null)) {
            retryLocked = true
            lockedRetryScid = retry
        }
        val vn = c.receivedVnVersions?.toList()
        if (firstVn != null && vn != firstVn) fail("client acted on a second Version Negotiation: $firstVn, then $vn")
        if (firstVn == null) firstVn = vn
        if (vnLocked && vn != lockedVn) fail("client acted on a Version Negotiation after another server packet")
        if (!vnLocked && (c.anyPeerPacket || c.retryScid != null)) {
            vnLocked = true
            lockedVn = vn
        }
    }

    /** At the end of the run. */
    fun finish() {
        round()
    }
}
