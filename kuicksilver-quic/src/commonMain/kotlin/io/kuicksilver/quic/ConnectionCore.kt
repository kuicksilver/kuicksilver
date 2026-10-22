// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.core.AmplificationLimit
import io.kuicksilver.quic.core.CidRegistrar
import io.kuicksilver.quic.core.ConnectionHandshakeSink
import io.kuicksilver.quic.core.ConnectionIdManager
import io.kuicksilver.quic.core.ConnectionLossListener
import io.kuicksilver.quic.core.CryptoStreams
import io.kuicksilver.quic.core.DatagramQueue
import io.kuicksilver.quic.core.DatagramWriter
import io.kuicksilver.quic.core.GlitchBucket
import io.kuicksilver.quic.core.HandshakeDriver
import io.kuicksilver.quic.core.KeyPhase
import io.kuicksilver.quic.core.NoopRegistrar
import io.kuicksilver.quic.core.PacketBuilder
import io.kuicksilver.quic.core.PacketReceiver
import io.kuicksilver.quic.core.Path
import io.kuicksilver.quic.core.Paths
import io.kuicksilver.quic.core.Pmtud
import io.kuicksilver.quic.core.Timers
import io.kuicksilver.quic.core.armBlockedRepeat
import io.kuicksilver.quic.core.buildLocalTp
import io.kuicksilver.quic.core.checkPmtuBlackHoles
import io.kuicksilver.quic.core.checkTlsInput
import io.kuicksilver.quic.core.discardSpace
import io.kuicksilver.quic.core.discardZeroRttKeys
import io.kuicksilver.quic.core.driveTls
import io.kuicksilver.quic.core.ecnCeReceived
import io.kuicksilver.quic.core.ecnPathFailed
import io.kuicksilver.quic.core.enableServerEarlyData
import io.kuicksilver.quic.core.enterClosing
import io.kuicksilver.quic.core.fail
import io.kuicksilver.quic.core.glitch
import io.kuicksilver.quic.core.idleDeadline
import io.kuicksilver.quic.core.installInitialKeys
import io.kuicksilver.quic.core.keepAliveDeadline
import io.kuicksilver.quic.core.largePacketUnanswered
import io.kuicksilver.quic.core.markClosed
import io.kuicksilver.quic.core.nextChallengeDelay
import io.kuicksilver.quic.core.onBlockedRepeatTimer
import io.kuicksilver.quic.core.onHandshakeDatagramDone
import io.kuicksilver.quic.core.onPathFailed
import io.kuicksilver.quic.core.pmtudUpperBound
import io.kuicksilver.quic.core.probeOtherHandshakeSpace
import io.kuicksilver.quic.core.pto
import io.kuicksilver.quic.core.refreshLocalTp
import io.kuicksilver.quic.core.release
import io.kuicksilver.quic.core.releasePathCid
import io.kuicksilver.quic.core.requeueForProbe
import io.kuicksilver.quic.core.revertHandshakeMove
import io.kuicksilver.quic.core.setMtu
import io.kuicksilver.quic.core.settleHandshakeValidated
import io.kuicksilver.quic.core.silentClose
import io.kuicksilver.quic.core.startValidation
import io.kuicksilver.quic.core.switchPath
import io.kuicksilver.quic.core.validationTimeout
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.qlog.QlogWriter
import io.kuicksilver.quic.recovery.LossDetection
import io.kuicksilver.quic.recovery.Pacer
import io.kuicksilver.quic.recovery.RttEstimator
import io.kuicksilver.quic.recovery.SentPacket
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.stream.StreamManager
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.quic.wire.TransportParameters
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.quic.wire.VarInt
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.PacketProtector
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.ResetKey
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.VerifyResult
import kotlin.random.Random

/**
 * The sans-IO state machine of one QUIC connection (ADR-0004): datagrams in through [handleDatagram],
 * datagrams out through [poll], time through [nextTimeout]/[onTimeout], everything else through [nextEvent].
 * Never touches a socket, a clock or a coroutine.
 *
 * This class owns the state and the public API; the internal transitions are extension functions in `core/`:
 * `ConnectionCore.handshake.kt`, `ConnectionCore.paths.kt`, `ConnectionCore.close.kt` and `ConnectionCore.timers.kt`.
 */
@ExperimentalKuicksilverApi
public class ConnectionCore internal constructor(
    /** Whether this core is the client or the server side of the connection. */
    public val role: TlsRole,
    internal val config: QuicConfig,
    internal val tlsConfig: TlsConfig,
    internal val crypto: QuicCrypto,
    remote: InetSocketAddress,
    internal val random: Random,
    now: TimeMark,
    internal val odcid: ConnectionId,
    internal var localCid: ConnectionId,
    internal var remoteCid: ConnectionId,
    startVersion: VersionProfile,
    resetKey: ResetKey?,
    /** Client: whether to resume and send 0-RTT (ADR-0015). */
    internal val earlyMode: io.kuicksilver.tls.EarlyDataState,
    /** Server: the 0-RTT setup, or null when this server does not accept early data. */
    internal val serverEarly: io.kuicksilver.quic.core.ServerEarlyData?,
    // no default arguments: they would add a public synthetic constructor exposing these internal types to the ABI dumps
) {
    /** Where the connection is in its life (RFC 9000 section 10); [ConnectionState.Closed] once its TLS session and keys are freed. */
    public var state: ConnectionState = ConnectionState.Handshaking
        internal set

    /** The QUIC version in use; may change once during a compatible upgrade (RFC 9368). */
    public var version: VersionProfile = startVersion
        internal set
    internal val originalVersion: VersionProfile = startVersion

    /** The DCID the Initial keys are derived from: the original DCID until a Retry replaces it with the server's Retry SCID (RFC 9001 section 5.2). */
    internal var initialKeyCid: ConnectionId = odcid

    /** Client: the SCID of the Retry we accepted; server: our SCID in the Retry we sent. The transport parameters must agree (RFC 9000 section 7.3). */
    internal var retryScid: ConnectionId? = null

    /** Client: the Retry token to put in every Initial; it replaces [initialToken] (RFC 9000 section 17.2.5.3). */
    internal var retryToken: ByteArray? = null

    /** Client: a NEW_TOKEN token from an earlier connection, sent in every Initial until a Retry brings another (RFC 9000 section 8.1.3). */
    internal var initialToken: ByteArray? = null

    /** Server: mints a NEW_TOKEN token bound to an address (RFC 9000 section 8.1.3); null when the endpoint issues none. */
    internal var newTokenMinter: ((InetSocketAddress) -> ByteArray?)? = null

    /** Server: the NEW_TOKEN token to send or resend, and its number ([SentFrames.ID_NEW_TOKEN]); null once acknowledged. */
    internal var newToken: ByteArray? = null
    internal var newTokenSeq = 0L
    internal var sendNewToken = false

    /** Server: the IP addresses tokens were issued for on this connection, at most [MAX_NEW_TOKENS]. */
    internal val newTokenIps = ArrayList<ByteArray>(2)

    /** Client: NEW_TOKEN frames received on this connection; past [NEW_TOKENS_KEPT] each one spends a glitch token. */
    internal var newTokensReceived = 0

    /** Client: tokens received and not yet handed to the endpoint's token store ([takeReceivedTokens]); at most [NEW_TOKENS_KEPT]. */
    internal var receivedTokens: ArrayList<ByteArray>? = null

    /** Server: HANDSHAKE_DONE went out at least once (tests check that NEW_TOKEN never precedes it). */
    internal var handshakeDoneSent = false
    internal val newTokenSendsForTest = ArrayList<ByteArray>()
    internal var newTokenAfterHandshakeDoneForTest = true
    internal val retryReceivedForTest: Boolean get() = retryScid != null && role == TlsRole.Client
    internal var validatedByToken = false
    internal val addressValidatedByHandshakeForTest: Boolean get() = amplification.validated && !validatedByToken
    internal var testForgeRetryScid = false

    /** The paths of this connection (RFC 9000 section 9); the first one is the handshake path on the endpoint's one socket. */
    internal val paths =
        Paths(
            Path(PathId.Initial, remote, PathId.Initial, config.congestionController(), config.initialRtt).also {
                if (role ==
                    TlsRole.Client
                ) {
                    it.amplification.validated = true
                }
            },
        )

    /** The active path: where packets go and whose congestion state, RTT and pacer are in use. */
    internal val path: Path get() = paths.active
    internal val rtt: RttEstimator get() = paths.active.rtt
    internal val cc: CongestionController get() = paths.active.cc
    internal val pacer: Pacer get() = paths.active.pacer
    internal var loss = LossDetection(paths.active.rtt, config, role, ConnectionLossListener(this))

    /** The highest packet number of a non-probing 1-RTT packet; only a higher one moves the connection to its source address (RFC 9000 section 9.3). */
    internal var largestNonProbingPn = -1L

    /** The sequence number of our ID that the 1-RTT packet being processed carries (-1: none of them, or not known yet). */
    internal var rxDcidSeq = -1L

    /** Our ID the peer's packets on the active path carry, by sequence number (-1 until the first 1-RTT packet). */
    internal var activeDcidSeq = -1L
    internal var oneRttSinceRotation = 0
    internal var testInjectPathChallenges = 0
    internal var testInjectPathResponse: Long? = null
    internal var pathResponsesSentForTest = 0
    internal val challengedAddressesForTest = ArrayList<InetSocketAddress>()
    internal var pathChallengesSentForTest = 0

    /** The data of every PATH_CHALLENGE sent, in order (bounded). */
    internal val challengeDataSentForTest = ArrayList<Long>()
    internal val pathCountForTest: Int get() = paths.all.size

    // ---- DPLPMTUD (RFC 8899) ----
    internal var datagramsDroppedSend = 0L

    /** Datagrams of this connection the socket refused (counted by the runtime that sends them). */
    internal var datagramsDroppedSocket = 0L
    internal val ccMtuUpdatesForTest = ArrayList<Int>()
    internal var pmtudProbesSentForTest = 0
    internal val pmtudSearchDoneForTest: Boolean get() = path.pmtud?.searchDone == true

    // ---- ECN (RFC 9000 section 13.4; ADR-0006) ----
    internal var ecnCeEvents = 0L
    internal var ceRecoveryStart: TimeMark = TimeMark.NEVER

    /** The runtime's hook: ECN validation failed on [PathId]; a per-socket marker clears its IP_TOS. */
    internal var onEcnFailed: ((PathId) -> Unit)? = null

    /** Set by the endpoint: the active path's remote address changed (old, new), for its address index. */
    internal var onRemoteChanged: ((InetSocketAddress, InetSocketAddress) -> Unit)? = null

    /** Tells the path what its socket can do; `ecnSend` starts ECN validation (the first ten packets go out ECT(0)). */
    public fun setPathCapabilities(
        path: PathId,
        caps: IoCapabilities,
    ) {
        val p =
            paths.byId(path) ?: return
        p.caps = caps
        if (caps.ecnSend) p.ecn.enable() else p.ecn.disable()
        p.pmtud =
            if (caps.df && config.pmtud) Pmtud(upperBound = pmtudUpperBound()) else null
    }

    internal fun pathCapabilitiesForTest(id: PathId): IoCapabilities? = paths.byId(id)?.caps

    /**
     * The socket [socket] (a path id: the endpoint's socket is [PathId.Initial]) now reports [caps]. Only losses apply to the
     * paths already on it: no ECN marking stops ECN on them, no DF ends PMTUD and drops back to 1200 bytes, fewer GSO segments
     * or a smaller batch shrink theirs. A gain waits for the next path (validation would have to start over).
     */
    internal fun updateSocketCapabilities(
        socket: PathId,
        caps: IoCapabilities,
    ) {
        for (i in 0 until paths.all.size) {
            val p = paths.all[i]
            if (p.socket != socket) continue
            val had = p.caps
            if (had.ecnSend && !caps.ecnSend) p.ecn.socketStoppedMarking()
            if (had.df && !caps.df) {
                p.pmtud = null
                if (p.mtu > 1200) setMtu(p, 1200)
            }
            p.caps =
                IoCapabilities(
                    ecnSend = had.ecnSend && caps.ecnSend,
                    ecnReceive = had.ecnReceive && caps.ecnReceive,
                    gsoMaxSegments = minOf(had.gsoMaxSegments, caps.gsoMaxSegments),
                    gro = had.gro && caps.gro,
                    df = had.df && caps.df,
                    batch = minOf(had.batch, caps.batch),
                )
        }
    }

    /**
     * Validation state of path [id] (RFC 9000 section 8.2); [PathState.Closed] for a path the connection closed or evicted,
     * [PathState.Unknown] for an id it never issued.
     */
    public fun pathState(id: PathId): PathState =
        paths.byId(id)?.state ?: if (id.value in 0 until paths.issuedIds) PathState.Closed else PathState.Unknown

    internal fun ecnReceivedForTest(): LongArray = loss.space(SpaceId.Application).ack.ecnCounts ?: LongArray(3)

    internal fun ecnPeerCountsForTest(): LongArray = loss.space(SpaceId.Application).peerEcn

    // ---- DATAGRAM (RFC 9221) ----

    /** Asked for DATAGRAM frames on every 1-RTT packet with room while the window is open; null sends none. */
    public var datagramSender: DatagramSender? = null
    internal val datagramWriter = DatagramWriter()
    private val datagramQueue = DatagramQueue(config.datagramReceiveQueue)
    private var datagramsReadableSignalled = false

    /** Bytes kept free in a packet next to a full-size datagram, enough for an ACK of a few ranges; larger ACKs go in a packet without the datagram. */
    private val datagramAckReserve = 32

    /**
     * Largest DATAGRAM payload the peer accepts in one of our packets (RFC 9221 section 3): min(peer `max_datagram_frame_size`, MTU minus
     * short header and tag) minus the frame header and 32 bytes kept for a short ACK; 0 when the peer did not advertise support.
     */
    public val maxDatagramPayload: Int get() {
        val peer = peerTp?.maxDatagramFrameSize ?: 0L
        if (peer <= 0L) return 0
        val frameMax = minOf(peer, (path.mtu - (1 + remoteCid.length + 4 + 16)).toLong()).toInt()
        if (frameMax <= 2) return 0
        // a datagram of this size still fits a packet that carries a short ACK
        return frameMax - 1 - VarInt.size(frameMax.toLong()) - datagramAckReserve
    }

    /** Copies the oldest received datagram into [into] at [offset]; -1 when the queue is empty. */
    public fun readDatagram(
        into: ByteArray,
        offset: Int,
    ): Int {
        val n = datagramQueue.poll(into, offset)
        if (n <
            0
        ) {
            datagramsReadableSignalled = false
        }
        return n
    }

    internal fun onDatagramFrame(
        data: PacketBuffer,
        off: Int,
        len: Int,
    ) {
        if (datagramQueue.push(data, off, len)) datagramsDropped++
        if (!datagramsReadableSignalled) {
            datagramsReadableSignalled = true
            events += ConnectionEvent.DatagramsReadable
        }
    }

    internal val connFlow = RecvFlowController(config.initialConnectionWindow, config.maxConnectionWindow)
    internal val connSend = SendFlowController(0)
    internal val streams = StreamManager(role, config, connFlow, connSend, StreamLimits(role, config.maxBidiStreams, config.maxUniStreams))
    internal var cryptoStreams = CryptoStreams(config.limits)

    /** The active path's anti-amplification budget (RFC 9000 sections 8.1 and 9.3.1). */
    internal val amplification: AmplificationLimit get() = paths.active.amplification

    /** The glitch token bucket (docs/guide/quic.md, "Glitch protection"); null when `QuicConfig.glitchProtection` is off. */
    internal val glitch: GlitchBucket? =
        if (config.glitchProtection) {
            GlitchBucket(
                config.limits.glitchTokens,
                config.limits.glitchRefillPerSecond,
            )
        } else {
            null
        }
    internal val readKeys = arrayOfNulls<PacketProtector>(4)
    internal val writeKeys = arrayOfNulls<PacketProtector>(4)

    /** 1-RTT key phases (RFC 9001 section 6); readKeys[3]/writeKeys[3] mirror its current generation. */
    internal var keyPhase: KeyPhase? = null
    internal val keyPhaseForTest: KeyPhase? get() = keyPhase

    /** Handshake and 1-RTT packets that failed authentication (Initial keys are public and do not count; RFC 9001 section 6.6). */
    internal var authenticationFailures = 0L

    /** Initial read keys of the client's Original Version on a server that negotiated another one. */
    internal var initialReadOriginal: PacketProtector? = null
    internal val spaceDiscarded = BooleanArray(3)
    internal val events = ArrayDeque<ConnectionEvent>()
    internal var handshake: HandshakeDriver =
        HandshakeDriver(
            crypto.newSession(tlsConfig, earlyMode != io.kuicksilver.tls.EarlyDataState.Disabled || serverEarly != null),
            ConnectionHandshakeSink(this),
        )

    // ---- 0-RTT (ADR-0015) ----

    /** Client: the server's remembered transport parameters while 0-RTT is pending; null once settled or when none is used. */
    internal var remembered: TransportParameters? = null
    internal var rememberedAlpn: String? = null

    /** The peer's transport parameters as they arrived, stored with tickets (client). */
    internal var peerTpEncoded: ByteArray? = null
    internal var earlyAccepted: Boolean? = null

    /** Server: when the 0-RTT read key goes (3 PTO after the first 1-RTT packet, RFC 9001 section 4.9.3). */
    internal var zeroRttReadDiscardAt: TimeMark = TimeMark.NEVER

    /**
     * Whether 0-RTT was accepted (RFC 9001 section 4.6.2): client, known with the server's EncryptedExtensions; server,
     * as soon as it decided. Null when none was attempted or not known yet.
     */
    @ExperimentalKuicksilverApi
    public val earlyDataAccepted: Boolean? get() = earlyAccepted ?: if (released) null else handshake.session.earlyDataAccepted

    /** Server: true when any STREAM frame of stream [id] arrived in a 0-RTT packet (it may be a replay, RFC 8446 section 8). */
    @ExperimentalKuicksilverApi
    public fun streamReceivedEarly(id: Long): Boolean = streams.receivedEarly(id)

    /** Set by the endpoint so issued connection IDs route back to this core. */
    internal var registrar: CidRegistrar = NoopRegistrar

    /** Endpoint bookkeeping (several loops, ADR-0004): on the endpoint's dirty list; position and key in the loop's timer heap (-1 = not queued). */
    internal var dirty: Boolean = false
    internal var heapIndex: Int = -1
    internal var heapDeadline: TimeMark = TimeMark.NEVER
    internal val cids =
        ConnectionIdManager(
            config.activeConnectionIdLimit,
            config.limits.retiredConnectionIds,
            config.connectionIdLength,
            random,
            resetKey = resetKey,
            registrar =
                object : CidRegistrar {
                    override fun add(
                        cid: ConnectionId,
                        core: ConnectionCore,
                    ) = registrar.add(cid, core)

                    override fun remove(cid: ConnectionId) = registrar.remove(cid)
                },
        )
    internal val timers = Timers()
    internal var peerIdleMs: Long = 0
    internal var receivedVnVersions: IntArray? = null
    internal var anyPeerPacket = false

    /**
     * The time of the current call into the core. The stream manager reads the same clock: receive-window auto-tuning compares
     * the interval between window updates with the RTT, and it used to see a clock stuck at zero, so every update doubled the
     * window up to its maximum (RFC 9000 section 4.2; `core.WindowAutoTuneTest`).
     */
    internal var now: TimeMark = now
        set(v) {
            field = v
            streams.now = v
            streams.smoothedRtt = rtt.smoothed
        }

    init {
        streams.now = now
    }

    internal val qlog: QlogWriter? =
        config.qlog?.let {
            QlogWriter(it, config.limits.qlogBytes, now, role, odcid.toString())
        } // opens its trace at the first event, closed in release()
    internal val receiver = PacketReceiver(this)
    internal val builder = PacketBuilder(this)
    internal var peerTp: TransportParameters? = null
    internal var peerGreaseQuicBit = false
    internal var tlsDirty = false
    internal var handshakeDoneReceived = false
    internal var sendHandshakeDone = false
    internal val probePending = IntArray(3)
    internal var discardHandshakeKeysAfterPacket = false
    internal var discardInitialPending = false

    /** A handshake-time address change seen before the server had 1-RTT keys: decided once TLS ran on its datagram (`afterInput`). */
    internal var pendingHandshakeMove: InetSocketAddress? = null

    /** Bytes received from a client address the handshake may move the active path to (`onHandshakeAddressChange`). */
    internal var handshakeCredit: io.kuicksilver.quic.core.HandshakeCredit? = null

    /** The address an Initial moved the active path away from during the handshake, until the new one is validated (`revertHandshakeMove`). */
    internal var handshakeFallback: io.kuicksilver.quic.core.HandshakeFallback? = null

    /** A handshake-time move failed its validation: the active path keeps its address until the handshake completes. */
    internal var handshakeMovesFrozen = false

    /** Handshake-time moves undone so far (`restoreHandshakeAddress`): only the first resends at once. */
    internal var handshakeRestores = 0
    internal var handshakeResendsAtOnceForTest = 0

    /** Server: where the first CRYPTO data of our handshake flight went (`onHandshakeFlightSent`). */
    internal var handshakeFlightTo: InetSocketAddress? = null

    /** Server: some of that flight went to another address too, so a client Handshake packet no longer shows which one reached it. */
    internal var handshakeFlightElsewhere = false
    internal var closeFrame: CloseFrame? = null

    /** CONNECTION_CLOSE already carried by a packet of this space since the last (re)send trigger. */
    internal val closeSentIn = BooleanArray(3)
    internal var closeSent: Boolean
        get() =
            (0 until 3).all {
                closeSentIn[it] || spaceDiscarded[it] || writeKeys[
                    if (it == 0) {
                        0
                    } else if (it == 1) {
                        2
                    } else {
                        3
                    },
                ] == null
            }
        set(v) {
            for (i in 0 until 3) closeSentIn[i] = v
        }
    internal var closedReason: QuicException.ConnectionLost? = null
    internal var handshakeConfirmedAt: TimeMark? = null
    internal val createdAt: TimeMark = now

    /** `QuicEndpointConfig.maxConnectionLifetime`: the endpoint sets it at creation; the connection closes with NO_ERROR when it passes. */
    internal var lifetimeDeadline: TimeMark = TimeMark.NEVER

    /** The per-IP counting key the endpoint registered this connection under (null for client connections). */
    internal var admissionIpKey: Any? = null

    /** Bytes this unfinished handshake holds: undecryptable packets waiting for keys, out-of-order CRYPTO data and CRYPTO data TLS has not read (`ConnectionAttempt.handshakeBufferBytes` for admission). */
    internal val handshakeBufferBytes: Long get() = receiver.bufferedBytes + cryptoStreams.bufferedBytes + tlsPendingBytes

    /** CRYPTO bytes TLS held unread after it last ran, while the handshake keys are live (`checkTlsInput`). */
    internal var tlsPendingBytes = 0L
    internal val createdAtForTest: TimeMark get() = createdAt
    internal val remoteAddressForTest: InetSocketAddress get() = path.remote
    internal var lastActivity: TimeMark = now

    // ---- stats ----
    internal var lostPackets = 0L

    /** Packets declared lost and acknowledged after all (RFC 9002 section 6.1). */
    internal var spuriousLosses = 0L
    internal var datagramsDropped = 0L
    internal var packetsReceived = 0L
    internal var packetsSent = 0L
    internal var bytesReceived = 0L
    internal var bytesSent = 0L
    internal var duplicatesDropped = 0L

    /**
     * Fuzzing probe: the sizes of the per-connection collections a peer can make grow, by name (the stateful fuzzer checks
     * them against bounds derived from the configuration).
     */
    internal fun sizesForTest(): Map<String, Long> {
        val m = LinkedHashMap<String, Long>()
        m["events"] = events.size.toLong()
        val st = streams.sizesForTest()
        m["streams"] = st[0].toLong()
        m["streamControlFrames"] = st[1].toLong()
        m["streamEvents"] = st[2].toLong()
        m["streamSendLimits"] = st[3].toLong()
        m["streamsEarly"] = st[4].toLong()
        m["reassemblyRanges"] = streams.reassemblyRanges.toLong()
        m["sendBufferedBytes"] = streams.sendBufferedBytes
        val ci = cids.sizesForTest()
        m["cidsLocal"] = ci[0].toLong()
        m["cidsPeer"] = ci[1].toLong()
        m["cidsRetiredLocal"] = ci[2].toLong()
        m["cidsRetiredUntil"] = ci[3].toLong()
        m["cidsPendingRetire"] = ci[4].toLong()
        m["cidsUnackedRetire"] = ci[5].toLong()
        m["paths"] = paths.all.size.toLong()
        m["pathResponses"] = paths.responses.toLong()
        for (space in io.kuicksilver.quic.recovery.SpaceId.entries) {
            val sp = loss.space(space)
            m["sent${space.name}"] = sp.sent.size.toLong()
            m["ackRanges${space.name}"] = sp.ack.rangeCount.toLong()
        }
        m["receiverBufferedBytes"] = receiver.bufferedBytes
        m["cryptoBufferedBytes"] = cryptoStreams.bufferedBytes
        m["datagramsQueued"] = datagramQueue.size.toLong()
        m["challengedAddresses"] = challengedAddressesForTest.size.toLong()
        m["mtuUpdates"] = ccMtuUpdatesForTest.size.toLong()
        return m
    }

    // ---- test hooks (internal, used by the module's tests only) ----
    internal var testForgeInitialSourceCid = false
        set(v) {
            field = v
            refreshLocalTp()
        }
    internal var testForgeChosenVersion = false
        set(v) {
            field = v
            refreshLocalTp()
        }
    internal var testInjectHandshakeDone = false
    internal var testInjectDatagramFrame = false
    internal var testInjectDatagramInHandshake = false
    internal var testInjectDatagramBytes = 0

    /**
     * (level, frames): raw frame bytes written verbatim into the next packet of that level (0 Initial, 1 0-RTT, 2 Handshake,
     * 3 1-RTT), so the stateful fuzzer can make a peer seal arbitrary frames under real keys.
     */
    internal val testInjectFrames = ArrayDeque<Pair<Int, ByteArray>>()

    /** (level, offset, length): inject one CRYPTO frame of zeros into the next packet of that level. */
    internal var testInjectCrypto: Triple<Int, Long, Int>? = null
    internal var testAdvertisePreferredAddress = false
        set(v) {
            field = v
            refreshLocalTp()
        }
    internal var testInjectCloseReasonBytes: ByteArray? = null
        set(v) {
            field = v
            if (v !=
                null
            ) {
                closeFrame = CloseFrame(false, TransportError.INTERNAL_ERROR, 0, v.copyOf(minOf(v.size, 1024)))
                enterClosing(QuicException.ConnectionLost.TransportClosed(TransportError.INTERNAL_ERROR, 0, "", v, Initiator.Local, null))
            }
        }
    internal var testInjectNewCids = 0

    /** Test hook: this many MAX_DATA frames that do not raise the limit (glitches). */
    internal var testInjectMaxData = 0

    /** Test hook: this many DATA_BLOCKED frames, each with a different stale limit (the remaining count). */
    internal var testInjectDataBlocked = 0

    /** Test hook: this many repeats of our NEW_CONNECTION_ID with sequence 1 (duplicates). */
    internal var testInjectRepeatNewCid = 0
    internal var testRetirePriorTo = false
        set(v) {
            field = v
            if (v) cids.issueRetiringOlder()
        }
    internal val peerCidCount: Int get() = cids.peerCount
    internal val retiredByPeer: Int get() = cids.retiredByPeer

    internal fun testCidForBuffering(
        bytes: ByteArray,
        off: Int,
    ) {
        localCid = ConnectionId(bytes.copyOfRange(off, off + 8))
    }

    internal val hasInitialKeys: Boolean get() = readKeys[0] != null && !spaceDiscarded[0]
    internal val hasHandshakeKeys: Boolean get() = readKeys[2] != null && !spaceDiscarded[1]

    /** Server: the client's address was validated by a Handshake packet (RFC 9000 section 8.1). */
    public val addressValidated: Boolean get() = role == TlsRole.Client || amplification.validated

    internal class CloseFrame(
        val application: Boolean,
        val code: Long,
        val frameType: Long,
        val reason: ByteArray,
    )

    init {
        paths.onEvicted = { releasePathCid(it) }
        if (role == TlsRole.Server) {
            loss.amplificationBlocked = {
                !amplification.validated && amplification.budget() < 64
            } // what PacketBuilder needs for a datagram
        }
        cids.core = this
        cids.adoptInitialLocalCid(localCid)
        // before the transport parameters: the server's stateless_reset_token is the token of its handshake ID
        if (role == TlsRole.Server) cids.adoptInitialPeerCid(remoteCid)
        val tp = buildLocalTp()
        handshake.session.setTransportParameters(TransportParametersCodec.encode(tp, role, 27))
        handshake.session.setQuicVersion(startVersion.version)
        serverEarly?.let { enableServerEarlyData(it) }
        if (role == TlsRole.Client) {
            installInitialKeys(startVersion)
            tlsDirty = true
        } // the first poll drives TLS to produce the ClientHello
        timers.handshakeDeadline = now + config.handshakeTimeout
        timers.lastActivity = now
    }

    // ---- public API ----

    /** The certificate chain the peer presented; empty before the handshake got that far or when the peer sent none. */
    public val peerCertificates: List<Certificate> get() = handshake.session.peerCertificates

    /** The ALPN protocol agreed in the handshake (RFC 9001 section 8.1); null until the handshake settled it. */
    public val negotiatedAlpn: String? get() = handshake.session.negotiatedAlpn

    /**
     * Keying material from the TLS exporter (RFC 5705, RFC 8446 section 7.5) for [label] and [context], [length] bytes; usable once the
     * handshake completed.
     */
    public fun exportKeyingMaterial(
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray = handshake.session.exportKeyingMaterial(label, context, length)

    /** A new [ConnectionStats] snapshot of the connection and its active path; it allocates, so read it per report, not per packet. */
    public val stats: ConnectionStats get() =
        ConnectionStats(
            rtt.min,
            rtt.smoothed,
            rtt.rttVar,
            cc.cwnd,
            cc.bytesInFlight,
            lostPackets,
            loss.ptoCount,
            path.mtu,
            path.id,
            datagramsDropped,
            memoryCeiling(),
            packetsReceived,
            packetsSent,
            bytesReceived,
            bytesSent,
            duplicatesDropped,
            receiver.bufferedCount,
            SpaceId.entries.maxOf {
                loss.space(it).ack.rangeCount
            },
            streams.reassemblyRanges,
            keyPhase?.updates ?: 0L,
            authenticationFailures,
            invalidResets,
            glitch?.spent ?: 0L,
            path.amplification.sent,
            path.amplification.received,
            path.ecn.state,
            ecnCeReceived(),
            ecnCeEvents,
            datagramsDroppedSend,
            datagramsDroppedSocket,
        )

    private fun memoryCeiling(): Long =
        config.maxConnectionWindow + config.maxSendBuffer +
            3L * config.limits.cryptoOutOfOrderPerLevel + config.limits.cryptoPostHandshake +
            config.limits.undecryptablePackets.toLong() * path.mtu + config.limits.qlogBytes

    /** Test hook: thrown out of the next [handleDatagram] to exercise the endpoint's per-connection isolation. */
    internal var testInjectFailure: Throwable? = null

    /** Feeds one received datagram; the buffer is only read during the call. */
    public fun handleDatagram(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
    ): Unit = handleDatagram(data, length, from, ecn, now, PathId.Initial)

    /** [handleDatagram] for an endpoint with several sockets: [socket] names the one the datagram arrived on. */
    public fun handleDatagram(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
        socket: PathId,
    ) {
        if (state == ConnectionState.Closed) return
        testInjectFailure?.let {
            testInjectFailure = null
            throw it
        }
        this.now = now
        lastActivity = now
        if (state == ConnectionState.Draining) return
        // RFC 9001 section 6.6: past the integrity limit "not process any more packets"; the bytes still count (amplification), and
        // the close is repeated as in any closing state
        if (state == ConnectionState.Closing &&
            closeFrame?.let { !it.application && it.code == TransportError.AEAD_LIMIT_REACHED } == true
        ) {
            receiver.countOnly(length, from, socket)
        } else {
            receiver.onDatagram(data, length, from, socket, ecn, now)
        }
        if (state ==
            ConnectionState.Closing
        ) {
            val last = timers.lastCloseSent
            if (last == null || now - last >= pto()) closeSent = false
            return
        } // answer with CONNECTION_CLOSE at most once per PTO
        afterInput(now)
    }

    internal fun afterInput(now: TimeMark) {
        if (tlsDirty) {
            tlsDirty = false
            driveTls(now)
        }
        pendingHandshakeMove?.let {
            pendingHandshakeMove = null
            onHandshakeDatagramDone(it)
        }
        if (discardHandshakeKeysAfterPacket) {
            discardHandshakeKeysAfterPacket = false
            discardSpace(SpaceId.Handshake)
        }
        if (discardInitialPending) {
            discardInitialPending = false
            discardSpace(SpaceId.Initial)
        }
        drainStreamEvents()
    }

    /** Fills [out] with datagrams to send now; returns their number (at most one send quantum). */
    public fun poll(
        out: PacketBatch,
        now: TimeMark,
    ): Int {
        if (state == ConnectionState.Closed || state == ConnectionState.Draining) return 0
        this.now = now
        if (tlsDirty) {
            tlsDirty = false
            driveTls(now)
        }
        val n = builder.poll(out, now)
        armBlockedRepeat(now)
        if (discardInitialPending) {
            discardInitialPending = false
            discardSpace(SpaceId.Initial)
        }
        if (discardHandshakeKeysAfterPacket) {
            discardHandshakeKeysAfterPacket = false
            discardSpace(SpaceId.Handshake)
        }
        return n
    }

    /** The earliest deadline at which [onTimeout] must run, or null when no timer is armed; ask again after every call into the core. */
    public fun nextTimeout(): TimeMark? {
        val t = nextTimeoutOrNever()
        return if (t == TimeMark.NEVER) null else t
    }

    /** [nextTimeout] without the nullable box: [TimeMark.NEVER] when no timer is armed. */
    public fun nextTimeoutOrNever(): TimeMark {
        if (state == ConnectionState.Closed) return TimeMark.NEVER
        if (state == ConnectionState.Closing || state == ConnectionState.Draining) return timers.closeDeadline ?: TimeMark.NEVER
        var t: TimeMark = loss.timeout()
        for (i in 0 until 3) {
            if (spaceDiscarded[i]) continue
            val d = loss.space(SpaceId.entries[i]).ack.ackDeadline(config.maxAckDelay)
            if (d <
                t
            ) {
                t = d
            }
        }
        if (builder.pacerWakeup < t) t = builder.pacerWakeup
        if (state == ConnectionState.Handshaking) timers.handshakeDeadline?.let { if (it < t) t = it }
        handshakeFallback?.let { if (it.deadline < t) t = it.deadline }
        val idle = idleDeadline()
        if (idle < t) t = idle
        val keep = keepAliveDeadline()
        if (keep < t) t = keep
        if (timers.blockedRepeatAt < t) t = timers.blockedRepeatAt
        if (lifetimeDeadline < t) t = lifetimeDeadline
        keyPhase?.let { if (it.discardAt < t) t = it.discardAt }
        if (keyUpdateRetryAt < t) t = keyUpdateRetryAt
        if (zeroRttReadDiscardAt < t) t = zeroRttReadDiscardAt
        for (i in 0 until paths.all.size) {
            val p = paths.all[i]
            if (p.state ==
                PathState.Validating
            ) {
                if (p.challengeDeadline <
                    t
                ) {
                    t = p.challengeDeadline
                }
                if (p.nextChallengeAt <
                    t
                ) {
                    t = p.nextChallengeAt
                }
            }
            p.pmtud?.let { m ->
                val mt = m.timeout()
                if (mt < t) t = mt
            }
        }
        val retired = cids.nextRetiredExpiry()
        if (retired < t) t = retired
        return t
    }

    /**
     * Runs every timer due at [now]: loss detection and PTO, idle, handshake and lifetime limits, path validation, PMTUD, key discard. Call
     * it once [nextTimeout] passed, then [poll]; an early call does nothing harmful.
     */
    public fun onTimeout(now: TimeMark) {
        if (state == ConnectionState.Closed) return
        this.now = now
        if (state == ConnectionState.Closing ||
            state == ConnectionState.Draining
        ) {
            timers.closeDeadline?.let { if (it <= now) markClosed() }
            return
        }
        if (state ==
            ConnectionState.Handshaking
        ) {
            timers.handshakeDeadline?.let {
                if (it <=
                    now
                ) {
                    silentClose(QuicException.ConnectionLost.Timeout(TimeoutKind.Handshake, config.handshakeTimeout))
                    return
                }
            }
        }
        if (idleDeadline() <=
            now
        ) {
            silentClose(
                QuicException.ConnectionLost.Timeout(TimeoutKind.Idle, timers.effectiveIdle(config.maxIdleTimeout, peerIdleMs, pto())),
            )
            return
        }
        if (lifetimeDeadline <= now) {
            fail(TransportError.NO_ERROR, 0, "connection lifetime reached", null)
            return
        }
        // before the path loop: an unvalidated handshake-time move is undone, not given another validation period nor failed (it may
        // outlive the handshake when a raced copy carried the client's Finished)
        handshakeFallback?.let { if (it.deadline <= now) revertHandshakeMove(it) }
        cids.expireRetired(now)
        if (zeroRttReadDiscardAt <= now) discardZeroRttKeys()
        for (i in 0 until paths.all.size) paths.all[i].pmtud?.onTimeout(now)
        var pi = paths.all.size - 1
        while (pi >=
            0
        ) {
            val p = paths.all.getOrNull(pi)
            pi--
            if (p == null ||
                p.state != PathState.Validating
            ) {
                continue
            }
            if (p.challengeDeadline <=
                now
            ) {
                if (p.awaitingCid) {
                    onPathFailed(p, PathFailureReason.NoSpareConnectionId)
                } else if (p === paths.active &&
                    p.handshakeValidated
                ) {
                    settleHandshakeValidated(p)
                } else if (p === paths.active &&
                    state == ConnectionState.Handshaking
                ) {
                    // not reached since 0.2.1: every handshake-time move that leaves the active path validating keeps a HandshakeFallback
                    // whose deadline comes first and undoes it (revertHandshakeMove); kept so that a deadline never stays in the past
                    p.challengePending = true
                    p.challengeDeadline = now + validationTimeout()
                    p.nextChallengeAt = now + nextChallengeDelay(p)
                } else {
                    onPathFailed(p)
                }
            } else if (p.nextChallengeAt <=
                now
            ) {
                p.challengePending = true
                p.nextChallengeAt = now + nextChallengeDelay(p)
            }
        } // RFC 9000 section 8.2.4
        // QuicEndpointConfig.maxConnectionLifetime: a transport close with NO_ERROR
        if (state == ConnectionState.Closed || state == ConnectionState.Closing || state == ConnectionState.Draining) return
        if (keepAliveDeadline() <= now) timers.keepAlivePending = true
        onBlockedRepeatTimer(now)
        if (loss.timeout() <=
            now
        ) {
            val probe = loss.onTimeout(now)
            checkPmtuBlackHoles()
            if (probe !=
                null
            ) {
                probePending[probe.space.ordinal] = probe.packets
                requeueForProbe(probe.space, probe.packets)
                probeOtherHandshakeSpace(probe.space)
                if (probe.space ==
                    SpaceId.Application
                ) {
                    path.let { p ->
                        if (p.ecn.state ==
                            EcnState.Unknown
                        ) {
                            p.ecn.onPto()
                            ecnPathFailed(p)
                        }
                        ; p.pmtud?.let { m ->
                            if (loss.ptoCount >= 2 &&
                                m.current > 1200 &&
                                largePacketUnanswered(p)
                            ) {
                                m.onBlackHole(now)
                                setMtu(p, 1200)
                            }
                        }
                    }
                }
            }
            // RFC 9000 appendix A.4: a 1-RTT PTO with all ten test packets outstanding means the marked packets vanish; two PTOs above the base
            // MTU with nothing acknowledged are a PMTU black hole (RFC 8899 section 4.3)
        }
        if (builder.pacerWakeup <= now) builder.pacerWakeup = TimeMark.NEVER
        keyPhase?.onTimeout(now)
        if (now >= keyUpdateRetryAt) keyUpdateRetryAt = TimeMark.NEVER // a wake-up for a caller retrying initiateKeyUpdate, nothing more
    }

    /**
     * Starts a key update (RFC 9001 section 6.1); false while one is not allowed yet: handshake not confirmed, no packet of the
     * current phase acknowledged, or less than 3 x PTO since that acknowledgment (section 6.5; the next [nextTimeout] wakes the caller then).
     */
    public fun initiateKeyUpdate(now: TimeMark): Boolean {
        if (state != ConnectionState.Confirmed) return false
        val kp = keyPhase ?: return false
        this.now = now
        if (kp.initiate(now, pto())) {
            keyUpdateRetryAt = TimeMark.NEVER
            return true
        }
        keyUpdateRetryAt = kp.initiateAllowedAt(pto())
        return false
    }

    /** When a refused [initiateKeyUpdate] may succeed (3 x PTO after the confirming ACK): a timer, so a retrying caller is woken. */
    private var keyUpdateRetryAt = TimeMark.NEVER

    internal val probeScratch = ArrayList<SentPacket>()

    internal var released = false

    /** True once the TLS session and every packet protector were freed (test hook). */
    internal val releasedForTest: Boolean get() = released

    internal fun isStreamOpenForTest(id: Long): Boolean = streams.isOpen(id)

    /** The next application-visible event; stream events raised by the application's own reads/writes (no datagram involved) are collected here too. */
    public fun nextEvent(): ConnectionEvent? {
        if (events.isEmpty()) drainStreamEvents()
        return events.removeFirstOrNull()
    }

    /**
     * Resumes a handshake paused by [ConnectionEvent.VerifyRequested] with the verdict of `session.verifyPeer`; a rejected chain closes the
     * connection with the TLS alert (CRYPTO_ERROR).
     */
    public fun resumeVerify(result: VerifyResult) {
        try {
            handshake.resumeVerify(result)
            checkTlsInput()
        } catch (e: QuicWireException) {
            fail(e.code, e.frameType, e.message ?: "", null)
            return
        }
        if (handshake.failed) return
        drainStreamEvents()
    }

    /**
     * Opens a local stream and returns its id, or -1 while the peer's stream limit is reached (a STREAMS_BLOCKED goes out, RFC 9000 section
     * 4.6); retry after later input, since no event announces the peer's MAX_STREAMS in this version.
     */
    public fun openStream(
        bidi: Boolean,
        priority: StreamPriority = StreamPriority.Default,
    ): Long = streams.open(bidi, priority)

    /**
     * Queues up to [length] bytes of [data] from [offset] on stream [id] and returns how many were taken, fewer (even 0) while
     * `QuicConfig.maxSendBuffer` is full; [fin] ends the stream once all of them were taken. IllegalStateException for a stream we cannot
     * write or one we reset.
     */
    public fun writeStream(
        id: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
        fin: Boolean,
    ): Int = streams.write(id, data, offset, length, fin)

    /**
     * Copies up to [length] received bytes of stream [id] into [into] at [offset]: the count, 0 when nothing is readable yet, -1 at the end
     * (FIN reached or the stream reset). Reading returns flow-control credit to the peer; IllegalStateException for a send-only stream.
     */
    public fun readStream(
        id: Long,
        into: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        streams.smoothedRtt = rtt.smoothed
        return streams.read(id, into, offset, length)
    }

    /**
     * Abandons sending on stream [id] with RESET_STREAM carrying application error [code] (RFC 9000 section 3.1); unsent data is dropped.
     * Nothing happens for an unknown or already reset stream.
     */
    public fun resetStream(
        id: Long,
        code: Long,
    ) {
        streams.reset(id, code)
    }

    /**
     * Asks the peer to stop sending on stream [id] with STOP_SENDING carrying [code] (RFC 9000 section 3.5); buffered data is discarded and
     * its credit returned. Nothing happens for an unknown or already stopped stream.
     */
    public fun stopSending(
        id: Long,
        code: Long,
    ) {
        streams.stopSending(id, code)
    }

    /** Changes the send priority of stream [id] for the next packets; ignored for a stream without a sending half. */
    public fun setPriority(
        id: Long,
        priority: StreamPriority,
    ) {
        streams.setPriority(id, priority)
    }

    /** Closes with an application error (RFC 9000 section 10.2); Initial/Handshake copies carry APPLICATION_ERROR (0x0c) without the reason, the 1-RTT copy the application's code. */
    public fun close(
        code: Long,
        reason: String,
        now: TimeMark,
    ) {
        require(code in 0..((1L shl 62) - 1)) { "error code must be 0..2^62-1" }
        if (state == ConnectionState.Closing || state == ConnectionState.Draining || state == ConnectionState.Closed) return
        this.now = now
        val bytes = reason.encodeToByteArray().let { if (it.size > 1024) it.copyOf(1024) else it }
        // the builder sends 0x1c APPLICATION_ERROR without the reason in Initial/Handshake copies (RFC 9000 section 10.2.3)
        closeFrame = CloseFrame(true, code, 0, bytes)
        enterClosing(QuicException.ConnectionLost.ApplicationClosed(code, reason, Initiator.Local))
    }

    /** Where the peer is (the address datagrams go to). */
    internal val remoteAddress: InetSocketAddress get() = path.remote
    internal var invalidResets = 0L

    internal fun peerResetTokenForTest(seq: Long): ByteArray? = cids.peerTokensForTest().getOrNull(seq.toInt())?.second

    internal fun peerCidsForTest(): List<Pair<ConnectionId, ByteArray?>> = cids.peerTokensForTest()

    // ---- paths (RFC 9000 sections 8.2 and 9) ----

    /** When a packet from the active path's address and socket was last processed (the handshake-time rebind follows an Initial only after a PTO of silence there). */
    internal var lastReceivedOnActivePath: TimeMark = now

    // ---- active migration, client only (RFC 9000 section 9.2) ----

    /** A new, unvalidated path to the server through the socket [socket] (defaults to the path's own id); the runtime binds a DatagramIo to it. */
    public fun addPath(
        remote: InetSocketAddress,
        now: TimeMark,
        socket: PathId? = null,
    ): PathId {
        check(role == TlsRole.Client) { "only a client migrates (RFC 9000 section 9)" }
        check(state == ConnectionState.Confirmed) { "migration before the handshake is confirmed (RFC 9000 section 9)" }
        check(peerTp?.disableActiveMigration != true) { "the peer advertised disable_active_migration" }
        // RFC 9000 section 9.5: traffic on a new path to a peer without connection IDs is trivially linkable to the old one
        check(remoteCid.length != 0) { "the peer uses a zero-length connection ID (RFC 9000 section 9.5)" }
        this.now = now
        val p =
            paths.add(socket, remote, config.congestionController(), config.newPathInitialRtt, evict = false)
                ?: throw IllegalStateException("at most 4 paths")
        p.amplification.validated = true // our own address: nothing to amplify against
        return p.id
    }

    /** Sends a PATH_CHALLENGE on [id]; the outcome arrives as [ConnectionEvent.PathValidated] or [ConnectionEvent.PathFailed]. */
    public fun probePath(
        id: PathId,
        now: TimeMark,
    ) {
        val p =
            paths.byId(id) ?: throw IllegalStateException("unknown path $id")
        check(p.state != PathState.Closed) { "path $id is closed" }
        this.now = now
        if (p.state != PathState.Validating) startValidation(p)
    }

    /** Moves the connection to the validated path [id]; the previous path stays as a fallback. */
    public fun switchPath(
        id: PathId,
        now: TimeMark,
    ) {
        val p =
            paths.byId(id) ?: throw IllegalStateException("unknown path $id")
        check(p.state == PathState.Validated) { "path $id is ${p.state}, not Validated" }
        this.now = now
        switchPath(p, PathChangeReason.ActiveMigration, challengeOld = false)
    }

    /** Forgets path [id] (never the active one). */
    public fun closePath(id: PathId) {
        val p = paths.byId(id) ?: return
        check(p !== paths.active) { "path $id is active" }
        paths.remove(p)
        releasePathCid(p)
    }

    /** Glitch tokens spent per frame type (index 31 for anything above; 0 for an undecryptable packet, 1 for a PING flood), for diagnostics. */
    internal val glitchCounts = LongArray(32)

    /**
     * Glitch tokens the peer spent per frame type (index 31 for anything above; 0 for an undecryptable packet, 1 for a PING flood): the
     * live array, for diagnostics only.
     */
    @DelicateKuicksilverApi public val glitchByFrameType: LongArray get() = glitchCounts

    private fun drainStreamEvents() {
        while (true) events += streams.events.removeFirstOrNull() ?: break
    }

    /** Holds [client]; the server-side factory is the `ConnectionCore.Companion.server` extension. */
    public companion object {
        /** The most entries a test-only record of this connection keeps (the latest ones): a peer must not grow it. */
        internal const val TEST_RECORD_LIMIT = 64

        /** NEW_TOKEN tokens a server issues per connection: one at confirmation, one per new client IP after that (as ngtcp2). */
        internal const val MAX_NEW_TOKENS = 4

        /** NEW_TOKEN frames a client keeps per connection; each further one spends a glitch token (RFC 9000 section 21.9). */
        internal const val NEW_TOKENS_KEPT = 8

        /** The longest NEW_TOKEN token a client keeps: the bound it applies to Retry tokens (threat-model 3.3). */
        internal const val MAX_KEPT_TOKEN = 1024

        /** A client connection to [remote]; the first [poll] produces the Initial datagrams. [random] supplies its connection IDs, PATH_CHALLENGE data and skipped packet numbers: a CSPRNG outside tests (predictable IDs would let an off-path attacker forge them). */
        public fun client(
            config: QuicConfig,
            tls: TlsConfig,
            crypto: QuicCrypto,
            remote: InetSocketAddress,
            random: Random,
            now: TimeMark,
        ): ConnectionCore = client(config, tls, crypto, remote, random, now, null)

        internal fun client(
            config: QuicConfig,
            tls: TlsConfig,
            crypto: QuicCrypto,
            remote: InetSocketAddress,
            random: Random,
            now: TimeMark,
            resetKey: ResetKey?,
            earlyMode: io.kuicksilver.tls.EarlyDataState = io.kuicksilver.tls.EarlyDataState.Disabled,
            localCid: ConnectionId? = null,
        ): ConnectionCore {
            // the crypto provider validates the rest (sniSelector etc.)
            require(tls.role == TlsRole.Client) { "client core needs a client TlsConfig" }
            val odcid = ConnectionId(ByteArray(8).also { random.nextBytes(it) })
            // [localCid]: a loop group's client connection carries its loop's routing byte (EndpointCore.connect)
            val scid = localCid ?: ConnectionId(ByteArray(config.connectionIdLength).also { random.nextBytes(it) })
            return ConnectionCore(
                TlsRole.Client,
                config,
                tls,
                crypto,
                remote,
                random,
                now,
                odcid,
                scid,
                odcid,
                config.firstVersion,
                resetKey,
                earlyMode,
                serverEarly = null,
            )
        }
    }
}

/**
 * A server connection from the client's first Initial datagram, or null when the datagram cannot start one (too short,
 * not an Initial, unsupported version). The datagram itself is then fed with [ConnectionCore.handleDatagram]; an
 * endpoint ([EndpointCore]) passes the connection ID it registered in [localCidBytes].
 */
@ExperimentalKuicksilverApi
public fun ConnectionCore.Companion.server(
    config: QuicConfig,
    tls: TlsConfig,
    crypto: QuicCrypto,
    remote: InetSocketAddress,
    random: Random,
    now: TimeMark,
    data: PacketBuffer,
    length: Int,
    localCidBytes: ByteArray? = null,
): ConnectionCore? = serverWithKeys(config, tls, crypto, remote, random, now, data, length, localCidBytes, null)

internal fun ConnectionCore.Companion.serverWithKeys(
    config: QuicConfig,
    tls: TlsConfig,
    crypto: QuicCrypto,
    remote: InetSocketAddress,
    random: Random,
    now: TimeMark,
    data: PacketBuffer,
    length: Int,
    localCidBytes: ByteArray?,
    resetKey: ResetKey?,
    originalDcid: ConnectionId? = null,
    retryScid: ConnectionId? = null,
    early: io.kuicksilver.quic.core.ServerEarlyData? = null,
    tokenValidated: Boolean = false,
): ConnectionCore? {
    require(tls.role == TlsRole.Server) { "a server connection needs a server TlsConfig" }
    val hv = PacketHeaderView()
    if (length < 1200 || !PacketHeaderCodec.parse(data, 0, length, config.connectionIdLength, hv) ||
        hv.type != PacketType.Initial
    ) {
        return null
    }
    val profile = VersionProfile.of(hv.version) ?: return null
    if (profile !in config.versions) return null
    val packetDcid = ConnectionId(ByteArray(hv.dcidLen).also { data.copyTo(it, hv.dcidOff, 0, hv.dcidLen) })
    // after a Retry the client's DCID is our Retry SCID; the original one comes from the token (RFC 9000 section 7.3)
    val odcid = originalDcid ?: packetDcid
    val remoteCid = ConnectionId(ByteArray(hv.scidLen).also { data.copyTo(it, hv.scidOff, 0, hv.scidLen) })
    val scid = localCidBytes?.let { ConnectionId(it) } ?: ConnectionId(ByteArray(config.connectionIdLength).also { random.nextBytes(it) })
    val core =
        ConnectionCore(
            TlsRole.Server,
            config,
            tls,
            crypto,
            remote,
            random,
            now,
            odcid,
            scid,
            remoteCid,
            profile,
            resetKey,
            earlyMode = io.kuicksilver.tls.EarlyDataState.Disabled,
            serverEarly = early,
        )
    if (tokenValidated) {
        // a NEW_TOKEN token validated the address (RFC 9000 section 8.1.3): no anti-amplification limit, no Retry state
        core.validatedByToken = true
        core.amplification.validated = true
        core.loss.peerAddressValidated = true
    }
    if (retryScid !=
        null
    ) {
        core.initialKeyCid = packetDcid
        core.retryScid = retryScid
        core.validatedByToken = true
        core.amplification.validated =
            true
        core.loss.peerAddressValidated = true
        core.refreshLocalTp()
    }
    core.installInitialKeys(profile)
    return core
}

/** Appends to a test-only record of a connection, dropping the oldest entry beyond [ConnectionCore.TEST_RECORD_LIMIT]. */
internal fun <T> MutableList<T>.recordForTest(value: T) {
    if (size >= ConnectionCore.TEST_RECORD_LIMIT) removeAt(0)
    add(value)
}
