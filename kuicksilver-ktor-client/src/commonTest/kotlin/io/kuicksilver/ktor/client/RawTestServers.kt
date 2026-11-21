// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.BoundDatagramSocket
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.close
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.ktor.network.setCloseTimeout
import io.kuicksilver.ktor.network.tlsServer
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.io.readByteArray
import kotlin.time.Duration.Companion.seconds

/** Reads a request head and its Content-Length body; returns the request line ("" at end of stream). */
internal suspend fun readRequest(input: ByteReadChannel): String {
    val line = input.readLine(LineEnding.Lenient) ?: return ""
    var length = 0
    while (true) {
        val h = input.readLine(LineEnding.Lenient) ?: break
        if (h.isEmpty()) break
        if (h.startsWith("Content-Length:", ignoreCase = true)) length = h.substringAfter(':').trim().toInt()
    }
    if (length > 0) input.readByteArray(length)
    return line
}

/** A UDP socket on 127.0.0.1:[port] (0: a free one) with its port. */
internal suspend fun udpOn(
    selector: SelectorManager,
    port: Int,
) = aSocket(selector).udp().bind(InetSocketAddress("127.0.0.1", port)).let { it to (it.localAddress as InetSocketAddress).port }

/** A TCP listener on 127.0.0.1:[port] (0: a free one) with its port. */
internal suspend fun tcpOn(
    selector: SelectorManager,
    port: Int,
) = bindTcp(selector, "127.0.0.1", port).let { it to (it.localAddress as InetSocketAddress).port }

/** How long the server's close of a connection may wait for the client to take what the handler wrote ([tlsWithSilentUdp]). */
private val SERVER_CLOSE_BOUND = 10.seconds

/**
 * A TLS (HTTP/1.1) listener on 127.0.0.1 that runs [handler] once per accepted connection with its index, then closes it
 * in order (what the handler wrote, then close_notify, within [SERVER_CLOSE_BOUND]) before the raw socket;
 * with [silentUdp] the UDP port of the same number is bound too and never answers (QUIC blocked): the UDP side binds a
 * free port and TCP takes that number, or the other way round ([bindOnSamePort]; a free port of one says nothing about its twin). With
 * [listener] (not closed here) it serves on that socket instead of binding one. Connections are accepted once
 * [acceptAfter] completed (they wait in the backlog until then). [block] gets the port.
 */
internal suspend fun tlsH1WithSilentUdp(
    silentUdp: Boolean = true,
    listener: ServerSocket? = null,
    acceptAfter: kotlinx.coroutines.Deferred<Unit>? = null,
    handler: suspend CoroutineScope.(index: Int, input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
    block: suspend (Int) -> Unit,
) = tlsWithSilentUdp(listOf("http/1.1"), silentUdp, listener, acceptAfter, { i, _, input, output -> handler(i, input, output) }, block)

/**
 * [tlsH1WithSilentUdp] with the server's ALPN list [alpn] (its own order of preference picks the protocol, RFC 7301
 * section 3.2): [handler] also gets the protocol the connection negotiated (null without one).
 */
internal suspend fun tlsWithSilentUdp(
    alpn: List<String>,
    silentUdp: Boolean = true,
    listener: ServerSocket? = null,
    acceptAfter: kotlinx.coroutines.Deferred<Unit>? = null,
    handler: suspend CoroutineScope.(index: Int, negotiated: String?, input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
    block: suspend (Int) -> Unit,
) {
    require(listener == null || !silentUdp) { "a given listener comes with its own UDP side" }
    val serverAlpn = alpn
    val tls =
        tlsConfig(TlsRole.Server) {
            identity = ClientFixtures.identity()
            this.alpn = serverAlpn
        }
    val selector = SelectorManager(Dispatchers.IO)
    var udp: BoundDatagramSocket? = null
    val tcp: ServerSocket
    try {
        tcp =
            when {
                listener != null -> {
                    listener
                }

                silentUdp -> {
                    bindOnSamePort(
                        first = { p -> udpOn(selector, p) },
                        releaseFirst = { it.close() },
                        second = { p -> tcpOn(selector, p) },
                        releaseSecond = { it.close() },
                    ).let { (u, t, _) ->
                        udp = u
                        t
                    }
                }

                else -> {
                    bindTcp(selector, "127.0.0.1", 0)
                }
            }
    } catch (e: Throwable) {
        selector.close()
        throw e
    }
    val bound = (tcp.localAddress as InetSocketAddress).port
    try {
        coroutineScope {
            val server =
                launch {
                    acceptAfter?.await()
                    var index = 0
                    while (true) {
                        val raw = tcp.accept()
                        val i = index++
                        launch {
                            runCatching {
                                val s = raw.tlsServer(tls)
                                @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                                s.setCloseTimeout(SERVER_CLOSE_BOUND)
                                try {
                                    handler(i, s.negotiatedAlpn, s.openReadChannel(), s.openWriteChannel(autoFlush = true))
                                } finally {
                                    // the TLS socket's close is graceful and runs on its own: what the handler queued, then
                                    // close_notify, then the raw socket. Closing the raw socket before that is over cut the
                                    // server's writer short (the session failed, the connection was reset), so the client saw
                                    // a reset where the test meant a whole response; its own bound ends it otherwise
                                    s.close()
                                    s.socketContext.join()
                                }
                            }
                            raw.close() // a no-op after the close above; a failed handshake's socket ends here
                        }
                    }
                }
            block(bound)
            server.cancel()
        }
    } finally {
        udp?.close()
        if (listener == null) tcp.close()
        selector.close()
    }
}

/**
 * An HTTP/3 server on 127.0.0.1:[port] (0: a free UDP port) that answers every request 200 "h3" with [headers]; with
 * [earlyData] it accepts 0-RTT. Nothing listens on the TCP port of the same number.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal suspend fun CoroutineScope.h3Origin(
    headers: List<Pair<String, String>> = emptyList(),
    earlyData: Boolean = false,
    port: Int = 0,
): Http3Endpoint {
    val tls =
        tlsConfig(TlsRole.Server) {
            alpn = listOf(Http3Endpoint.H3)
            identity = ClientFixtures.identity()
        }
    val ep =
        Http3Endpoint.bind(
            InetSocketAddress("127.0.0.1", port),
            QuicEndpointConfig
                .Builder()
                .apply {
                    server = QuicServerConfig.Builder(tls).apply { this.earlyData = earlyData }.build()
                }.build(),
        )
    launch {
        runCatching {
            while (true) {
                val conn = ep.accept()
                launch {
                    runCatching {
                        while (true) {
                            val r = conn.acceptRequest()
                            launch {
                                runCatching {
                                    r.body.discardAll()
                                    val w = r.respond(200, Http3Headers(headers))
                                    w.output.writeStringUtf8("h3")
                                    w.finish()
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return ep
}

private suspend fun ByteReadChannel.discardAll() {
    val b = ByteArray(4096)
    while (readAvailable(b, 0, b.size) >= 0) continue
}

/** Control of a [udpRelay]. */
internal class UdpRelay(
    /** With `tcpTwin`: a TCP listener on 127.0.0.1 at the relay's port number, bound with it and accepting nothing yet. */
    val tcp: ServerSocket?,
) {
    /** While true every datagram is dropped, both ways: QUIC is blocked on the path. */
    @kotlin.concurrent.Volatile var blocked: Boolean = false

    /** How many more datagrams of the server reach the client; the rest are dropped (a handshake that starts, then stalls). */
    @kotlin.concurrent.Volatile var serverDatagramsLeft: Int = Int.MAX_VALUE

    /** Completed by the first datagram from the client dropped while [blocked]. */
    val dropped: kotlinx.coroutines.CompletableDeferred<Unit> = kotlinx.coroutines.CompletableDeferred()

    /**
     * While true, the relay answers the first client Initial the way an msquic server does before its listener accepted the
     * connection ([msquicProvisionalInitial]): an ACK-only Initial from the client's own DCID reaches the client before the
     * server sees the datagram; the server's own answer, from its real SCID, follows. Only the first connection gets it,
     * unless [provisionalForEveryConnection].
     */
    @kotlin.concurrent.Volatile var msquicProvisionalScid: Boolean = false

    /** With [msquicProvisionalScid]: every new connection (a client Initial to a DCID not seen yet) gets a provisional Initial. */
    @kotlin.concurrent.Volatile var provisionalForEveryConnection: Boolean = false

    /**
     * With [msquicProvisionalScid], as msquic really does: only a connection whose client sends a third Initial datagram to
     * its first DCID (a ClientHello of 3 datagrams: a resumption with ML-KEM and GREASE ECH) gets the provisional Initial,
     * just before that third datagram reaches the server (msquic acknowledges after 2 ack-eliciting packets). Every such
     * connection gets one.
     */
    @kotlin.concurrent.Volatile var onlyLargeClientHellos: Boolean = false

    /** Runs before each provisional Initial goes out (tests change the client's state at that point). */
    @kotlin.concurrent.Volatile var onProvisional: (() -> Unit)? = null

    /** How many provisional Initials the relay sent ([msquicProvisionalScid]). */
    @kotlin.concurrent.Volatile var provisionalInitialsSent: Int = 0

    /** Client Initial datagrams per first DCID, and the server's SCIDs (a DCID that is one of those is no first DCID). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val initials = kotlin.concurrent.atomics.AtomicReference(emptyMap<String, Int>())

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val serverScids = kotlin.concurrent.atomics.AtomicReference(emptySet<String>())

    /** Counts a client Initial datagram to [dcid]; returns how many there were to it, 0 when [dcid] is a server's SCID. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    fun countInitial(dcid: String): Int {
        while (true) {
            if (dcid in serverScids.load()) return 0
            val now = initials.load()
            val n = (now[dcid] ?: 0) + 1
            if (initials.compareAndSet(now, now + (dcid to n))) return n
        }
    }

    /** Notes a server SCID. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    fun addServerScid(scid: String) {
        while (true) {
            val now = serverScids.load()
            if (scid in now || serverScids.compareAndSet(now, now + scid)) return
        }
    }

    /** Datagrams of the server passed on to the client. */
    @kotlin.concurrent.Volatile var serverDatagramsForwarded: Int = 0
}

/** The DCID (or with [scid] the SCID) of the long-header packet at the start of [d], in hex; null for a short header. */
private fun longHeaderCid(
    d: ByteArray,
    scid: Boolean,
): String? {
    if (d.size < 7 || d[0].toInt() and 0x80 == 0) return null
    val dcidLen = d[5].toInt() and 0xff
    if (d.size < 7 + dcidLen) return null
    val off = if (scid) 7 + dcidLen else 6
    val len = if (scid) d[6 + dcidLen].toInt() and 0xff else dcidLen
    if (d.size < off + len) return null
    return d.copyOfRange(off, off + len).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}

/** The QUIC v2 version number (RFC 9369 section 3.1). */
private const val QUIC_V2 = 0x6b3343cf

/**
 * The provisional answer an msquic server gives a ClientHello it has only part of (msquic#3762, #4905; docs/spec/interop.md):
 * a server Initial of the same QUIC version (v1 or v2) to the client Initial at the start of [datagram] from the client's
 * own DCID, with an ACK of the client's packet 0 and PADDING, sealed with the server's Initial keys (RFC 9001 section 5.2);
 * null when [datagram] does not start with a v1 or v2 client Initial.
 */
internal fun msquicProvisionalInitial(datagram: ByteArray): ByteArray? {
    if (datagram.size < 7) return null
    val version =
        ((datagram[1].toInt() and 0xff) shl 24) or ((datagram[2].toInt() and 0xff) shl 16) or ((datagram[3].toInt() and 0xff) shl 8) or
            (datagram[4].toInt() and 0xff)
    // the Initial's long-header type bits: 0b00 in QUIC v1, 0b01 in v2 (RFC 9369 section 3.2)
    val initialBits =
        when (version) {
            1 -> 0xc0
            QUIC_V2 -> 0xd0
            else -> return null
        }
    if (datagram[0].toInt() and 0xf0 != initialBits) return null
    val dcidLen = datagram[5].toInt() and 0xff
    if (datagram.size < 7 + dcidLen) return null
    val dcid = datagram.copyOfRange(6, 6 + dcidLen)
    val scidLen = datagram[6 + dcidLen].toInt() and 0xff
    if (datagram.size < 7 + dcidLen + scidLen) return null
    val clientScid = datagram.copyOfRange(7 + dcidLen, 7 + dcidLen + scidLen)
    val payload = byteArrayOf(0x02, 0, 0, 0, 0) + ByteArray(30) // ACK of packet 0, PADDING
    val pnLength = 2
    val length = pnLength + payload.size + 16
    val header =
        byteArrayOf(
            (initialBits or 0x01).toByte(),
            (version ushr 24).toByte(),
            (version ushr 16).toByte(),
            (version ushr 8).toByte(),
            version.toByte(),
            clientScid.size.toByte(),
        ) + clientScid + byteArrayOf(dcid.size.toByte()) + dcid +
            byteArrayOf(0, (0x40 or (length shr 8)).toByte(), length.toByte())
    val pnOffset = header.size
    val bytes = header + ByteArray(length) // packet number 0 in two bytes
    payload.copyInto(bytes, pnOffset + pnLength)
    val (read, write) =
        io.kuicksilver.tls.KslQuicCrypto
            .initialProtectors(dcid, version, TlsRole.Server)
    val buf =
        io.kuicksilver.native.PacketBuffer
            .allocate(bytes.size)
    try {
        buf.copyFrom(bytes, 0, 0, bytes.size)
        val payloadStart = pnOffset + pnLength
        write.seal(0, buf, 0, payloadStart, buf, payloadStart, payload.size)
        val mask = ByteArray(5)
        write.headerMask(buf, pnOffset + 4, mask)
        buf[0] = ((buf[0].toInt() and 0xff) xor (mask[0].toInt() and 0x0f)).toByte()
        for (i in 0 until pnLength) buf[pnOffset + i] = (buf[pnOffset + i].toInt() xor mask[1 + i].toInt()).toByte()
        return ByteArray(bytes.size) { buf[it] }
    } finally {
        buf.close()
        read.close()
        write.close()
    }
}

/**
 * A UDP relay from a free port of 127.0.0.1 to 127.0.0.1:[target] (for one client address at a time); [block] gets its port
 * and its [UdpRelay] switch. Without [tcpTwin] nothing of ours listens on the TCP port of the same number; with it that
 * port is bound together with the relay's ([bindOnSamePort]) and handed over as [UdpRelay.tcp], for a test that serves
 * HTTP/1.1 on the relay's port later: binding TCP on that number only then failed with "Address already in use" whenever
 * another process held it.
 */
internal suspend fun udpRelay(
    target: Int,
    tcpTwin: Boolean = false,
    block: suspend (port: Int, relay: UdpRelay) -> Unit,
) {
    val selector = SelectorManager(Dispatchers.IO)
    val (front, tcp) =
        try {
            if (tcpTwin) {
                bindOnSamePort(
                    first = { p -> udpOn(selector, p) },
                    releaseFirst = { it.close() },
                    second = { p -> tcpOn(selector, p) },
                    releaseSecond = { it.close() },
                ).let { (u, t, _) -> u to t }
            } else {
                aSocket(selector).udp().bind(InetSocketAddress("127.0.0.1", 0)) to null
            }
        } catch (e: Throwable) {
            selector.close()
            throw e
        }
    val back =
        try {
            aSocket(selector).udp().bind(InetSocketAddress("127.0.0.1", 0))
        } catch (e: Throwable) {
            front.close()
            tcp?.close()
            selector.close()
            throw e
        }
    val relay = UdpRelay(tcp)
    val to = InetSocketAddress("127.0.0.1", target)
    var client: io.ktor.network.sockets.SocketAddress? = null
    try {
        coroutineScope {
            val up =
                launch {
                    while (true) {
                        val d = front.receive()
                        if (relay.blocked) {
                            d.packet.close()
                            relay.dropped.complete(Unit)
                            continue
                        }
                        client = d.address
                        var packet: kotlinx.io.Source = d.packet
                        if (relay.msquicProvisionalScid) {
                            val bytes = d.packet.readByteArray()
                            val dcid = longHeaderCid(bytes, scid = false)
                            val provisional = if (dcid != null) msquicProvisionalInitial(bytes) else null
                            val n = if (provisional != null) relay.countInitial(dcid!!) else 0
                            val due =
                                if (relay.onlyLargeClientHellos) {
                                    n == 3
                                } else {
                                    n == 1 && (relay.provisionalForEveryConnection || relay.provisionalInitialsSent == 0)
                                }
                            if (due) {
                                provisional?.let {
                                    relay.onProvisional?.invoke()
                                    front.send(
                                        io.ktor.network.sockets
                                            .Datagram(kotlinx.io.Buffer().apply { write(it) }, d.address),
                                    )
                                    relay.provisionalInitialsSent++
                                }
                            }
                            packet = kotlinx.io.Buffer().apply { write(bytes) }
                        }
                        back.send(
                            io.ktor.network.sockets
                                .Datagram(packet, to),
                        )
                    }
                }
            val down =
                launch {
                    while (true) {
                        val d = back.receive()
                        val c = client
                        if (relay.blocked || c == null || relay.serverDatagramsLeft <= 0) {
                            d.packet.close()
                            continue
                        }
                        if (relay.serverDatagramsLeft != Int.MAX_VALUE) relay.serverDatagramsLeft--
                        relay.serverDatagramsForwarded++
                        if (relay.msquicProvisionalScid) {
                            val scid = longHeaderCid(d.packet.peek().readByteArray(), scid = true)
                            if (scid != null) relay.addServerScid(scid)
                        }
                        front.send(
                            io.ktor.network.sockets
                                .Datagram(d.packet, c),
                        )
                    }
                }
            block((front.localAddress as InetSocketAddress).port, relay)
            up.cancel()
            down.cancel()
        }
    } finally {
        front.close()
        back.close()
        tcp?.close()
        selector.close()
    }
}

/** What a [tlsH2WithSilentUdp] server saw: connections accepted, their ALPN, and the ones that have ended. */
internal class H2ServerLog {
    private val lock = kotlinx.coroutines.sync.Mutex()
    val accepted = kotlinx.coroutines.channels.Channel<String?>(kotlinx.coroutines.channels.Channel.UNLIMITED)
    val ended = kotlinx.coroutines.channels.Channel<Int>(kotlinx.coroutines.channels.Channel.UNLIMITED)

    @kotlin.concurrent.Volatile var acceptCount: Int = 0

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val seen = kotlin.concurrent.atomics.AtomicReference<List<String?>>(emptyList())

    /**
     * The ALPN of every connection so far: a snapshot, safe to read from the test's thread (a plain list written by the
     * server's threads could be read stale there).
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    val protocols: List<String?> get() = seen.load()

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    suspend fun accept(alpn: String?) {
        lock.lock()
        try {
            acceptCount++
            while (true) {
                val old = seen.load()
                if (seen.compareAndSet(old, old + alpn)) break
            }
        } finally {
            lock.unlock()
        }
        accepted.send(alpn)
    }
}

/**
 * An HTTP/2 server on 127.0.0.1 over TLS with ALPN [alpn] (`h2` first: picked whenever the client offers it): every
 * connection that negotiated `h2` runs our server runtime with [settings] and hands each request to [onRequest] (which
 * must answer it), the stream released after; a connection that negotiated anything else goes to [h1] (default: closed at
 * once). With [silentUdp] the UDP twin port is bound and silent (QUIC blocked). [block] gets the port and the log.
 */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal suspend fun tlsH2WithSilentUdp(
    settings: io.kuicksilver.http2.Http2Settings = io.kuicksilver.http2.Http2Settings(),
    alpn: List<String> = listOf("h2", "http/1.1"),
    silentUdp: Boolean = false,
    h1: suspend CoroutineScope.(index: Int, input: ByteReadChannel, output: ByteWriteChannel) -> Unit = { _, _, _ -> },
    onConnection: suspend (index: Int, connection: io.kuicksilver.http2.runtime.H2ServerConnection) -> Unit = { _, _ -> },
    onRequest: suspend CoroutineScope.(connection: Int, request: io.kuicksilver.http2.runtime.H2ServerStream) -> Unit,
    // RFC 8441 section 3: SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, and Extended CONNECT requests are taken
    enableConnectProtocol: Boolean = false,
    // the server's frames (its SETTINGS first) reach the client only once this completes
    holdOutputUntil: kotlinx.coroutines.Deferred<Unit>? = null,
    block: suspend (port: Int, log: H2ServerLog) -> Unit,
) {
    val log = H2ServerLog()
    tlsWithSilentUdp(alpn, silentUdp, handler = { index, negotiated, input, output ->
        log.accept(negotiated)
        if (negotiated != "h2") return@tlsWithSilentUdp h1(index, input, output)
        val out =
            if (holdOutputUntil == null) {
                output
            } else {
                io.ktor.utils.io.ByteChannel().also { gate ->
                    launch {
                        holdOutputUntil.await()
                        runCatching { gate.copyTo(output) }
                        output.flushAndClose()
                    }
                }
            }
        val conn =
            io.kuicksilver.http2.runtime.H2ServerConnection.start(input, out, settings, this, closeTransport = {
                // a clean close (the last frames are flushed, then close_notify), as a server ends a connection
                out.close(null)
            }, enableConnectProtocol = enableConnectProtocol)
        onConnection(index, conn)
        val requests =
            launch {
                for (r in conn.requests) {
                    launch {
                        try {
                            onRequest(index, r)
                        } catch (e: kotlinx.coroutines.CancellationException) {
                            throw e
                        } catch (_: Throwable) {
                            // the client went away mid-answer: nothing to do
                        } finally {
                            r.release()
                        }
                    }
                }
            }
        try {
            conn.awaitClosed()
            // the socket closes when this returns: first let the client close its side (it does once it saw our last
            // frames), so our close_notify is out before the socket goes; closing at once sometimes cut the TLS
            // output and the client saw a truncation instead of our SETTINGS and GOAWAY
            kotlinx.coroutines.withTimeoutOrNull(5_000) { runCatching { input.readBuffer() } }
        } finally {
            requests.cancel()
            log.ended.trySend(index)
        }
    }) { port -> block(port, log) }
}

/**
 * A raw HTTP/2 server by hand: reads the client preface, sends an empty SETTINGS, acknowledges the client's, answers
 * every request with `:status 200` and END_STREAM and every PING with its ACK; with [answerOnce] it answers only the first
 * request and then nothing at all (a dead peer that still holds the connection). Returns when the client closes.
 */
internal suspend fun rawH2Server(
    input: ByteReadChannel,
    output: ByteWriteChannel,
    answerOnce: Boolean = false,
    // the first answer leaves its stream open (a long poll); completing this sends its last DATA ("done", END_STREAM)
    finishFirst: kotlinx.coroutines.Deferred<Unit>? = null,
) = coroutineScope {
    val writeLock = kotlinx.coroutines.sync.Mutex()

    fun frame(
        type: Int,
        flags: Int,
        stream: Int,
        payload: ByteArray = ByteArray(0),
    ): ByteArray =
        byteArrayOf(
            (payload.size shr 16).toByte(),
            (payload.size shr 8).toByte(),
            payload.size.toByte(),
            type.toByte(),
            flags.toByte(),
            (stream ushr 24).toByte(),
            (stream shr 16).toByte(),
            (stream shr 8).toByte(),
            stream.toByte(),
        ) + payload
    try {
        input.readByteArray(24) // PRI * HTTP/2.0...
        output.writeFully(frame(4, 0, 0))
        output.flush()
        var answered = 0
        while (true) {
            val head = input.readByteArray(9)
            val len = ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
            val type = head[3].toInt() and 0xff
            val flags = head[4].toInt() and 0xff
            val stream =
                ((head[5].toInt() and 0x7f) shl 24) or ((head[6].toInt() and 0xff) shl 16) or
                    ((head[7].toInt() and 0xff) shl 8) or (head[8].toInt() and 0xff)
            val payload = input.readByteArray(len)
            val live = !answerOnce || answered == 0
            when {
                type == 4 && flags and 1 == 0 -> {
                    writeLock.withLock { output.writeFully(frame(4, 1, 0)) }
                }

                type == 1 && live && answered == 0 && finishFirst != null -> {
                    answered++
                    writeLock.withLock { output.writeFully(frame(1, 0x4, stream, byteArrayOf(0x88.toByte()))) } // stays open
                    launch {
                        finishFirst.await()
                        writeLock.withLock {
                            output.writeFully(frame(0, 0x1, stream, "done".encodeToByteArray()))
                            output.flush()
                        }
                    }
                }

                type == 1 && live -> {
                    // :status 200, END_HEADERS | END_STREAM
                    writeLock.withLock { output.writeFully(frame(1, 0x5, stream, byteArrayOf(0x88.toByte()))) }
                    answered++
                }

                type == 6 && flags and 1 == 0 && live -> {
                    writeLock.withLock { output.writeFully(frame(6, 1, 0, payload)) }
                }
            }
            writeLock.withLock { output.flush() }
        }
    } catch (_: Throwable) {
        // the client closed the connection
    }
    coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
}
