// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    ExperimentalKuicksilverApi::class,
    DelicateKuicksilverApi::class,
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
)

package io.kuicksilver.http3.connectudp

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.CapsuleConfig
import io.kuicksilver.http3.CapsuleProtocol
import io.kuicksilver.http3.ConnectUdp
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.MemoryIo
import io.kuicksilver.http3.UdpProxy
import io.kuicksilver.http3.UdpProxyConfig
import io.kuicksilver.http3.UdpProxyResolver
import io.kuicksilver.http3.UdpProxyTemplate
import io.kuicksilver.http3.UdpTargetFilter
import io.kuicksilver.http3.connectUdp
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.IpFamily
import io.kuicksilver.quic.PacketTooBigSender
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ipLiteral
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

internal val proxySettings = http3Settings { enableConnectProtocol = true }

/** The proxy's template as clients of these tests know it. */
internal val template = UdpProxyTemplate.wellKnown("server.test")

/**
 * A UDP proxy on [pair]'s server, its sockets on the pair's in-memory network ([socketsOpened], [socketsClosed]), and
 * echo targets the test opens with [echo]. Everything the rig launches runs in its own scope, which [close] cancels.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class ProxyRig(
    val pair: H3Pair,
    configure: (suspend (InetSocketAddress) -> io.kuicksilver.quic.DatagramIo) -> UdpProxyConfig,
) : AutoCloseable {
    /** What a rig coroutine threw: checked by [close], since on Kotlin/Native an uncaught exception ends the test process. */
    private val failures = Channel<Throwable>(Channel.UNLIMITED)
    private val scope =
        CoroutineScope(SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, e -> failures.trySend(e) })
    private val nextPort = AtomicInt(40_000)
    val socketsOpened = AtomicInt(0)
    val socketsClosed = Channel<InetSocketAddress>(Channel.UNLIMITED)

    /** The sockets the proxy opened, in order. */
    val sockets = ArrayList<ClosingIo>()
    val proxy =
        UdpProxy(
            configure { _ ->
                socketsOpened.incrementAndFetch()
                val io = pair.quic.net.open(InetSocketAddress("10.0.0.2", nextPort.incrementAndFetch()))
                ClosingIo(io) { socketsClosed.trySend(io.localAddress) }.also { sockets += it }
            },
        ).also {
            // tests send no ICMP: as root (the local matrix's containers) the real probe opens a raw socket, and a real Packet
            // Too Big lowers the kernel's cached path MTU of its destination for every later test in that network namespace;
            // a test of RFC 9298 section 6.1 sets its own probe and sender (LinuxIcmpCheckTest alone sends real ones)
            it.impl.probeForTest = { PacketTooBigSender.Probe(false, "tests send no ICMP") }
        }

    /** The address of the [n]th socket the proxy opened (from 1). */
    fun proxySocket(n: Int): InetSocketAddress = InetSocketAddress("10.0.0.2", 40_000 + n)

    /** Serves every request of the pair's server connection with the proxy. */
    fun serveAll() {
        scope.launch {
            while (true) {
                val r =
                    try {
                        pair.server.acceptRequest()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        return@launch // the server's connection ended (the test closed the pair)
                    }
                launch { proxy.serve(r) }
            }
        }
    }

    /** A target at [address] that answers each payload with "echo:" and the payload; returns what it received. */
    fun echo(address: InetSocketAddress): Channel<ByteArray> {
        val got = Channel<ByteArray>(Channel.UNLIMITED)
        val io = pair.quic.net.open(address)
        scope.launch {
            try {
                while (true) {
                    val (bytes, from) = io.inbox.receiveCatching().getOrNull() ?: return@launch // the socket was closed
                    got.trySend(bytes)
                    pair.quic.net.deliver(address, from, "echo:".encodeToByteArray() + bytes)
                }
            } finally {
                io.close()
            }
        }
        return got
    }

    /** Launches [block] in the rig's scope (a request whose answer the test does not wait for). */
    fun background(block: suspend CoroutineScope.() -> Unit): Job = scope.launch(block = block)

    override fun close() {
        scope.cancel()
        pair.close()
        failures.tryReceive().getOrNull()?.let { throw AssertionError("a coroutine of the rig failed", it) }
    }
}

/** A socket that reports its close, the ECN marks it was asked to send and whether ECN marking was turned off. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ClosingIo(
    val io: MemoryIo,
    private val onClose: () -> Unit,
) : io.kuicksilver.quic.DatagramIo by io,
    io.kuicksilver.quic.UnreachableReports {
    /** What [takeUnreachable] answers, oldest first, as a socket whose error queue held ICMP unreachable messages. */
    val unreachable = Channel<io.kuicksilver.quic.Unreachable>(Channel.UNLIMITED)

    override fun takeUnreachable(): io.kuicksilver.quic.Unreachable? = unreachable.tryReceive().getOrNull()

    val ecnSent = ArrayList<io.kuicksilver.quic.Ecn>()
    var ecnMarkingDisabled = false

    /** Runs before each send (the tests' observer of when the proxy first sent). */
    @kotlin.concurrent.Volatile var onSend: (() -> Unit)? = null

    override fun disableEcnMarking() {
        ecnMarkingDisabled = true
    }

    /** The address the socket says it is bound to, when a test makes it another than its own (a wildcard bind). */
    @kotlin.concurrent.Volatile var boundTo: InetSocketAddress? = null

    override val localAddress: InetSocketAddress get() = boundTo ?: io.localAddress

    /** Reports each received datagram's destination as the socket's address, as the accelerated socket does on a wildcard bind. */
    @kotlin.concurrent.Volatile var reportLocal = false

    override suspend fun receive(into: io.kuicksilver.quic.PacketBatch): Int {
        val first = into.count
        val n = io.receive(into)
        if (reportLocal) for (i in first until into.count) into.setLocalAddress(i, io.localAddress)
        return n
    }

    override suspend fun send(batch: io.kuicksilver.quic.PacketBatch): Int {
        onSend?.invoke()
        for (i in 0 until batch.count) ecnSent += batch.ecn(i)
        return io.send(batch)
    }

    override fun close() {
        io.close()
        onClose()
    }
}

internal val echoAt = InetSocketAddress("192.0.2.50", 5000)

private fun allowAll(f: suspend (InetSocketAddress) -> io.kuicksilver.quic.DatagramIo) =
    UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, socketFactory = f)

class ConnectUdpTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun rig(configure: (suspend (InetSocketAddress) -> io.kuicksilver.quic.DatagramIo) -> UdpProxyConfig = ::allowAll) =
        ProxyRig(H3Pair.open(serverSettings = proxySettings), configure).also { it.serveAll() }

    /** RFC 9298 sections 3 and 5: a 2xx opens the tunnel, UDP payloads go both ways as Context ID 0 datagrams. */
    @Test fun tunnelCarriesPayloadsBothWays() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val tunnel = p.client.connectUdp(template, "192.0.2.50", 5000)
                assertEquals("192.0.2.50", tunnel.targetHost)
                // the 2xx carries capsule-protocol: ?1 (RFC 9297 section 3.4)
                assertTrue(CapsuleProtocol.isEnabled(tunnel.stream.stream.headers))
                assertEquals(DatagramSendResult.Sent, tunnel.trySend("ping".encodeToByteArray()))
                // section 5: "endpoints MUST NOT send HTTP Datagrams with a UDP Proxying Payload field longer than 65527"
                assertFailsWith<IllegalArgumentException> { tunnel.trySend(ByteArray(ConnectUdp.MAX_UDP_PAYLOAD + 1)) }
                assertContentEquals("ping".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                assertContentEquals("echo:ping".encodeToByteArray(), withTimeout(5.seconds) { tunnel.payloads.first() })
                assertEquals(1, rig.proxy.activeTunnels.value)
                tunnel.send(ByteArray(0)) // an empty UDP payload is a payload too (section 5: "this field can be empty")
                assertContentEquals(ByteArray(0), withTimeout(5.seconds) { got.receive() })
                // section 6.2: "it MUST set the ECN bits to Not-ECT on UDP packets it sends to the target"
                assertTrue(rig.sockets.single().ecnMarkingDisabled)
                assertEquals(listOf(io.kuicksilver.quic.Ecn.NotEct, io.kuicksilver.quic.Ecn.NotEct), rig.sockets.single().ecnSent)
                tunnel.close()
                // the client's FIN ends the tunnel: the proxy closes its socket and its side of the stream
                withTimeout(5.seconds) { rig.socketsClosed.receive() }
                withTimeout(5.seconds) { tunnel.payloads.toList() }
                withTimeout(5.seconds) { rig.proxy.activeTunnels.first { it == 0 } }
                assertEquals(1, rig.proxy.stats.tunnelsOpened)
            }
        }

    /**
     * Section 3.1, section 5: a datagram the client sent before the answer (it "MAY optimistically start sending") reaches
     * the target only after the 2xx went out: the proxy forwards nothing before it answered.
     */
    @Test fun noUdpGoesToTheTargetBeforeTheAnswer() =
        h3Test {
            rig().use { rig ->
                val p = rig.pair
                val got = rig.echo(echoAt)
                val requestArrived = CompletableDeferred<Unit>()
                val datagramSent = CompletableDeferred<Unit>()
                val answered = kotlin.concurrent.atomics.AtomicBoolean(false)
                val sentBeforeAnswer = kotlin.concurrent.atomics.AtomicBoolean(false)
                rig.proxy.impl.beforeAnswerForTest = { request ->
                    rig.sockets.single().onSend = { if (!answered.load()) sentBeforeAnswer.store(true) }
                    requestArrived.complete(Unit)
                    datagramSent.await()
                    // the early datagram waits on the request (32 at most, RFC 9297 section 2.1) while it is unanswered
                    withTimeout(5.seconds) {
                        while (!(request as io.kuicksilver.http3.runtime.ServerRequestImpl).datagramsWaitingForTest) {
                            kotlinx.coroutines
                                .yield()
                        }
                    }
                }
                rig.proxy.impl.answeredForTest = { answered.store(true) }
                val tunnel = async { p.client.connectUdp(template, "192.0.2.50", 5000) }
                withTimeout(5.seconds) { requestArrived.await() }
                // the client's first request stream is 0: Quarter Stream ID 0, Context ID 0 (RFC 9297 section 2.1, RFC 9298 section 5)
                assertEquals(DatagramSendResult.Sent, p.client.quic.trySendDatagram(byteArrayOf(0, 0) + "early".encodeToByteArray()))
                datagramSent.complete(Unit)
                assertContentEquals("early".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                assertTrue(answered.load())
                assertFalse(sentBeforeAnswer.load(), "the proxy sent to the target before it answered")
                withTimeout(5.seconds) { tunnel.await() }.close()
            }
        }

    /** Section 3: an IPv6 target goes percent-encoded and reaches its literal address. */
    @Test fun ipv6Target() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(InetSocketAddress("2001:db8::5", 4433))
                val tunnel = p.client.connectUdp(template, "[2001:db8::5]", 4433)
                tunnel.send("v6".encodeToByteArray())
                assertContentEquals("v6".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                assertContentEquals("echo:v6".encodeToByteArray(), withTimeout(5.seconds) { tunnel.payloads.first() })
                tunnel.close()
            }
        }

    /** Section 3.1: a DNS name is resolved before the answer, and the tunnel goes to the address that was allowed. */
    @Test fun dnsNameResolvedBeforeTheAnswer() =
        h3Test {
            val asked = CompletableDeferred<String>()
            val rig =
                rig { f ->
                    UdpProxyConfig(
                        targetFilter = UdpTargetFilter.AllowAll,
                        resolver =
                            UdpProxyResolver {
                                asked.complete(it)
                                listOf(byteArrayOf(192.toByte(), 0, 2, 50))
                            },
                        socketFactory = f,
                    )
                }
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val tunnel = p.client.connectUdp(template, "target.example", 5000)
                assertEquals("target.example", asked.await())
                tunnel.send("n".encodeToByteArray())
                assertContentEquals("n".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                // the client did not resolve the name: its QUIC socket reports a never-routed placeholder
                assertEquals("192.0.2.1", tunnel.remoteAddress.ipLiteral())
                assertEquals(5000, tunnel.remoteAddress.port)
                tunnel.close()
            }
        }

    /** Section 3.1: "If errors occur during this process, the UDP proxy MUST reject the request and SHOULD send details using an appropriate Proxy-Status". */
    @Test fun negative_dnsFailureAndTimeoutAreRefusedWithProxyStatus() =
        h3Test {
            val rig =
                rig { f ->
                    UdpProxyConfig(
                        targetFilter = UdpTargetFilter.AllowAll,
                        resolver =
                            UdpProxyResolver { host ->
                                when (host) {
                                    "fails.example" -> throw IllegalStateException("NXDOMAIN")
                                    "empty.example" -> emptyList()
                                    else -> awaitCancellation()
                                }
                            },
                        resolveTimeout = 200.milliseconds,
                        socketFactory = f,
                    )
                }
            rig.use { r ->
                val p = r.pair
                for ((host, status, error) in listOf(
                    Triple("fails.example", 502, "dns_error"),
                    Triple("empty.example", 502, "dns_error"),
                    Triple("slow.example", 504, "dns_timeout"),
                )) {
                    val e = assertFailsWith<Http3Exception.ConnectRejected>(host) { p.client.connectUdp(template, host, 53) }
                    assertEquals(status, e.status, host)
                    assertEquals("proxy; error=$error", e.headers["proxy-status"], host)
                }
                assertEquals(0, rig.socketsOpened.load())
            }
        }

    /** Section 7 (CWE-918): loopback, private, link-local, broadcast targets are refused by default, before any socket exists. */
    @Test fun negative_forbiddenTargetsAreRefusedByDefault() =
        h3Test {
            val rig =
                rig { f ->
                    UdpProxyConfig(
                        resolver = UdpProxyResolver { listOf(byteArrayOf(10, 0, 0, 1)) }, // a name that points inside
                        socketFactory = f,
                    )
                }
            rig.use { r ->
                val p = r.pair
                for (host in listOf(
                    "127.0.0.1",
                    "::1",
                    "::ffff:127.0.0.1",
                    "10.1.2.3",
                    "169.254.169.254",
                    "255.255.255.255",
                    "224.0.0.251",
                    "fe80::1",
                    "fd00::1",
                    "0.0.0.0",
                    "inside.example",
                )) {
                    val e = assertFailsWith<Http3Exception.ConnectRejected>(host) { p.client.connectUdp(template, host, 53) }
                    assertEquals(403, e.status, host)
                    assertEquals("proxy; error=destination_ip_prohibited", e.headers["proxy-status"], host)
                }
                assertEquals(0, rig.socketsOpened.load(), "a socket was opened for a forbidden target")
            }
        }

    /** Section 3.4 and 3: a value that breaks section 3 is answered 400, a path of another shape 404. */
    @Test fun negative_invalidTargetValuesAndPathsAreRefused() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                for ((path, status) in listOf(
                    "/.well-known/masque/udp/2001:db8::1/443/" to 400, // colons not percent-encoded
                    "/.well-known/masque/udp/192.0.2.1/0/" to 400,
                    "/.well-known/masque/udp/192.0.2.1/65536/" to 400,
                    "/.well-known/masque/udp//443/" to 400,
                    "/.well-known/masque/udp/fe80%3A%3A1%25en0/443/" to 400, // a zone ID
                    "/.well-known/masque/udp/127.1/443/" to 400, // not an IPv4address, and not a DNS name
                    "/masque?h=192.0.2.1&p=443" to 404,
                )) {
                    val e = assertFailsWith<Http3Exception.ConnectRejected>(path) { rawConnect(p, path) }
                    assertEquals(status, e.status, path)
                }
                assertEquals(0, rig.socketsOpened.load())
            }
        }

    /** A client refuses an invalid target or template before it sends anything (RFC 9298 section 2). */
    @Test fun negative_clientRefusesBeforeSending() =
        h3Test {
            // no proxy serves here: the test reads what reaches the server itself
            ProxyRig(H3Pair.open(serverSettings = proxySettings), ::allowAll).use { rig ->
                val p = rig.pair
                val first = CompletableDeferred<String?>()
                rig.background { first.complete(p.server.acceptRequest().path) }
                assertFailsWith<IllegalArgumentException> { p.client.connectUdp(template, "fe80::1%en0", 443) }
                assertFailsWith<IllegalArgumentException> { p.client.connectUdp(template, "192.0.2.1", 0) }
                assertFailsWith<IllegalArgumentException> { UdpProxyTemplate.parse("https://server.test/{+target_host}/{target_port}") }
                // the first request the server sees is the next valid one
                rig.background { runCatching { p.client.connectUdp(template, "192.0.2.9", 9) } }
                assertEquals("/.well-known/masque/udp/192.0.2.9/9/", withTimeout(5.seconds) { first.await() })
                assertEquals(0, rig.socketsOpened.load())
            }
        }

    @Test fun negative_missingCapsuleProtocolFieldIsRefused() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val e =
                    assertFailsWith<Http3Exception.ConnectRejected> {
                        rawConnect(
                            p,
                            "/.well-known/masque/udp/192.0.2.50/5000/",
                            capsuleField = false,
                        )
                    }
                assertEquals(400, e.status)
                val notTrue =
                    assertFailsWith<Http3Exception.ConnectRejected> {
                        rawConnect(p, "/.well-known/masque/udp/192.0.2.50/5000/", fields = listOf(CapsuleProtocol.FIELD to "?0"))
                    }
                assertEquals(400, notTrue.status)
                assertEquals(0, rig.socketsOpened.load())
            }
        }

    @Test fun capsuleProtocolFieldNotRequiredWhenConfigured() =
        h3Test {
            val rig =
                rig { f ->
                    UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, requireCapsuleProtocolField = false, socketFactory = f)
                }
            rig.use { r ->
                val p = r.pair
                val s = rawConnect(p, "/.well-known/masque/udp/192.0.2.50/5000/", capsuleField = false)
                s.reset(Http3ErrorCode.REQUEST_CANCELLED)
                withTimeout(5.seconds) { rig.socketsClosed.receive() }
            }
        }

    /**
     * Section 5: "An endpoint that receives an HTTP Datagram using Context ID zero whose UDP Proxying Payload field is
     * longer than 65527 MUST abort the corresponding stream", here a DATAGRAM capsule (no QUIC datagram is that large).
     */
    @Test fun negative_oversizedUdpPayloadAbortsTheStream() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val s = rawConnect(p, "/.well-known/masque/udp/192.0.2.50/5000/")
                val c = s.useCapsuleProtocol(CapsuleConfig())
                c.send(Capsule(CapsuleProtocol.DATAGRAM, ByteArray(1 + ConnectUdp.MAX_UDP_PAYLOAD + 1)))
                val e = assertFailsWith<Throwable> { withTimeout(5.seconds) { c.capsules.toList() } }
                assertEquals(Http3ErrorCode.DATAGRAM_ERROR, h3Code(e), "$e")
                withTimeout(5.seconds) { rig.socketsClosed.receive() }
                assertEquals(null, got.tryReceive().getOrNull(), "the target received a datagram")
            }
        }

    /** Section 5: a payload the proxy's link cannot carry unfragmented is dropped, the tunnel lives on. */
    @Test fun negative_payloadAboveTheLinkMtuIsDropped() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val s = rawConnect(p, "/.well-known/masque/udp/192.0.2.50/5000/")
                val c = s.useCapsuleProtocol(CapsuleConfig())
                c.send(Capsule(CapsuleProtocol.DATAGRAM, ByteArray(1 + 1473))) // IPv4: 1500 - 28 = 1472 at most
                c.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1472)))
                assertEquals(1472, withTimeout(5.seconds) { got.receive() }.size)
                assertEquals(1, rig.proxy.stats.droppedTooLargeForLink)
                c.close()
            }
        }

    /** Section 4: datagrams with a Context ID nobody registered are dropped silently, on both transports. */
    @Test fun negative_unknownContextIdIsDroppedByTheProxy() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val s = rawConnect(p, "/.well-known/masque/udp/192.0.2.50/5000/")
                val c = s.useCapsuleProtocol(CapsuleConfig())
                c.sendDatagram(VarInt.encode(2) + "two".encodeToByteArray())
                c.send(Capsule(CapsuleProtocol.DATAGRAM, VarInt.encode(4) + "four".encodeToByteArray()))
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedUnknownContext == 2L }
                }
                c.sendDatagram(byteArrayOf(0) + "zero".encodeToByteArray())
                assertContentEquals("zero".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                assertEquals(null, got.tryReceive().getOrNull(), "the target received a datagram")
                c.close()
            }
        }

    /** Section 4 on the client: a proxy's datagram with another Context ID never reaches the application. */
    @Test fun negative_unknownContextIdIsDroppedByTheClient() =
        h3Test {
            H3Pair.open(serverSettings = proxySettings).useScoped { p ->
                launch {
                    val c =
                        p.server
                            .acceptRequest()
                            .acceptConnect(
                                Http3Headers(listOf(CapsuleProtocol.Enabled)),
                            ).useCapsuleProtocol(CapsuleConfig())
                    c.sendDatagram(VarInt.encode(1) + "odd".encodeToByteArray())
                    c.send(Capsule(CapsuleProtocol.DATAGRAM, VarInt.encode(3) + "three".encodeToByteArray()))
                    c.send(Capsule(CapsuleProtocol.DATAGRAM, ByteArray(0)))
                    c.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + "udp".encodeToByteArray()))
                    c.capsules.toList()
                    c.close()
                }
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                assertContentEquals("udp".encodeToByteArray(), withTimeout(5.seconds) { t.payloads.first() })
                assertTrue(t.droppedDatagrams >= 1, "dropped ${t.droppedDatagrams}")
                t.close()
            }
        }

    /** Section 5: a full 65527-byte payload arrives even behind a Context ID in its longest (8-byte) encoding. */
    @Test fun largestPayloadWithALongContextIdIsDelivered() =
        h3Test {
            H3Pair.open(serverSettings = proxySettings).useScoped { p ->
                launch {
                    val c =
                        p.server
                            .acceptRequest()
                            .acceptConnect(
                                Http3Headers(listOf(CapsuleProtocol.Enabled)),
                            ).useCapsuleProtocol(CapsuleConfig())
                    val ctx = byteArrayOf(0xc0.toByte(), 0, 0, 0, 0, 0, 0, 0)
                    c.send(Capsule(CapsuleProtocol.DATAGRAM, ctx + ByteArray(ConnectUdp.MAX_UDP_PAYLOAD) { 7 }))
                    c.capsules.toList()
                    c.close()
                }
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                val got = withTimeout(5.seconds) { t.payloads.first() }
                assertEquals(ConnectUdp.MAX_UDP_PAYLOAD, got.size)
                assertEquals(7, got.last().toInt())
                t.close()
            }
        }

    /** Section 3.1: "If the UDP proxy uses a non-connected socket, it MUST validate the IP source address and UDP source port". */
    @Test fun negative_datagramFromAnotherSourceIsDiscarded() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                t.send("a".encodeToByteArray())
                got.receive()
                assertContentEquals("echo:a".encodeToByteArray(), withTimeout(5.seconds) { t.payloads.first() })
                val proxySocket = InetSocketAddress("10.0.0.2", 40_001)
                p.quic.net.deliver(InetSocketAddress("192.0.2.50", 5001), proxySocket, "spoof-port".encodeToByteArray())
                p.quic.net.deliver(InetSocketAddress("192.0.2.51", 5000), proxySocket, "spoof-ip".encodeToByteArray())
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedForeignSource == 2L }
                }
                t.send("b".encodeToByteArray())
                assertContentEquals("echo:b".encodeToByteArray(), withTimeout(5.seconds) { t.payloads.first() })
                t.close()
            }
        }

    /** Section 7 (CWE-400): payloads beyond the tunnel's rate are dropped; a frozen clock refills nothing. */
    @Test fun negative_rateLimitDropsBeyondTheBurst() =
        h3Test {
            val rig =
                rig { f ->
                    UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, packetRate = 1, packetBurst = 3, socketFactory = f)
                }
            rig.proxy.impl.clock = TestTimeSource()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                repeat(10) { t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0, it.toByte()))) }
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes.first {
                        rig.proxy.stats.droppedRateLimited + rig.proxy.stats.toTargets ==
                            10L
                    }
                }
                assertEquals(3, rig.proxy.stats.toTargets)
                assertEquals(listOf<Byte>(0, 1, 2), List(3) { got.receive()[0] })
                t.close()
            }
        }

    /** Section 7: a target that never answers gets at most `unansweredLimit` payloads. */
    @Test fun negative_unansweredTargetIsNotFlooded() =
        h3Test {
            val rig = rig { f -> UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, unansweredLimit = 4, socketFactory = f) }
            rig.use { r ->
                val p = r.pair
                val silent = p.quic.net.open(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                repeat(10) { t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0, it.toByte()))) }
                withTimeout(
                    5.seconds,
                ) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedUnanswered + rig.proxy.stats.toTargets == 10L }
                }
                assertEquals(4, rig.proxy.stats.toTargets)
                // one answer lifts the limit
                p.quic.net.deliver(echoAt, InetSocketAddress("10.0.0.2", 40_001), "hi".encodeToByteArray())
                assertContentEquals("hi".encodeToByteArray(), withTimeout(5.seconds) { t.payloads.first() })
                t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0, 99)))
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.toTargets == 5L }
                }
                silent.close()
                t.close()
            }
        }

    /** A client whose connection disappears: the proxy closes the socket and frees the tunnel (CWE-400). */
    @Test fun negative_clientThatDisappearsFreesTheTunnel() =
        h3Test {
            rig().use { rig ->
                val p = rig.pair
                rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                assertEquals(1, rig.proxy.activeTunnels.value)
                p.quic.client.close() // the client's whole endpoint goes away
                withTimeout(10.seconds) { rig.socketsClosed.receive() }
                withTimeout(10.seconds) { rig.proxy.activeTunnels.first { it == 0 } }
                runCatching { withTimeout(5.seconds) { t.payloads.toList() } }
            }
        }

    /**
     * Section 3.1: "If a UDP proxy is notified by its operating system that its socket is no longer usable, it MUST close
     * the request stream": a socket whose receive fails resets the stream with H3_CONNECT_ERROR.
     */
    @Test fun negative_socketFailureClosesTheRequestStream() =
        h3Test {
            rig().use { rig ->
                val p = rig.pair
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                rig.sockets
                    .single()
                    .io.inbox
                    .close(IllegalStateException("network unreachable"))
                val e = assertFailsWith<Throwable> { withTimeout(5.seconds) { t.stream.capsules.toList() } }
                assertEquals(Http3ErrorCode.CONNECT_ERROR, h3Code(e), "$e")
                withTimeout(5.seconds) { rig.socketsClosed.receive() }
                withTimeout(5.seconds) { rig.proxy.activeTunnels.first { it == 0 } }
            }
        }

    /** A client that resets its request stream ends the tunnel too. */
    @Test fun negative_clientResetFreesTheTunnel() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                t.stream.stream.reset(Http3ErrorCode.REQUEST_CANCELLED)
                withTimeout(5.seconds) { rig.socketsClosed.receive() }
                withTimeout(5.seconds) { rig.proxy.activeTunnels.first { it == 0 } }
            }
        }

    /** Section 3.1: a tunnel idle for the idle timeout is closed with its request stream. */
    @Test fun idleTunnelIsClosedWithItsStream() =
        h3Test {
            val rig = rig()
            rig.proxy.impl.idleTimeoutForTest = 300.milliseconds
            rig.use { r ->
                val p = r.pair
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                withTimeout(10.seconds) { rig.socketsClosed.receive() }
                // the proxy's FIN ends the client's payloads
                withTimeout(10.seconds) { t.payloads.toList() }
                t.close()
            }
        }

    /** Limits per client address and in all: one tunnel more is refused with connection_limit_reached. */
    @Test fun negative_tunnelLimitsAreEnforced() =
        h3Test {
            val rig = rig { f -> UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, maxTunnelsPerClient = 2, socketFactory = f) }
            rig.use { r ->
                val p = r.pair
                val a = p.client.connectUdp(template, "192.0.2.50", 5000)
                val b = p.client.connectUdp(template, "192.0.2.50", 5001)
                val e = assertFailsWith<Http3Exception.ConnectRejected> { p.client.connectUdp(template, "192.0.2.50", 5002) }
                assertEquals(429, e.status)
                assertEquals("proxy; error=connection_limit_reached", e.headers["proxy-status"])
                a.close()
                withTimeout(5.seconds) { rig.proxy.activeTunnels.first { it == 1 } }
                val c = p.client.connectUdp(template, "192.0.2.50", 5002)
                b.close()
                c.close()
            }
        }

    /**
     * No DF, no tunnel (RFC 9298 section 3.1: "UDP proxies MUST NOT introduce fragmentation at the IP layer"): a target of
     * a family the proxy's sockets have no Don't Fragment for is refused with 500 `proxy_configuration_error` (RFC 9209
     * section 2.3.24), whether the factory refuses the socket or the socket names that family; the other family is served.
     */
    @Test fun negative_aTargetFamilyWithoutDontFragmentIsRefused() =
        h3Test {
            val rig =
                rig { f ->
                    UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, socketFactory = { a -> NoDfFor(f(a), IpFamily.V4) })
                }
            rig.use { r ->
                val p = r.pair
                val e = assertFailsWith<Http3Exception.ConnectRejected> { p.client.connectUdp(template, "192.0.2.50", 5000) }
                assertEquals(500, e.status)
                assertEquals(
                    "proxy; error=proxy_configuration_error; details=\"no Don't Fragment for IPv4 targets on this host\"",
                    e.headers["proxy-status"],
                )
                // the other family: served
                val got = rig.echo(InetSocketAddress("2001:db8::50", 5000))
                val t = p.client.connectUdp(template, "2001:db8::50", 5000)
                t.send("v6".encodeToByteArray())
                assertContentEquals("v6".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                t.close()
            }
        }

    /** An IPv4-mapped literal target (`::ffff:a.b.c.d`) is an IPv4 target: refused where IPv4 has no DF, served where IPv6 has none. */
    @Test fun negative_aMappedLiteralTargetIsIpv4() =
        h3Test {
            for (noDf in listOf(IpFamily.V4, IpFamily.V6)) {
                val rig =
                    rig { f -> UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, socketFactory = { a -> NoDfFor(f(a), noDf) }) }
                rig.use { r ->
                    if (noDf == IpFamily.V4) {
                        val e =
                            assertFailsWith<Http3Exception.ConnectRejected> {
                                r.pair.client.connectUdp(template, "::ffff:192.0.2.50", 5000)
                            }
                        assertEquals(500, e.status)
                        assertTrue("for IPv4 targets" in e.headers["proxy-status"]!!, e.headers["proxy-status"])
                    } else {
                        val got = rig.echo(echoAt)
                        val t = r.pair.client.connectUdp(template, "::ffff:192.0.2.50", 5000)
                        t.send("mapped".encodeToByteArray())
                        assertContentEquals("mapped".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                        t.close()
                    }
                }
            }
        }

    /**
     * A name with addresses of both families, the one without DF first: the proxy uses the other family; a name with only
     * addresses of the family without DF is refused with 500 `proxy_configuration_error`.
     */
    @Test fun aNameIsServedThroughTheFamilyWithDontFragment() =
        h3Test {
            val v4 = byteArrayOf(192.toByte(), 0, 2, 50)
            val v6 =
                ByteArray(16).also {
                    it[0] = 0x20
                    it[1] = 0x01
                    it[2] = 0x0d
                    it[3] = 0xb8.toByte()
                    it[15] = 0x50
                }
            val rig =
                rig { f ->
                    UdpProxyConfig(
                        targetFilter = UdpTargetFilter.AllowAll,
                        resolver = UdpProxyResolver { host -> if (host == "dual.example") listOf(v4, v6) else listOf(v4) },
                        socketFactory = { a -> NoDfFor(f(a), IpFamily.V4) },
                    )
                }
            rig.use { r ->
                val got = rig.echo(InetSocketAddress("2001:db8::50", 5000))
                val t = r.pair.client.connectUdp(template, "dual.example", 5000)
                t.send("dual".encodeToByteArray())
                assertContentEquals("dual".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                t.close()
                val e = assertFailsWith<Http3Exception.ConnectRejected> { r.pair.client.connectUdp(template, "v4only.example", 5000) }
                assertEquals(500, e.status)
                assertEquals(
                    "proxy; error=proxy_configuration_error; details=\"no Don't Fragment for IPv4 targets on this host\"",
                    e.headers["proxy-status"],
                )
            }
        }

    /** A socket factory that cannot set DF at all (no DF, no QUIC or tunnel) refuses the tunnel the same way. */
    @Test fun negative_aSocketFactoryWithoutDontFragmentRefusesTheTunnel() =
        h3Test {
            val rig =
                rig { _ ->
                    UdpProxyConfig(
                        targetFilter = UdpTargetFilter.AllowAll,
                        socketFactory = {
                            throw io.kuicksilver.quic.QuicException
                                .DontFragmentUnavailable(null, "test: no DF")
                        },
                    )
                }
            rig.use { r ->
                val e = assertFailsWith<Http3Exception.ConnectRejected> { r.pair.client.connectUdp(template, "192.0.2.50", 5000) }
                assertEquals(500, e.status)
                assertTrue("error=proxy_configuration_error" in e.headers["proxy-status"]!!)
            }
        }

    /** Section 6.1: a target payload too large for the client's QUIC DATAGRAM frames is dropped, not sent as a capsule. */
    @Test fun negative_targetPayloadTooLargeForTheClientIsDropped() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                // 1400 bytes fit the proxy's link but not a QUIC DATAGRAM frame on a 1200-byte path
                val s = rawCapsules(t)
                s.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400)))
                assertEquals(1400, withTimeout(5.seconds) { got.receive() }.size)
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedTooLargeForClient == 1L }
                }
                t.send("small".encodeToByteArray())
                assertContentEquals("echo:small".encodeToByteArray(), withTimeout(5.seconds) { t.payloads.first() })
                t.close()
            }
        }

    /**
     * RFC 9298 section 6.1 without the privilege (the probe fails: no CAP_NET_RAW, or not Linux): a target payload too large
     * for the client's QUIC DATAGRAM frames is dropped and counted, and no Packet Too Big goes out.
     */
    @Test fun negative_withoutThePrivilegeAnOversizedTargetPayloadIsOnlyDropped() =
        h3Test {
            val rig = rig()
            var sinks = 0
            rig.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(false, "no CAP_NET_RAW (test)")
            }
            rig.proxy.impl.senderForTest = {
                sinks++
                error("no sender without the privilege")
            }
            assertEquals(io.kuicksilver.http3.PacketTooBigStatus.NotProbed, rig.proxy.stats.packetTooBig)
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                rig.sockets.single().reportLocal = true
                t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400)))
                assertEquals(1400, withTimeout(5.seconds) { got.receive() }.size)
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedTooLargeForClient == 1L }
                }
                assertEquals(io.kuicksilver.http3.PacketTooBigStatus.Unavailable, rig.proxy.stats.packetTooBig)
                assertEquals(0, rig.proxy.stats.packetTooBigSent)
                assertEquals(0, sinks)
                t.close()
            }
        }

    /**
     * RFC 9298 section 6.1 with the privilege: each dropped payload is answered with a Packet Too Big to the target, from
     * the address it sent to, with the MTU that fits the client's DATAGRAM frames, at most 5 at once (RFC 4443 section 2.4
     * (f); a frozen clock refills nothing) and never more than the drops. The raw socket is replaced: tests send no ICMP.
     */
    @Test fun withThePrivilegeEachDropIsAnsweredWithinTheRateLimit() =
        h3Test {
            val rig = rig()
            val sent = Channel<Triple<InetSocketAddress, InetSocketAddress, Pair<Int, Int>>>(Channel.UNLIMITED)
            var closed = 0
            rig.proxy.impl.clock = TestTimeSource()
            rig.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(true, "test")
            }
            rig.proxy.impl.senderForTest = {
                object : PtbSink {
                    override fun send(
                        target: InetSocketAddress,
                        local: InetSocketAddress,
                        payload: ByteArray,
                        len: Int,
                        mtu: Int,
                    ): Boolean {
                        sent.trySend(Triple(target, local, len to mtu))
                        return true
                    }

                    override fun close() {
                        closed++
                    }
                }
            }
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                rig.sockets.single().reportLocal = true
                repeat(8) { t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400))) }
                repeat(8) { assertEquals(1400, withTimeout(5.seconds) { got.receive() }.size) }
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedTooLargeForClient == 8L }
                }
                assertEquals(io.kuicksilver.http3.PacketTooBigStatus.Available, rig.proxy.stats.packetTooBig)
                assertEquals(5, rig.proxy.stats.packetTooBigSent, "the burst of 5, nothing refilled")
                val (target, local, sizes) = sent.receive()
                assertEquals(echoAt, target)
                assertEquals(rig.proxySocket(1), local)
                assertEquals(1405, sizes.first) // the echo's payload that did not fit
                val (_, mtu) = sizes
                assertTrue(mtu in 68 until 1405 + 28, "MTU $mtu: the largest datagram that fits, with its UDP and IPv4 headers")
                t.close()
                // the tunnel's slot is released after its sender was closed
                withTimeout(5.seconds) { rig.proxy.activeTunnels.first { it == 0 } }
            }
            assertEquals(1, closed, "the tunnel's sender is closed with it")
        }

    /** A recording [PtbSink] for the tests: what was sent, how often it was closed. */
    private class RecordingSink(
        private val accept: Boolean = true,
    ) : PtbSink {
        val sent = Channel<InetSocketAddress>(Channel.UNLIMITED)

        /** The source address of each message sent: the address the target sent to. */
        val locals = Channel<InetSocketAddress>(Channel.UNLIMITED)

        /** The MTU of each message sent. */
        val mtus = Channel<Int>(Channel.UNLIMITED)
        var closed = 0

        override fun send(
            target: InetSocketAddress,
            local: InetSocketAddress,
            payload: ByteArray,
            len: Int,
            mtu: Int,
        ): Boolean {
            sent.trySend(target)
            locals.trySend(local)
            mtus.trySend(mtu)
            return accept
        }

        override fun close() {
            closed++
        }
    }

    /**
     * RFC 4443 section 2.4 (f): the Packet Too Big limit is the target's, over every tunnel to it (two tunnels to one target
     * share its burst of 5), and the proxy's (a burst of 3 here, over two targets); one sender (two raw sockets at most)
     * serves every tunnel, closed when the last one ends.
     */
    @Test fun negative_packetTooBigLimitsArePerTargetAndProxyWide() =
        h3Test {
            val rig = rig()
            val sink = RecordingSink()
            rig.proxy.impl.clock = TestTimeSource()
            rig.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(true, "test")
            }
            rig.proxy.impl.senderForTest = { sink }
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val a = p.client.connectUdp(template, "192.0.2.50", 5000)
                val b = p.client.connectUdp(template, "192.0.2.50", 5000)
                rig.sockets.forEach { it.reportLocal = true }
                repeat(4) { a.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400))) }
                repeat(4) { b.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400))) }
                repeat(8) { got.receive() }
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedTooLargeForClient == 8L }
                }
                assertEquals(5, rig.proxy.stats.packetTooBigSent, "the target's burst of 5 over both tunnels")
                assertEquals(
                    1,
                    rig.proxy.impl.ptbSinksOpened
                        .load(),
                    "one sender for the proxy",
                )
                a.close()
                b.close()
                withTimeout(5.seconds) { rig.proxy.activeTunnels.first { it == 0 } }
                assertEquals(1, sink.closed, "closed with the last tunnel")
            }
            // the proxy-wide limit: two targets, each with a burst of 5 of its own, get 3 together
            val capped = rig()
            val sink2 = RecordingSink()
            capped.proxy.impl.clock = TestTimeSource()
            capped.proxy.impl.ptbTotalBurst = 3
            capped.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(true, "test")
            }
            capped.proxy.impl.senderForTest = { sink2 }
            capped.use { r ->
                val p = r.pair
                val other = InetSocketAddress("192.0.2.51", 5000)
                val got1 = capped.echo(echoAt)
                val got2 = capped.echo(other)
                val a = p.client.connectUdp(template, "192.0.2.50", 5000)
                val b = p.client.connectUdp(template, "192.0.2.51", 5000)
                capped.sockets.forEach { it.reportLocal = true }
                repeat(3) { a.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400))) }
                repeat(3) { b.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400))) }
                repeat(3) { got1.receive() }
                repeat(3) { got2.receive() }
                withTimeout(5.seconds) {
                    capped.proxy.impl.changes
                        .first { capped.proxy.stats.droppedTooLargeForClient == 6L }
                }
                assertEquals(3, capped.proxy.stats.packetTooBigSent, "the proxy's burst of 3 over both targets")
                a.close()
                b.close()
            }
        }

    /**
     * RFC 9298 section 6.1 from a socket bound to one address that does not report each datagram's destination (the portable
     * socket, or the accelerated one off a wildcard bind): the target sent to the socket's own address, so the Packet Too Big
     * leaves from it.
     */
    @Test fun packetTooBigFromASpecificBindLeavesFromTheSocketsAddress() =
        h3Test {
            val rig = rig()
            val sink = RecordingSink()
            rig.proxy.impl.clock = TestTimeSource()
            rig.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(true, "test")
            }
            rig.proxy.impl.senderForTest = { sink }
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                assertFalse(rig.sockets.single().reportLocal, "no destination per datagram")
                t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400)))
                assertEquals(1400, withTimeout(5.seconds) { got.receive() }.size)
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedTooLargeForClient == 1L && rig.proxy.stats.packetTooBigSent == 1L }
                }
                assertEquals(echoAt, sink.sent.receive())
                assertEquals(rig.proxySocket(1), sink.locals.receive(), "from the address the socket is bound to")
                t.close()
            }
        }

    /**
     * RFC 9298 section 6.1 from a socket bound to a wildcard address that does not report each datagram's destination (the
     * portable socket): there is no address the message could leave from, so none goes, and the drop is counted.
     */
    @Test fun negative_wildcardBindWithoutDestinationsSendsNoPacketTooBig() =
        h3Test {
            val rig = rig()
            val sink = RecordingSink()
            rig.proxy.impl.clock = TestTimeSource()
            rig.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(true, "test")
            }
            rig.proxy.impl.senderForTest = { sink }
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                rig.sockets.single().boundTo = InetSocketAddress("0.0.0.0", rig.proxySocket(1).port)
                repeat(2) { t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400))) }
                repeat(2) { assertEquals(1400, withTimeout(5.seconds) { got.receive() }.size) }
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedTooLargeForClient == 2L && rig.proxy.stats.packetTooBigNoSource == 2L }
                }
                assertEquals(0, rig.proxy.stats.packetTooBigSent)
                assertEquals(null, sink.sent.tryReceive().getOrNull(), "nothing sent")
                assertEquals(
                    0,
                    rig.proxy.impl.ptbSinksOpened
                        .load(),
                    "no sender opened",
                )
                t.close()
            }
            // a wildcard in any spelling: all its address bytes zero
            assertEquals(null, sourceOf(null, InetSocketAddress("0.0.0.0", 4433)))
            assertEquals(null, sourceOf(null, InetSocketAddress("::", 4433)))
            assertEquals(null, sourceOf(null, InetSocketAddress("::ffff:0.0.0.0", 1)))
            assertEquals(null, sourceOf(null, InetSocketAddress("::%1", 4433)), "a zoned IPv6 wildcard")
            assertEquals(null, sourceOf(null, InetSocketAddress("10.0.0.2", 0)), "a port not known")
            // a dual-stack socket's IPv4-mapped address is its IPv4 address, the family of an IPv4 target's raw socket
            assertEquals("10.0.0.2", sourceOf(null, InetSocketAddress("::ffff:10.0.0.2", 4433))?.ipLiteral())
            assertEquals("10.0.0.2", sourceOf(InetSocketAddress("::ffff:10.0.0.2", 4433), InetSocketAddress("::", 4433))?.ipLiteral())
            val v6 = InetSocketAddress("2001:db8::1", 4433)
            assertEquals(v6, sourceOf(null, v6))
            assertEquals(v6, sourceOf(v6, InetSocketAddress("0.0.0.0", 4433)), "the datagram's own destination first")
        }

    /**
     * RFC 9298 section 6.1 from a dual-stack socket bound to an IPv4-mapped address (`::ffff:10.0.0.2`, which Kotlin/Native
     * keeps as IPv6): the sender is handed the IPv4 address, the family of the IPv4 target, not one it would refuse.
     */
    @Test fun packetTooBigFromAnIpv4MappedBindIsSentAsIpv4() =
        h3Test {
            val rig = rig()
            val sink = RecordingSink()
            rig.proxy.impl.clock = TestTimeSource()
            rig.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(true, "test")
            }
            rig.proxy.impl.senderForTest = { sink }
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                val port = rig.proxySocket(1).port
                rig.sockets.single().boundTo = InetSocketAddress("::ffff:10.0.0.2", port)
                t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400)))
                assertEquals(1400, withTimeout(5.seconds) { got.receive() }.size)
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.packetTooBigSent == 1L }
                }
                assertEquals("192.0.2.50", sink.sent.receive().ipLiteral())
                val local = sink.locals.receive()
                assertEquals("10.0.0.2", local.ipLiteral(), "IPv4, as the target")
                assertEquals(port, local.port)
                t.close()
            }
        }

    /**
     * A request for an IPv4-mapped target (`::ffff:192.0.2.51`, which Kotlin/Native keeps as IPv6) reaches the IPv4 address,
     * and its Packet Too Big is IPv4: the sender gets the IPv4 target and the MTU with the IPv4 and UDP headers (28 bytes),
     * the same as for a plain IPv4 target, not 48.
     */
    @Test fun packetTooBigToAnIpv4MappedTargetIsIpv4() =
        h3Test {
            val rig = rig()
            val sink = RecordingSink()
            rig.proxy.impl.clock = TestTimeSource()
            rig.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(true, "test")
            }
            rig.proxy.impl.senderForTest = { sink }
            rig.use { r ->
                val p = r.pair
                val mapped = InetSocketAddress("192.0.2.51", 5000) // where the proxy sends: the address unmapped
                val gotPlain = rig.echo(echoAt)
                val gotMapped = rig.echo(mapped)
                val plain = p.client.connectUdp(template, "192.0.2.50", 5000)
                plain.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400)))
                assertEquals(1400, withTimeout(5.seconds) { gotPlain.receive() }.size)
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.packetTooBigSent == 1L }
                }
                assertEquals("192.0.2.50", sink.sent.receive().ipLiteral())
                sink.locals.receive()
                val plainMtu = sink.mtus.receive()
                val t = p.client.connectUdp(template, "::ffff:192.0.2.51", 5000)
                t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400)))
                assertEquals(1400, withTimeout(5.seconds) { gotMapped.receive() }.size)
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.packetTooBigSent == 2L }
                }
                assertEquals("192.0.2.51", sink.sent.receive().ipLiteral(), "IPv4, not IPv4-mapped IPv6")
                assertEquals("10.0.0.2", sink.locals.receive().ipLiteral())
                assertEquals(plainMtu, sink.mtus.receive(), "the IPv4 headers' 28 bytes on top of the same payload")
                plain.close()
                t.close()
            }
        }

    /** A Packet Too Big the sender refuses (no socket for the family, the kernel) is counted, not taken for one sent. */
    @Test fun negative_aPacketTooBigTheSenderRefusesIsCounted() =
        h3Test {
            val rig = rig()
            val sink = RecordingSink(accept = false)
            rig.proxy.impl.clock = TestTimeSource()
            rig.proxy.impl.probeForTest = {
                io.kuicksilver.quic.PacketTooBigSender
                    .Probe(true, "test")
            }
            rig.proxy.impl.senderForTest = { sink }
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                repeat(2) { t.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0) + ByteArray(1400))) }
                repeat(2) { assertEquals(1400, withTimeout(5.seconds) { got.receive() }.size) }
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.packetTooBigFailed == 2L }
                }
                assertEquals(0, rig.proxy.stats.packetTooBigSent)
                assertEquals(0, rig.proxy.stats.packetTooBigNoSource)
                assertTrue("packetTooBigFailed=2" in rig.proxy.stats.toString())
                t.close()
            }
        }

    /** One client has at most 4 name lookups at once (a blocked one counts until it returns); a fifth is refused 503. */
    @Test fun negative_oneClientCannotTakeEveryLookup() =
        h3Test {
            val gate = CompletableDeferred<Unit>()
            val started = Channel<Unit>(Channel.UNLIMITED)
            val rig =
                rig { f ->
                    UdpProxyConfig(
                        targetFilter = UdpTargetFilter.AllowAll,
                        resolver = {
                            started.send(Unit)
                            gate.await()
                            listOf(byteArrayOf(192.toByte(), 0, 2, 50))
                        },
                        resolveTimeout = 30.seconds,
                        socketFactory = f,
                    )
                }
            rig.use { r ->
                val p = r.pair
                val slow = List(SystemResolver.MAX_PER_CLIENT) { async { p.client.connectUdp(template, "slow$it.example", 5000) } }
                repeat(SystemResolver.MAX_PER_CLIENT) { withTimeout(5.seconds) { started.receive() } }
                val e = assertFailsWith<Http3Exception.ConnectRejected> { p.client.connectUdp(template, "one-more.example", 5000) }
                assertEquals(503, e.status)
                gate.complete(Unit)
                slow.forEach { it.await().close() }
            }
            // the system resolver counts a client's lookups until they return, given up or not
            val owner = kotlin.concurrent.atomics.AtomicInt(0)
            val gate2 = CompletableDeferred<Unit>()
            try {
                SystemResolver.lookupForTest =
                    {
                        kotlinx.coroutines.runBlocking { gate2.await() }
                        listOf(byteArrayOf(192.toByte(), 0, 2, 1))
                    }
                repeat(SystemResolver.MAX_PER_CLIENT) {
                    assertEquals(
                        null,
                        kotlinx.coroutines.withTimeoutOrNull(20.milliseconds) { SystemResolver.resolveFor("x.example", owner) },
                    )
                }
                assertEquals(SystemResolver.MAX_PER_CLIENT, owner.load())
                assertFailsWith<ResolverBusyException> { SystemResolver.resolveFor("y.example", owner) }
                // another client is not held back by this one's cap
                val owner2 = kotlin.concurrent.atomics.AtomicInt(0)
                val other = async { SystemResolver.resolveFor("other-client.example", owner2) }
                withTimeout(5.seconds) { while (owner2.load() != 1) kotlinx.coroutines.yield() }
                gate2.complete(Unit)
                assertEquals(1, other.await().size)
                withTimeout(5.seconds) { while (owner.load() > 0) kotlinx.coroutines.yield() }
            } finally {
                gate2.complete(Unit)
                SystemResolver.lookupForTest = null
            }
        }

    /** `packetTooBig = false`: no probe, no raw socket; the status says so. */
    @Test fun packetTooBigOffNeverProbes() =
        h3Test {
            val rig = rig { f -> UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, packetTooBig = false, socketFactory = f) }
            rig.proxy.impl.probeForTest = { error("probed although off") }
            rig.use { r ->
                val t = r.pair.client.connectUdp(template, "192.0.2.50", 5000)
                assertEquals(io.kuicksilver.http3.PacketTooBigStatus.Off, rig.proxy.stats.packetTooBig)
                t.close()
            }
        }

    /**
     * Section 3.1: an ICMP port unreachable for the tunnel's target is the operating system saying the socket is no longer
     * usable: the request stream is reset and stopped with H3_CONNECT_ERROR. RFC 8085 section 5.2: only one that quotes the
     * start of a payload the tunnel sent; a forged one (another destination, a payload never sent, the headers only) and a
     * host unreachable (often transient) are ignored and counted.
     */
    @Test fun negative_targetUnreachableClosesTheTunnel() =
        h3Test {
            rig().use { rig ->
                val p = rig.pair
                rig.proxy.impl.unreachablePoll = 20.milliseconds
                rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                t.send("hello".encodeToByteArray())
                assertContentEquals("echo:hello".encodeToByteArray(), withTimeout(5.seconds) { t.payloads.first() })
                val socket = rig.sockets.single()

                fun report(
                    to: InetSocketAddress,
                    port: Boolean,
                    quote: String,
                ) = socket.unreachable.trySend(io.kuicksilver.quic.Unreachable(to, port, quote.encodeToByteArray()))
                report(InetSocketAddress("192.0.2.99", 5000), true, "hello") // another destination
                report(InetSocketAddress("192.0.2.50", 5001), true, "hello") // another port
                report(echoAt, false, "hello") // host unreachable
                report(echoAt, true, "") // the headers only: nothing to check
                report(echoAt, true, "spoof") // a payload never sent
                report(echoAt, true, "hello!") // longer than what was sent
                report(echoAt, true, "hel") // part of a payload shorter than 8 bytes: a guess could do as well
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.ignoredUnreachable == 7L }
                }
                assertEquals(1, rig.proxy.activeTunnels.value)
                report(echoAt, true, "hello") // what was sent, whole
                val e = assertFailsWith<Throwable> { withTimeout(5.seconds) { t.stream.capsules.toList() } }
                assertEquals(Http3ErrorCode.CONNECT_ERROR, h3Code(e), "$e")
                assertEquals(1, rig.proxy.stats.closedUnreachable)
                withTimeout(5.seconds) { rig.proxy.activeTunnels.first { it == 0 } }
            }
        }

    /** The prefixes a tunnel keeps: the latest 16 payloads, 64 bytes of each. */
    @Test fun sentPrefixes() {
        val s = SentPrefixes()
        assertFalse(s.matches("a".encodeToByteArray()))
        val long = ByteArray(100) { it.toByte() }
        s.record(long, 0, 100)
        assertTrue(s.matches(long.copyOf(64)))
        assertFalse(s.matches(long.copyOf(65)), "64 bytes kept")
        assertFalse(s.matches(ByteArray(0)), "an empty quote matches nothing")
        assertTrue(s.matches(long.copyOf(8)), "8 bytes of a long payload")
        assertFalse(s.matches(long.copyOf(7)), "7 bytes of a long payload: too short to tell from a guess")
        assertFalse(s.matches(long.copyOf(2)), "nor a byte or two")
        s.record(byteArrayOf(9, 1, 2, 3), 1, 2)
        assertTrue(s.matches(byteArrayOf(1, 2)), "a payload shorter than 8 bytes, quoted whole")
        assertFalse(s.matches(byteArrayOf(1)), "part of a short payload")
        assertFalse(s.matches(byteArrayOf(1, 2, 3)), "only the recorded range")
        repeat(SentPrefixes.SLOTS) { s.record(byteArrayOf(7), 0, 1) }
        assertFalse(s.matches(byteArrayOf(1, 2)), "the oldest forgotten")
        assertFalse(s.matches(long.copyOf(8)), "the oldest forgotten")
    }

    /** Section 7: the proxy's own address (the one this request's connection reached) is refused, whatever the filter allows. */
    @Test fun negative_theProxysOwnAddressIsRefused() =
        h3Test {
            rig().use { rig ->
                val p = rig.pair
                // the in-memory server is bound to 10.0.0.2:443, which the AllowAll filter of the rig would let through
                val e = assertFailsWith<Http3Exception.ConnectRejected> { p.client.connectUdp(template, "10.0.0.2", 53) }
                assertEquals(403, e.status)
                assertEquals("proxy; error=destination_ip_prohibited", e.headers["proxy-status"])
                assertEquals(0, rig.socketsOpened.load())
            }
            // the same address as IPv4-mapped, NAT64 (64:ff9b::/96) and 6to4 (2002::/16) forms: delivered to it all the same
            rig().use { rig ->
                for (form in listOf("::ffff:10.0.0.2", "64:ff9b::a00:2", "2002:a00:2::1")) {
                    val e = assertFailsWith<Http3Exception.ConnectRejected>(form) { rig.pair.client.connectUdp(template, form, 53) }
                    assertEquals(403, e.status, form)
                }
                assertEquals(0, rig.socketsOpened.load())
            }
            val allowed =
                rig { f ->
                    UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, refuseOwnAddresses = false, socketFactory = f)
                }
            allowed.use { rig ->
                rig.pair.client
                    .connectUdp(template, "10.0.0.2", 53)
                    .close()
            }
        }

    /** CWE-400: a client's tunnels share one rate; more tunnels do not multiply it (a frozen clock refills nothing). */
    @Test fun negative_aClientsTunnelsShareOneRate() =
        h3Test {
            val rig =
                rig { f ->
                    UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, clientPacketRate = 1, clientPacketBurst = 3, socketFactory = f)
                }
            rig.proxy.impl.clock = TestTimeSource()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val a = p.client.connectUdp(template, "192.0.2.50", 5000)
                val b = p.client.connectUdp(template, "192.0.2.50", 5000)
                repeat(3) { a.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0, 1))) }
                repeat(3) { b.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0, 2))) }
                withTimeout(
                    5.seconds,
                ) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedRateLimited + rig.proxy.stats.toTargets == 6L }
                }
                assertEquals(3, rig.proxy.stats.toTargets, "the client's burst of 3 over both tunnels")
                repeat(3) { got.receive() }
                a.close()
                b.close()
            }
        }

    /** Section 7: a silent target's unanswered budget is the client's, not each tunnel's: reopening does not start over. */
    @Test fun negative_reopeningATunnelDoesNotResetTheUnansweredLimit() =
        h3Test {
            val rig = rig { f -> UdpProxyConfig(targetFilter = UdpTargetFilter.AllowAll, unansweredLimit = 3, socketFactory = f) }
            rig.use { r ->
                val p = r.pair
                val silent = p.quic.net.open(echoAt)
                val first = p.client.connectUdp(template, "192.0.2.50", 5000)
                repeat(3) { first.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0, 1))) }
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.toTargets == 3L }
                }
                first.close()
                withTimeout(5.seconds) { rig.proxy.activeTunnels.first { it == 0 } }
                val second = p.client.connectUdp(template, "192.0.2.50", 5000)
                second.stream.send(Capsule(CapsuleProtocol.DATAGRAM, byteArrayOf(0, 2)))
                withTimeout(5.seconds) {
                    rig.proxy.impl.changes
                        .first { rig.proxy.stats.droppedUnanswered == 1L }
                }
                assertEquals(3, rig.proxy.stats.toTargets)
                second.close()
                silent.close()
            }
        }

    /** An IPv6 client is known by its /64 for its limits; IPv4 and IPv4-mapped by the address. */
    @Test fun clientKeys() {
        assertEquals("2001:db8:1:2::/64", clientKey(InetSocketAddress("2001:db8:1:2:aaaa:bbbb:cccc:dddd", 1), 64))
        assertEquals(clientKey(InetSocketAddress("2001:db8:1:2::1", 1), 64), clientKey(InetSocketAddress("2001:db8:1:2:ffff::9", 2), 64))
        assertTrue(clientKey(InetSocketAddress("2001:db8:1:3::1", 1), 64) != clientKey(InetSocketAddress("2001:db8:1:2::1", 1), 64))
        assertEquals("2001:db8:1:2::1/128", clientKey(InetSocketAddress("2001:db8:1:2::1", 1), 128))
        assertEquals("192.0.2.7", clientKey(InetSocketAddress("192.0.2.7", 1), 64))
        assertEquals("192.0.2.7", clientKey(InetSocketAddress("::ffff:192.0.2.7", 1), 64))
    }

    /**
     * The system resolver's lookups block threads no deadline interrupts: 16 at most run at once, counted until they
     * return even when their callers gave up, and one more is refused at once.
     */
    @Test fun negative_theSystemResolverBoundsItsBlockedLookups() =
        h3Test {
            val gate = CompletableDeferred<Unit>()
            try {
                SystemResolver.lookupForTest =
                    {
                        kotlinx.coroutines.runBlocking { gate.await() }
                        listOf(byteArrayOf(192.toByte(), 0, 2, 1))
                    }
                val callers =
                    List(SystemResolver.MAX_IN_FLIGHT) {
                        async { kotlinx.coroutines.withTimeoutOrNull(50.milliseconds) { SystemResolver.resolve("slow.example") } }
                    }
                callers.forEach { assertEquals(null, it.await(), "a caller's deadline ends its wait") }
                assertEquals(SystemResolver.MAX_IN_FLIGHT, SystemResolver.inFlightNow, "abandoned lookups still count")
                assertFailsWith<ResolverBusyException> { SystemResolver.resolve("one.more.example") }
                gate.complete(Unit)
                withTimeout(5.seconds) { while (SystemResolver.inFlightNow > 0) kotlinx.coroutines.yield() }
                assertEquals(1, SystemResolver.resolve("fast.example").size)
            } finally {
                gate.complete(Unit)
                SystemResolver.lookupForTest = null
            }
        }

    /** HTTP datagrams off on the connection (RFC 9297 section 3.5): both sides fall back to DATAGRAM capsules. */
    @Test fun datagramCapsulesWhenHttpDatagramsAreOff() =
        h3Test {
            val off =
                http3Settings {
                    enableConnectProtocol = true
                    h3Datagram = false
                }
            val rig = ProxyRig(H3Pair.open(serverSettings = off, clientSettings = http3Settings { h3Datagram = false }), ::allowAll)
            rig.serveAll()
            rig.use { r ->
                val p = r.pair
                val got = rig.echo(echoAt)
                val t = p.client.connectUdp(template, "192.0.2.50", 5000)
                assertEquals(DatagramSendResult.Sent, t.trySend("cap".encodeToByteArray()))
                assertContentEquals("cap".encodeToByteArray(), withTimeout(5.seconds) { got.receive() })
                assertContentEquals("echo:cap".encodeToByteArray(), withTimeout(5.seconds) { t.payloads.first() })
                t.close()
            }
        }

    /** A request that is no CONNECT-UDP handed to the proxy is refused, never served. */
    @Test fun negative_otherProtocolIsRefused() =
        h3Test {
            val rig = rig()
            rig.use { r ->
                val p = r.pair
                val e =
                    assertFailsWith<Http3Exception.ConnectRejected> {
                        p.client.connect(
                            http3Request("CONNECT", "server.test", "/.well-known/masque/udp/192.0.2.50/5000/") {
                                headers = Http3Headers(listOf(CapsuleProtocol.Enabled))
                            },
                            "connect-ip",
                        )
                    }
                assertEquals(400, e.status)
            }
        }

    private suspend fun rawConnect(
        p: H3Pair,
        path: String,
        capsuleField: Boolean = true,
        fields: List<Pair<String, String>> = if (capsuleField) listOf(CapsuleProtocol.Enabled) else emptyList(),
    ): Http3Stream =
        p.client.connect(
            http3Request("CONNECT", "server.test", path) { headers = Http3Headers(fields) },
            ConnectUdp.PROTOCOL,
        )

    /** The tunnel's capsule stream, for capsules a well-behaved client would not send. */
    private fun rawCapsules(t: io.kuicksilver.http3.UdpTunnel) = t.stream
}

/** The HTTP/3 error code of a stream the peer reset or stopped. */
internal fun h3Code(e: Throwable): Long? =
    generateSequence(e) { it.cause }.firstNotNullOfOrNull {
        when (it) {
            is Http3Exception.Protocol -> it.h3Code
            is Http3Exception.MessageError -> null
            is QuicException.StreamError.Reset -> it.code
            is QuicException.StreamError.Stopped -> it.code
            else -> null
        }
    }

/** A proxy socket without Don't Fragment for [family] ([DatagramIo.noDontFragmentFamily]). */
private class NoDfFor(
    private val inner: io.kuicksilver.quic.DatagramIo,
    private val family: IpFamily,
) : io.kuicksilver.quic.DatagramIo by inner {
    override val noDontFragmentFamily: IpFamily? get() = family
}
