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
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ipLiteral
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
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
        )

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
) : io.kuicksilver.quic.DatagramIo by io {
    val ecnSent = ArrayList<io.kuicksilver.quic.Ecn>()
    var ecnMarkingDisabled = false

    override fun disableEcnMarking() {
        ecnMarkingDisabled = true
    }

    override suspend fun send(batch: io.kuicksilver.quic.PacketBatch): Int {
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
