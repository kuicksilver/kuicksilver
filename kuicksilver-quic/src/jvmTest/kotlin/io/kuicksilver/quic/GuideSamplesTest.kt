// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.discard
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import java.nio.file.Files
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/** The code blocks of docs/guide/quic.md, kept compiling and running (block markers `guide:quic:*`). */
class GuideSamplesTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val tlsClientConfig = CoreFixtures.client()
    private val tlsServerConfig = CoreFixtures.server()

    @Test fun configSample() {
        // guide:quic:config
        val quic =
            quicConfig {
                maxIdleTimeout = 30.seconds
                initialStreamWindow = 512 * 1024L
                maxBidiStreams = 100
                // preference order; listOf(VersionProfile.V2, VersionProfile.V1) opts into v2 (RFC 9368/9369)
                versions = listOf(VersionProfile.V1)
                greaseQuicBit = true // RFC 9287
            }
        assertEquals(listOf(VersionProfile.V1), quic.versions)
        val prefersV2 =
            quicConfig {
                versions = listOf(VersionProfile.V2, VersionProfile.V1)
                initialVersion = VersionProfile.V1
            }
        assertEquals(VersionProfile.V1, prefersV2.firstVersion)
    }

    @Test fun connectEchoAndServerAcceptSamples(): Unit =
        runBlocking {
            val quic = QuicConfig.Default
            // guide:quic:server-accept (the bind)
            val server =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    quicEndpointConfig { this.server = quicServerConfig(tlsServerConfig) { this.quic = quic } },
                )
            val serverAddress = server.localAddress
            try {
                withTimeout(60.seconds) {
                    val serverSide =
                        async {
                            // guide:quic:server-accept (the loop body)
                            val incoming = server.accept()
                            val echoed = incoming.acceptStream()
                            echoed.output.writeStringUtf8(echoed.input.readUTF8Line() ?: "")
                            echoed.output.flushAndClose()
                        }
                    // guide:quic:client-connect
                    val client = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0))
                    val connection =
                        client.connect(
                            serverAddress, // an InetSocketAddress; the TLS config carries the name to verify
                            quicClientConfig(tlsClientConfig) { this.quic = quic },
                        )
                    try {
                        // guide:quic:echo
                        val stream = connection.openBidi()
                        stream.output.writeStringUtf8("ping\n")
                        stream.output.flushAndClose()
                        val reply = stream.input.readUTF8Line()
                        connection.close(code = 0, reason = "done")
                        assertEquals("ping", reply)
                        serverSide.await()
                    } finally {
                        client.close()
                    }
                }
            } finally {
                server.close()
            }
        }

    @Test fun incomingSample(): Unit =
        runBlocking {
            val server =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    quicEndpointConfig {
                        this.server =
                            quicServerConfig(tlsServerConfig)
                    },
                )
            val client = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                withTimeout(60.seconds) {
                    val serving =
                        launch {
                            // guide:quic:incoming
                            supervisorScope {
                                // one failing connection or stream does not stop the others
                                server.incomingConnections().collect { connection ->
                                    launch {
                                        connection.incomingStreams().collect { stream ->
                                            launch {
                                                try {
                                                    if (stream.isUnidirectional) {
                                                        stream.input.discard()
                                                        return@launch
                                                    } // a peer's uni stream: input only
                                                    val line = stream.input.readUTF8Line() ?: return@launch
                                                    stream.output.writeStringUtf8(line + "\n")
                                                    stream.output.flushAndClose()
                                                } catch (e: IOException) {
                                                    // the peer reset the stream or left
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    val connection = client.connect(server.localAddress, quicClientConfig(tlsClientConfig))
                    val uni = connection.openUni()
                    uni.output.writeStringUtf8("ignored\n")
                    uni.output.flushAndClose()
                    val stream = connection.openBidi()
                    stream.output.writeStringUtf8("ping\n")
                    stream.output.flushAndClose()
                    assertEquals("ping", stream.input.readUTF8Line())
                    connection.close()
                    server.close()
                    serving.join() // the flows complete once the endpoint closes
                }
            } finally {
                client.close()
                server.close()
            }
        }

    @Test fun qlogSample() {
        val qlogDir = Files.createTempDirectory("qlog").toFile().path
        // guide:quic:qlog
        val quicWithQlog = quicConfig { qlog = DirectoryQlogSink(qlogDir) }
        assertTrue(quicWithQlog.qlog is DirectoryQlogSink)
        // guide:quic:qlog-async
        val quicWithAsyncQlog = quicConfig { qlog = AsyncQlogSink(DirectoryQlogSink(qlogDir), sampleEvery = 10) }
        val async = assertIs<AsyncQlogSink>(quicWithAsyncQlog.qlog)
        assertEquals(10, async.sampleEvery)
        async.close()
    }

    @Test fun observabilityAndShutdownSamples(): Unit =
        runBlocking {
            // guide:quic:observability
            val observed =
                quicEndpointConfig {
                    this.server = quicServerConfig(tlsServerConfig)
                    logger = KuicksilverLogger.stderr(LogLevel.Info)
                    listener =
                        object : ConnectionListener {
                            override fun onClosed(
                                connection: ConnectionInfo,
                                reason: QuicException.ConnectionLost,
                            ) {
                                println("${connection.id} ${connection.remoteAddress}: ${reason.message}")
                            }
                        }
                }
            val server = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0), observed)
            val client = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                withTimeout(60.seconds) {
                    val accepted = async { server.accept() }
                    val connection = client.connect(server.localAddress, quicClientConfig(tlsClientConfig))
                    accepted.await()
                    // guide:quic:stats
                    val stats = server.stats
                    println(
                        "${stats.connectionsActive} live, ${stats.handshakesCompleted} handshakes, ${stats.connectionsRefusedAcceptQueue} refused",
                    )
                    assertEquals(1, stats.handshakesCompleted)
                    connection.close(0, "done")
                    // guide:quic:shutdown
                    server.shutdown(grace = 30.seconds)
                    assertEquals(0, server.stats.connectionsActive)
                }
            } finally {
                client.close()
                server.close()
            }
        }

    private class Datagram(
        val buffer: PacketBuffer,
        val length: Int,
        val from: InetSocketAddress,
    )

    @Test fun coreLoopSample() {
        val quic = QuicConfig.Default
        val remote = InetSocketAddress("10.0.0.2", 4433)
        var now = TimeMark(0)
        var running = true
        var iterations = 0
        val sent = ArrayList<Int>()

        fun send(
            buffer: PacketBuffer,
            length: Int,
            to: InetSocketAddress,
        ) {
            assertEquals(remote, to)
            sent += length
            assertTrue(buffer.capacity >= length)
        }

        fun receiveOrWaitUntil(deadline: TimeMark): Datagram? {
            if (++iterations == 3) running = false
            return null
        }

        fun clock(): TimeMark = now + 400.seconds / 1000 // the virtual clock jumps 400 ms per iteration: the PTO fires

        fun handle(event: ConnectionEvent) {}
        // guide:quic:core-loop
        val core = ConnectionCore.client(quic, tlsClientConfig, KslQuicCrypto, remote, Random, now)
        val out = PacketBatch(capacity = 4)
        try {
            while (running) {
                val n = core.poll(out, now)
                for (i in 0 until n) send(out.buffer(i), out.length(i), out.address(i)!!)
                val deadline = core.nextTimeoutOrNever() // TimeMark.NEVER when no timer is armed; nextTimeout() is the nullable form
                val datagram = receiveOrWaitUntil(deadline) // your socket; returns null when the deadline passed first
                now = clock()
                if (datagram != null) {
                    core.handleDatagram(datagram.buffer, datagram.length, datagram.from, Ecn.NotEct, now)
                } else if (deadline <= now) {
                    core.onTimeout(now)
                }
                while (true) {
                    val event = core.nextEvent() ?: break
                    handle(event)
                }
            }
        } finally {
            out.close()
        }
        assertTrue(sent.isNotEmpty() && sent.all { it >= 1200 }, "client Initial datagrams are padded: $sent")
    }

    @Test fun keyUpdateCoreSample() {
        val p = CorePair(crypto = KslQuicCrypto)
        try {
            assertTrue(
                p.handshake() &&
                    p.runUntil(limit = 2.seconds) {
                        p.client.state == ConnectionState.Confirmed &&
                            p.server!!.state == ConnectionState.Confirmed
                    },
            )
            val core = p.client
            val now = p.now
            // guide:quic:key-update
            if (core.initiateKeyUpdate(now)) println("key phase ${core.stats.keyUpdates}") // false while RFC 9001 section 6.1 forbids it
            assertEquals(1L, core.stats.keyUpdates)
        } finally {
            p.close()
        }
    }

    @Test fun admissionAndLoopsSamples() {
        val serverConfig = QuicServerConfig.Builder(tlsServerConfig).build()
        // guide:quic:admission
        val config =
            quicEndpointConfig {
                server = serverConfig
                admission = ConnectionAdmission.default(maxInflightHandshakes = 256, maxHandshakeBufferBytes = 8L * 1024 * 1024)
                maxConnectionsPerIp = 64
                maxConnectionLifetime = 12.hours // closed with NO_ERROR when it passes
            }
        assertEquals(64, config.maxConnectionsPerIp)
        assertEquals(12.hours, config.maxConnectionLifetime)
        // guide:quic:loops (the configuration; binding needs the accelerated transport, MultiLoopTest covers it on Linux)
        val withLoops =
            QuicEndpointConfig
                .Builder()
                .apply {
                    this.server = serverConfig
                    loops = 4
                }.build()
        assertEquals(4, withLoops.loops)
    }

    @Test fun keyUpdateDatagramsAndMigrationSamples(): Unit =
        runBlocking {
            val server =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(tlsServerConfig).build()
                            ; crypto = KslQuicCrypto
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build(),
                )
            try {
                withTimeout(60.seconds) {
                    val accepted = async { server.accept() }
                    val connection = client.connect(server.localAddress, QuicClientConfig.Builder(tlsClientConfig).build())
                    val peer = accepted.await()
                    // guide:quic:key-update-api
                    connection.keyUpdate()
                    println(connection.stats.keyUpdates) // ours and the peer's
                    assertTrue(connection.stats.keyUpdates >= 1)
                    val reading = ByteArray(16) { 1 }
                    val frame = ByteArray(16) { 2 }
                    var dropped = 0

                    fun dropFrame() {
                        dropped++
                    }

                    fun stop() {}
                    val received = ArrayList<ByteArray>()

                    fun handle(data: ByteArray) {
                        received += data
                    }
                    val collector =
                        async {
                            // guide:quic:datagrams
                            // replaces a queued reading of the same key
                            connection.sendDatagram(reading, DatagramPolicy.LatestWins(key = "temperature"))
                            when (val r = connection.trySendDatagram(frame, DatagramPolicy.Reject)) {
                                DatagramSendResult.QueueFull -> {
                                    dropFrame()
                                }

                                DatagramSendResult.Closed -> {
                                    stop()
                                }

                                else -> {}
                            }
                            peer.datagrams.collect { d ->
                                handle(d.data)
                                if (received.size ==
                                    2
                                ) {
                                    throw kotlinx.coroutines.CancellationException("enough")
                                }
                            }
                        }
                    runCatching { collector.await() }
                    assertEquals(2, received.size)
                    assertEquals(0, dropped)
                    // guide:quic:migration
                    val change = connection.migrate(DatagramIo.open(InetSocketAddress("0.0.0.0", 0))) // addPath + probe + switchTo
                    println("now on ${change.new.localAddress} (${change.reason})")
                    assertEquals(PathChangeReason.ActiveMigration, change.reason)
                    val networks = kotlinx.coroutines.flow.MutableStateFlow<String?>("wifi") // what the platform reports
                    val scope = this
                    // guide:quic:network-migrator
                    val migrator = NetworkMigrator(connection, networks, { DatagramIo.open(InetSocketAddress("0.0.0.0", 0)) }, scope)
                    val log = scope.launch { migrator.events.collect { println("network: $it") } }
                    migrator.start()
                    migrator.network.first { it == "wifi" }
                    val moved = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { migrator.events.first() }
                    networks.value = "cell"
                    assertIs<MigrationEvent.Migrated<String>>(moved.await())
                    assertEquals("cell", migrator.network.value)
                    migrator.close()
                    log.cancel()
                    connection.close(0, "done")
                    peer.close(0, "done")
                }
            } finally {
                client.close()
                server.close()
            }
        }
}
