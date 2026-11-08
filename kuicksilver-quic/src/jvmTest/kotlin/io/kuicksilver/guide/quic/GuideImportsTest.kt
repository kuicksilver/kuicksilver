// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.guide.quic

// guide:quic:imports
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.discard
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.Datagram
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.MemoryTokenStore
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.incomingConnections
import io.kuicksilver.quic.incomingStreams
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.quic.quicClientConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.quic.quicServerConfig
import io.kuicksilver.quic.rebind
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.io.IOException
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readString
import kotlin.random.Random
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The import block docs/guide/quic.md shows for its samples (`guide:quic:imports`), in a package of its own so that every
 * import is a real one: [everyQuicImport] uses each, so a name that moves breaks this file.
 */
suspend fun everyQuicImport(dir: String) {
    val chainPem = SystemFileSystem.source(Path(dir, "fullchain.pem")).buffered().use { it.readString() }
    val keyPem = SystemFileSystem.source(Path(dir, "privkey.pem")).buffered().use { it.readString() }
    val caPem = SystemFileSystem.source(Path(dir, "ca.pem")).buffered().use { it.readString() }
    CoroutineScope(Dispatchers.Default).launch { }
    val serverTls =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("my-proto/1")
            identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        }
    val clientTls =
        tlsConfig(TlsRole.Client) {
            serverName = "server.test"
            alpn = listOf("my-proto/1")
            trust = TrustConfig.AnchoredCa(Certificate.parsePem(caPem))
        }
    val quic =
        quicConfig {
            maxIdleTimeout = 30.seconds
            initialRtt = 100.milliseconds
            versions = listOf(VersionProfile.V1)
            qlog = AsyncQlogSink(DirectoryQlogSink("qlog"))
        }
    val config =
        quicEndpointConfig {
            server = quicServerConfig(serverTls) { this.quic = quic }
            admission = ConnectionAdmission.AlwaysRetry
            maxConnectionLifetime = 12.hours
            logger = KuicksilverLogger.stderr(LogLevel.Debug)
            loadBalancer =
                QuicLbConfig(configId = 1, serverId = byteArrayOf(1, 2, 3), nonceLength = 4, key = KslQuicCrypto.newLoadBalancerKey(null))
            listener =
                object : ConnectionListener {
                    override fun onClosed(
                        connection: ConnectionInfo,
                        reason: QuicException.ConnectionLost,
                    ) {}
                }
        }
    val endpoint = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 4433), config)
    supervisorScope {
        launch {
            endpoint.incomingConnections().collect { c ->
                c.incomingStreams().collect { s ->
                    try {
                        s.input.discard()
                    } catch (_: IOException) {
                    }
                }
            }
        }
        val client = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0), QuicEndpointConfig.Default)
        val clientConfig =
            quicClientConfig(clientTls) {
                earlyData = EarlyDataState.Allowed
                tokenStore = MemoryTokenStore()
            }
        val connection = client.connect(endpoint.localAddress, clientConfig)
        val stream = connection.openBidi()
        stream.output.writeFully(byteArrayOf(1))
        stream.output.writeStringUtf8("ping\n")
        println(stream.input.readLine(LineEnding.Lenient))
        if (connection.trySendDatagram(byteArrayOf(1), DatagramPolicy.Reject) == DatagramSendResult.QueueFull) return@supervisorScope
        val d: Datagram = connection.datagrams.first()
        println(d.data.size)
        connection.pathEvents.collect { if (it is PathEvent.SocketLost) connection.rebind() }
        NetworkMigrator(connection, kotlinx.coroutines.flow.emptyFlow<String>(), { DatagramIo.open(InetSocketAddress("0.0.0.0", 0)) }, this)
        println(Ecn.NotEct to PacketBatch(capacity = 4))
        println(ConnectionCore::class to Random.nextInt())
    }
}
