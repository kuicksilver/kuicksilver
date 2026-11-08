// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.readString
import kotlinx.io.writeString
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * docs/guide/quic.md, "A complete example" (`guide:quic:custom-alpn`), in common code: it compiles for every target the
 * guide promises a client on (Kotlin/Native included) and runs wherever the common tests run.
 */
class GuideCompleteExampleTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun customAlpnSample(): Unit =
        runBlocking {
            val dir = Path(SystemTemporaryDirectory, "kuicksilver-guide-${Random.nextLong().toULong()}").toString()
            SystemFileSystem.createDirectories(Path(dir))
            for ((name, pem) in listOf(
                "fullchain.pem" to TestCerts.toPem("CERTIFICATE", TestCerts.server),
                "privkey.pem" to TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey),
                "ca.pem" to TestCerts.toPem("CERTIFICATE", TestCerts.testCa),
            )) {
                SystemFileSystem.sink(Path(dir, name)).buffered().use { it.writeString(pem) }
            }
            withTimeout(60.seconds) {
                // guide:quic:custom-alpn
                // the PEM files, read with kotlinx-io: common code, the same on every target
                val chainPem = SystemFileSystem.source(Path(dir, "fullchain.pem")).buffered().use { it.readString() } // leaf first
                val keyPem = SystemFileSystem.source(Path(dir, "privkey.pem")).buffered().use { it.readString() } // PKCS#8
                val caPem = SystemFileSystem.source(Path(dir, "ca.pem")).buffered().use { it.readString() } // the client trusts it
                val scope = CoroutineScope(Dispatchers.Default)
                // ALPN: both sides list it, or the handshake ends with no_application_protocol (120)
                val myProtocol = listOf("my-proto/1")
                // the server: JVM, or Kotlin/Native on Linux, Apple and Windows
                val serverTls =
                    tlsConfig(TlsRole.Server) {
                        alpn = myProtocol
                        identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
                    }
                val server =
                    QuicEndpoint.bind(
                        InetSocketAddress("127.0.0.1", 0),
                        quicEndpointConfig {
                            this.server =
                                quicServerConfig(
                                    serverTls,
                                ) { quic = quicConfig { maxIdleTimeout = 30.seconds } }
                        },
                    )
                val serving =
                    scope.launch {
                        server.incomingConnections().collect { connection ->
                            launch {
                                // datagrams: each one sent back as it comes
                                try {
                                    connection.datagrams.collect { d: Datagram -> connection.sendDatagram(d.data) }
                                } catch (e: IOException) {
                                    // the flow ends with the connection's QuicException.ConnectionLost
                                }
                            }
                            launch {
                                // streams: one line in, one line out (the flow completes when the connection ends)
                                connection.incomingStreams().collect { stream ->
                                    launch {
                                        try {
                                            val line = stream.input.readLine(LineEnding.Lenient) ?: return@launch
                                            stream.output.writeStringUtf8("echo: $line\n")
                                            stream.output.flushAndClose()
                                        } catch (e: IOException) {
                                            // the client reset the stream or left
                                        }
                                    }
                                }
                            }
                        }
                    }
                // the client: any target, Kotlin/Native included
                val clientTls =
                    tlsConfig(TlsRole.Client) {
                        serverName = "server.test" // SNI, and the name the server's certificate must carry
                        alpn = myProtocol
                        trust = TrustConfig.AnchoredCa(Certificate.parsePem(caPem)) // a private CA; TrustConfig.Platform for a public one
                    }
                val client = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0))
                val connection = client.connect(InetSocketAddress("127.0.0.1", server.localAddress.port), quicClientConfig(clientTls))
                val stream = connection.openBidi()
                stream.output.writeStringUtf8("ping\n")
                stream.output.flushAndClose()
                val reply: String? = stream.input.readLine(LineEnding.Lenient) // "echo: ping"
                connection.sendDatagram("tick".encodeToByteArray()) // a ByteArray out; datagrams are never retransmitted
                val echoed: Datagram = connection.datagrams.first() // a Datagram in; its payload is echoed.data, a ByteArray
                connection.close(code = 0, reason = "done")
                client.close()

                assertEquals("echo: ping", reply)
                assertEquals("tick", echoed.data.decodeToString())
                server.close()
                serving.join() // the flow completes once the endpoint closes
                scope.cancel()
            }
            for (name in listOf("fullchain.pem", "privkey.pem", "ca.pem")) SystemFileSystem.delete(Path(dir, name))
            SystemFileSystem.delete(Path(dir))
        }
}
