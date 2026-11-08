// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.guide.http3

// guide:http3:imports
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.capsuleConfig
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.webTransport
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsConfig
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.io.readString

/**
 * The import block docs/guide/http3.md shows for its samples (`guide:http3:imports`), in a package of its own so that every
 * import is a real one: [everyHttp3Import] uses each, so a name that moves breaks this file.
 */
suspend fun everyHttp3Import(
    serverTls: TlsConfig,
    clientTls: TlsConfig,
    quicConnection: QuicConnection,
) = coroutineScope {
    val settings = http3Settings { enableConnectProtocol = true }
    val server =
        Http3Endpoint.bind(
            InetSocketAddress("0.0.0.0", 443),
            QuicEndpointConfig.Builder().apply { this.server = QuicServerConfig.Builder(serverTls).build() }.build(),
        )
    launch {
        val connection = server.accept()
        val request = connection.acceptRequest()
        if (request.isWebTransport) {
            val session = request.acceptWebTransport(protocol = null)
            val s = session.acceptBidi()
            s.input.copyTo(s.output)
        } else {
            request.respond(200, Http3Headers.of("content-type" to "text/plain")).finish()
        }
    }
    val client = Http3Connection.client(quicConnection, settings)
    val endpoint = Http3Endpoint.bind(InetSocketAddress("0.0.0.0", 0))
    val connection = endpoint.connect(InetSocketAddress("127.0.0.1", 443), clientTls)
    val capsules =
        connection.connect(http3Request("CONNECT", "example.com", "/chat"), protocol = "echo").useCapsuleProtocol(
            capsuleConfig {
                knownTypes =
                    setOf(0x2843)
            },
        )
    capsules.send(Capsule(0x2843, "hello".encodeToByteArray()))
    println(capsules.capsules.toList().size)
    val session = client.webTransport(http3Request("CONNECT", "example.com", "/wt"), protocols = listOf("chat-v1"))
    val stream = session.openBidi()
    stream.output.writeFully("ping".encodeToByteArray())
    stream.output.writeStringUtf8("\n")
    println(stream.input.readBuffer().readString())
}
