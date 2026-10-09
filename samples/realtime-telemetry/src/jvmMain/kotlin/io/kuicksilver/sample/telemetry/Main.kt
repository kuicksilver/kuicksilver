// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.telemetry

import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.quicClientConfig
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.quic.quicServerConfig
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.system.exitProcess

/**
 * `server [port]` serves until killed and prints what it sees; `client <host> <port> [name]` plays one session:
 * hello, readings, media, a switch to a second socket, more readings, bye.
 */
fun main(args: Array<String>): Unit = runBlocking {
    when (args.firstOrNull()) {
        "server" -> {
            val endpoint = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", args.getOrNull(1)?.toInt() ?: 4433), quicEndpointConfig { server = quicServerConfig(TelemetryTls.server()) })
            println("listening on ${endpoint.localAddress}")
            val server = TelemetryServer(endpoint)
            launch { server.report.collect { println(it) } }
            server.run()
        }
        "client" -> {
            if (args.size < 3) usage()
            val endpoint = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0))
            try {
                val app = TelemetryClient(endpoint.connect(InetSocketAddress(args[1], args[2].toInt()), quicClientConfig(TelemetryTls.client())))
                println(app.hello(args.getOrNull(3) ?: "probe"))
                for (i in 1..50) app.sendReading("temperature", 20.0 + i / 10.0)
                app.streamMedia(1 shl 20)
                val change = app.switchNetwork(DatagramIo.open(InetSocketAddress("0.0.0.0", 0)))
                println("moved from ${change.old.localAddress} to ${change.new.localAddress} (${change.reason})")
                app.sendReading("temperature", 25.0)
                println(app.bye())
            } finally { endpoint.close() }
        }
        else -> usage()
    }
}

private fun usage(): Nothing { System.err.println("usage: server [port] | client <host> <port> [name]"); exitProcess(2) }
