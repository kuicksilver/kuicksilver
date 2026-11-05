// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.server
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds

/**
 * Whole QUIC connections, one after another, between two [ConnectionCore]s under virtual time: each [connection] runs a full
 * 1-RTT handshake (ksl crypto unless [crypto] says otherwise), then the client closes and both cores run until they are
 * closed, so every native object of the connection is freed inside the call. The server and client configurations are
 * built once, as a server and a client process keep theirs, so what a call costs is what one more connection costs.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
public class CoreHandshakes(
    private val crypto: QuicCrypto = io.kuicksilver.tls.KslQuicCrypto,
    private val quic: QuicConfig = QuicConfig.Default,
) : AutoCloseable {
    private val clientAddr = InetSocketAddress("10.0.0.1", 40000)
    private val serverAddr = InetSocketAddress("10.0.0.2", 443)
    private val identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
    private val serverTls = tlsConfig(TlsRole.Server) { alpn = listOf("bench"); identity = this@CoreHandshakes.identity }
    private val clientTls = tlsConfig(TlsRole.Client) { alpn = listOf("bench"); serverName = "server.test"; trust = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) } }
    private val toServer = PacketBatch(64)
    private val toClient = PacketBatch(64)
    private var now = TimeMark(0L)
    private val random = Random(1)

    /** Connections completed so far. */
    public var completed: Long = 0L
        private set

    /** One connection from the client's first Initial to both cores closed; false when the handshake or the close did not finish within 10 virtual seconds. */
    public fun connection(): Boolean {
        val client = ConnectionCore.client(quic, clientTls, crypto, serverAddr, random, now)
        var server: ConnectionCore? = null
        var clientDone = false
        var serverDone = false
        var closing = false
        val deadline = now + 10_000.milliseconds
        while (now < deadline) {
            if (client.nextTimeoutOrNever() <= now) client.onTimeout(now)
            server?.let { if (it.nextTimeoutOrNever() <= now) it.onTimeout(now) }
            server?.let { deliver(it, toServer, clientAddr) }
            deliver(client, toClient, serverAddr)
            client.poll(toServer, now)
            if (server == null && toServer.count > 0) server = ConnectionCore.server(quic, serverTls, crypto, clientAddr, random, now, toServer.buffer(0), toServer.length(0))
            server?.poll(toClient, now)
            while (true) { val e = client.nextEvent() ?: break; if (e is ConnectionEvent.VerifyRequested) client.resumeVerify(VerifyResult.Accepted(e.chain)); if (e === ConnectionEvent.HandshakeCompleted) clientDone = true }
            server?.let { s -> while (true) { val e = s.nextEvent() ?: break; if (e === ConnectionEvent.HandshakeCompleted) serverDone = true } }
            if (!closing && clientDone && serverDone && toServer.count == 0 && toClient.count == 0) { closing = true; client.close(0, "", now) }
            if (client.state == ConnectionState.Closed && server?.state == ConnectionState.Closed) { completed++; toServer.clear(); toClient.clear(); return true }
            // nothing in flight: jump to the next timer instead of stepping through idle milliseconds
            now = if (toServer.count > 0 || toClient.count > 0) now + 1.milliseconds
            else maxOf(now + 1.milliseconds, minOf(client.nextTimeoutOrNever(), server?.nextTimeoutOrNever() ?: client.nextTimeoutOrNever()))
        }
        toServer.clear(); toClient.clear()
        return false
    }

    private fun deliver(core: ConnectionCore, batch: PacketBatch, from: InetSocketAddress) {
        for (i in 0 until batch.count) core.handleDatagram(batch.buffer(i), batch.length(i), from, Ecn.NotEct, now)
        batch.clear()
    }

    override fun close() { toServer.close(); toClient.close(); identity.close() }
}
