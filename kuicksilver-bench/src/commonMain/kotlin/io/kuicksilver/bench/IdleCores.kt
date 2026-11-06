// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
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
 * Idle QUIC connections held open: [open] runs one full 1-RTT handshake between two [ConnectionCore]s (ksl crypto unless
 * [crypto] says otherwise) under its own virtual clock, lets the post-handshake traffic (HANDSHAKE_DONE, NEW_CONNECTION_ID,
 * NEW_TOKEN and their ACKs) settle, and returns the pair without closing it, so what a pair holds is what an idle connection
 * costs each side. [closeClient] ends the client's side alone (its CONNECTION_CLOSE is never delivered), which leaves the
 * server's side as a server process would hold it. The configurations are built once, as processes keep theirs.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, InternalKuicksilverApi::class)
public class IdleCores(
    private val crypto: QuicCrypto = io.kuicksilver.tls.KslQuicCrypto,
    private val quic: QuicConfig = QuicConfig.Default,
) : AutoCloseable {
    /** One idle connection: both endpoints' cores and the client's virtual clock. */
    public class Pair internal constructor(public val client: ConnectionCore, public val server: ConnectionCore, internal var now: TimeMark)

    private val clientAddr = InetSocketAddress("10.0.0.1", 40000)
    private val serverAddr = InetSocketAddress("10.0.0.2", 443)
    private val identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
    private val serverTls = tlsConfig(TlsRole.Server) { alpn = listOf("bench"); identity = this@IdleCores.identity }
    private val clientTls = tlsConfig(TlsRole.Client) { alpn = listOf("bench"); serverName = "server.test"; trust = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) } }
    private val toServer = PacketBatch(64)
    private val toClient = PacketBatch(64)
    private val random = Random(1)

    /** A handshaken, idle connection, or null when the handshake did not finish within 10 virtual seconds. */
    public fun open(): Pair? {
        var now = TimeMark(0L)
        val client = ConnectionCore.client(quic, clientTls, crypto, serverAddr, random, now)
        var server: ConnectionCore? = null
        var clientDone = false
        var serverDone = false
        var settleUntil: TimeMark? = null
        val deadline = now + 10_000.milliseconds
        while (now < deadline) {
            if (client.nextTimeoutOrNever() <= now) client.onTimeout(now)
            server?.let { if (it.nextTimeoutOrNever() <= now) it.onTimeout(now) }
            server?.let { deliver(it, toServer, clientAddr, now) }
            deliver(client, toClient, serverAddr, now)
            client.poll(toServer, now)
            if (server == null && toServer.count > 0) server = ConnectionCore.server(quic, serverTls, crypto, clientAddr, random, now, toServer.buffer(0), toServer.length(0))
            server?.poll(toClient, now)
            while (true) { val e = client.nextEvent() ?: break; if (e is ConnectionEvent.VerifyRequested) client.resumeVerify(VerifyResult.Accepted(e.chain)); if (e === ConnectionEvent.HandshakeCompleted) clientDone = true }
            server?.let { s -> while (true) { val e = s.nextEvent() ?: break; if (e === ConnectionEvent.HandshakeCompleted) serverDone = true } }
            // a few round trips and every ACK delay after both completed: what is left after that is the idle state
            if (settleUntil == null && clientDone && serverDone) settleUntil = now + SETTLE
            val until = settleUntil
            if (until != null && now >= until && toServer.count == 0 && toClient.count == 0) return Pair(client, server!!, now)
            now = if (toServer.count > 0 || toClient.count > 0) now + 1.milliseconds
            else minOf(until ?: deadline, maxOf(now + 1.milliseconds, minOf(client.nextTimeoutOrNever(), server?.nextTimeoutOrNever() ?: client.nextTimeoutOrNever())))
        }
        toServer.clear(); toClient.clear()
        return null
    }

    /** Closes the client's side of [pair] without telling the server and runs its timers until it is closed (its native state freed). */
    public fun closeClient(pair: Pair) {
        val c = pair.client
        c.close(0, "", pair.now)
        val deadline = pair.now + 60_000.milliseconds
        while (c.state != ConnectionState.Closed && pair.now < deadline) {
            c.poll(toServer, pair.now); toServer.clear()
            while (c.nextEvent() != null) Unit
            pair.now = maxOf(pair.now + 1.milliseconds, c.nextTimeoutOrNever())
            if (c.nextTimeoutOrNever() <= pair.now) c.onTimeout(pair.now)
        }
        check(c.state == ConnectionState.Closed) { "the client did not close" }
    }

    private fun deliver(core: ConnectionCore, batch: PacketBatch, from: InetSocketAddress, now: TimeMark) {
        for (i in 0 until batch.count) core.handleDatagram(batch.buffer(i), batch.length(i), from, Ecn.NotEct, now)
        batch.clear()
    }

    override fun close() { toServer.close(); toClient.close(); identity.close() }

    private companion object { val SETTLE = 300.milliseconds }
}
