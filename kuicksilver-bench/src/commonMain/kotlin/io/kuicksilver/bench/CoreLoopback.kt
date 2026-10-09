// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.server
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds

/**
 * Two [ConnectionCore]s joined back to back under virtual time, with the Null crypto provider: the datagrams one core
 * polls into its [PacketBatch] are handed to the other core's `handleDatagram` from that same buffer, so the transport
 * itself allocates nothing. One side (the client unless [reverse]) writes [payload] bytes per stream per [step], the
 * other reads everything readable into one pre-allocated array.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
public class CoreLoopback(private val streams: Int = 1, private val payload: Int = 1200, private val reverse: Boolean = false, private val useDatagrams: Boolean = false, private val quic: QuicConfig = QuicConfig.Default) : AutoCloseable {
    private val clientAddr = InetSocketAddress("10.0.0.1", 40000)
    private val serverAddr = InetSocketAddress("10.0.0.2", 443)
    private val serverTls = tlsConfig(TlsRole.Server) { alpn = listOf("bench"); identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf()) }
    private val clientTls = tlsConfig(TlsRole.Client) { alpn = listOf("bench"); serverName = "server.test"; trust = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) } }

    public var now: TimeMark = TimeMark(0L)
        private set
    public val client: ConnectionCore = ConnectionCore.client(quic, clientTls, NullCryptoProvider, serverAddr, Random(1), now)
    public var server: ConnectionCore? = null
        private set
    private val toServer = PacketBatch(64)
    private val toClient = PacketBatch(64)
    private val sendBuffer = ByteArray(payload) { (it * 7).toByte() }
    private val readBuffer = ByteArray(64 * 1024)
    private val streamIds = LongArray(streams)
    private var finished = false

    /** Bytes the reading side has consumed so far. */
    public var bytesReceived: Long = 0L
        private set
    /** Datagrams moved so far (both directions). */
    public var datagrams: Long = 0L
        private set

    private val sender: ConnectionCore get() = if (reverse) server!! else client
    private val receiver: ConnectionCore get() = if (reverse) client else server!!

    /** Drives both cores until both report `HandshakeCompleted`; false after 5 virtual seconds. */
    public fun handshake(): Boolean {
        var clientDone = false; var serverDone = false
        val deadline = now + 5000.milliseconds
        while (now < deadline) {
            round { e, isClient -> if (e === ConnectionEvent.HandshakeCompleted) { if (isClient) clientDone = true else serverDone = true } }
            if (clientDone && serverDone) {
                for (i in 0 until streams) streamIds[i] = sender.openStream(bidi = true)
                if (useDatagrams) sender.datagramSender = datagramSender
                return true
            }
        }
        return false
    }

    /**
     * One virtual millisecond: due timers fire, pending datagrams are delivered, the sender writes [payload]-byte
     * chunks on every stream while the core accepts them (at most 64 per step), the receiver drains what is readable,
     * both cores are polled. Returns the datagrams moved.
     */
    public fun step(): Int {
        val before = datagrams
        if (!finished && !useDatagrams) for (i in 0 until streams) { var writes = 0; while (writes < MAX_WRITES_PER_STEP && sender.writeStream(streamIds[i], sendBuffer, 0, payload, false) == payload) writes++ }
        round { _, _ -> }
        if (useDatagrams) { while (true) { val n = receiver.readDatagram(readBuffer, 0); if (n < 0) break; bytesReceived += n } }
        else for (i in 0 until streams) {
            while (true) { val n = receiver.readStream(streamIds[i], readBuffer, 0, readBuffer.size); if (n <= 0) break; bytesReceived += n }
        }
        return (datagrams - before).toInt()
    }

    /** The sending side starts a key update (RFC 9001 section 6); false while one is not allowed yet. */
    public fun initiateKeyUpdate(): Boolean = sender.initiateKeyUpdate(now)
    /** DATAGRAM frames (RFC 9221): the sender's [io.kuicksilver.quic.DatagramSender] writes [payload]-byte datagrams into every packet with room, the receiver drains its queue each step. */
    private val datagramSender = object : io.kuicksilver.quic.DatagramSender {
        override fun onTransmit(packet: io.kuicksilver.quic.DatagramPacketWriter) { val n = minOf(payload, packet.remaining - 3); if (n > 0) packet.write(sendBuffer, 0, n) }   /* one datagram per packet, as large as the packet has room for (type + length varint) */
        override fun hasPending(): Boolean = !finished
    }
    /** Sends FIN on every stream; following [step]s drain the connection. */
    public fun finish() { if (!finished) { finished = true; for (i in 0 until streams) sender.writeStream(streamIds[i], sendBuffer, 0, 0, true) } }

    private inline fun round(onEvent: (ConnectionEvent, Boolean) -> Unit) {
        now += 1.milliseconds
        if (client.nextTimeoutOrNever() <= now) client.onTimeout(now)
        server?.let { s -> if (s.nextTimeoutOrNever() <= now) s.onTimeout(now) }
        server?.let { deliver(it, toServer, clientAddr) }
        deliver(client, toClient, serverAddr)
        drain(client, true, onEvent); server?.let { drain(it, false, onEvent) }
        client.poll(toServer, now)
        if (server == null && toServer.count > 0) {
            server = ConnectionCore.server(quic, serverTls, NullCryptoProvider, clientAddr, Random(2), now, toServer.buffer(0), toServer.length(0))
        }
        server?.let { it.poll(toClient, now); drain(it, false, onEvent) }
        drain(client, true, onEvent)
    }

    private fun deliver(core: ConnectionCore, batch: PacketBatch, from: InetSocketAddress) {
        for (i in 0 until batch.count) core.handleDatagram(batch.buffer(i), batch.length(i), from, Ecn.NotEct, now)
        datagrams += batch.count
        batch.clear()
    }

    private inline fun drain(core: ConnectionCore, isClient: Boolean, onEvent: (ConnectionEvent, Boolean) -> Unit) {
        while (true) {
            val e = core.nextEvent() ?: break
            if (e is ConnectionEvent.VerifyRequested) core.resumeVerify(VerifyResult.Accepted(e.chain))
            onEvent(e, isClient)
        }
    }

    override fun close() { toServer.close(); toClient.close() }

    private companion object { const val MAX_WRITES_PER_STEP = 64 }
}
