// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.io.readByteArray
import kotlin.concurrent.Volatile
import kotlin.time.Duration

/** In-memory UDP for tests on every platform; [delayFrom] holds datagrams from one address back (reordering between streams). */
@OptIn(ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class MemoryNet {
    /**
     * The open sockets by address, copied on write: sockets are opened on several threads at once (a CONNECT-UDP proxy's
     * tunnels set up together) while the endpoints' loops deliver, and a HashMap could lose one of them.
     */
    private val sockets = kotlin.concurrent.atomics.AtomicReference<Map<InetSocketAddress, MemoryIo>>(emptyMap())

    @Volatile var delay: Duration = Duration.ZERO

    /** Sees every datagram (from, to, bytes) before delivery: the 0-RTT tests capture a client's flight to replay it. */
    @Volatile var tap: ((InetSocketAddress, InetSocketAddress, ByteArray) -> Unit)? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    fun open(
        local: InetSocketAddress,
        capabilities: IoCapabilities = IoCapabilities.Portable,
    ): MemoryIo {
        val io = MemoryIo(this, local, capabilities)
        while (true) {
            val now = sockets.load()
            if (sockets.compareAndSet(now, now + (local to io))) break
        }
        return io
    }

    /** Sees every datagram (from, to, bytes) when the endpoint at `to` takes it from its socket, past [drop] and [delay]. */
    @Volatile var taken: ((InetSocketAddress, InetSocketAddress, ByteArray) -> Unit)? = null

    /** Datagrams it returns true for are lost (after [tap] saw them): an attacker who keeps the client's flight. */
    @Volatile var drop: ((InetSocketAddress, InetSocketAddress, ByteArray) -> Boolean)? = null

    fun deliver(
        from: InetSocketAddress,
        to: InetSocketAddress,
        bytes: ByteArray,
    ) {
        tap?.invoke(from, to, bytes)
        if (drop?.invoke(from, to, bytes) == true) return
        val d = delay
        if (d ==
            Duration.ZERO
        ) {
            sockets.load()[to]?.inbox?.trySend(bytes to from)
        } else {
            scope.launch {
                delay(d)
                sockets.load()[to]?.inbox?.trySend(bytes to from)
            }
        }
    }
}

@OptIn(ExperimentalKuicksilverApi::class)
internal class MemoryIo(
    private val net: MemoryNet,
    override val localAddress: InetSocketAddress,
    caps: IoCapabilities = IoCapabilities.Portable,
) : DatagramIo {
    val inbox = Channel<Pair<ByteArray, InetSocketAddress>>(Channel.UNLIMITED)
    override val capabilities: StateFlow<IoCapabilities> = MutableStateFlow(caps)

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        val (bytes, from) = inbox.receive()
        net.taken?.invoke(from, localAddress, bytes)
        val i = into.count
        into.buffer(i).copyFrom(bytes, 0, 0, bytes.size)
        into.setLength(i, bytes.size)
        into.setAddress(i, from)
        return 1
    }

    /** Runs before each suspending send: a test stalls the loop's flush in it, as a socket without room would. */
    @Volatile var beforeSend: (suspend () -> Unit)? = null

    override suspend fun send(batch: PacketBatch): Int {
        beforeSend?.invoke()
        return trySend(batch)
    }

    override fun trySend(batch: PacketBatch): Int {
        for (i in 0 until batch.count) net.deliver(localAddress, batch.address(i) ?: continue, batch.buffer(i).toByteArray(batch.length(i)))
        return batch.count
    }

    override fun close() {
        inbox.close()
    }
}

internal object H3Fixtures {
    val testCa = Certificate(TestCerts.testCa)

    /** The transport of WebTransport tests: `reset_stream_at` on, as draft-14 and later need it on both sides (draft-16 section 3.1). */
    val quic: QuicConfig = io.kuicksilver.quic.quicConfig { resetStreamAt = true }

    fun client(alpn: String = "h3"): TlsConfig =
        tlsConfig(TlsRole.Client) {
            this.alpn = listOf(alpn)
            serverName = "server.test"
            trust =
                TrustConfig.AnchoredCa(listOf(testCa))
        }

    fun server(alpn: String = "h3"): TlsConfig =
        tlsConfig(TlsRole.Server) {
            this.alpn = listOf(alpn)
            identity =
                TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        }
}

/** Two QUIC endpoints over [MemoryNet] with null crypto; [connect] gives a raw client/server QUIC connection pair. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal class QuicPair private constructor(
    val server: QuicEndpoint,
    val client: QuicEndpoint,
    val net: MemoryNet,
) : AutoCloseable {
    override fun close() {
        client.close()
        server.close()
    }

    suspend fun connect(clientQuic: QuicConfig = QuicConfig.Default): Pair<QuicConnection, QuicConnection> =
        coroutineScope {
            val accepted = async { server.accept() }
            val c = client.connect(server.localAddress, QuicClientConfig.Builder(H3Fixtures.client()).apply { quic = clientQuic }.build())
            c to accepted.await()
        }

    companion object {
        /** [df]: the sockets set Don't Fragment, so DPLPMTUD raises the path MTU above 1200 (the network has no limit). */
        suspend fun open(
            serverQuic: QuicConfig = QuicConfig.Default,
            df: Boolean = false,
        ): QuicPair {
            val net = MemoryNet()
            val caps = if (df) IoCapabilities(false, false, 1, false, true, 1) else IoCapabilities.Portable
            val a = net.open(InetSocketAddress("10.0.0.1", 1111), caps)
            val b = net.open(InetSocketAddress("10.0.0.2", 443), caps)
            val server =
                QuicEndpoint.bind(
                    b.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(H3Fixtures.server()).apply { quic = serverQuic }.build()
                            ; crypto = NullCryptoProvider
                            io = { b }
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    a.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            crypto = NullCryptoProvider
                            io = { a }
                        }.build(),
                )
            return QuicPair(server, client, net)
        }
    }
}

/** An HTTP/3 client and server connection over a [QuicPair]. */
internal class H3Pair(
    val quic: QuicPair,
    val client: Http3Connection,
    val server: Http3Connection,
) : AutoCloseable {
    override fun close() {
        client.close()
        server.close()
        quic.close()
    }

    companion object {
        suspend fun open(
            clientSettings: Http3Settings = Http3Settings.Default,
            serverSettings: Http3Settings = Http3Settings.Default,
            // WebTransport needs reset_stream_at; every other pair keeps the default transport
            serverQuic: QuicConfig = if (serverSettings.webTransport) H3Fixtures.quic else QuicConfig.Default,
            clientQuic: QuicConfig = if (clientSettings.webTransport) H3Fixtures.quic else QuicConfig.Default,
            df: Boolean = false,
        ): H3Pair {
            val q = QuicPair.open(serverQuic, df)
            val (c, s) = q.connect(clientQuic)
            return coroutineScope {
                val server = async { Http3Connection.server(s, serverSettings) }
                H3Pair(q, Http3Connection.client(c, clientSettings), server.await())
            }
        }
    }
}

/**
 * [use] for a [QuicPair] or [H3Pair] whose test launches the peer side (usually the server) next to the client: [block]
 * runs in its own scope, so the pair closes only after every coroutine [block] launched has finished. With plain [use]
 * those coroutines belong to the enclosing test scope, and when the client side returns first the pair is closed under
 * a server coroutine that is still writing; the failure that close provokes then fails the test (run 38292521169,
 * ExtendedConnectTest.streamCarriesThePeersFields and LimitsTest.responseHeadersTooLargeOnClient on the Linux arm64
 * runner). A coroutine that runs until cancelled is cancelled by the test before [block] returns.
 */
internal suspend fun <P : AutoCloseable, R> P.useScoped(block: suspend CoroutineScope.(P) -> R): R = use { coroutineScope { block(it) } }

/** Reads to the end: ktor-io reports a cancelled channel as EOF with the cause in closedCause, so surface it. */
internal suspend fun ByteReadChannel.readAllBytes(): ByteArray {
    val out = kotlinx.io.Buffer()
    val buf = ByteArray(8192)
    while (true) {
        val n = readAvailable(buf, 0, buf.size)
        if (n < 0) break
        out.write(buf, 0, n)
    }
    closedCause?.let { throw it }
    return out.readByteArray()
}
