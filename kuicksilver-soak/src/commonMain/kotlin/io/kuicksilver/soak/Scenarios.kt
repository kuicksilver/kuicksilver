// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.tls.EarlyDataState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile
import kotlin.math.exp
import kotlin.math.ln
import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** A socket that can stop delivering what it receives: the stateless-reset scenario makes a client miss its server's CONNECTION_CLOSE. */
internal class GateIo(
    private val inner: DatagramIo,
) : DatagramIo {
    @Volatile var dropInbound: Boolean = false

    override val localAddress: InetSocketAddress get() = inner.localAddress
    override val capabilities: StateFlow<IoCapabilities> get() = inner.capabilities

    override suspend fun receive(into: PacketBatch): Int {
        while (true) {
            val start = into.count
            val n = inner.receive(into)
            if (!dropInbound) return n
            into.count = start
        }
    }

    override suspend fun send(batch: PacketBatch): Int = inner.send(batch)

    override fun trySend(batch: PacketBatch): Int = inner.trySend(batch)

    override fun disableEcnMarking() = inner.disableEcnMarking()

    override fun close() = inner.close()
}

/** One scenario of the mix; [weight] is its share of iterations. */
internal enum class Scenario(
    val weight: Int,
) {
    QuicTransfer(22),
    QuicAbort(8),
    QuicIdleTimeout(4),
    QuicStatelessReset(3),
    QuicMigration(5),
    QuicZeroRtt(8),
    QuicEndpointChurn(4),
    QuicRefusal(4),
    KtorH1(14),
    KtorH3(14),
    KtorAbort(6),
    KtorClientChurn(3),
    ;

    companion object {
        private val total = entries.sumOf { it.weight }

        fun pick(
            r: Random,
            only: Set<Scenario> = entries.toSet(),
        ): Scenario {
            val from = entries.filter { it in only }
            var x = r.nextInt(if (from.size == entries.size) total else from.sumOf { it.weight })
            for (s in from) {
                x -= s.weight
                if (x < 0) return s
            }
            return from.last()
        }

        /** `KSL_SOAK_SCENARIOS` (`-Pkuicksilver.soak.scenarios=KtorH3,KtorAbort`), or every scenario. */
        fun fromEnvironment(): Set<Scenario> =
            ProcessResources
                .env("KSL_SOAK_SCENARIOS")
                ?.split(',')
                ?.map { valueOf(it.trim()) }
                ?.toSet() ?: entries.toSet()
    }
}

/** What an iteration ended with: [Outcome.Ok], or an expected end that is not success (a refusal, a reset, a timeout we asked for). */
internal sealed class Outcome(
    val tag: String,
) {
    object Ok : Outcome("ok")

    class Expected(
        tag: String,
    ) : Outcome(tag)
}

/** The shared clients and servers every scenario uses; per-iteration resources are opened and closed inside the scenario. */
internal class Workload(
    private val httpPort: Int,
    private val raw: RawServer,
    private val refuser: RawServer,
    private val quic: QuicEndpoint,
    private val zeroRtt: QuicEndpoint,
    private val h1: HttpClient,
    private val h3: HttpClient,
) {
    private val local = InetSocketAddress("127.0.0.1", 0)
    private val rawAddr get() = InetSocketAddress("127.0.0.1", raw.port)
    private val clientTls = SoakPki.clientTls(RawProtocol.ALPN)
    private val plain = QuicClientConfig.Builder(clientTls).build()
    private val early = QuicClientConfig.Builder(clientTls).apply { earlyData = EarlyDataState.Allowed }.build()
    private val shortIdle = QuicClientConfig.Builder(clientTls).apply { quic = quicConfig { maxIdleTimeout = 1.seconds } }.build()

    /** Sizes 1 KiB..[max], log-uniform: many small exchanges, some large. */
    private fun size(
        r: Random,
        max: Int = 4 shl 20,
    ): Int = exp(ln(1024.0) + r.nextDouble() * (ln(max.toDouble()) - ln(1024.0))).toInt()

    suspend fun run(
        s: Scenario,
        r: Random,
    ): Outcome =
        when (s) {
            Scenario.QuicTransfer -> quicTransfer(r)
            Scenario.QuicAbort -> quicAbort(r)
            Scenario.QuicIdleTimeout -> idleTimeout()
            Scenario.QuicStatelessReset -> statelessReset()
            Scenario.QuicMigration -> migration(r)
            Scenario.QuicZeroRtt -> zeroRtt(r)
            Scenario.QuicEndpointChurn -> endpointChurn(r)
            Scenario.QuicRefusal -> refusal()
            Scenario.KtorH1 -> ktor(h1, r)
            Scenario.KtorH3 -> ktor(h3, r)
            Scenario.KtorAbort -> ktorAbort(if (r.nextBoolean()) h1 else h3, r)
            Scenario.KtorClientChurn -> clientChurn(r)
        }

    private suspend fun QuicConnection.get(n: Int) {
        val st = openBidi()
        st.output.writeStringUtf8("GET $n\n")
        st.output.flushAndClose()
        val got = st.input.discard()
        check(got == n.toLong()) { "GET $n returned $got bytes" }
    }

    private suspend fun QuicConnection.put(n: Int) {
        val st = openBidi()
        st.output.writeStringUtf8("PUT $n\n")
        var left = n
        while (left > 0) {
            val k = minOf(left, RawProtocol.CHUNK)
            st.output.writeFully(RawProtocol.pattern, 0, k)
            left -= k
        }
        st.output.flushAndClose()
        val line = st.input.readUTF8Line(64)
        check(line == "ok $n") { "PUT $n answered $line" }
    }

    private suspend fun quicTransfer(r: Random): Outcome {
        val c = quic.connect(rawAddr, plain)
        try {
            repeat(1 + r.nextInt(3)) { if (r.nextBoolean()) c.get(size(r)) else c.put(size(r)) }
        } finally {
            c.close(0, "done")
        }
        return Outcome.Ok
    }

    /** A large download abandoned midway: by STOP_SENDING + RESET of the stream, or by closing the whole connection. */
    private suspend fun quicAbort(r: Random): Outcome {
        val c = quic.connect(rawAddr, plain)
        try {
            val st = c.openBidi()
            st.output.writeStringUtf8("GET ${8 shl 20}\n")
            st.output.flushAndClose()
            val buf = ByteArray(16 * 1024)
            var read = 0
            val stopAt = 1 + r.nextInt(2 shl 20)
            while (read < stopAt) {
                val n = st.input.readAvailable(buf, 0, buf.size)
                if (n < 0) break
                read += n
            }
            if (r.nextBoolean()) {
                st.stopSending(3)
                st.reset(3)
                c.get(1024) // the connection stays usable
            }
        } finally {
            c.close(0, "abort")
        }
        return Outcome.Expected("aborted")
    }

    /** One exchange, then silence until the 1 s idle timeout ends the connection on both sides. */
    private suspend fun idleTimeout(): Outcome {
        val c = quic.connect(rawAddr, shortIdle)
        c.get(4096)
        val why = withTimeout(10.seconds) { c.closed.await() }
        return if (why is QuicException.ConnectionLost.Timeout) {
            Outcome.Expected(
                "idle-timeout",
            )
        } else {
            error("idle connection ended with $why")
        }
    }

    /**
     * The server closes the connection while the client cannot hear it; once the server forgot the connection (after its
     * closing period) the client's next packet is answered with a Stateless Reset (RFC 9000 section 10.3).
     */
    private suspend fun statelessReset(): Outcome {
        val gate = GateIo(DatagramIo.open(local))
        val ep = QuicEndpoint.bind(local, quicEndpointConfig { io = { gate } })
        try {
            val c = ep.connect(rawAddr, plain)
            c.get(1024)
            gate.dropInbound = true
            val st = c.openBidi()
            st.output.writeStringUtf8("CLOSE\n")
            st.output.flushAndClose()
            delay(1500.milliseconds) // longer than the server's closing period (3 PTO on loopback)
            gate.dropInbound = false
            // the reset may answer a retransmission of the CLOSE stream first: then this write fails with it, which is the outcome
            runCatching {
                val probe = c.openBidi()
                probe.output.writeStringUtf8("GET 1\n")
                probe.output.flushAndClose()
            }.onFailure { if (it is CancellationException) throw it }
            val why = withTimeoutOrNull(10.seconds) { c.closed.await() } ?: error("no stateless reset within 10 s")
            return when (why) {
                is QuicException.ConnectionLost.StatelessReset -> {
                    Outcome.Expected("stateless-reset")
                }

                is QuicException.ConnectionLost.TransportClosed, is QuicException.ConnectionLost.ApplicationClosed -> {
                    Outcome.Expected(
                        "close-seen",
                    )
                }

                else -> {
                    error("expected a stateless reset, got $why")
                }
            }
        } finally {
            ep.closeAndJoin()
        }
    }

    /** A transfer, a move to a new local socket (path validation, new connection IDs), another transfer. */
    private suspend fun migration(r: Random): Outcome {
        val c = quic.connect(rawAddr, plain)
        try {
            c.get(size(r, 256 shl 10))
            c.migrate(DatagramIo.open(local))
            c.get(size(r, 256 shl 10))
        } finally {
            c.close(0, "migrated")
        }
        return Outcome.Ok
    }

    /** Resumption with 0-RTT on the endpoint that keeps the tickets; the first ever connection has none and runs 1-RTT. */
    private suspend fun zeroRtt(r: Random): Outcome {
        val c = zeroRtt.connectEarly(rawAddr, early)
        try {
            c.get(size(r, 64 shl 10))
            c.awaitHandshake()
        } finally {
            c.close(0, "0rtt")
        }
        return when (c.earlyDataAccepted) {
            true -> Outcome.Ok
            else -> Outcome.Expected("1rtt")
        }
    }

    /** A client endpoint (its socket, wake pipe and loop) for one connection only. */
    private suspend fun endpointChurn(r: Random): Outcome {
        val ep = QuicEndpoint.bind(local, quicEndpointConfig { })
        try {
            val c = ep.connect(rawAddr, plain)
            c.get(size(r, 64 shl 10))
            c.close(0, "churn")
        } finally {
            ep.closeAndJoin()
        }
        return Outcome.Ok
    }

    /** A burst against the server whose accept queue holds two and drains one connection per 500 ms: some are refused. */
    private suspend fun refusal(): Outcome {
        val addr = InetSocketAddress("127.0.0.1", refuser.port)
        val results =
            coroutineScope {
                List(4) {
                    async {
                        try {
                            val c = quic.connect(addr, plain)
                            c.close(0, "refusal probe")
                            true
                        } catch (e: QuicException.ConnectionLost) {
                            false
                        }
                    }
                }.awaitAll()
            }
        return if (results.all { it }) Outcome.Ok else Outcome.Expected("refused")
    }

    private val base get() = "https://127.0.0.1:$httpPort"

    private suspend fun ktor(
        client: HttpClient,
        r: Random,
    ): Outcome {
        if (r.nextInt(4) == 0) {
            val n = size(r, 1 shl 20)
            val text = client.post("$base/upload") { setBody(ByteArray(n)) }.bodyAsText()
            check(text == "ok $n") { "upload $n answered $text" }
        } else {
            val n = size(r, 1 shl 20)
            val got = client.get("$base/bytes/$n").bodyAsChannel().discard()
            check(got == n.toLong()) { "GET /bytes/$n returned $got" }
        }
        return Outcome.Ok
    }

    /** A streamed body read partway, then the call is left: the engine must cancel the stream (RST/STOP_SENDING or a dropped HTTP/1.1 connection). */
    private suspend fun ktorAbort(
        client: HttpClient,
        r: Random,
    ): Outcome {
        client.prepareGet("$base/stream/${8 shl 20}").execute { resp ->
            val ch: ByteReadChannel = resp.bodyAsChannel()
            val buf = ByteArray(16 * 1024)
            var read = 0
            val stopAt = 1 + r.nextInt(1 shl 20)
            while (read < stopAt) {
                val n = ch.readAvailable(buf, 0, buf.size)
                if (n < 0) break
                read += n
            }
        }
        return Outcome.Expected("aborted")
    }

    /** A new HttpClient (engine, selector, HTTP/3 endpoint, pools) for two requests, then closed. */
    private suspend fun clientChurn(r: Random): Outcome {
        val client = soakHttpClient(if (r.nextBoolean()) Http3DiscoveryMode.H3Only else Http3DiscoveryMode.Auto)
        try {
            repeat(2) { ktor(client, r) }
        } finally {
            client.close()
        }
        return Outcome.Ok
    }
}

/** The failure-only qlog sink of the run (`-Pkuicksilver.soak.qlog=<dir>`, `KSL_SOAK_QLOG`), shared by the Ktor clients and server. */
internal object SoakQlog {
    val sink: FailureQlog? by lazy { ProcessResources.env("KSL_SOAK_QLOG")?.let { FailureQlog(it) } }
}

/** A Kuicksilver HttpClient that trusts the soak CA. */
internal fun soakHttpClient(discovery: Http3DiscoveryMode): HttpClient =
    HttpClient(Kuicksilver) {
        engine {
            trust = SoakPki.trust
            http3 { this.discovery = discovery }
            SoakQlog.sink?.let { sink -> quic = quicConfig { qlog = sink } }
        }
    }

/** True for an exception a scenario lets through on purpose: never a cancellation of the run itself. */
internal fun Throwable.isCancellation(): Boolean = this is CancellationException
