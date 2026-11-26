// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client.publich3

import io.ktor.client.HttpClient
import io.ktor.client.plugins.UserAgent
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.contentType
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.ktor.client.AlternativeSource
import io.kuicksilver.ktor.client.FallbackReason
import io.kuicksilver.ktor.client.Http3Discovery
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.KuicksilverDiagnosticsKey
import io.kuicksilver.ktor.client.KuicksilverEngine
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.ktor.client.QuicConnectionSnapshot
import io.kuicksilver.ktor.client.TcpConnectionSnapshot
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.kuicksilverDiagnostics
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.MigrationRefusedException
import io.kuicksilver.quic.PathValidationException
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ZeroRttOutcome
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.EchConfigList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** The QUIC versions the client offers (QuicConfig's default list): a connection on any other is our bug. */
internal val OFFERED_VERSIONS: List<Int> = QuicConfig.Default.versions.map { it.version }

/** `v1`, `v2` or the version in hex. */
internal fun versionName(v: Int): String =
    when (v) {
        0x00000001 -> "v1"
        0x6b3343cf -> "v2"
        else -> "0x" + v.toUInt().toString(16)
    }

/** The value of [key] in a Cloudflare `/cdn-cgi/trace` body (`key=value` lines), null when it has no such line. */
internal fun traceField(
    trace: String,
    key: String,
): String? = trace.lineSequence().firstNotNullOfOrNull { l -> l.trim().takeIf { it.startsWith("$key=") }?.substringAfter('=') }

/** `http=` values of the trace that name a protocol other than HTTP/3: a contradiction of the client's report. */
private val NOT_HTTP3 = setOf("http/1.0", "http/1.1", "http/2", "h2")

/**
 * The trace's `http=` [value] against the client's HTTP/3: null when it says `http/3`, a Fail for a value known to name
 * another protocol, a warning when it is missing or unknown (the trace format changed).
 */
internal fun judgeTraceHttp(value: String?): Judged? =
    when (value) {
        "http/3" -> null
        null -> Judged.warn("/cdn-cgi/trace has no http= line any more")
        in NOT_HTTP3 -> Judged.fail("the client reports HTTP/3, the server saw $value")
        else -> Judged.warn("/cdn-cgi/trace says http=$value, a value this check does not know")
    }

/** The trace's `sni=` [value] with ECH configured: `encrypted` passes, `plaintext` fails, anything else (or none) warns. */
internal fun judgeTraceSni(value: String?): Judged =
    when (value) {
        "encrypted" -> Judged.pass("the server saw sni=encrypted over HTTP/3")
        "plaintext" -> Judged.fail("ECH configured, but the server saw sni=plaintext")
        null -> Judged.warn("/cdn-cgi/trace has no sni= line any more")
        else -> Judged.warn("/cdn-cgi/trace says sni=$value, a value this check does not know")
    }

/** The message of [io.kuicksilver.quic.QuicPath.switchTo] when the server left no unused connection ID for the new path. */
private const val NO_UNUSED_CID = "no unused connection ID of the peer"

/**
 * What a failed [QuicConnection.migrate] says: a refusal of the transport is "n/a" (the server does not allow it), a
 * failed validation or the switch finding no unused connection ID of the server's a warning (the server or the runner's
 * NAT); any other IllegalStateException is the client's own failure, and the rest is judged as any failure.
 */
internal fun judgeMigrationFailure(e: Throwable): Judged =
    when {
        e is MigrationRefusedException -> Judged.notApplicable("the transport refused to migrate: ${e.reason}")

        e is PathValidationException -> Judged.warn("the new path did not validate (${e.reason}): the server or the runner's NAT")

        e is IllegalStateException &&
            e.message.orEmpty().startsWith(
                NO_UNUSED_CID,
            )
        -> Judged.warn("the server left no unused connection ID for the new path")

        e is IllegalStateException -> Judged.fail("migrate() failed: ${e.message}")

        else -> classify(evidenceOf(e, null, stalledAfterHandshake = true))
    }

/** The User-Agent of every request of the check: who sends it and where it is described. */
internal val USER_AGENT: String =
    "kuicksilver-public-h3/${System.getProperty("kuicksilver.version") ?: "dev"} " +
        "(+https://github.com/kuicksilver/kuicksilver/blob/main/docs/how-we-verify.md#public-http3-servers)"

/** Whether an `Alt-Svc` field value names `h3` (RFC 7838 section 3; RFC 9114 section 3.1.1). */
internal fun altSvcHasH3(value: String): Boolean = Regex("""(^|[\s,])h3\s*=""").containsMatchIn(value)

/** One completed handshake as the connection listener heard it, on the endpoint loop. */
internal class HandshakeSeen(
    val alpn: String?,
    val version: Int,
    val connection: QuicConnection,
)

/** The connection the attempt's latest call went over, as its diagnostics name it ([Recorder.calls]). */
internal sealed interface CallConnection {
    /** An HTTP/3 connection, by its [id] (`ConnectionInfo.id`). */
    data class Quic(
        val id: String,
    ) : CallConnection

    /** A TCP connection (HTTP/1.1 or HTTP/2): no QUIC handshake to judge. */
    data object Tcp : CallConnection
}

/**
 * Whether a stalled exchange waited on a connection whose handshake had completed: the stalled call's own connection when
 * its diagnostics named one ([last]; [completed] holds the ids of the connections whose handshake completed), else, when
 * the call had none yet (it stalled before any connection was its), whether an open connection of the attempt had
 * ([openAfterHandshake]): the limit of what the listeners can tell.
 */
internal fun stalledAfterHandshake(
    last: CallConnection?,
    completed: Set<String>,
    openAfterHandshake: Boolean,
): Boolean =
    when (last) {
        is CallConnection.Quic -> last.id in completed
        CallConnection.Tcp -> false
        null -> openAfterHandshake
    }

/** What the client's connections did during one attempt ([ConnectionListener]: callbacks on the endpoint loop, kept short). */
internal class Recorder : ConnectionListener {
    val opened = MutableStateFlow(0)
    val handshakes = CopyOnWriteArrayList<HandshakeSeen>()
    val handshakeCount = MutableStateFlow(0)
    val zeroRtt = CopyOnWriteArrayList<ZeroRttOutcome>()
    val closed = CopyOnWriteArrayList<QuicException.ConnectionLost>()

    /** Each connection by its id, while it is open: whether its handshake completed. */
    private val open = ConcurrentHashMap<String, Boolean>()

    /** The ids of every connection whose handshake completed. */
    private val completed: MutableSet<String> = ConcurrentHashMap.newKeySet()

    /** The connection of the latest call, null from its start until its diagnostics name one. */
    private val lastCall = AtomicReference<CallConnection?>(null)

    /** The engine's event listener of the attempt: notes which connection each call went over. */
    val calls: KuicksilverEventListener =
        object : KuicksilverEventListener() {
            override fun callStart(request: HttpRequestData) = lastCall.set(null)

            override fun callEnd(
                request: HttpRequestData,
                protocol: HttpProtocolVersion,
                status: Int,
            ) = note(request)

            override fun callFailed(
                request: HttpRequestData,
                cause: Throwable,
            ) = note(request)

            private fun note(request: HttpRequestData) {
                when (val c = request.attributes.getOrNull(KuicksilverDiagnosticsKey)?.connection) {
                    is QuicConnectionSnapshot -> {
                        c.connectionId?.let { lastCall.set(CallConnection.Quic(it)) }
                    }

                    is TcpConnectionSnapshot -> {
                        lastCall.set(CallConnection.Tcp)
                    }

                    null -> {}
                }
            }
        }

    /** [stalledAfterHandshake] for this attempt. */
    val stalledAfterHandshake: Boolean get() = stalledAfterHandshake(lastCall.get(), completed, openAfterHandshake)

    /** Whether a connection still open had completed its handshake: the one a stalled exchange was waiting on. */
    val openAfterHandshake: Boolean get() = open.values.any { it }

    override fun onOpened(connection: ConnectionInfo) {
        open[connection.id] = false
        opened.update { it + 1 }
    }

    override fun onHandshakeCompleted(connection: ConnectionInfo) {
        val c = connection.connection
        handshakes += HandshakeSeen(c.negotiatedAlpn, c.core.version.version, c)
        open.replace(connection.id, true)
        completed += connection.id
        handshakeCount.update { it + 1 }
    }

    override fun onZeroRtt(
        connection: ConnectionInfo,
        outcome: ZeroRttOutcome,
    ) {
        zeroRtt += outcome
    }

    override fun onClosed(
        connection: ConnectionInfo,
        reason: QuicException.ConnectionLost,
    ) {
        open.remove(connection.id)
        closed += reason
    }

    /** Waits until [n] handshakes completed, at most [limit]; whether they did. */
    suspend fun awaitHandshakes(
        n: Int,
        limit: Duration,
    ): Boolean = withTimeoutOrNull(limit) { handshakeCount.first { it >= n } } != null
}

/**
 * The network side of the public HTTP/3 check: one [attempt] of one [Check] against one [Target], on a client of its own,
 * judged by [classify] when it throws. Each attempt writes qlog traces to its own directory, which [attempt] removes when
 * the check passed (or did not apply), so what is left are the traces of what went wrong.
 */
internal class PublicH3Probe(
    private val out: Path,
    private val attemptTimeout: Duration = 60.seconds,
) {
    /** The client of an attempt: no redirect followed (any status is an answer), the deadlines below [attemptTimeout]. */
    private fun client(
        mode: Http3Discovery?,
        rec: Recorder,
        qlogDir: Path,
        configure: KuicksilverEngineConfig.() -> Unit = {},
    ): HttpClient =
        HttpClient(Kuicksilver) {
            followRedirects = false
            expectSuccess = false
            install(UserAgent) { agent = USER_AGENT }
            engine {
                observability { eventListener = rec.calls }
                quicHandshakeTimeoutForTest = 15.seconds
                quicHandshakeTimeoutForTest = 15.seconds
                http3 { mode?.let { discovery = it } ?: run { enabled = false } }
                observability { connectionListener = rec }
                observability { qlog = DirectoryQlogSink(qlogDir.toString()) }
                configure()
            }
        }

    private suspend fun HttpResponse.drain(): HttpResponse = also { bodyAsBytes() }

    /** Runs attempt [n] of [check] against [target]. */
    suspend fun attempt(
        target: Target,
        check: Check,
        n: Int,
    ): Judged {
        val dir =
            out
                .resolve("qlog")
                .resolve(target.name)
                .resolve(check.name)
                .resolve("attempt-$n")
        Files.createDirectories(dir.parent)
        val rec = Recorder()
        val judged =
            try {
                withTimeout(attemptTimeout) {
                    when (check) {
                        Check.Http3 -> http3(target, rec, dir)
                        Check.AltSvc -> altSvc(target, rec, dir)
                        Check.ZeroRtt -> zeroRtt(target, rec, dir)
                        Check.Migration -> migration(target, rec, dir)
                        Check.Ech -> ech(target, rec, dir)
                    }
                }
            } catch (e: Throwable) {
                classify(evidenceOf(e, stalledAfterHandshake = rec.stalledAfterHandshake))
            }
        if (judged.verdict == Verdict.Pass || judged.verdict == Verdict.NotApplicable) dir.toFile().deleteRecursively()
        return judged
    }

    /** The QUIC facts of the attempt's first handshake, or the failure that their absence or content is. */
    private fun handshakeFacts(rec: Recorder): Pair<HandshakeSeen?, Judged?> {
        val hs = rec.handshakes.firstOrNull() ?: return null to Judged.fail("an HTTP/3 response, but the listener heard no handshake")
        if (hs.alpn != "h3") return hs to Judged.fail("an HTTP/3 response on a connection with ALPN ${hs.alpn}")
        if (hs.version !in OFFERED_VERSIONS) return hs to Judged.fail("QUIC version ${versionName(hs.version)}, which we never offered")
        return hs to null
    }

    private suspend fun http3(
        t: Target,
        rec: Recorder,
        dir: Path,
    ): Judged =
        client(Http3Discovery.H3Only, rec, dir).use { c ->
            val r = c.get(t.url).drain()
            val d = r.kuicksilverDiagnostics
            if (r.version != HttpProtocolVersion.HTTP_3_0) return Judged.fail("H3Only answered over ${r.version}")
            if (d?.connection !is QuicConnectionSnapshot) return Judged.fail("an HTTP/3 response whose diagnostics name no QUIC connection")
            val (hs, wrong) = handshakeFacts(rec)
            if (wrong != null) return wrong
            val note = "QUIC ${versionName(hs!!.version)}, status ${r.status.value}"
            if (!t.cloudflareTrace) return Judged.pass(note)
            // the server's own view: Cloudflare's trace says which protocol it served the request over
            val trace = c.get("https://${t.host}/cdn-cgi/trace").bodyAsText()
            judgeTraceHttp(traceField(trace, "http")) ?: Judged.pass("$note; the server saw http/3")
        }

    private suspend fun altSvc(
        t: Target,
        rec: Recorder,
        dir: Path,
    ): Judged =
        client(Http3Discovery.Auto, rec, dir).use { c ->
            val first = c.get(t.url).drain()
            if (first.version == HttpProtocolVersion.HTTP_3_0) {
                return Judged.fail("the first request went over HTTP/3 with no alternative known yet")
            }
            val alt =
                first.headers
                    .getAll("Alt-Svc")
                    .orEmpty()
                    .joinToString(", ")
            if (!altSvcHasH3(alt)) return Judged.warn("the first answer (${first.version}) has no h3 in Alt-Svc any more")
            for (i in 2..5) {
                val r = c.get(t.url).drain()
                val d = r.kuicksilverDiagnostics
                if (r.version == HttpProtocolVersion.HTTP_3_0) {
                    if (d?.alternativeSource != AlternativeSource.AltSvc) {
                        return Judged.fail("HTTP/3 from alternative source ${d?.alternativeSource}, not the Alt-Svc it was sent")
                    }
                    val (_, wrong) = handshakeFacts(rec)
                    if (wrong != null) return wrong
                    return if (first.version == HttpProtocolVersion.HTTP_2_0) {
                        Judged.pass("${first.version} first, HTTP/3 at request $i")
                    } else {
                        Judged.warn("HTTP/3 at request $i, but the first contact was ${first.version}, not HTTP/2")
                    }
                }
                when (val why = d?.fallback) {
                    FallbackReason.NoAlternative -> {
                        return Judged.fail("the client did not learn the h3 alternative it was sent ($alt)")
                    }

                    // HTTP/1.1 or HTTP/2 was ready first (the pooled TCP connection): the QUIC setup goes on for later calls
                    FallbackReason.H3NotReady, null -> {
                        rec.awaitHandshakes(1, 10.seconds)
                    }

                    // an earlier request's HTTP/3 setup of this attempt failed in the background: its end says why
                    FallbackReason.BrokenAlternative -> {
                        val end = rec.closed.firstOrNull()
                        return if (end != null) {
                            classify(evidenceOf(end, null, rec.stalledAfterHandshake))
                        } else {
                            Judged.warn("the h3 alternative was marked broken by a setup that never opened a connection")
                        }
                    }

                    else -> {
                        val failure = d.h3Failure
                        return if (failure != null) {
                            classify(evidenceOf(failure, d, rec.stalledAfterHandshake))
                        } else {
                            val progress = d.connectFailures.lastOrNull { it.quicProgress != null }?.quicProgress
                            if (why == FallbackReason.HandshakeTimeout) {
                                classify(Evidence.ConnectTimeout(progress))
                            } else {
                                Judged.warn("HTTP/3 not used: $why")
                            }
                        }
                    }
                }
            }
            Judged.warn("TCP was ready first four times in a row: HTTP/3 served no request")
        }

    private suspend fun zeroRtt(
        t: Target,
        rec: Recorder,
        dir: Path,
    ): Judged =
        client(Http3Discovery.H3Only, rec, dir, configure = { http3 { earlyData { enabled = true } } }).use { c ->
            // two requests on the first connection: the session ticket follows the handshake, the second gives it time
            repeat(2) { c.get(t.url).drain() }
            (c.engine as KuicksilverEngine).h3.dropConnectionsForTest().forEach { it.close() }
            val r = c.get(t.url).drain()
            if (r.version != HttpProtocolVersion.HTTP_3_0) return Judged.fail("H3Only answered over ${r.version}")
            if (rec.opened.value < 2) return Judged.fail("the request after the connection was dropped opened no new connection")
            if (!rec.awaitHandshakes(2, 15.seconds)) return Judged.fail("the resumed connection answered but never completed its handshake")
            when (rec.zeroRtt.lastOrNull()) {
                ZeroRttOutcome.Accepted -> {
                    Judged.pass("early data accepted")
                }

                ZeroRttOutcome.Rejected -> {
                    Judged.notApplicable(
                        "the server rejected 0-RTT (its choice, RFC 9001 section 4.6.2); 1-RTT retry fine",
                    )
                }

                null -> {
                    Judged.notApplicable("no 0-RTT attempt: no session ticket that allows early data")
                }
            }
        }

    private suspend fun migration(
        t: Target,
        rec: Recorder,
        dir: Path,
    ): Judged =
        client(Http3Discovery.H3Only, rec, dir).use { c ->
            c.get(t.url).drain()
            val (hs, wrong) = handshakeFacts(rec)
            if (wrong != null) return wrong
            val conn = hs!!.connection
            val remote =
                conn.info
                    ?.paths
                    ?.firstOrNull()
                    ?.remoteAddress ?: return Judged.fail("the connection has no path")
            // the same family as the first path, any address and a new port: an active migration as the server sees it
            val any = if (remote.resolveAddress()?.size == 16) "::" else "0.0.0.0"
            val io = DatagramIo.open(InetSocketAddress(any, 0))
            try {
                conn.migrate(io)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e // the attempt's deadline: judged by attempt()
            } catch (e: Throwable) {
                return judgeMigrationFailure(e)
            }
            // the pooled HTTP/3 connection over it, to tell a server's GOAWAY after the move from a lost connection
            val pooled = (c.engine as KuicksilverEngine).h3.connectionsForTest().firstOrNull { it.quic === conn }
            val r = c.get(t.url).drain()
            val snapshot = r.kuicksilverDiagnostics?.connection as? QuicConnectionSnapshot
            when {
                r.version != HttpProtocolVersion.HTTP_3_0 -> {
                    Judged.fail("H3Only answered over ${r.version}")
                }

                snapshot == null || !snapshot.reused -> {
                    val end = rec.closed.firstOrNull()
                    if (pooled?.goAwayReceived?.value != null) {
                        Judged.warn("the server sent GOAWAY after the move: the next request went on a new connection")
                    } else if (end != null) {
                        classify(evidenceOf(end, null, true))
                    } else {
                        Judged.fail("the request after the migration went on a new connection, the migrated one still open")
                    }
                }

                (conn.info?.pathChanges ?: 0) < 1 -> {
                    Judged.fail("migrate() returned, but the connection counts no path change")
                }

                else -> {
                    Judged.pass("moved to a new local port, the next request went on the new path")
                }
            }
        }

    /** The `ech` of [host]'s HTTPS record from Cloudflare's DNS over HTTPS, null when the record has none. */
    private suspend fun echConfigOf(host: String): ByteArray? =
        HttpClient(Kuicksilver) {
            install(UserAgent) { agent = USER_AGENT }
            engine { http3 { enabled = false } }
        }.use { doh ->
            val answer =
                doh
                    .post("https://cloudflare-dns.com/dns-query") {
                        contentType(ContentType("application", "dns-message"))
                        setBody(DnsMessage.query(host))
                    }.bodyAsBytes()
            DnsMessage.read(answer, host).records.firstNotNullOfOrNull { it.ech }
        }

    private suspend fun ech(
        t: Target,
        rec: Recorder,
        dir: Path,
    ): Judged {
        val raw =
            try {
                echConfigOf(t.host) ?: return Judged.warn("the HTTPS record of ${t.host} has no ech parameter any more")
            } catch (e: Throwable) {
                return Judged.warn("the HTTPS record lookup (DNS over HTTPS) failed: ${classify(evidenceOf(e)).reason}")
            }
        val list =
            try {
                EchConfigList.parse(raw)
            } catch (e: IllegalArgumentException) {
                return Judged.fail("our parser rejects the ECHConfigList the record publishes: ${e.message}")
            }
        return client(Http3Discovery.H3Only, rec, dir, configure = { tls { ech { configLists = mapOf(t.host to list) } } }).use { c ->
            val r = c.get("https://${t.host}/cdn-cgi/trace")
            val trace = r.bodyAsText()
            if (r.version != HttpProtocolVersion.HTTP_3_0) return Judged.fail("H3Only answered over ${r.version}")
            // both lines must confirm: a missing or unknown http= is a warning even when sni=encrypted
            judgeTraceHttp(traceField(trace, "http")) ?: judgeTraceSni(traceField(trace, "sni"))
        }
    }
}
