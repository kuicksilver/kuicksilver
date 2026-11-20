// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.interop

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** The QUIC Interop Runner endpoint: ROLE, TESTCASE, REQUESTS, SSLKEYLOGFILE, QLOGDIR (and our KSL_CC) from the environment; exit 0 / 1 (a failed transfer or a lost connection) / 127 (unsupported). */
internal object Interop {
    val v1: List<VersionProfile> get() = Testcases.v1
    private val keys = listOf("ROLE", "TESTCASE", "REQUESTS", "DOWNLOADS", "CERTS", "WWW", "SSLKEYLOGFILE", "QLOGDIR", "KSL_INTEROP_EXPECTED_NAME", "KSL_CC")
    fun environment(): Map<String, String> = keys.mapNotNull { k -> envVar(k)?.let { k to it } }.toMap()

    fun run(env: Map<String, String>): Int {
        val testcase = env["TESTCASE"] ?: "handshake"
        val role = env["ROLE"] ?: return 127
        if (testcase !in Testcases.supported) { Files.log("unsupported test case $testcase"); return 127 }
        val cc = Testcases.congestionController(env["KSL_CC"]) ?: run { Files.log("unknown KSL_CC ${env["KSL_CC"]}"); return 127 }
        if (env["KSL_CC"] != null) Files.log("congestion controller ${env["KSL_CC"]}")
        KslLoader.ensureLoaded()
        return when (role) {
            "server" -> {
                // the runner stops the server container with SIGTERM: the endpoints are then closed and joined, so every qlog trace is
                // closed and written (a DirectoryQlogSink trace buffers until then; the server qlogs were empty files), within STOP_GRACE
                val stop = CompletableDeferred<Unit>(); val closed = CompletableDeferred<Unit>()
                installStopSignal(stop, closed)
                try {
                    runBlocking {
                        val plan = Testcases.server(testcase, cc)!!; val certs = env["CERTS"] ?: "/certs"
                        val identity = TlsIdentity.fromPem(Files.readText("$certs/cert.pem"), Files.readText("$certs/priv.key").toCharArray())
                        val www = env["WWW"] ?: "/www"; val qlog = env["QLOGDIR"]?.let { DirectoryQlogSink(it) }
                        val server = if (plan.http3) H3InteropServer.start(identity, 443, www, plan.versions, admission = plan.admission, cipherSuites = plan.cipherSuites, handshakeTimeout = plan.handshakeTimeout, qlog = qlog, congestionController = plan.congestionController)
                            else HqInteropServer.start(identity, 443, www, plan.versions, admission = plan.admission, cipherSuites = plan.cipherSuites, handshakeTimeout = plan.handshakeTimeout, qlog = qlog, congestionController = plan.congestionController, earlyData = plan.earlyData)
                        serveUntilStopped(server, stop)
                    }
                } finally { closed.complete(Unit) }
                0
            }
            "client" -> runBlocking {
                val plan = Testcases.client(testcase, cc)!!
                val requests = (env["REQUESTS"] ?: "").split(Regex("\\s+")).filter { it.isNotBlank() }
                // a lost connection (idle timeout, the peer's close, a stateless reset) is a failed cell, exit 1: uncaught it ended the
                // JVM with 1 but Kotlin/Native with 133 (ngtcp2->kuicksilver-native:rebind-addr, 2026-10-20). A stream's output reports
                // it as a ClosedWriteChannelException with the ConnectionLost as its cause (a close that lands between openBidi and the
                // request's write: Linux arm64 Docker JVM 2026-10-23, 3 in 1000 loaded macOS runs), so the cause chain is searched for it
                try {
                    val ok = if (plan.http3) H3InteropClient.download(requests, env["DOWNLOADS"] ?: "/downloads", plan, InteropTrust.config(env), env["SSLKEYLOGFILE"], env["QLOGDIR"]?.let { DirectoryQlogSink(it) })
                        else HqInteropClient.download(requests, env["DOWNLOADS"] ?: "/downloads", plan, InteropTrust.config(env), env["SSLKEYLOGFILE"], env["QLOGDIR"]?.let { DirectoryQlogSink(it) })
                    if (ok) 0 else 1
                } catch (e: Exception) {
                    val lost = connectionLost(e) ?: throw e
                    Files.log("connection lost: $lost"); 1
                }
            }
            else -> 127
        }
    }

    /** [e] or the first of its causes that is a lost connection (ktor-io's channels wrap it), else null. */
    internal fun connectionLost(e: Throwable): QuicException.ConnectionLost? =
        generateSequence(e) { it.cause.takeUnless { c -> c === it } }.take(16).filterIsInstance<QuicException.ConnectionLost>().firstOrNull()
}

/** A running interop server: [closeAndJoin] closes its endpoints and waits until their connections and qlog traces are released. */
internal interface InteropServer : AutoCloseable {
    suspend fun closeAndJoin()
}

/** How long a stopped server may take to close its endpoints: the runner's compose stop sends SIGKILL 10 s after SIGTERM. */
internal val STOP_GRACE = 3.seconds

/**
 * Serves until [stop] completes, then closes [server] and joins its endpoints within [grace], so the qlog traces of its connections
 * are closed and written; a close that does not finish in time is abandoned (logged) and false is returned, so a stuck close never
 * holds the container's stop.
 */
internal suspend fun serveUntilStopped(server: InteropServer, stop: Deferred<Unit>, grace: Duration = STOP_GRACE): Boolean {
    var joined = false
    try { stop.await() } finally {
        joined = withContext(NonCancellable) { withTimeoutOrNull(grace) { server.closeAndJoin(); true } } ?: false
        if (!joined) { Files.log("the endpoints did not close within $grace"); server.close() }
    }
    return joined
}

/**
 * Completes [stop] when the process is asked to stop (SIGTERM; SIGINT too). JVM: a shutdown hook, which also holds the JVM's
 * shutdown until [closed] completes (at most [STOP_GRACE] and a second). Native: a handler written in C that only stores to a
 * lock-free atomic_int and restores the default action (a second signal ends a stop that hangs; SIGINT ignored on entry stays
 * ignored), read by a coroutine every 20 ms; the process
 * then exits on its own, so [closed] is not waited for.
 */
internal expect fun installStopSignal(stop: CompletableDeferred<Unit>, closed: CompletableDeferred<Unit>)

fun main() { exitWith(Interop.run(Interop.environment())) }
