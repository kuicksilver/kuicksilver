// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.ios

import io.kuicksilver.quic.QuicConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A running operation the Swift side can cancel (leaving the screen, pressing Stop). */
class SampleTask internal constructor(private val job: Job) {
    fun cancel() { job.cancel() }
}

/**
 * The thin facade the SwiftUI app calls. Every operation runs on a background dispatcher and reports back through a
 * plain callback on the main thread (no SKIE, no Swift concurrency bridging): `(result, error)` with exactly one non-null.
 * One instance per app; [close] stops everything.
 */
class SampleFacade internal constructor(private val callbacks: CoroutineDispatcher) {
    constructor() : this(Dispatchers.Main)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val tofu = MemoryTofuStore()
    private var server: SampleServer? = null
    private var echoConnection: QuicConnection? = null

    /** True once the library can follow the default network (k7/ios-lib); the echo screen enables its toggle then. */
    val followDefaultNetworkAvailable: Boolean get() = FOLLOW_DEFAULT_NETWORK_AVAILABLE

    /** HTTP/3 GET of an `https://` [url]. */
    fun http3Get(url: String, trust: TrustMode, onResult: (HttpResult?, String?) -> Unit): SampleTask =
        launchOp({ http3Get(url, trust, tofu) }, onResult)

    /**
     * A raw QUIC echo session against [host]:[port] (the in-app server of this or another phone). [onLog] gets one line
     * per round and per path event; [followNetwork] asks the connection to follow the default network where available.
     */
    fun quicEcho(
        host: String,
        port: Int,
        message: String,
        rounds: Int,
        intervalMs: Long,
        trust: TrustMode,
        followNetwork: Boolean,
        onLog: (String) -> Unit,
        onResult: (EchoResult?, String?) -> Unit,
    ): SampleTask {
        val log = logger(onLog)
        return launchOp({
            quicEcho(host, port, message, rounds, intervalMs, trust, tofu, log) { c ->
                echoConnection = c
                if (followNetwork) log(if (followDefaultNetwork(c, scope)) "following the default network" else "following the default network is not available in this build (k7/ios-lib)")
            }.also { echoConnection = null }
        }, onResult)
    }

    /** Moves the running echo session to a new socket (what an app does on a network change); no-op without one. */
    fun rebindEcho(onLog: (String) -> Unit) {
        val c = echoConnection ?: return onLog("no echo session")
        val log = logger(onLog)
        scope.launch { try { rebind(c, log) } catch (e: CancellationException) { throw e } catch (e: Exception) { log("rebind failed: ${e.message}") } }
    }

    /** Starts the server on `[::]:[port]` (0 picks one); [onResult] gets the bound port. */
    fun startServer(port: Int, onLog: (String) -> Unit, onResult: (Int?, String?) -> Unit): SampleTask =
        launchOp({ (server ?: SampleServer.start(port, scope, logger(onLog)).also { server = it }).port }, onResult)

    fun stopServer() { server?.close(); server = null }

    val serverPort: Int get() = server?.port ?: -1

    fun close() { stopServer(); scope.cancel() }

    private fun logger(onLog: (String) -> Unit): (String) -> Unit = { line -> scope.launch(callbacks) { onLog(line) } }

    private fun <T : Any> launchOp(block: suspend () -> T, onResult: (T?, String?) -> Unit): SampleTask = SampleTask(scope.launch {
        val outcome = try { Result.success(block()) } catch (e: CancellationException) { throw e } catch (e: Throwable) { Result.failure(e) }
        withContext(callbacks) { outcome.fold({ onResult(it, null) }, { onResult(null, describe(it)) }) }
    })

    private fun describe(e: Throwable): String = buildString {
        append(e::class.simpleName ?: "Error"); e.message?.let { append(": ").append(it) }
        e.cause?.let { c -> append(" (").append(c::class.simpleName).append(c.message?.let { ": $it" } ?: "").append(')') }
    }
}
