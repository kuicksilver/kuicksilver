// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PathFailureReason
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicPath
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A [QuicPath] of the coroutine runtime: a socket ([io], null for the endpoint's own) and the core path it feeds. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class PathRuntime(
    private val conn: ConnectionRuntime,
    private val loop: EndpointLoop,
    override val id: PathId,
    override val localAddress: InetSocketAddress,
    internal val io: DatagramIo?,
) : QuicPath {
    internal val stateFlow = MutableStateFlow(conn.core.pathState(id))
    override val state: StateFlow<PathState> get() = stateFlow
    override val remoteAddress: InetSocketAddress get() = conn.core.remoteAddress

    /** Completed by the next PathValidated / PathFailed event for this path. */
    internal var validation = CompletableDeferred<Boolean>()

    /** Why the last validation failed (set with the PathFailed event); null while none did. Loop dispatcher only. */
    internal var failureReason: PathFailureReason? = null

    /** The receive coroutine of [io]; null for the endpoint's own socket. */
    internal var receiver: Job? = null

    override suspend fun probe(): Boolean {
        val d =
            withContext(loop.dispatcher) {
                if (validation.isCompleted) validation = CompletableDeferred()
                failureReason = null
                stateFlow.value =
                    PathState.Validating
                conn.core.probePath(id, loop.now())
                loop.flush(conn.core)
                validation
            } // a validated path is re-validated
        return d.await()
    }

    override suspend fun switchTo() {
        withContext(loop.dispatcher) {
            conn.core.switchPath(id, loop.now())
            loop.flush(conn.core)
        }
    }

    /**
     * IllegalStateException on the active path. Otherwise the loop closes the path: it checks again there (a migration may
     * have made it active meanwhile, then nothing happens) before it touches the socket.
     */
    override fun close() {
        if (stateFlow.value == PathState.Closed) return
        check(id != conn.activePathId) { "the active path cannot be closed" }
        loop.scope.launch { if (conn.core.path.id != id) conn.closePath(this@PathRuntime) }
    }

    override fun toString(): String = "QuicPath(${id.value}, $localAddress -> $remoteAddress, ${stateFlow.value})"
}
