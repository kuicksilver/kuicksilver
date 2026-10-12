// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Keeps a client [connection] on the current network: whenever [networks] reports a different network, it opens a socket on it
 * through [openIo] and migrates the connection there (RFC 9000 section 9), then closes the path it left.
 *
 * - The first non-null value is the network the connection is on already: nothing happens.
 * - A different value opens `openIo(network)` and migrates ([QuicConnection.addPath], [QuicPath.probe], [QuicPath.switchTo]).
 *   On success the previous path is closed (its socket too, unless it is the endpoint's own) and [MigrationEvent.Migrated]
 *   follows. On failure (the new network never answers, [openIo] throws, the server sent `disable_active_migration`) the new
 *   path and its socket are closed, the connection stays where it was and [MigrationEvent.Failed] follows.
 * - `null` (no network) emits [MigrationEvent.NetworkLost] and waits: the next network is migrated to, unless it is the one the
 *   connection is still on. Like Chromium's QUIC session pool, the connection is not closed on a network loss; its idle timeout
 *   decides if no network comes back.
 * - Repeated equal values are ignored. A change while a migration runs supersedes it: the unfinished path and its socket are
 *   closed and nothing is reported for it.
 *
 * The migrator stops when [close] is called, when [scope] is cancelled or when the connection ends. Server connections are
 * rejected with IllegalArgumentException: only the client migrates (RFC 9000 section 9).
 *
 * @param N the platform's network handle (`android.net.Network` on Android); compared with `equals`.
 * @param openIo opens a socket on a network. It is not cancelled midway (a superseded or closed migration closes the socket
 *   it returns), so it should not wait long.
 * @param scope where [start] runs the migrator.
 */
@ExperimentalKuicksilverApi
public class NetworkMigrator<N : Any>(
    private val connection: QuicConnection,
    private val networks: Flow<N?>,
    private val openIo: suspend (N) -> DatagramIo,
    private val scope: CoroutineScope,
) : AutoCloseable {
    init {
        require(connection.core.role == TlsRole.Client) { "only a client migrates (RFC 9000 section 9)" }
    }

    private val eventFlow = MutableSharedFlow<MigrationEvent<N>>(extraBufferCapacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    /** What the migrator did, in order. A hot flow without replay (the oldest of 64 unread events are dropped): collect it before [start]. */
    public val events: Flow<MigrationEvent<N>> = eventFlow.asSharedFlow()

    private val onNetwork = MutableStateFlow<N?>(null)

    /**
     * The network the connection is on as far as the migrator knows: null until [networks] reported its first network, then
     * that one, then each network a migration succeeded to. A failed migration and a lost network leave it unchanged.
     */
    public val network: StateFlow<N?> = onNetwork.asStateFlow()

    private var job: Job? = null
    private var closed = false

    /** Starts following [networks] in the scope; once only (IllegalStateException on a second call). The job ends with [close]. */
    public fun start(): Job {
        check(job == null) { "already started" }
        val j = scope.launch { if (!closed) run() }
        job = j
        return j
    }

    /** Stops following the networks; a migration in progress is abandoned and its socket closed. The connection stays open. */
    override fun close() {
        closed = true
        job?.cancel()
    }

    private suspend fun run() =
        coroutineScope {
            val self = coroutineContext
            val watcher =
                launch {
                    connection.closed.await()
                    self.cancel() // nothing left to migrate
                }
            try {
                follow()
            } finally {
                watcher.cancel()
            }
        }

    private suspend fun follow() {
        var path: QuicPath? = null // and its path; null until the first migration (then the path the connection started on is active)
        networks.distinctUntilChanged().collectLatest { n ->
            val current = onNetwork.value
            when {
                n == null -> {
                    eventFlow.tryEmit(MigrationEvent.NetworkLost)
                }

                current == null -> {
                    onNetwork.value = n
                }

                n != current -> {
                    val from = path ?: connection.activePath
                    migrateTo(n) { p ->
                        // runs once the connection switched, even if this migration is being superseded right now
                        onNetwork.value = n
                        path = p
                        try {
                            from?.takeIf { it.id != p.id }?.close()
                        } catch (_: IllegalStateException) {
                            // the peer's own move made it active again: it stays
                        }
                        eventFlow.tryEmit(MigrationEvent.Migrated(current, n, p))
                    }
                }
            }
        }
    }

    /**
     * Migrates to [n] and calls [switched] with the new, active path; a failure is reported and changes nothing. The steps that
     * hand resources over (openIo, addPath, switchTo) are not cancelled midway, so a cancellation never loses a socket or a
     * path: whatever it opened and did not switch to is closed.
     */
    private suspend fun migrateTo(
        n: N,
        switched: (QuicPath) -> Unit,
    ) {
        var p: QuicPath? = null
        var done = false
        try {
            // not cancelled midway: a socket opened by a cancelled openIo (withContext drops its result) would leak
            val io = withContext(NonCancellable) { openIo(n) }
            if (!currentCoroutineContext().isActive) {
                io.close() // superseded or closed while the socket was being opened
                currentCoroutineContext().ensureActive()
            }
            // addPath owns io from here and closes it on any failure of its own
            withContext(NonCancellable) { p = connection.addPath(io) }
            val path = p!!
            if (!path.probe()) {
                eventFlow.tryEmit(MigrationEvent.Failed(n, IllegalStateException("path validation failed")))
                return
            }
            withContext(NonCancellable) {
                path.switchTo()
                done = true
                switched(path)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: QuicException.ConnectionLost) {
            throw CancellationException("connection lost", e)
        } catch (e: Exception) {
            eventFlow.tryEmit(MigrationEvent.Failed(n, e))
        } finally {
            if (!done) {
                try {
                    p?.close()
                } catch (_: IllegalStateException) {
                    // became active through the peer: the connection owns it now
                }
            }
        }
    }
}

/** What a [NetworkMigrator] did. */
@ExperimentalKuicksilverApi
public sealed interface MigrationEvent<out N> {
    /** The connection moved from network [old] to network [new] and sends on [path] now; the old path was closed. */
    public class Migrated<out N>(
        /** The network the connection left. */
        public val old: N,
        /** The network the connection is on now. */
        public val new: N,
        /** The validated path on [new] the connection switched to. */
        public val path: QuicPath,
    ) : MigrationEvent<N> {
        /** For logs. */
        override fun toString(): String = "Migrated($old -> $new, $path)"
    }

    /** Migrating to [network] failed with [cause]; the connection stays on its previous path and the new socket is closed. */
    public class Failed<out N>(
        /** The network that could not be used. */
        public val network: N,
        /** Why: path validation failed (IllegalStateException), the peer disabled migration, or opening the socket threw. */
        public val cause: Throwable,
    ) : MigrationEvent<N> {
        /** For logs. */
        override fun toString(): String = "Failed($network, $cause)"
    }

    /** The source reported no network; the migrator waits for the next one and leaves the connection as it is. */
    public data object NetworkLost : MigrationEvent<Nothing>
}
