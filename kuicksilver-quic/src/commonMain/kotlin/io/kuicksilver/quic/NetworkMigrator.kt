// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
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
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

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
 * - If [networks] throws, [MigrationEvent.SourceFailed] is the last event and the migrator stops; the exception never reaches
 *   [scope]. When [networks] completes, the migrator stops too.
 * - Repeated equal values are ignored. A change while a migration runs supersedes it: the unfinished path and its socket are
 *   closed and nothing is reported for it.
 *
 * The migrator stops when [close] is called, when [scope] is cancelled or when the connection ends (a migration cut short by
 * the end of the connection reports nothing: no [MigrationEvent.Failed] for a dead connection). Server connections are
 * rejected with IllegalArgumentException: only the client migrates (RFC 9000 section 9).
 *
 * @param N the platform's network handle (`android.net.Network` on Android); compared with `equals`.
 * @param openIo opens a socket on a network. It is not cancelled midway (a superseded or closed migration closes the socket
 *   it returns), so it should not wait long.
 * @param scope where [start] runs the migrator.
 */
@OptIn(ExperimentalAtomicApi::class)
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

    /** Test hook: runs after a successful probe, right before the switch. */
    internal var beforeSwitch: () -> Unit = {}

    private val job = AtomicReference<Job?>(null)
    private val closedFlag = AtomicBoolean(false)
    private val closed get() = closedFlag.load()

    /**
     * Starts following [networks] in the scope; once only (IllegalStateException on a second call, also from another thread).
     * The job ends with [close]; after [close] it ends at once. Thread-safe.
     */
    public fun start(): Job {
        val j = scope.launch(start = CoroutineStart.LAZY) { run() }
        if (!job.compareAndSet(null, j)) {
            j.cancel()
            throw IllegalStateException("already started")
        }
        if (closed) j.cancel() // close() ran before the job was published: it never runs
        j.start()
        return j
    }

    /**
     * Stops following the networks. A migration that has not switched yet is abandoned: its new path and socket are closed,
     * nothing is reported, and the connection stays on the path it was on. A switch already under way completes (the
     * connection is on the new network then) and still reports [MigrationEvent.Migrated]. The connection stays open.
     * Thread-safe, also against a concurrent [start].
     */
    override fun close() {
        closedFlag.store(true)
        job.load()?.cancel()
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
        var path: QuicPath? = null // the path of the last migration; only a fallback for when the connection has no active path
        var failure: Throwable? = null
        // a failing source (Android: registerDefaultNetworkCallback throws TooManyRequestsException) ends the migrator, never the caller's scope
        networks.catch { failure = it }.distinctUntilChanged().collectLatest { n ->
            val current = onNetwork.value
            when {
                n == null -> {
                    eventFlow.tryEmit(MigrationEvent.NetworkLost)
                }

                current == null -> {
                    onNetwork.value = n
                }

                n != current -> {
                    // the path the connection is on now: the core may have fallen back (or the peer moved) since the last migration
                    val from = connection.activePath ?: path
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
        failure?.let { eventFlow.tryEmit(MigrationEvent.SourceFailed(it)) }
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
                fail(n, IllegalStateException("path validation failed"))
                return
            }
            beforeSwitch()
            val self = currentCoroutineContext().job
            withContext(NonCancellable) {
                // the last point of no return: a migrator closed (or a migration superseded) by now does not switch
                if (closed || !self.isActive) return@withContext
                path.switchTo()
                done = true
                switched(path)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            fail(n, e)
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

    /** Reports a failed migration, unless the connection is gone: a dead connection has nothing left to migrate, the watcher ends the migrator. */
    private fun fail(
        n: N,
        cause: Exception,
    ) {
        if (cause is QuicException.ConnectionLost || connection.closed.isCompleted) return
        eventFlow.tryEmit(MigrationEvent.Failed(n, cause))
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

    /**
     * The network source failed with [cause] (on Android, for example, the system refused another network callback); the
     * migrator has stopped, its job completed normally, and the connection stays where it is. The last event.
     */
    public class SourceFailed(
        /** What the source threw. */
        public val cause: Throwable,
    ) : MigrationEvent<Nothing> {
        /** For logs. */
        override fun toString(): String = "SourceFailed($cause)"
    }
}
