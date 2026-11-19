// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.sockets.Socket
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * `SO_SNDBUF` of [writer] plus `SO_RCVBUF` of [reader] (a TLS socket: its TCP socket's), as the system reports them now:
 * about what a connection whose reader reads nothing holds before its writer has to wait.
 */
internal expect fun kernelBufferBytes(
    writer: Socket,
    reader: Socket,
): Long

/** How long the writer must have been waiting inside one write before the connection counts as full. */
internal val STUCK_IN_WRITE: Duration = 300.milliseconds

/**
 * How long a writer waiting inside one write counts as stuck on a full connection without the byte count: the sizes the
 * system reports can exceed what a connection holds (Linux reports twice what it was set to, bookkeeping included).
 */
internal val STUCK_LONG: Duration = 5.seconds

/**
 * Writes 64 KiB chunks, each flushed, to [out] until the connection is full, and returns the writer, still writing (it
 * ends with the failure of its write, null never). Full means: the writer has been waiting inside one write for
 * [STUCK_IN_WRITE] and at least [kernelBytes] (the system's buffers of both ends, read once it waits, as autotuning may
 * have grown them) went out; or it has been waiting inside one write for [STUCK_LONG]. A writer that only paused between
 * writes, or whose bytes were not all taken yet (a loaded host), is never taken for a full connection, as "no chunk for
 * 300 ms" alone took it.
 */
internal suspend fun CoroutineScope.fillUntilStuck(
    out: ByteWriteChannel,
    fill: Byte = 0,
    kernelBytes: () -> Long,
): Deferred<Throwable?> {
    val written = AtomicLong(0)
    val inWriteSince = AtomicReference<TimeSource.Monotonic.ValueTimeMark?>(null)
    val progress = Channel<Unit>(Channel.CONFLATED)
    val writer =
        async {
            runCatching {
                val chunk = ByteArray(64 * 1024) { fill }
                while (true) {
                    inWriteSince.store(TimeSource.Monotonic.markNow())
                    out.writeFully(chunk)
                    out.flush()
                    inWriteSince.store(null)
                    written.addAndFetch(chunk.size.toLong())
                    progress.trySend(Unit)
                }
            }.exceptionOrNull()
        }
    while (true) {
        if (withTimeoutOrNull(STUCK_IN_WRITE) { progress.receive() } != null) continue
        val waiting = inWriteSince.load()?.elapsedNow() ?: continue
        if (waiting >= STUCK_LONG || (waiting >= STUCK_IN_WRITE && written.load() >= kernelBytes())) return writer
    }
}
