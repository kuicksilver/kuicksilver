// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic.qlog

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.tls.PrivateFileWriter
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.checkPrivateDirectory
import io.kuicksilver.tls.createPrivateFile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.random.Random

/**
 * One `<odcid>_<client|server>_<random>.sqlog` file per connection inside [directory] (docs/guide/quic.md, "qlog").
 *
 * On a server the original destination connection ID is chosen by the client, so the file handling assumes a hostile name
 * (threat model 3.2): the directory is created owner-only when missing and refused (the trace is not opened, an exception the
 * endpoint logs) when it is a symbolic link, not a directory, owned by another user, or writable by group or others without
 * the sticky bit; each file is created exclusively and never through a link (an existing name, a planted symlink or FIFO, is
 * never truncated, followed or blocked on), with a random suffix so a client reusing another connection's ID gets a file of
 * its own. Two ceilings bound what a flood of connections can write through this sink: at most [maxOpenTraces] traces open
 * at once (further connections are not traced), and at most [maxTotalBytes] written over the sink's lifetime (after that, no
 * new trace opens and open ones stop writing). A fixed 64 MiB per connection still bounds each trace. Files are opened and
 * written on the endpoint loop, so a slow disk stalls every connection of that loop: on a busy server wrap the sink in
 * [AsyncQlogSink].
 *
 * @param directory where the traces go; created when missing.
 * @property maxOpenTraces traces open at the same time; at least 1 (default 256).
 * @property maxTotalBytes bytes written by all traces of this sink together; at least 1 (default 1 GiB).
 */
public class DirectoryQlogSink
    @ExperimentalKuicksilverApi
    constructor(
        private val directory: String,
        public val maxOpenTraces: Int,
        public val maxTotalBytes: Long,
    ) : QlogSink {
        /** A sink with the default ceilings: 256 open traces, 1 GiB over its lifetime. */
        @OptIn(ExperimentalKuicksilverApi::class)
        public constructor(directory: String) : this(directory, DEFAULT_MAX_OPEN_TRACES, DEFAULT_MAX_TOTAL_BYTES)

        init {
            require(maxOpenTraces >= 1) { "maxOpenTraces must be positive" }
            require(maxTotalBytes >= 1) { "maxTotalBytes must be positive" }
        }

        private val openTraces = AtomicInt(0)
        private val written = AtomicLong(0)

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace? {
            // the name comes from the peer on a server: only the hex the endpoint formats is accepted, never a path
            require(odcidHex.length in 1..40 && odcidHex.all { it in '0'..'9' || it in 'a'..'f' }) { "not a connection ID in hex" }
            if (written.load() >= maxTotalBytes) return null
            if (!reserveSlot()) return null
            val file: PrivateFileWriter
            try {
                checkPrivateDirectory(directory)
                val base = "${odcidHex}_${role.name.lowercase()}"
                // a taken name (another trace, or one planted for us) is skipped, never reused; a second clash gives up
                file = createPrivateFile(directory, "${base}_${suffix()}.sqlog")
                    ?: createPrivateFile(directory, "${base}_${suffix()}.sqlog")
                    ?: return null.also { openTraces.decrementAndFetch() }
            } catch (t: Throwable) {
                openTraces.decrementAndFetch()
                throw t
            }
            return Trace(file)
        }

        private fun reserveSlot(): Boolean {
            while (true) {
                val n = openTraces.load()
                if (n >= maxOpenTraces) return false
                if (openTraces.compareAndSet(n, n + 1)) return true
            }
        }

        private fun suffix(): String =
            Random
                .nextLong()
                .toULong()
                .toString(16)
                .padStart(16, '0')

        private inner class Trace(
            private val file: PrivateFileWriter,
        ) : QlogTrace {
            private var open = true

            override fun write(record: String) {
                if (!open) return
                val bytes = record.encodeToByteArray()
                if (written.addAndFetch(bytes.size.toLong()) > maxTotalBytes) {
                    close() // the sink's lifetime budget is spent: this trace ends here
                    return
                }
                file.write(bytes)
            }

            override fun close() {
                if (open) {
                    open = false
                    openTraces.decrementAndFetch()
                    file.close()
                }
            }
        }

        private companion object {
            const val DEFAULT_MAX_OPEN_TRACES = 256
            const val DEFAULT_MAX_TOTAL_BYTES = 1L shl 30
        }
    }
