// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.tls.TlsRole
import kotlinx.io.Sink
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.writeString

/**
 * One `<odcid>_<client|server>.sqlog` file per connection inside [directory] (created when missing).
 *
 * The file is opened and written on the endpoint loop, so a slow disk stalls every connection of that loop: on a busy
 * server wrap it in [AsyncQlogSink]. A server's file name is the original destination connection ID the client chose, so
 * two connections (or a client that repeats an ID on purpose) can name the same file, and the later one replaces it; keep
 * traces of untrusted clients in a directory of their own, or sample them with [AsyncQlogSink].
 */
public class DirectoryQlogSink(
    private val directory: String,
) : QlogSink {
    override fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace? {
        val dir = Path(directory)
        if (!SystemFileSystem.exists(dir)) SystemFileSystem.createDirectories(dir)
        val sink: Sink = SystemFileSystem.sink(Path(dir, "${odcidHex}_${role.name.lowercase()}.sqlog")).buffered()
        return object : QlogTrace {
            private var open = true

            override fun write(record: String) {
                if (open) sink.writeString(record)
            }

            override fun close() {
                if (open) {
                    open = false
                    sink.close()
                }
            }
        }
    }
}
