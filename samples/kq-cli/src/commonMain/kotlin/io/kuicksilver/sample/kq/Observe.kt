// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.sample.kq

import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.ZeroRttOutcome
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Duration
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/** What kq learned about one QUIC connection from its [ConnectionListener] callbacks. */
data class QuicFacts(
    val opened: TimeMark,
    val handshake: Duration? = null,
    val alpn: String? = null,
    val zeroRtt: ZeroRttOutcome? = null,
)

/**
 * Hears every QUIC connection of the engine (`http3 { connectionListener }`) and keeps, by connection ID, when it opened,
 * how long its handshake took, the ALPN it agreed and what became of 0-RTT. The callbacks run on the endpoint loops, so the
 * map is replaced atomically, never locked; kq joins it with `QuicConnectionSnapshot.connectionId` of each response.
 */
class QuicObserver : ConnectionListener {
    private val facts = AtomicReference(emptyMap<String, QuicFacts>())

    operator fun get(id: String): QuicFacts? = facts.load()[id]

    private fun update(
        id: String,
        f: (QuicFacts?) -> QuicFacts?,
    ) {
        while (true) {
            val now = facts.load()
            val next = f(now[id]) ?: return
            if (facts.compareAndSet(now, now + (id to next))) return
        }
    }

    override fun onOpened(connection: ConnectionInfo) = update(connection.id) { QuicFacts(TimeSource.Monotonic.markNow()) }

    override fun onHandshakeCompleted(connection: ConnectionInfo) =
        update(connection.id) { it?.copy(handshake = it.opened.elapsedNow(), alpn = connection.connection.negotiatedAlpn) }

    override fun onZeroRtt(
        connection: ConnectionInfo,
        outcome: ZeroRttOutcome,
    ) = update(connection.id) { it?.copy(zeroRtt = outcome) }
}

/**
 * Counts the qlog traces the endpoints have open in [delegate] (an `AsyncQlogSink`), so kq can wait until the endpoints
 * closed every trace before it flushes the sink and exits: the engine closes its QUIC endpoints in the background after
 * `HttpClient.close()`, and a trace ends when its connection is released. The counter sits in front of the asynchronous
 * sink, so it counts what the endpoints did, not what the writer got to.
 */
class CountingQlogSink(
    private val delegate: QlogSink,
) : QlogSink {
    private val open = MutableStateFlow(0)

    override val logHeaderValues: Boolean get() = delegate.logHeaderValues

    override fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace? {
        val t = delegate.open(odcidHex, role) ?: return null
        open.update { it + 1 }
        return object : QlogTrace {
            private val closed = AtomicBoolean(false)

            override fun write(record: String) = t.write(record)

            override fun close() {
                if (closed.compareAndSet(false, true)) {
                    try {
                        t.close()
                    } finally {
                        open.update { it - 1 }
                    }
                }
            }
        }
    }

    /** Waits until no trace is open, at most [timeout]; false when one still is (read after the wait, not from its result). */
    suspend fun awaitAllClosed(timeout: Duration): Boolean {
        withTimeoutOrNull(timeout) { open.first { it == 0 } }
        return open.value == 0
    }
}
