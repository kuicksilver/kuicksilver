// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

/** Stream states of RFC 9113 section 5.1 (the reserved states are not kept: we never push and refuse pushes). */
internal enum class StreamState { OPEN, HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSED }

/** Something a stream has to send, in order: a field list (HPACK-encoded only when it is written) or an encoded DATA frame. */
internal sealed interface OutItem {
    class Fields(
        val fields: List<Pair<String, String>>,
        val endStream: Boolean,
    ) : OutItem

    class Data(
        val frame: ByteArray,
    ) : OutItem
}

/** One stream of an [H2ConnectionCore]. */
internal class H2Stream(
    val id: Int,
    /** Opened by us. */
    val local: Boolean,
    var state: StreamState,
    /** The peer's window for our DATA (may go negative after a SETTINGS change, section 6.9.2). */
    var sendWindow: Long,
    val recv: RecvWindow,
) {
    /** What waits for [H2ConnectionCore.poll]: field lists and at most one DATA frame. */
    val out = ArrayDeque<OutItem>()

    /** In one of the core's ready queues. */
    var scheduled = false

    /** A DATA frame of this stream is queued: [H2ConnectionCore.sendData] accepts no more until it is written. */
    var dataQueued = false

    /** [H2ConnectionCore.sendData] accepted less than offered: report [H2Event.WindowAvailable] when it can take more. */
    var wantsWindow = false

    /** Stream credit (WINDOW_UPDATE increment) waiting to be written; dropped when the stream closes (section 6.4). */
    var pendingCredit = 0L

    /** Delivered content the application has not consumed yet: credited to the connection when the stream is dropped. */
    var unconsumed = 0L

    /** Receive side: a final (non-1xx) field section arrived, so DATA and trailers may follow (section 8.1). */
    var finalHeadersReceived = false

    /** Receive side: the decoded size of the interim (1xx) field sections so far (RFC 9110 section 15.2: any number of them). */
    var interimBytes = 0L

    /** Send side: the first field section was written (its HPACK encoding is on the wire): the stream is no longer idle to the peer. */
    var headersSent = false

    /** The driver said it is done with the stream ([H2ConnectionCore.release]). */
    var released = false
}
