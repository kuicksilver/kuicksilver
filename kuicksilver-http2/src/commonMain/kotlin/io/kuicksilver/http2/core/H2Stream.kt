// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

/** Stream states of RFC 9113 section 5.1 (the reserved states are not kept: we never push and refuse pushes). */
internal enum class StreamState { OPEN, HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSED }

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
    /** Frames of this stream waiting for [H2ConnectionCore.poll], in order (field blocks and at most one DATA frame). */
    val out = ArrayDeque<ByteArray>()

    /** The head of [out] is a field block (scheduled before DATA). */
    val outHeads = ArrayDeque<Boolean>()

    /** A DATA frame of this stream is queued: [H2ConnectionCore.sendData] accepts no more until it is written. */
    var dataQueued = false

    /** [H2ConnectionCore.sendData] accepted less than offered: report [H2Event.WindowAvailable] when it can take more. */
    var wantsWindow = false

    /** Receive side: a final (non-1xx) field section arrived, so DATA and trailers may follow (section 8.1). */
    var finalHeadersReceived = false

    /** Receive side: the decoded size of the interim (1xx) field sections so far (RFC 9110 section 15.2: any number of them). */
    var interimBytes = 0L

    /** Send side: the first field section went out. */
    var headersSent = false

    /** The driver said the stream's handler has finished ([H2ConnectionCore.release]). */
    var released = false
}
