// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.frame

/** A decoded HTTP/2 frame (RFC 9113 section 6); padding is already removed and the reserved bits are ignored (section 4.1). */
internal sealed interface Frame {
    /** The stream the frame belongs to; 0 for the connection. */
    val streamId: Int

    /** DATA (section 6.1); [flowLength] is the whole payload with the padding, which counts toward flow control. */
    class Data(
        override val streamId: Int,
        val data: ByteArray,
        val endStream: Boolean,
        val flowLength: Int,
    ) : Frame

    /**
     * HEADERS (section 6.2). The RFC 7540 priority fields are parsed (a stream that depends on itself is a stream error,
     * RFC 7540 section 5.3.1, kept for interoperability) and otherwise ignored (RFC 9113 section 5.3.2); [dependency] is -1
     * without the PRIORITY flag.
     */
    class Headers(
        override val streamId: Int,
        val fragment: ByteArray,
        val endStream: Boolean,
        val endHeaders: Boolean,
        val dependency: Int = -1,
        /** The RFC 7540 exclusive bit and weight (1 to 256) of the PRIORITY flag; false and 16 without it. */
        val exclusive: Boolean = false,
        val weight: Int = 16,
    ) : Frame

    /** PRIORITY (section 6.3): deprecated signal, checked and ignored. */
    class Priority(
        override val streamId: Int,
        val dependency: Int,
    ) : Frame

    /** RST_STREAM (section 6.4); [errorCode] is the raw code (unknown codes stay as they came). */
    class RstStream(
        override val streamId: Int,
        val errorCode: Long,
    ) : Frame

    /** SETTINGS (section 6.5): [ids] and [values] in the order they came; empty for an acknowledgement. */
    class Settings(
        val ack: Boolean,
        val ids: IntArray,
        val values: LongArray,
    ) : Frame {
        override val streamId: Int get() = 0
    }

    /** PUSH_PROMISE (section 6.6). */
    class PushPromise(
        override val streamId: Int,
        val promisedStreamId: Int,
        val fragment: ByteArray,
        val endHeaders: Boolean,
    ) : Frame

    /** PING (section 6.7): the 8 opaque octets as one big-endian Long. */
    class Ping(
        val ack: Boolean,
        val payload: Long,
    ) : Frame {
        override val streamId: Int get() = 0
    }

    /** GOAWAY (section 6.8). */
    class GoAway(
        val lastStreamId: Int,
        val errorCode: Long,
        val debug: ByteArray,
    ) : Frame {
        override val streamId: Int get() = 0
    }

    /** WINDOW_UPDATE (section 6.9): [increment] is 31 bits, 0 included (the caller decides the error kind). */
    class WindowUpdate(
        override val streamId: Int,
        val increment: Int,
    ) : Frame

    /** CONTINUATION (section 6.10). */
    class Continuation(
        override val streamId: Int,
        val fragment: ByteArray,
        val endHeaders: Boolean,
    ) : Frame

    /**
     * PRIORITY_UPDATE (RFC 9218 section 7.1, type 0x10, always on stream 0): the client's new Priority Field Value
     * ([value], ASCII) for [prioritizedStreamId].
     */
    class PriorityUpdate(
        val prioritizedStreamId: Int,
        val value: String,
    ) : Frame {
        override val streamId: Int get() = 0
    }

    /** A frame of an unknown type (section 5.5): its payload was skipped without being buffered. */
    class Unknown(
        override val streamId: Int,
        val type: Int,
        val flags: Int,
        val length: Int,
    ) : Frame
}
