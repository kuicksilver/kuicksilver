// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.frame

/** Frame types (RFC 9113 section 6) and flags. */
internal object FrameType {
    const val DATA: Int = 0x0
    const val HEADERS: Int = 0x1
    const val PRIORITY: Int = 0x2
    const val RST_STREAM: Int = 0x3
    const val SETTINGS: Int = 0x4
    const val PUSH_PROMISE: Int = 0x5
    const val PING: Int = 0x6
    const val GOAWAY: Int = 0x7
    const val WINDOW_UPDATE: Int = 0x8
    const val CONTINUATION: Int = 0x9

    /** RFC 9218 section 7.1: a client's new priority for a request; on stream 0 only. */
    const val PRIORITY_UPDATE: Int = 0x10
}

/** Frame flags (RFC 9113 section 6); a flag without meaning for a type is ignored on receipt and never set (section 4.1). */
internal object FrameFlags {
    const val END_STREAM: Int = 0x1
    const val ACK: Int = 0x1
    const val END_HEADERS: Int = 0x4
    const val PADDED: Int = 0x8
    const val PRIORITY: Int = 0x20
}

/** SETTINGS parameters (RFC 9113 section 6.5.2; RFC 8441 section 3; RFC 9218 section 2.1). */
internal object SettingId {
    const val HEADER_TABLE_SIZE: Int = 0x1
    const val ENABLE_PUSH: Int = 0x2
    const val MAX_CONCURRENT_STREAMS: Int = 0x3
    const val INITIAL_WINDOW_SIZE: Int = 0x4
    const val MAX_FRAME_SIZE: Int = 0x5
    const val MAX_HEADER_LIST_SIZE: Int = 0x6
    const val ENABLE_CONNECT_PROTOCOL: Int = 0x8
    const val NO_RFC7540_PRIORITIES: Int = 0x9
}

/** Protocol constants of RFC 9113. */
internal object H2 {
    const val FRAME_HEADER_SIZE: Int = 9

    /** SETTINGS_MAX_FRAME_SIZE: initial value and lower bound (section 6.5.2). */
    const val MIN_MAX_FRAME_SIZE: Int = 16_384

    /** SETTINGS_MAX_FRAME_SIZE: upper bound, 2^24 - 1 (section 6.5.2). */
    const val MAX_MAX_FRAME_SIZE: Int = 16_777_215

    /** The largest flow-control window, 2^31 - 1 (section 6.9.1). */
    const val MAX_WINDOW: Long = 2_147_483_647

    /** The initial window of every stream and of the connection (section 6.9.2). */
    const val DEFAULT_WINDOW: Int = 65_535

    /** The initial SETTINGS_HEADER_TABLE_SIZE (section 6.5.2). */
    const val DEFAULT_HEADER_TABLE_SIZE: Int = 4_096

    /** The highest stream identifier, 2^31 - 1 (section 5.1.1). */
    const val MAX_STREAM_ID: Int = Int.MAX_VALUE

    /** The client connection preface (section 3.4): "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n". */
    val PREFACE: ByteArray = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".encodeToByteArray()
}
