// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.quic.QlogRecorder

/**
 * The HTTP/3 events of a connection's qlog trace (docs/guide/http3.md, "qlog"), in the schema of the transport's trace:
 * qlog 0.3, draft-ietf-quic-qlog-main-schema-05, here draft-ietf-quic-qlog-h3-events-04 (docs/adr/0021-qlog-http3-events.md):
 * `http:parameters_set`, `http:parameters_restored`, `http:stream_type_set`, `http:frame_created`, `http:frame_parsed`,
 * `qpack:state_updated` and `qpack:stream_state_updated`.
 *
 * Member names are the draft's (section 4 and 5 for `http`, section 6 for `qpack`). PRIORITY_UPDATE (RFC 9218), which the
 * draft does not define, is a `priority_update` frame through its `$HTTPFrame` extension point (section 5.2), with the
 * members of the later drafts; WebTransport's stream signals are the draft's `unknown` frame (section 5.2.9) and stream
 * type (section 4.3) with their `frame_type_value` or `stream_type_value` and a `session_id` of their own (main-schema-05
 * section 3.4: tools allow unknown fields). Field values are redacted unless the sink opted in
 * ([QlogRecorder.logHeaderValues]; CWE-532).
 *
 * Every method formats on the caller's thread; callers check [enabled] first (or call through [H3Session.qlog]), so a
 * connection without a trace formats nothing. Never throws for any input: names and values are escaped here.
 */
internal class H3Qlog(
    private val recorder: QlogRecorder,
) {
    val enabled: Boolean get() = recorder.enabled
    private val values = recorder.logHeaderValues

    /** `http:parameters_set` for the SETTINGS [owner] ("local" or "remote") sent. */
    fun parametersSet(
        owner: String,
        settings: Map<Long, Long>,
    ) {
        recorder.record("http:parameters_set", "\"owner\":\"$owner\"" + parameters(settings))
    }

    /** `http:parameters_restored`: the server's SETTINGS a client remembered for 0-RTT (RFC 9114 section 7.2.4.2). */
    fun parametersRestored(settings: Map<Long, Long>) {
        recorder.record("http:parameters_restored", parameters(settings).removePrefix(","))
    }

    private fun parameters(m: Map<Long, Long>): String {
        val sb = StringBuilder()
        m[SettingsId.MAX_FIELD_SECTION_SIZE]?.let { sb.append(",\"max_field_section_size\":").append(it) }
        m[SettingsId.QPACK_MAX_TABLE_CAPACITY]?.let { sb.append(",\"max_table_capacity\":").append(it) }
        m[SettingsId.QPACK_BLOCKED_STREAMS]?.let { sb.append(",\"blocked_streams_count\":").append(it) }
        // section 4.1: "* text => uint64", additional settings for grease and extensions, here by their IANA names
        for ((id, v) in m) {
            if (id == SettingsId.MAX_FIELD_SECTION_SIZE || id == SettingsId.QPACK_MAX_TABLE_CAPACITY) continue
            if (id == SettingsId.QPACK_BLOCKED_STREAMS) continue
            sb
                .append(",\"")
                .append(SETTING_NAMES[id] ?: id.toString())
                .append("\":")
                .append(v)
        }
        return sb.toString()
    }

    /** `http:stream_type_set` for a unidirectional stream whose type [type] was sent or read. */
    fun streamTypeSet(
        owner: String,
        streamId: Long,
        type: Long,
        sessionId: Long? = null,
    ) {
        val sb = StringBuilder(96)
        sb
            .append("\"owner\":\"")
            .append(owner)
            .append("\",\"stream_id\":")
            .append(streamId)
            .append(",\"stream_type\":\"")
        val name =
            when {
                type == StreamType.CONTROL -> "control"
                type == StreamType.PUSH -> "push"
                type == StreamType.QPACK_ENCODER -> "qpack_encode"
                type == StreamType.QPACK_DECODER -> "qpack_decode"
                FrameType.isGrease(type) -> "reserved"
                else -> "unknown"
            }
        sb.append(name).append('"')
        // section 4.3: "only when stream_type === "unknown""
        if (name == "unknown") sb.append(",\"stream_type_value\":").append(type)
        if (sessionId != null) sb.append(",\"session_id\":").append(sessionId)
        recorder.record("http:stream_type_set", sb.toString())
    }

    /** `http:frame_created`: [frame] (a qlog HTTPFrame object) of [payloadLength] bytes, written on [streamId]. */
    fun frameCreated(
        streamId: Long,
        type: Long,
        payloadLength: Long,
        frame: String,
    ) = frame("http:frame_created", streamId, type, payloadLength, frame)

    /** `http:frame_parsed`: [frame] of [payloadLength] bytes (null: refused before its length was read), read on [streamId]. */
    fun frameParsed(
        streamId: Long,
        type: Long,
        payloadLength: Long?,
        frame: String,
    ) = frame("http:frame_parsed", streamId, type, payloadLength, frame)

    private fun frame(
        name: String,
        streamId: Long,
        type: Long,
        payloadLength: Long?,
        frame: String,
    ) {
        if (payloadLength == null) {
            recorder.record(name, "\"stream_id\":$streamId,\"frame\":$frame")
            return
        }
        val total = FrameHeaders.size(type, payloadLength) + payloadLength
        recorder.record(
            name,
            "\"stream_id\":$streamId,\"length\":$payloadLength,\"frame\":$frame," +
                "\"raw\":{\"length\":$total,\"payload_length\":$payloadLength}",
        )
    }

    /**
     * `qpack:state_updated` (draft-ietf-quic-qlog-h3-events-04): [owner] "local" is our encoder's dynamic table, "remote"
     * the peer's, which our decoder mirrors; [state] from [qpackState].
     */
    fun qpackStateUpdated(
        owner: String,
        state: String,
    ) {
        recorder.record("qpack:state_updated", "\"owner\":\"$owner\",$state")
    }

    /** `qpack:stream_state_updated`: a field section on [streamId] waits for (or got) the inserts it references (RFC 9204 section 2.1.2). */
    fun qpackStreamStateUpdated(
        streamId: Long,
        blocked: Boolean,
    ) {
        recorder.record("qpack:stream_state_updated", "\"stream_id\":$streamId,\"state\":\"${if (blocked) "blocked" else "unblocked"}\"")
    }

    /** A WebTransport stream's `WT_STREAM` signal, which has a Session ID where a frame has its length. */
    fun wtStreamSignal(
        name: String,
        streamId: Long,
        sessionId: Long,
    ) {
        recorder.record(
            name,
            "\"stream_id\":$streamId,\"frame\":{\"frame_type\":\"unknown\",\"frame_type_value\":${FrameType.WT_STREAM}," +
                "\"session_id\":$sessionId}",
        )
    }

    /** A HEADERS frame; [fields] in their order, values redacted unless the sink opted in. Empty: not decoded. */
    fun headers(fields: List<Pair<String, String>>): String {
        val sb = StringBuilder(32 + fields.size * 24)
        sb.append("{\"frame_type\":\"headers\",\"headers\":[")
        for ((i, f) in fields.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append("{\"name\":\"")
            escape(f.first, sb)
            sb.append("\",\"value\":\"")
            if (values || f.first in TOKEN_VALUES) escape(f.second, sb) else sb.append(REDACTED)
            sb.append("\"}")
        }
        return sb.append("]}").toString()
    }

    /** A frame of the control stream (or GREASE anywhere) from its type and payload; a payload that does not parse is described by its type alone. */
    fun controlFrame(
        type: Long,
        payload: ByteArray?,
    ): String =
        try {
            when (type) {
                FrameType.SETTINGS -> {
                    settings(if (payload == null) emptyMap() else SettingsCodec.decode(payload))
                }

                // the schema requires their identifier: one we did not read (or could not parse) is logged by its type number
                FrameType.GOAWAY -> {
                    if (payload == null) unread(type) else "{\"frame_type\":\"goaway\",\"id\":${ControlFrames.parseGoAway(payload)}}"
                }

                FrameType.MAX_PUSH_ID -> {
                    if (payload ==
                        null
                    ) {
                        unread(type)
                    } else {
                        "{\"frame_type\":\"max_push_id\",\"push_id\":${ControlFrames.parseMaxPushId(payload)}}"
                    }
                }

                FrameType.CANCEL_PUSH -> {
                    if (payload ==
                        null
                    ) {
                        unread(type)
                    } else {
                        "{\"frame_type\":\"cancel_push\",\"push_id\":${ControlFrames.parseMaxPushId(payload)}}"
                    }
                }

                // never read: we do not accept server push (RFC 9114 section 4.6)
                FrameType.PUSH_PROMISE -> {
                    unread(type)
                }

                FrameType.DATA -> {
                    DATA
                }

                FrameType.HEADERS -> {
                    "{\"frame_type\":\"headers\",\"headers\":[]}"
                }

                FrameType.PRIORITY_UPDATE_REQUEST, FrameType.PRIORITY_UPDATE_PUSH -> {
                    priorityUpdate(type, payload)
                }

                else -> {
                    other(type, payload?.size?.toLong())
                }
            }
        } catch (_: Exception) {
            // a malformed payload (the connection error that follows says why): the frame is logged by its type alone
            controlFrame(type, null)
        }

    /**
     * A frame we skipped unread: reserved (GREASE, h3-events-04 section 5.2.8: `length` only) or of a type we do not know
     * (section 5.2.9: `frame_type_value`; RFC 9114 section 9).
     */
    fun other(
        type: Long,
        length: Long?,
    ): String =
        if (FrameType.isGrease(type)) {
            if (length == null) "{\"frame_type\":\"reserved\"}" else "{\"frame_type\":\"reserved\",\"length\":$length}"
        } else {
            unread(type)
        }

    /** A frame whose payload was not read: section 5.2.9's `unknown` with its type number, as no other frame type allows that. */
    private fun unread(type: Long): String = "{\"frame_type\":\"unknown\",\"frame_type_value\":$type}"

    private fun priorityUpdate(
        type: Long,
        payload: ByteArray?,
    ): String {
        if (payload == null) return unread(type)
        val (id, value) = ControlFrames.parsePriorityUpdate(payload)
        val sb = StringBuilder(64)
        sb.append("{\"frame_type\":\"priority_update\"")
        sb.append(if (type == FrameType.PRIORITY_UPDATE_REQUEST) ",\"stream_id\":" else ",\"push_id\":").append(id)
        sb.append(",\"priority_field_value\":\"")
        escape(value, sb)
        return sb.append("\"}").toString()
    }

    private fun settings(m: Map<Long, Long>): String {
        val sb = StringBuilder(32 + m.size * 40)
        sb.append("{\"frame_type\":\"settings\",\"settings\":[")
        var first = true
        for ((id, v) in m) {
            if (!first) sb.append(',')
            first = false
            sb
                .append("{\"name\":\"")
                .append(SETTING_NAMES[id] ?: id.toString())
                .append("\",\"value\":")
                .append(v)
                .append('}')
        }
        return sb.append("]}").toString()
    }

    internal companion object {
        const val DATA: String = "{\"frame_type\":\"data\"}"

        /** The members of a `qpack:state_updated` event. */
        fun qpackState(
            capacity: Long,
            size: Long,
            knownReceived: Long,
            inserts: Long,
        ): String =
            "\"dynamic_table_capacity\":$capacity,\"dynamic_table_size\":$size,\"known_received_count\":$knownReceived," +
                "\"current_insert_count\":$inserts"

        /** What a redacted field value reads as. */
        const val REDACTED: String = "[redacted]"

        /**
         * Pseudo-header fields whose values are tokens the protocol defines (RFC 9114 section 4.3, RFC 9220 section 3), never
         * credentials: kept when values are redacted, so a trace still tells a GET from a POST and a 200 from a 403.
         */
        val TOKEN_VALUES: Set<String> = setOf(":method", ":scheme", ":status", ":protocol")

        /** The settings' names in their IANA registries (as quiche's qlog writes them); others go by their number. */
        val SETTING_NAMES: Map<Long, String> =
            mapOf(
                SettingsId.QPACK_MAX_TABLE_CAPACITY to "QPACK_MAX_TABLE_CAPACITY",
                SettingsId.MAX_FIELD_SECTION_SIZE to "MAX_FIELD_SECTION_SIZE",
                SettingsId.QPACK_BLOCKED_STREAMS to "QPACK_BLOCKED_STREAMS",
                SettingsId.ENABLE_CONNECT_PROTOCOL to "SETTINGS_ENABLE_CONNECT_PROTOCOL",
                SettingsId.H3_DATAGRAM to "H3_DATAGRAM",
                SettingsId.WT_ENABLED to "SETTINGS_WT_ENABLED",
                SettingsId.WT_MAX_SESSIONS_DRAFT14 to "SETTINGS_WT_MAX_SESSIONS",
                SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to "SETTINGS_ENABLE_WEBTRANSPORT",
                SettingsId.WT_INITIAL_MAX_STREAMS_UNI to "SETTINGS_WT_INITIAL_MAX_STREAMS_UNI",
                SettingsId.WT_INITIAL_MAX_STREAMS_BIDI to "SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI",
                SettingsId.WT_INITIAL_MAX_DATA to "SETTINGS_WT_INITIAL_MAX_DATA",
            )

        /** JSON string escaping (RFC 8259 section 7): quote, backslash and every control character; the rest as is. */
        fun escape(
            s: String,
            sb: StringBuilder,
        ) {
            for (ch in s) {
                when {
                    ch == '"' -> sb.append("\\\"")
                    ch == '\\' -> sb.append("\\\\")
                    ch < ' ' || ch == '\u007f' || ch.isSurrogate() -> sb.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
                    else -> sb.append(ch)
                }
            }
        }
    }
}

/** Runs [block] with the session's qlog when its connection is traced; nothing is formatted otherwise. */
internal inline fun H3Session.qlog(block: (H3Qlog) -> Unit) {
    val q = qlog ?: return
    if (q.enabled) block(q)
}
