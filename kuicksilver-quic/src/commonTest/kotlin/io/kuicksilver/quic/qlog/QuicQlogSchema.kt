// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

// A copy of kuicksilver-http3's test parser (the two test source sets share no code).

/**
 * A strict JSON parser (RFC 8259) for the tests: objects become maps (a repeated name is an error), arrays lists,
 * numbers doubles, and anything outside the grammar (a trailing comma, an unescaped control character, a lone value
 * after the end) throws [IllegalArgumentException].
 */
internal class StrictJson private constructor(
    private val s: String,
) {
    private var i = 0

    companion object {
        fun parse(text: String): Any? {
            val p = StrictJson(text)
            p.ws()
            val v = p.value()
            p.ws()
            require(p.i == text.length) { "trailing data at ${p.i}" }
            return v
        }
    }

    private fun ws() {
        while (i < s.length && s[i] in " \t\r\n") i++
    }

    private fun value(): Any? {
        require(i < s.length) { "unexpected end" }
        return when (val c = s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> lit("true", true)
            'f' -> lit("false", false)
            'n' -> lit("null", null)
            else -> if (c == '-' || c in '0'..'9') num() else throw IllegalArgumentException("unexpected '$c' at $i")
        }
    }

    private fun lit(
        word: String,
        v: Any?,
    ): Any? {
        require(s.startsWith(word, i)) { "bad literal at $i" }
        i += word.length
        return v
    }

    private fun obj(): Map<String, Any?> {
        i++
        val m = LinkedHashMap<String, Any?>()
        ws()
        if (s.getOrNull(i) == '}') {
            i++
            return m
        }
        while (true) {
            ws()
            require(s.getOrNull(i) == '"') { "object key expected at $i" }
            val k = str()
            require(k !in m) { "duplicate key '$k'" }
            ws()
            require(s.getOrNull(i) == ':') { "':' expected at $i" }
            i++
            ws()
            m[k] = value()
            ws()
            when (s.getOrNull(i)) {
                ',' -> {
                    i++
                }

                '}' -> {
                    i++
                    return m
                }

                else -> {
                    throw IllegalArgumentException("',' or '}' expected at $i")
                }
            }
        }
    }

    private fun arr(): List<Any?> {
        i++
        val l = ArrayList<Any?>()
        ws()
        if (s.getOrNull(i) == ']') {
            i++
            return l
        }
        while (true) {
            ws()
            l += value()
            ws()
            when (s.getOrNull(i)) {
                ',' -> {
                    i++
                }

                ']' -> {
                    i++
                    return l
                }

                else -> {
                    throw IllegalArgumentException("',' or ']' expected at $i")
                }
            }
        }
    }

    private fun str(): String {
        i++
        val sb = StringBuilder()
        while (true) {
            require(i < s.length) { "unterminated string" }
            val c = s[i++]
            when {
                c == '"' -> {
                    return sb.toString()
                }

                c == '\\' -> {
                    when (val e = s[i++]) {
                        '"', '\\', '/' -> {
                            sb.append(e)
                        }

                        'b' -> {
                            sb.append('\b')
                        }

                        'f' -> {
                            sb.append('\u000c')
                        }

                        'n' -> {
                            sb.append('\n')
                        }

                        'r' -> {
                            sb.append('\r')
                        }

                        't' -> {
                            sb.append('\t')
                        }

                        'u' -> {
                            sb.append(s.substring(i, i + 4).toInt(16).toChar())
                            i += 4
                        }

                        else -> {
                            throw IllegalArgumentException("bad escape \\$e")
                        }
                    }
                }

                c < ' ' -> {
                    throw IllegalArgumentException("raw control character in a string at $i")
                }

                else -> {
                    sb.append(c)
                }
            }
        }
    }

    private fun num(): Double {
        val start = i
        if (s[i] == '-') i++
        require(i < s.length && s[i] in '0'..'9') { "digit expected at $i" }
        if (s[i] == '0') i++ else while (i < s.length && s[i] in '0'..'9') i++
        if (s.getOrNull(i) == '.') {
            i++
            require(s.getOrNull(i)?.let { it in '0'..'9' } == true) { "fraction digits expected at $i" }
            while (i < s.length && s[i] in '0'..'9') i++
        }
        if (s.getOrNull(i) == 'e' || s.getOrNull(i) == 'E') {
            i++
            if (s.getOrNull(i) == '+' || s.getOrNull(i) == '-') i++
            require(s.getOrNull(i)?.let { it in '0'..'9' } == true) { "exponent digits expected at $i" }
            while (i < s.length && s[i] in '0'..'9') i++
        }
        return s.substring(start, i).toDouble()
    }
}

/**
 * The QUIC events' packets and frames as draft-ietf-quic-qlog-quic-events-04 defines them, checked offline: the
 * PacketHeader of section 8.7 (packet_type of section 8.5, packet_number), RawInfo (main-schema-05 section 5.1) and every
 * QuicFrame of section 8.11 with its required members, their types and enumerations, cited at each check; plus the two
 * frame types Kuicksilver adds through the `$QuicFrame` extension point (section 8.11): `reset_stream_at`
 * (draft-ietf-quic-reliable-stream-reset) and `datagram` (RFC 9221). Any member not listed fails.
 */
internal object QuicQlogSchema {
    private val packetTypes = setOf("initial", "handshake", "0RTT", "1RTT", "retry", "version_negotiation", "stateless_reset", "unknown")
    private val transportErrors =
        setOf(
            "no_error",
            "internal_error",
            "connection_refused",
            "flow_control_error",
            "stream_limit_error",
            "stream_state_error",
            "final_size_error",
            "frame_encoding_error",
            "transport_parameter_error",
            "connection_id_limit_error",
            "protocol_violation",
            "invalid_token",
            "application_error",
            "crypto_buffer_exceeded",
            "key_update_error",
            "aead_limit_reached",
            "no_viable_path",
        )

    /** The frame types section 8.11 (and our two extensions) define, each checked by [frame]. */
    val frameTypes =
        setOf(
            "padding",
            "ping",
            "ack",
            "reset_stream",
            "stop_sending",
            "crypto",
            "new_token",
            "stream",
            "max_data",
            "max_stream_data",
            "max_streams",
            "data_blocked",
            "stream_data_blocked",
            "streams_blocked",
            "new_connection_id",
            "retire_connection_id",
            "path_challenge",
            "path_response",
            "connection_close",
            "handshake_done",
            "reset_stream_at",
            "datagram",
        )

    /** A `transport:packet_sent` or `packet_received` event's data (sections 5.5, 5.6); returns its frames. */
    fun packet(data: Map<*, *>): List<Map<*, *>> {
        members(data, setOf("header"), setOf("frames", "raw"))
        val h = data["header"] as Map<*, *>
        members(h, setOf("packet_type"), setOf("packet_number"))
        require(h["packet_type"] in packetTypes) { "packet_type ${h["packet_type"]}" }
        h["packet_number"]?.let { uint(it) }
        (data["raw"] as Map<*, *>?)?.let {
            members(it, emptySet(), setOf("length", "payload_length", "data"))
            it["length"]?.let { v -> uint(v) }
        }
        val frames = (data["frames"] as List<*>?)?.map { it as Map<*, *> }.orEmpty()
        for (f in frames) frame(f)
        return frames
    }

    /** One QuicFrame (section 8.11). */
    fun frame(f: Map<*, *>) {
        try {
            // the optional lengths every frame may give (e.g. section 8.11.2: length and payload_length are uint32)
            for (k in listOf("length", "payload_length")) f[k]?.let { require(it is Double && uint32Ok(it)) { "$k $it" } }
            when (f["frame_type"]) {
                // 8.11.1, Figure 45
                "padding" -> {
                    members(f, setOf("frame_type", "payload_length"), setOf("length"))
                    uint(f["payload_length"])
                }

                // 8.11.2
                "ping" -> {
                    members(f, setOf("frame_type"), setOf("length", "payload_length"))
                }

                // 8.11.3: AckRange = [1*2 uint64]
                "ack" -> {
                    members(f, setOf("frame_type"), setOf("ack_delay", "acked_ranges", "ect1", "ect0", "ce", "length", "payload_length"))
                    f["ack_delay"]?.let { require(it is Double && it >= 0) { "ack_delay $it" } }
                    (f["acked_ranges"] as List<*>?)?.let { rs ->
                        require(rs.isNotEmpty()) { "acked_ranges is [+ AckRange]" }
                        for (r in rs) {
                            r as List<*>
                            require(r.size in 1..2) { "range $r" }
                            r.forEach { uint(it) }
                            if (r.size == 2) require((r[0] as Double) <= (r[1] as Double)) { "from above to: $r" }
                        }
                    }
                    for (k in listOf("ect0", "ect1", "ce")) f[k]?.let { uint(it) }
                }

                // 8.11.4
                "reset_stream" -> {
                    members(f, setOf("frame_type", "stream_id", "error_code", "final_size"), setOf("length", "payload_length"))
                    uint(f["stream_id"])
                    applicationError(f["error_code"])
                    uint(f["final_size"])
                }

                // 8.11.5
                "stop_sending" -> {
                    members(f, setOf("frame_type", "stream_id", "error_code"), setOf("length", "payload_length"))
                    uint(f["stream_id"])
                    applicationError(f["error_code"])
                }

                // 8.11.6
                "crypto" -> {
                    members(f, setOf("frame_type", "offset", "length"), setOf("payload_length"))
                    uint(f["offset"])
                    uint(f["length"])
                }

                // 8.11.7 with Token, 8.8
                "new_token" -> {
                    members(f, setOf("frame_type", "token"), emptySet())
                    val t = f["token"] as Map<*, *>
                    members(t, emptySet(), setOf("type", "details", "raw"))
                    t["type"]?.let { require(it == "retry" || it == "resumption") }
                    (t["raw"] as Map<*, *>?)?.let { members(it, emptySet(), setOf("length", "payload_length", "data")) }
                }

                // 8.11.8: offset and length "MUST always be set", fin "MUST only be set if the value is true"
                "stream" -> {
                    members(f, setOf("frame_type", "stream_id", "offset", "length"), setOf("fin", "raw"))
                    uint(f["stream_id"])
                    uint(f["offset"])
                    uint(f["length"])
                    f["fin"]?.let { require(it == true) { "fin false is left out" } }
                }

                // 8.11.9
                "max_data" -> {
                    members(f, setOf("frame_type", "maximum"), emptySet())
                    uint(f["maximum"])
                }

                // 8.11.10
                "max_stream_data" -> {
                    members(f, setOf("frame_type", "stream_id", "maximum"), emptySet())
                    uint(f["stream_id"])
                    uint(f["maximum"])
                }

                // 8.11.11 and 8.11.14 with StreamType
                "max_streams", "streams_blocked" -> {
                    val v = if (f["frame_type"] == "max_streams") "maximum" else "limit"
                    members(f, setOf("frame_type", "stream_type", v), emptySet())
                    require(f["stream_type"] == "bidirectional" || f["stream_type"] == "unidirectional") { "stream_type" }
                    uint(f[v])
                }

                // 8.11.12
                "data_blocked" -> {
                    members(f, setOf("frame_type", "limit"), emptySet())
                    uint(f["limit"])
                }

                // 8.11.13
                "stream_data_blocked" -> {
                    members(f, setOf("frame_type", "stream_id", "limit"), emptySet())
                    uint(f["stream_id"])
                    uint(f["limit"])
                }

                // 8.11.15
                "new_connection_id" -> {
                    members(
                        f,
                        setOf("frame_type", "sequence_number", "retire_prior_to", "connection_id"),
                        setOf("connection_id_length", "stateless_reset_token"),
                    )
                    uint32(f["sequence_number"])
                    uint32(f["retire_prior_to"])
                    hex(f["connection_id"])
                    f["connection_id_length"]?.let { require(it is Double && it in 0.0..255.0) }
                }

                // 8.11.16
                "retire_connection_id" -> {
                    members(f, setOf("frame_type", "sequence_number"), emptySet())
                    uint32(f["sequence_number"])
                }

                // 8.11.17, 8.11.18: "always 64-bit"
                "path_challenge", "path_response" -> {
                    members(f, setOf("frame_type"), setOf("data"))
                    f["data"]?.let {
                        hex(it)
                        require((it as String).length == 16) { "data is 64 bits" }
                    }
                }

                // 8.11.19
                "connection_close" -> {
                    members(f, setOf("frame_type"), setOf("error_space", "error_code", "error_code_value", "reason", "trigger_frame_type"))
                    val space = f["error_space"]
                    space?.let { require(it == "transport" || it == "application") }
                    f["error_code"]?.let {
                        if (space == "transport") {
                            require(
                                it in transportErrors || (it is String && CRYPTO.matches(it)) || (it is Double && uint32Ok(it)),
                            ) { "code $it" }
                        } else {
                            applicationError(it)
                        }
                    }
                    f["error_code_value"]?.let { uint(it) }
                    f["reason"]?.let { require(it is String) }
                    f["trigger_frame_type"]?.let { require(it is String || it is Double) }
                }

                // 8.11.20
                "handshake_done" -> {
                    members(f, setOf("frame_type"), emptySet())
                }

                // $QuicFrame extensions (section 8.11): draft-ietf-quic-reliable-stream-reset and RFC 9221
                "reset_stream_at" -> {
                    members(f, setOf("frame_type", "stream_id", "error_code", "final_size", "reliable_size"), emptySet())
                    uint(f["stream_id"])
                    applicationError(f["error_code"])
                    uint(f["final_size"])
                    uint(f["reliable_size"])
                    require((f["reliable_size"] as Double) <= (f["final_size"] as Double))
                }

                "datagram" -> {
                    members(f, setOf("frame_type"), setOf("length", "raw"))
                    f["length"]?.let { uint(it) }
                }

                else -> {
                    error("frame type ${f["frame_type"]}")
                }
            }
        } catch (t: Throwable) {
            throw IllegalArgumentException("${t.message}: $f", t)
        }
    }

    private val CRYPTO = Regex("crypto_error_0x1[0-9a-f][0-9a-f]")
    private val APPLICATION = Regex("application_error_0x[0-9a-f]+")

    /** `$ApplicationError / uint32` (section 8.11.23): a uint32, or our `application_error_0x<hex>` extension of the socket. */
    private fun applicationError(v: Any?) {
        require((v is Double && uint32Ok(v)) || (v is String && APPLICATION.matches(v))) { "application error $v" }
    }

    private fun uint32Ok(v: Double) = v >= 0 && v <= 4294967295.0 && v == kotlin.math.floor(v)

    private fun uint32(v: Any?) = require(v is Double && uint32Ok(v)) { "not a uint32: $v" }

    private fun hex(v: Any?) = require(v is String && v.all { it in '0'..'9' || it in 'a'..'f' } && v.length % 2 == 0) { "not hex: $v" }

    fun members(
        m: Map<*, *>,
        required: Set<String>,
        optional: Set<String>,
    ) {
        for (r in required) require(r in m) { "missing '$r'" }
        for (k in m.keys) require(k in required || k in optional) { "unexpected member '$k'" }
    }

    private fun uint(v: Any?) {
        require(v is Double && v >= 0 && v == kotlin.math.floor(v)) { "not a uint: $v" }
    }

    /** The required members of each frame type, for the negative controls: dropping any one must fail [frame]. */
    val required: Map<String, List<String>> =
        mapOf(
            "padding" to listOf("payload_length"),
            "reset_stream" to listOf("stream_id", "error_code", "final_size"),
            "stop_sending" to listOf("stream_id", "error_code"),
            "crypto" to listOf("offset", "length"),
            "new_token" to listOf("token"),
            "stream" to listOf("stream_id", "offset", "length"),
            "max_data" to listOf("maximum"),
            "max_stream_data" to listOf("stream_id", "maximum"),
            "max_streams" to listOf("stream_type", "maximum"),
            "data_blocked" to listOf("limit"),
            "stream_data_blocked" to listOf("stream_id", "limit"),
            "streams_blocked" to listOf("stream_type", "limit"),
            "new_connection_id" to listOf("sequence_number", "retire_prior_to", "connection_id"),
            "retire_connection_id" to listOf("sequence_number"),
            "reset_stream_at" to listOf("stream_id", "error_code", "final_size", "reliable_size"),
        )
}
