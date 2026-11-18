// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.tls.TlsRole
import kotlin.concurrent.Volatile

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
 * The qlog schema the traces follow, checked offline (no qvis here): qlog 0.3 JSON-SEQ (draft-ietf-quic-qlog-main-schema-05)
 * with the HTTP/3 event definitions of draft-ietf-quic-qlog-h3-events-04 as their CDDL gives them (required members, types
 * and enumerations), and the extension members Kuicksilver adds, listed here; any other member fails. QUIC events
 * (`transport:`, `recovery:`, `connectivity:`) are checked for the event envelope only.
 */
internal object QlogSchema {
    private val streamTypes = setOf("request", "control", "push", "reserved", "unknown", "qpack_encode", "qpack_decode")
    private val owners = setOf("local", "remote")
    private val parameters =
        setOf("max_field_section_size", "max_table_capacity", "blocked_streams_count", "enable_connect_protocol", "h3_datagram")

    /** One trace: every record framed as JSON-SEQ (RFC 7464), the header first; returns the events, parsed. */
    fun check(records: List<String>): List<Map<String, Any?>> {
        require(records.isNotEmpty()) { "an empty trace" }
        val parsed =
            records.mapIndexed { n, r ->
                require(r.length >= 3 && r[0] == '\u001e' && r.last() == '\n') { "record $n is not RS ... LF: $r" }
                val body = r.substring(1, r.length - 1)
                require('\u001e' !in body && '\n' !in body) { "record $n holds a second record: $r" }
                val v = runCatching { StrictJson.parse(body) }.getOrElse { throw IllegalArgumentException("record $n: ${it.message}: $r") }
                val m = v as? Map<*, *> ?: throw IllegalArgumentException("record $n is not an object")
                m.entries.associate { (k, x) -> k as String to x }
            }
        header(parsed[0])
        val events = parsed.drop(1)
        var last = -1.0
        for (e in events) {
            event(e)
            last = e["time"] as Double
            require(last >= 0) { "negative time" }
        }
        return events
    }

    private fun header(h: Map<String, Any?>) {
        require(h["qlog_format"] == "JSON-SEQ") { "qlog_format: $h" }
        require(h["qlog_version"] == "0.3") { "qlog_version: $h" }
        val trace = h["trace"] as Map<*, *>
        require((trace["vantage_point"] as Map<*, *>)["type"] in setOf("client", "server")) { "vantage_point: $h" }
        require((trace["common_fields"] as Map<*, *>)["time_format"] == "relative") { "time_format: $h" }
    }

    private fun event(e: Map<String, Any?>) {
        require(e.keys == setOf("time", "name", "data")) { "event members: $e" }
        require(e["time"] is Double) { "time: $e" }
        val name = e["name"] as? String ?: error("name: $e")
        val data = e["data"] as? Map<*, *> ?: error("data: $e")
        val (category, type) = name.split(':').also { require(it.size == 2) { "name $name" } }
        if (category == "qpack") {
            qpack(type, data)
            return
        }
        if (category != "http") {
            require(category in setOf("transport", "recovery", "connectivity")) { "category of $name" }
            return
        }
        try {
            when (type) {
                "parameters_set" -> {
                    members(data, required = emptySet(), optional = parameters + "owner" + "waits_for_settings")
                    data["owner"]?.let { require(it in owners) { "owner $it" } }
                    for (p in parameters) data[p]?.let { uint(it) }
                }

                "parameters_restored" -> {
                    members(data, required = emptySet(), optional = parameters)
                    for (p in parameters) data[p]?.let { uint(it) }
                }

                "stream_type_set" -> {
                    // raw_stream_type and session_id: Kuicksilver's extension members
                    members(data, setOf("stream_id", "new"), setOf("owner", "old", "associated_push_id", "raw_stream_type", "session_id"))
                    uint(data["stream_id"])
                    require(data["new"] in streamTypes) { "stream type ${data["new"]}" }
                    data["owner"]?.let { require(it in owners) }
                    data["raw_stream_type"]?.let { uint(it) }
                    if (data["new"] == "unknown" || data["new"] == "reserved") require(data["raw_stream_type"] != null) { "no raw type" }
                }

                "frame_created", "frame_parsed" -> {
                    members(data, setOf("stream_id", "frame"), setOf("length", "raw"))
                    uint(data["stream_id"])
                    data["length"]?.let { uint(it) }
                    (data["raw"] as Map<*, *>?)?.let { raw ->
                        members(raw, emptySet(), setOf("length", "payload_length", "data"))
                        raw["length"]?.let { uint(it) }
                        raw["payload_length"]?.let { uint(it) }
                    }
                    frame(data["frame"] as Map<*, *>)
                }

                else -> {
                    error("an http event the draft does not define")
                }
            }
        } catch (t: Throwable) {
            throw IllegalArgumentException("$name: ${t.message}: $e", t)
        }
    }

    private fun qpack(
        type: String,
        data: Map<*, *>,
    ) {
        when (type) {
            "state_updated" -> {
                val counts = setOf("dynamic_table_capacity", "dynamic_table_size", "known_received_count", "current_insertion_count")
                members(data, setOf("owner"), counts)
                require(data["owner"] in owners) { "owner ${data["owner"]}" }
                for (c in counts) data[c]?.let { uint(it) }
            }

            "stream_state_updated" -> {
                members(data, setOf("stream_id", "state"), emptySet())
                uint(data["stream_id"])
                require(data["state"] in setOf("blocked", "unblocked")) { "state ${data["state"]}" }
            }

            else -> {
                error("a qpack event we do not write: $type")
            }
        }
    }

    private fun frame(f: Map<*, *>) {
        when (f["frame_type"]) {
            "data" -> {
                members(f, setOf("frame_type"), setOf("raw"))
            }

            "headers" -> {
                members(f, setOf("frame_type", "headers"), emptySet())
                for (h in f["headers"] as List<*>) {
                    h as Map<*, *>
                    members(h, setOf("name", "value"), emptySet())
                    require(h["name"] is String && h["value"] is String) { "header $h" }
                }
            }

            "settings" -> {
                members(f, setOf("frame_type", "settings"), emptySet())
                for (s in f["settings"] as List<*>) {
                    s as Map<*, *>
                    members(s, setOf("name", "value"), emptySet())
                    require(s["name"] is String) { "setting $s" }
                    uint(s["value"])
                }
            }

            "goaway" -> {
                members(f, setOf("frame_type", "id"), emptySet())
                uint(f["id"])
            }

            "cancel_push", "max_push_id" -> {
                members(f, setOf("frame_type", "push_id"), emptySet())
                uint(f["push_id"])
            }

            "push_promise" -> {
                members(f, setOf("frame_type", "push_id", "headers"), emptySet())
            }

            // raw_frame_type on a reserved frame, and the PRIORITY_UPDATE and WT_STREAM members on an unknown one: extensions
            "reserved" -> {
                members(f, setOf("frame_type"), setOf("length", "raw_frame_type"))
            }

            "unknown" -> {
                members(f, setOf("frame_type", "raw_frame_type"), setOf("stream_id", "push_id", "priority_field_value", "session_id"))
                uint(f["raw_frame_type"])
            }

            else -> {
                error("frame type ${f["frame_type"]}")
            }
        }
    }

    private fun members(
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
}

/** Collects every record of every trace in memory; [logHeaderValues] as the sink's opt-in. Records are read after the traces closed. */
internal class MemoryQlogSink(
    override val logHeaderValues: Boolean = false,
    /** Runs on each record before it is kept (on the endpoint loop): a test makes the sink throw or stall here. */
    private val onWrite: ((String) -> Unit)? = null,
) : QlogSink {
    class Trace(
        val role: TlsRole,
    ) {
        @Volatile var records: List<String> = emptyList()

        @Volatile var closed: Boolean = false
    }

    @Volatile var traces: List<Trace> = emptyList()

    fun trace(role: TlsRole): Trace = traces.single { it.role == role }

    override fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace {
        val t = Trace(role)
        traces = traces + t
        return object : QlogTrace {
            override fun write(record: String) {
                onWrite?.invoke(record)
                t.records = t.records + record
            }

            override fun close() {
                t.closed = true
            }
        }
    }
}
