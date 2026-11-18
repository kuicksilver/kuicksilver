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
 * The qlog schema the traces follow, checked offline (no qvis here), as the drafts' text gives it:
 * draft-ietf-quic-qlog-main-schema-05 (JSON-SEQ file, section 6.2, Figures 38 and 39: `qlog_format` "JSON-SEQ",
 * `qlog_version` "0.3" per section 3; `common_fields`, section 3.4.7; times section 3.4.1) and the CDDL of
 * draft-ietf-quic-qlog-h3-events-04 (sections 4 to 7), cited at each check. The members Kuicksilver adds through the
 * drafts' extension points are listed where they are allowed; any other member fails. QUIC events (`transport:`,
 * `recovery:`, `connectivity:`) are checked for the event envelope only.
 */
internal object QlogSchema {
    // h3-events-04 section 4.3, Figure 4
    private val streamTypes = setOf("request", "control", "push", "reserved", "unknown", "qpack_encode", "qpack_decode")

    // section 5.1, Figure 8
    private val owners = setOf("local", "remote")

    // section 4.1, Figure 2: the named HTTPParameters; any other member is "* text => uint64"
    private val parameters = setOf("max_field_section_size", "max_table_capacity", "blocked_streams_count")

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
        val protocols = header(parsed[0])
        val events = parsed.drop(1)
        var last = 0.0
        for (e in events) {
            event(e)
            val t = e["time"] as Double
            // main-schema-05 section 3.4.1: "SHOULD be logged in strictly ascending timestamp order"; events of one loop
            // turn share a time, so the check is that time never goes back
            require(t >= last) { "time goes back from $last to $t: $e" }
            last = t
            val category = (e["name"] as String).substringBefore(':')
            // quic-events-04 and h3-events-04, section 2: protocol_type MUST contain "QUIC" / "HTTP3" with their events
            if (category == "http" || category == "qpack") require("HTTP3" in protocols) { "an HTTP/3 event without HTTP3: $protocols" }
        }
        return events
    }

    /** The header (main-schema-05 Figures 38, 39 and 27); returns its protocol_type. */
    private fun header(h: Map<String, Any?>): List<*> {
        require(h["qlog_format"] == "JSON-SEQ") { "qlog_format: $h" }
        require(h["qlog_version"] == "0.3") { "qlog_version: $h" }
        val trace = h["trace"] as Map<*, *>
        require((trace["vantage_point"] as Map<*, *>)["type"] in setOf("client", "server")) { "vantage_point: $h" }
        val common = trace["common_fields"] as Map<*, *>
        require(common["time_format"] == "relative") { "time_format: $h" }
        // section 3.4.1: a relative time counts from the reference_time ("Specify a full reference_time timestamp")
        require(common["reference_time"] is Double) { "reference_time: $h" }
        val protocols = common["protocol_type"] as? List<*> ?: error("protocol_type: $h")
        require(protocols.isNotEmpty() && protocols.all { it is String } && "QUIC" in protocols) { "protocol_type: $h" }
        return protocols
    }

    private fun event(e: Map<String, Any?>) {
        require(e.keys == setOf("time", "name", "data")) { "event members: $e" }
        require(e["time"] is Double) { "time: $e" }
        val name = e["name"] as? String ?: error("name: $e")
        val data = e["data"] as? Map<*, *> ?: error("data: $e")
        val (category, type) = name.split(':').also { require(it.size == 2) { "name $name" } }
        try {
            when (category) {
                "qpack" -> qpack(type, data)
                "http" -> http(type, data)
                else -> require(category in setOf("transport", "recovery", "connectivity")) { "category of $name" }
            }
        } catch (t: Throwable) {
            throw IllegalArgumentException("$name: ${t.message}: $e", t)
        }
    }

    private fun http(
        type: String,
        data: Map<*, *>,
    ) {
        when (type) {
            // section 4.1, Figure 2
            "parameters_set" -> {
                data["owner"]?.let { require(it in owners) { "owner $it" } }
                data["waits_for_settings"]?.let { require(it is Boolean) }
                for ((k, v) in data) if (k != "owner" && k != "waits_for_settings") uint(v)
            }

            // section 4.2, Figure 3
            "parameters_restored" -> {
                for (v in data.values) uint(v)
            }

            // section 4.3, Figure 4; session_id: Kuicksilver's, on a WebTransport stream
            "stream_type_set" -> {
                members(data, setOf("stream_id", "stream_type"), setOf("owner", "stream_type_value", "associated_push_id", "session_id"))
                uint(data["stream_id"])
                require(data["stream_type"] in streamTypes) { "stream type ${data["stream_type"]}" }
                data["owner"]?.let { require(it in owners) }
                // "only when stream_type === "unknown"" (we always give it then)
                if (data["stream_type"] == "unknown") uint(data["stream_type_value"]) else require("stream_type_value" !in data)
                if (data["stream_type"] != "push") require("associated_push_id" !in data)
            }

            // sections 4.4 and 4.5, Figures 5 and 6
            "frame_created", "frame_parsed" -> {
                members(data, setOf("stream_id", "frame"), setOf("length", "raw"))
                uint(data["stream_id"])
                data["length"]?.let { uint(it) }
                (data["raw"] as Map<*, *>?)?.let { raw(it) }
                frame(data["frame"] as Map<*, *>)
            }

            // section 4.6 (push_resolved) is not written: no server push
            else -> {
                error("an http event we do not write")
            }
        }
    }

    /** RawInfo (main-schema-05 section 5.1, Figure 28): length, payload_length, data, all optional. */
    private fun raw(r: Map<*, *>) {
        members(r, emptySet(), setOf("length", "payload_length", "data"))
        r["length"]?.let { uint(it) }
        r["payload_length"]?.let { uint(it) }
    }

    private fun qpack(
        type: String,
        data: Map<*, *>,
    ) {
        when (type) {
            // section 6.1, Figure 24
            "state_updated" -> {
                val counts = setOf("dynamic_table_capacity", "dynamic_table_size", "known_received_count", "current_insert_count")
                members(data, setOf("owner"), counts)
                require(data["owner"] in owners) { "owner ${data["owner"]}" }
                for (c in counts) data[c]?.let { uint(it) }
            }

            // section 6.2, Figure 25
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
            // section 5.2.1, Figure 11
            "data" -> {
                members(f, setOf("frame_type"), setOf("raw"))
            }

            // section 5.2.2, Figures 13 and 14
            "headers" -> {
                members(f, setOf("frame_type", "headers"), emptySet())
                for (h in f["headers"] as List<*>) {
                    h as Map<*, *>
                    members(h, setOf("name", "value"), emptySet())
                    require(h["name"] is String && h["value"] is String) { "header $h" }
                }
            }

            // section 5.2.3, Figure 15; section 5.2.7, Figure 19
            "cancel_push", "max_push_id" -> {
                members(f, setOf("frame_type", "push_id"), emptySet())
                uint(f["push_id"])
            }

            // section 5.2.4, Figure 16
            "settings" -> {
                members(f, setOf("frame_type", "settings"), emptySet())
                for (s in f["settings"] as List<*>) {
                    s as Map<*, *>
                    members(s, setOf("name", "value"), emptySet())
                    require(s["name"] is String) { "setting $s" }
                    uint(s["value"])
                }
            }

            // section 5.2.5, Figure 17
            "push_promise" -> {
                members(f, setOf("frame_type", "push_id", "headers"), emptySet())
            }

            // section 5.2.6, Figure 18
            "goaway" -> {
                members(f, setOf("frame_type", "id"), emptySet())
                uint(f["id"])
            }

            // section 5.2.8, Figure 20
            "reserved" -> {
                members(f, setOf("frame_type"), setOf("length"))
                f["length"]?.let { uint(it) }
            }

            // section 5.2.9, Figure 21; session_id: Kuicksilver's, on WebTransport's WT_STREAM signal
            "unknown" -> {
                members(f, setOf("frame_type", "frame_type_value"), setOf("raw", "session_id"))
                uint(f["frame_type_value"])
                (f["raw"] as Map<*, *>?)?.let { raw(it) }
            }

            // RFC 9218 PRIORITY_UPDATE through the $HTTPFrame extension point (section 5.2, Figure 9), with the members of
            // the later drafts: stream_id or push_id, and priority_field_value
            "priority_update" -> {
                members(f, setOf("frame_type", "priority_field_value"), setOf("stream_id", "push_id"))
                require(("stream_id" in f) != ("push_id" in f)) { "stream_id or push_id" }
                (f["stream_id"] ?: f["push_id"]).let { uint(it) }
                require(f["priority_field_value"] is String)
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
