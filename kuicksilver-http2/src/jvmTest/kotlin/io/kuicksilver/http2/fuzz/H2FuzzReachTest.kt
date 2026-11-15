// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.fuzz

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The reach of the stateful HTTP/2 fuzz targets: every input of a target (its seeds in `<Class>Inputs/<method>/` and its
 * committed corpus `tools/fuzz/corpus/http2.<method>/`) runs through the target with a [Reach] collector, and the
 * table counts, per feature, the inputs that reached it. The table goes to `build/reports/fuzz-reach/<method>.tsv` (and to
 * the console; what each input reached goes to `<method>-inputs.txt`). Every input must pass the target's checks, and the seeds alone must reach every feature of [required]:
 * a seed set that stops reaching CONTINUATION, PING, a setting, a window change, an error path or Extended CONNECT fails
 * here instead of leaving the campaign blind to it.
 */
class H2FuzzReachTest {
    private class Target(
        val method: String,
        val inputs: String,
        val run: (ByteArray) -> Unit,
        val required: List<String>,
    )

    private val frames =
        listOf("DATA", "DATA (empty)", "HEADERS", "CONTINUATION", "RST_STREAM", "SETTINGS", "SETTINGS ACK", "PING", "GOAWAY")
            .map { "frame $it" } +
            listOf("frame WINDOW_UPDATE (connection)", "frame WINDOW_UPDATE (stream)", "frame PUSH_PROMISE", "frame unknown type")
    private val settings =
        listOf(
            "HEADER_TABLE_SIZE",
            "ENABLE_PUSH",
            "MAX_CONCURRENT_STREAMS",
            "INITIAL_WINDOW_SIZE",
            "MAX_FRAME_SIZE",
            "MAX_HEADER_LIST_SIZE",
            "ENABLE_CONNECT_PROTOCOL",
            "NO_RFC7540_PRIORITIES",
            "unknown",
        ).map { "setting $it" }

    private val targets =
        listOf(
            Target(
                "connectionServer",
                "H2ConnectionFuzzTestInputs",
                { H2ConnectionFuzzTest().connectionServer(it) },
                frames + settings +
                    listOf(
                        "frame PING ACK",
                        "frame PRIORITY",
                        "frame PRIORITY_UPDATE",
                        "flow: initial window shrinks",
                        "flow: initial window grows",
                        "flow: window available again",
                        "Extended CONNECT (:protocol)",
                        "Extended CONNECT accepted",
                        "malformed request",
                        "field section too large",
                        "event GOAWAY",
                        "event PRIORITY_UPDATE",
                        "connection error PROTOCOL_ERROR",
                        "connection error FLOW_CONTROL_ERROR",
                        "connection error FRAME_SIZE_ERROR",
                        "connection error COMPRESSION_ERROR",
                        "connection error SETTINGS_TIMEOUT",
                        "connection error ENHANCE_YOUR_CALM",
                        "calm: control frame queue",
                        "calm: glitch budget",
                        "calm: field block limits",
                        "calm: field block time",
                        "calm: empty DATA in a row",
                        "calm: reset budget",
                        "stream error PROTOCOL_ERROR",
                        "stream error FLOW_CONTROL_ERROR",
                        "stream error REFUSED_STREAM",
                        "stream error STREAM_CLOSED",
                        "stream error NO_ERROR",
                    ),
            ),
            Target(
                "connectionClient",
                "H2ClientConnectionFuzzTestInputs",
                { H2ClientConnectionFuzzTest().connectionClient(it) },
                frames + settings +
                    listOf(
                        "frame ALTSVC",
                        "flow: initial window shrinks",
                        "flow: initial window grows",
                        "Extended CONNECT opened",
                        "Extended CONNECT established",
                        "event GOAWAY",
                        "event ALTSVC",
                        "field section too large",
                        "connection error PROTOCOL_ERROR",
                        "connection error FRAME_SIZE_ERROR",
                        "connection error STREAM_CLOSED",
                        "connection error ENHANCE_YOUR_CALM",
                        "calm: control frame queue",
                        "calm: empty DATA in a row",
                        "stream error CANCEL",
                        "stream error PROTOCOL_ERROR",
                    ),
            ),
        )

    private fun root(): File {
        var d: File? = File("").absoluteFile
        while (d != null && !File(d, "tools/fuzz/campaign.sh").exists()) d = d.parentFile
        return d ?: error("no repository root above ${File("").absolutePath}")
    }

    /** The inputs of [t]: seeds (true) and the committed corpus (false), by file name. */
    private fun inputs(t: Target): List<Triple<String, Boolean, ByteArray>> {
        val seeds =
            javaClass
                .getResource("${t.inputs}/${t.method}")
                ?.let { File(it.toURI()) }
                ?.listFiles()
                .orEmpty()
                .filter { it.isFile }
                .sortedBy { it.name }
                .map { Triple(it.name, true, it.readBytes()) }
        val corpus =
            File(root(), "tools/fuzz/corpus/http2.${t.method}")
                .listFiles()
                .orEmpty()
                .filter { it.isFile }
                .sortedBy { it.name }
                .map { Triple(it.name, false, it.readBytes()) }
        return seeds + corpus
    }

    @Test
    fun seedsAndCorpusReachEveryFeature() {
        val out = File("build/reports/fuzz-reach").apply { mkdirs() }
        val failures = mutableListOf<String>()
        for (t in targets) {
            val all = inputs(t)
            val perInput = StringBuilder()
            val seedHits = HashMap<String, Int>()
            val allHits = HashMap<String, Int>()
            for ((name, seed, bytes) in all) {
                val r = Reach()
                reach = r
                try {
                    t.run(bytes)
                } catch (e: Throwable) {
                    failures += "${t.method}/$name: $e"
                } finally {
                    reach = null
                }
                perInput.append("$name: ${r.features.sorted().joinToString(", ")}${r.closed?.let { " [closed: $it]" } ?: ""}\n")
                for (f in r.features) {
                    allHits.merge(f, 1, Int::plus)
                    if (seed) seedHits.merge(f, 1, Int::plus)
                }
            }
            val features = (t.required + allHits.keys.sorted()).distinct()
            val seeds = all.count { it.second }
            val table =
                buildString {
                    append("feature\tseeds ($seeds)\tseeds + corpus (${all.size})\n")
                    for (f in features) append("$f\t${seedHits[f] ?: 0}\t${allHits[f] ?: 0}\n")
                }
            File(out, "${t.method}.tsv").writeText(table)
            File(out, "${t.method}-inputs.txt").writeText(perInput.toString())
            println("== http2.${t.method}\n$table")
            for (f in t.required) if ((seedHits[f] ?: 0) == 0) failures += "${t.method}: no seed reaches \"$f\""
        }
        assertEquals(emptyList(), failures)
    }
}
