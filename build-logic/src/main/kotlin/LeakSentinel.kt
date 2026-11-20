// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import java.io.File

/** `<mode> | <target> | <kinds> | <reason>` lines of [allow] as a Kotlin object; tools/check/sentinel.py checks the file. */
fun writeLeakAllowlist(
    allow: File,
    out: File,
) {
    fun quote(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$") + "\""
    val entries =
        allow.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.map { line ->
            val f = line.split("|").map { it.trim() }
            require(f.size == 4) { "$allow: expected <mode> | <target> | <kinds> | <reason>: $line" }
            val kinds = if (f[2] == "-") emptyList() else f[2].split(",").map { it.trim() }
            buildString {
                append("            LeakAllowEntry(\n")
                append("                ").append(quote(f[0])).append(",\n")
                append("                ").append(quote(f[1])).append(",\n")
                if (kinds.isEmpty()) {
                    append("                emptyList(),\n")
                } else {
                    append("                listOf(\n")
                    for (k in kinds) append("                    ").append(quote(k)).append(",\n")
                    append("                ),\n")
                }
                append("            ),\n")
            }
        }
    out.parentFile.mkdirs()
    // laid out as ktlint lays it out: the generated file is part of the test sources lintKotlin checks
    out.writeText(
        buildString {
            append("// Generated from tools/check/sentinel.allow by kuicksilver.leak-sentinel: do not edit\n")
            append("package io.kuicksilver.testing.sentinel\n\n")
            append("internal object LeakAllowlist {\n")
            if (entries.isEmpty()) {
                append("    val entries: List<LeakAllowEntry> = emptyList()\n")
            } else {
                append("    val entries: List<LeakAllowEntry> =\n")
                append("        listOf(\n")
                for (e in entries) append(e)
                append("        )\n")
            }
            append("}\n")
        },
    )
}
