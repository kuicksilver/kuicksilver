// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.QuicCrypto
import java.io.File
import kotlin.test.Test

/**
 * Gives the connection fuzzer's older inputs back the meaning they were recorded with. Until 0.3.0 operation kind 7 of
 * [ConnProgram] was "one round" whatever its argument; since then an argument other than 0 and 15 is a PATH operation that reads
 * argument bytes of its own, so an input recorded before (the campaign corpora of 2026-10-14, the crash reproducers of 0.2.0)
 * would run PATH operations it never had and read its later operations out of step, and its flags byte's bits 3 to 7 (DF, ECN,
 * RETRY, VN, SETUP) would turn on what it never had, a setup byte among them; they are cleared first. How many bytes an operation reads depends on
 * the run (an application call on a side whose connection does not exist yet reads none), so the rewriter runs the program: at the
 * first PATH operation it sets that byte's argument to 0 (`o and 0x0f`: kind and side kept) and runs it again from the start, until
 * a run has none. Bytes inside a RAW payload or an operation's arguments are never touched.
 */
internal object ConnectionProgramRewriter {
    private class Stop(
        val at: Int,
    ) : RuntimeException(null, null, false, false)

    /** [input] with every PATH operation the run reaches turned into one round, for a run over [crypto]. */
    fun rewrite(
        input: ByteArray,
        crypto: QuicCrypto,
    ): ByteArray {
        KslLoader.ensureLoaded()
        val d = input.copyOf()
        // the flags byte: until 0.3.0 its bits 0 to 2 meant what they mean now (LIVE, SMALL, NO_PMTUD), the others nothing; DF, ECN,
        // RETRY, VN and SETUP (which also makes the next byte a setup byte) came later
        if (d.isNotEmpty()) d[0] = (d[0].toInt() and (ConnProgram.LIVE or ConnProgram.SMALL or ConnProgram.NO_PMTUD)).toByte()
        while (true) {
            val at =
                try {
                    ConnectionFuzz(d, crypto, pathOpSeen = { throw Stop(it) }).run()
                    null
                } catch (s: Stop) {
                    s.at
                } catch (_: Throwable) {
                    null // the run ends before any later operation (an invariant, as the input's own finding)
                } ?: return d
            d[at] = (d[at].toInt() and 0x0f).toByte()
        }
    }
}

/**
 * Where a rewritten input goes: an input named by the SHA-1 of its [old] bytes (a campaign corpus input, [corpusNameFinding]) is
 * named by the SHA-1 of its [new] ones, any other one (`seed-*`, `crash-*`) keeps its [name].
 */
internal fun rewrittenName(
    name: String,
    old: ByteArray,
    new: ByteArray,
): String {
    if (corpusNameFinding(name, old) != null) return name
    return java.security.MessageDigest
        .getInstance("SHA-1")
        .digest(new)
        .joinToString("") { "%02x".format(it) }
}

/**
 * `KUICKSILVER_FUZZ_REWRITE=<file listing input paths, one per line>` (tools/fuzz/rewrite-conn-path-ops.sh): rewrites those inputs
 * in place with [ConnectionProgramRewriter], over real TLS for a path containing `connectionTls`, else over NullCryptoProvider. A
 * corpus input is renamed to the SHA-1 of its new bytes ([rewrittenName]); one whose new name is taken (the same bytes) is removed.
 */
class ConnectionProgramRewriterTool {
    @Test fun rewriteListedFiles() {
        val list = System.getenv("KUICKSILVER_FUZZ_REWRITE") ?: return
        var changed = 0
        var duplicates = 0
        val files = File(list).readLines().filter { it.isNotBlank() }
        for (name in files) {
            val f = File(name)
            val old = f.readBytes()
            val new = ConnectionProgramRewriter.rewrite(old, if (name.contains("connectionTls")) ksl else NullCryptoProvider)
            if (!new.contentEquals(old)) {
                val to = File(f.parentFile, rewrittenName(f.name, old, new))
                if (to != f && to.exists()) {
                    duplicates++
                } else {
                    to.writeBytes(new)
                }
                if (to != f) f.delete()
                changed++
            }
        }
        println("rewrite-conn-path-ops: $changed of ${files.size} file(s) rewritten ($duplicates the same as another input, removed)")
    }
}
