// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls.fuzz

import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull

/**
 * The seed corpus of the kuicksilver-tls fuzz targets: hand-built TLS 1.3 ClientHellos (with and without early_data and
 * pre_shared_key, malformed variants). With `KUICKSILVER_FUZZ_SEEDS_OUT` set (`tools/fuzz/gen-seeds.sh`) the seeds are
 * written to that directory in Jazzer's `<Class>Inputs/<method>/` layout; otherwise the committed corpus must match.
 */
class TlsSeedCorpusTest {
    @Test fun corpusMatchesGenerator() {
        val seeds = generate()
        val out = System.getenv("KUICKSILVER_FUZZ_SEEDS_OUT")
        if (out != null) {
            for ((path, bytes) in seeds) {
                File(out, path).apply {
                    parentFile.mkdirs()
                    writeBytes(bytes)
                }
            }
            return
        }
        for ((path, bytes) in seeds) {
            val committed = javaClass.getResourceAsStream(path)?.use { it.readBytes() }
            assertNotNull(committed, "seed $path is missing: run tools/fuzz/gen-seeds.sh")
            assertContentEquals(bytes, committed, "seed $path is stale: run tools/fuzz/gen-seeds.sh")
        }
    }

    private fun cat(vararg parts: ByteArray): ByteArray = ByteArrayOutputStream().also { o -> parts.forEach { o.write(it) } }.toByteArray()

    private fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())

    private fun ext(
        type: Int,
        body: ByteArray,
    ) = cat(u16(type), u16(body.size), body)

    /** A TLS 1.3 ClientHello with [extensions] (RFC 9846 section 4.2.2). */
    private fun hello(vararg extensions: ByteArray): ByteArray {
        val exts = cat(*extensions)
        val body =
            cat(
                byteArrayOf(3, 3),
                ByteArray(32) { (it * 5).toByte() },
                byteArrayOf(0),
                u16(2),
                byteArrayOf(0x13, 0x01),
                byteArrayOf(1, 0),
                u16(exts.size),
                exts,
            )
        return cat(byteArrayOf(1, (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()), body)
    }

    /** pre_shared_key with one identity of [idLen] bytes and one 32-byte binder. */
    private fun psk(idLen: Int): ByteArray {
        val identity = cat(u16(idLen), ByteArray(idLen) { (it + 1).toByte() }, byteArrayOf(0, 0, 0x10, 0))
        val binder = cat(byteArrayOf(32), ByteArray(32) { 7 })
        return ext(41, cat(u16(identity.size), identity, u16(binder.size), binder))
    }

    private val versions = ext(43, byteArrayOf(2, 3, 4))
    private val groups = ext(10, cat(u16(2), byteArrayOf(0, 0x1d)))
    private val keyShare = ext(51, cat(u16(36), byteArrayOf(0, 0x1d), u16(32), ByteArray(32) { 9 }))
    private val sigAlgs = ext(13, cat(u16(2), byteArrayOf(8, 4)))
    private val alpn = ext(16, cat(u16(3), byteArrayOf(2), "h3".encodeToByteArray()))
    private val sni = ext(0, cat(u16(14), byteArrayOf(0), u16(11), "server.test".encodeToByteArray()))
    private val quicTp = ext(0x39, byteArrayOf(0x01, 0x02, 0x67, 0x10))
    private val early = ext(42, ByteArray(0))
    private val pskModes = ext(45, byteArrayOf(1, 1))

    private fun generate(): Map<String, ByteArray> {
        val seeds = LinkedHashMap<String, ByteArray>()

        fun put(
            method: String,
            name: String,
            data: ByteArray,
        ) {
            seeds["ZeroRttHelloFuzzTestInputs/$method/seed-$name"] = data
        }
        val base = arrayOf(sni, versions, groups, keyShare, sigAlgs, alpn, quicTp)
        val resumption = hello(*base, pskModes, early, psk(112))
        val variants =
            mapOf(
                "full" to hello(*base),
                "resumption-early" to resumption,
                "resumption-no-early" to hello(*base, pskModes, psk(112)),
                "early-without-psk" to hello(*base, early),
                "short-identity" to hello(*base, pskModes, early, psk(8)),
                "two-psk-extensions" to hello(*base, pskModes, early, psk(64), psk(112)),
                "truncated" to resumption.copyOf(resumption.size - 20),
                "not-a-hello" to byteArrayOf(2, 0, 0, 4, 3, 3, 0, 0),
            )
        for ((name, h) in variants) {
            put("clientHelloScan", name, cat(byteArrayOf(0xff.toByte()), h))
            put("clientHelloScan", "$name-fragmented", cat(byteArrayOf(6), h))
            put("zeroRttHello", "raw-$name", cat(byteArrayOf(0), h))
        }
        // fresh resumption hellos of this process: an exact replay, an edited replay, interleaved deliveries
        put("zeroRttHello", "fresh-replay", byteArrayOf(1, 0xff.toByte()))
        put("zeroRttHello", "fresh-replay-fragmented", byteArrayOf(1, 30))
        put("zeroRttHello", "fresh-edited", byteArrayOf(3, 0xff.toByte(), 0, 10, 1, 1, 0, 0x40))
        put("zeroRttHello", "fresh-interleaved", byteArrayOf(5, 100))
        return seeds
    }
}
