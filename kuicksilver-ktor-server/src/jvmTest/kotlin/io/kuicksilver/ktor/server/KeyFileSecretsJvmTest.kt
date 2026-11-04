// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsIdentity
import java.io.File
import java.io.FileOutputStream
import java.lang.management.ManagementFactory
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The key file of `kuicksilver.tls.privateKey` (EngineMain and the PEM watcher) is read without leaving the key on the heap:
 * no `String` of it, no pooled kotlinx-io segment, no JDK temporary buffer. A heap dump that includes unreachable objects holds
 * neither the private scalar nor a line-spanning stretch of the PEM text (as `SecretsJvmTest` in kuicksilver-tls checks
 * `TlsIdentity.fromPem` itself).
 */
class KeyFileSecretsJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_heapDumpNoKeyFromPemKeyFile() {
        val der =
            java.util.Base64
                .getDecoder()
                .decode(KEY_FILE_TEST_KEY)
        val at =
            (0 until der.size - 34).first { der[it] == 0x04.toByte() && der[it + 1] == 0x20.toByte() && der[it - 3] == 0x02.toByte() } + 2
        val maskedScalar = ByteArray(32) { (der[at + it].toInt() xor 0x5a).toByte() }
        val pem = pemBytes(der)
        der.fill(0)
        val body = pem.indexOf('\n'.code.toByte()) + 1
        val maskedText = ByteArray(21) { (pem[body + 54 + it].toInt() xor 0x5a).toByte() } // 10 chars, '\n', 10 chars
        assertEquals('\n'.code, maskedText[10].toInt() xor 0x5a)
        val keyFile = File.createTempFile("ksl-key", ".pem").also { it.deleteOnExit() }
        FileOutputStream(keyFile).use { it.write(pem) }
        pem.fill(0)
        val certPem = "-----BEGIN CERTIFICATE-----\n" + KEY_FILE_TEST_CERT.chunked(64).joinToString("\n") + "\n-----END CERTIFICATE-----\n"
        val id = TlsIdentity.fromPem(certPem, readPemKey(keyFile.path))
        keyFile.delete()
        val dump =
            File.createTempFile("ksl-heap", ".hprof").also {
                it.delete()
                it.deleteOnExit()
            }
        try {
            val bean =
                ManagementFactory.newPlatformMXBeanProxy(
                    ManagementFactory.getPlatformMBeanServer(),
                    "com.sun.management:type=HotSpotDiagnostic",
                    com.sun.management.HotSpotDiagnosticMXBean::class.java,
                )
            bean.dumpHeap(dump.path, false) // unreachable objects too
            assertEquals(1, id.chain.size)
        } finally {
            id.close()
        }
        val heap = dump.readBytes()
        dump.delete()
        assertFalse(
            contains(heap, ByteArray(32) { (maskedScalar[it].toInt() xor 0x5a).toByte() }),
            "the private key was found in the heap dump",
        )
        assertFalse(
            contains(
                heap,
                ByteArray(21) {
                    (maskedText[it].toInt() xor 0x5a).toByte()
                },
            ),
            "the PEM text of the key file was found in the heap dump",
        )
        assertTrue(contains(heap, "kuicksilver".encodeToByteArray()), "sanity: the dump is searchable")
    }

    /** PKCS#8 PEM of [der] as ASCII bytes, 64 characters a line, built without a String of the key. */
    private fun pemBytes(der: ByteArray): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val b64 = ByteArray((der.size + 2) / 3 * 4)
        var o = 0
        var i = 0
        while (i < der.size) {
            val n = minOf(3, der.size - i)
            val v = (0 until 3).fold(0) { acc, k -> (acc shl 8) or (if (k < n) der[i + k].toInt() and 0xff else 0) }
            for (k in 0 until 4) b64[o++] = (if (k <= n) alphabet[(v shr (18 - 6 * k)) and 0x3f] else '=').code.toByte()
            i += 3
        }
        val begin = "-----BEGIN PRIVATE KEY-----\n".encodeToByteArray()
        val end = "-----END PRIVATE KEY-----\n".encodeToByteArray()
        val out = ByteArray(begin.size + b64.size + (b64.size + 63) / 64 + end.size)
        var p = 0
        for (c in begin) out[p++] = c
        for (j in b64.indices) {
            out[p++] = b64[j]
            if (j % 64 == 63 || j == b64.size - 1) out[p++] = '\n'.code.toByte()
        }
        for (c in end) out[p++] = c
        b64.fill(0)
        return out
    }

    private fun contains(
        hay: ByteArray,
        needle: ByteArray,
    ): Boolean {
        var i = 0
        while (i <= hay.size - needle.size) {
            var j = 0
            while (j < needle.size && hay[i + j] == needle[j]) j++
            if (j == needle.size) return true
            i++
        }
        return false
    }
}

/** A P-256 key and its self-signed certificate used only here (the same pair as kuicksilver-tls's SecretsJvmTest). */
private const val KEY_FILE_TEST_KEY =
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkurDS6tlARHsfz6oak6PgHs/SXvWtQNwkR5wy5f5VOuhRANCAATpGhO4BkysWPUd5oM2arp0/5ylD+IAHWhuvV/eS7LElH2vO8aQ/HsL2dxcPg4Btoy5zYHzGdoOzuIgYl784hzH"
private const val KEY_FILE_TEST_CERT =
    "MIIBfjCCASOgAwIBAgIUTlytV3OQG7F2dBfriiAjGmhWtq0wCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwIcGVtLnRlc3QwIBcNMjYxMDEyMTgxMDU5WhgPMjEyNjA5MTgxODEwNTlaMBMxETAPBgNVBAMMCHBlbS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6RoTuAZMrFj1HeaDNmq6dP+cpQ/iAB1obr1f3kuyxJR9rzvGkPx7C9ncXD4OAbaMuc2B8xnaDs7iIGJe/OIcx6NTMFEwHQYDVR0OBBYEFGil2JFWBPR1dMOE1aCKXtYhAVbuMB8GA1UdIwQYMBaAFGil2JFWBPR1dMOE1aCKXtYhAVbuMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAIYIMTibazWqEpqMIxPeUPl9rrplGuKZiWop+s0I3MyDAiEAsSqxnw6SDx9WaBuXlXUeDlY7r6w6ttFisFt4daH1aSY="
