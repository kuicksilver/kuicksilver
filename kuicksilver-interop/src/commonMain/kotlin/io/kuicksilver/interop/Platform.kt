// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import kotlinx.io.Buffer
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray
import kotlinx.io.writeString

/** One environment variable, or null (JVM: `System.getenv`, Native: `getenv`). */
internal expect fun envVar(name: String): String?

/** Ends the process with [code] (`kotlin.system.exitProcess` exists on the JVM and Native, but not in common Kotlin). */
internal expect fun exitWith(code: Int): Nothing

/** Files for the endpoint over kotlinx-io: the same code on the JVM and on Linux. */
internal object Files {
    /**
     * Hands [path]'s bytes to [chunk] in pieces of [CHUNK] bytes (the last may be shorter), in order; false when it is not a
     * regular file. The hq server streams with it: reading the whole file first cost a 1 GiB allocation and two copies of it per
     * request in the CPU-per-GB benchmark, 0.9 s/GB of the JVM server's CPU (docs/benchmarks.md).
     */
    suspend fun stream(path: String, chunk: suspend (ByteArray, Int) -> Unit): Boolean {
        val p = Path(path); val meta = SystemFileSystem.metadataOrNull(p); if (meta?.isRegularFile != true) return false
        SystemFileSystem.source(p).buffered().use { src ->
            // no larger than the file: a 1 MiB array per 32-byte request cost the Kotlin/Native server 0.25 ms of system time per handshake
            val b = ByteArray(meta.size.coerceIn(1L, CHUNK.toLong()).toInt())
            while (true) {
                var n = 0
                while (n < b.size) { val r = src.readAtMostTo(b, n, b.size); if (r < 0) break; n += r }   // a buffered source hands out one segment (8 KiB) per call
                if (n > 0) chunk(b, n)
                if (n < b.size) break
            }
        }
        return true
    }
    /** 1 MiB: every write into a QUIC stream is a flush that ends in a short packet; 8 KiB writes cost two to four times the CPU per GB. */
    const val CHUNK = 1 shl 20
    fun read(path: String): ByteArray? { val p = Path(path); if (SystemFileSystem.metadataOrNull(p)?.isRegularFile != true) return null; return SystemFileSystem.source(p).buffered().use { it.readByteArray() } }
    fun write(path: String, bytes: ByteArray) { val p = Path(path); p.parent?.let { if (!SystemFileSystem.exists(it)) SystemFileSystem.createDirectories(it) }; SystemFileSystem.sink(p).buffered().use { val b = Buffer(); b.write(bytes); it.write(b, b.size) } }
    fun readText(path: String): String = read(path)?.decodeToString() ?: throw IllegalArgumentException("missing file $path")
    fun log(line: String) { println(line) }
    /** True when [file] resolves inside [root] (no `..` escape from the www directory). */
    fun inside(root: String, file: String): Boolean = try { SystemFileSystem.resolve(Path(file)).toString().startsWith(SystemFileSystem.resolve(Path(root)).toString()) } catch (e: Exception) { false }
}
