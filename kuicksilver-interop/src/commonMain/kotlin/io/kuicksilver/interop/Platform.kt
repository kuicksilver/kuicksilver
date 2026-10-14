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
    fun read(path: String): ByteArray? { val p = Path(path); if (SystemFileSystem.metadataOrNull(p)?.isRegularFile != true) return null; return SystemFileSystem.source(p).buffered().use { it.readByteArray() } }
    fun write(path: String, bytes: ByteArray) { val p = Path(path); p.parent?.let { if (!SystemFileSystem.exists(it)) SystemFileSystem.createDirectories(it) }; SystemFileSystem.sink(p).buffered().use { val b = Buffer(); b.write(bytes); it.write(b, b.size) } }
    fun readText(path: String): String = read(path)?.decodeToString() ?: throw IllegalArgumentException("missing file $path")
    fun log(line: String) { println(line) }
    /** True when [file] resolves inside [root] (no `..` escape from the www directory). */
    fun inside(root: String, file: String): Boolean = try { SystemFileSystem.resolve(Path(file)).toString().startsWith(SystemFileSystem.resolve(Path(root)).toString()) } catch (e: Exception) { false }
}
