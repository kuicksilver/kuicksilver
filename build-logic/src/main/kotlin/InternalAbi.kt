// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.DataInputStream
import java.io.File

/** The annotation that marks API public only for other Kuicksilver modules; it is left out of the ABI dumps. */
const val INTERNAL_API_ANNOTATION: String = "io.kuicksilver.annotations.InternalKuicksilverApi"

private val internalAnnotationLine = Regex("""^@(io\.kuicksilver\.annotations\.)?InternalKuicksilverApi\b""")
private val classDeclaration =
    Regex("""^(?:@\S+\s+)*(?:(?:public|expect|actual|sealed|abstract|open|final|data|enum|value|annotation|fun|inner)\s+)*(?:class|object|interface)\s+(\w+)""")

/**
 * `<package>.<Name>.**` for every top-level class, object or interface of [sourceDirs] annotated with
 * [INTERNAL_API_ANNOTATION]. The ABI filter's `annotatedWith` excludes the class itself but, in the JVM dumps, not its
 * companion object or nested classes; excluding these names by pattern covers them too.
 */
fun internalClassPatterns(sourceDirs: Iterable<File>): List<String> {
    val out = sortedSetOf<String>()
    for (dir in sourceDirs) {
        dir.walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach { f ->
            val lines = f.readLines()
            val pkg = lines.firstOrNull { it.startsWith("package ") }?.removePrefix("package ")?.trim() ?: return@forEach
            for ((i, line) in lines.withIndex()) {
                if (!internalAnnotationLine.containsMatchIn(line)) continue
                // the declaration is on the annotation's line or on the next line at column 0 that is no other annotation
                val rest = line.replaceFirst(internalAnnotationLine, "").trim()
                val decl =
                    if (rest.isNotEmpty() && !rest.startsWith("//")) {
                        rest
                    } else {
                        lines.drop(i + 1).firstOrNull { it.isNotBlank() && !it.startsWith("@") && !it.startsWith("//") } ?: continue
                    }
                classDeclaration.find(decl)?.let { out += "$pkg.${it.groupValues[1]}.**" }
            }
        }
    }
    return out.toList()
}

/**
 * Fails when a JVM or Android ABI dump lists a class that is, or is nested in, a class annotated with
 * [INTERNAL_API_ANNOTATION] (docs/stability.md: internal API is not in the dumps). Reads the annotation from the compiled
 * class files, independently of how the dump filter was configured.
 */
abstract class CheckInternalAbiTask : DefaultTask() {
    /** The `.api` dumps of the JVM and Android targets. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val dumps: ConfigurableFileCollection

    /** Class output directories of the compilations the dumps were made from. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val classDirs: ConfigurableFileCollection

    @TaskAction
    fun check() {
        val descriptor = "L" + INTERNAL_API_ANNOTATION.replace('.', '/') + ";"
        val cache = HashMap<String, Boolean>()
        fun internal(name: String): Boolean =
            cache.getOrPut(name) {
                val file = classDirs.files.map { File(it, "$name.class") }.firstOrNull { it.isFile }
                file != null && descriptor in ClassAnnotations.of(file.readBytes())
            }
        val violations = mutableListOf<String>()
        for (dump in dumps.files.filter { it.isFile }) {
            val classes = dump.readLines().mapNotNull { Regex("""^public .*?(?:class|interface) (\S+)""").find(it)?.groupValues?.get(1) }
            for (c in classes) {
                // the class itself and every class it is nested in
                val chain = c.indices.filter { c[it] == '$' }.map { c.substring(0, it) } + c
                chain.firstOrNull(::internal)?.let { violations += "${dump.parentFile.name}/${dump.name}: $c (in @InternalKuicksilverApi $it)" }
            }
        }
        if (violations.isNotEmpty()) {
            throw GradleException(
                "ABI dumps list internal API (fix the filter in kuicksilver.kmp, then updateKotlinAbi):\n" + violations.joinToString("\n"),
            )
        }
    }
}

/** The class-level annotation types (descriptors) of a class file: RuntimeVisibleAnnotations and RuntimeInvisibleAnnotations. */
object ClassAnnotations {
    fun of(bytes: ByteArray): Set<String> {
        val d = DataInputStream(bytes.inputStream())
        require(d.readInt() == 0xCAFEBABE.toInt()) { "not a class file" }
        d.readUnsignedShort()
        d.readUnsignedShort()
        val count = d.readUnsignedShort()
        val utf8 = arrayOfNulls<String>(count)
        var i = 1
        while (i < count) {
            when (val tag = d.readUnsignedByte()) {
                1 -> utf8[i] = d.readUTF()
                3, 4 -> d.skipBytes(4)
                5, 6 -> { d.skipBytes(8); i++ }   // long and double take two slots
                7, 8, 16, 19, 20 -> d.skipBytes(2)
                9, 10, 11, 12, 17, 18 -> d.skipBytes(4)
                15 -> d.skipBytes(3)
                else -> error("constant pool tag $tag")
            }
            i++
        }
        d.skipBytes(6)   // access flags, this class, super class
        d.skipBytes(2 * d.readUnsignedShort())   // interfaces
        repeat(2) {   // fields, then methods
            repeat(d.readUnsignedShort()) {
                d.skipBytes(6)
                repeat(d.readUnsignedShort()) { d.skipBytes(2); d.skipBytes(d.readInt()) }
            }
        }
        val out = HashSet<String>()
        repeat(d.readUnsignedShort()) {
            val name = utf8[d.readUnsignedShort()]
            val length = d.readInt()
            if (name == "RuntimeVisibleAnnotations" || name == "RuntimeInvisibleAnnotations") {
                repeat(d.readUnsignedShort()) { out += annotation(d, utf8) }
            } else {
                d.skipBytes(length)
            }
        }
        return out
    }

    private fun annotation(d: DataInputStream, utf8: Array<String?>): String {
        val type = utf8[d.readUnsignedShort()] ?: ""
        repeat(d.readUnsignedShort()) { d.skipBytes(2); elementValue(d, utf8) }
        return type
    }

    private fun elementValue(d: DataInputStream, utf8: Array<String?>) {
        when (val tag = d.readUnsignedByte().toChar()) {
            'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 's', 'c' -> d.skipBytes(2)
            'e' -> d.skipBytes(4)
            '@' -> annotation(d, utf8)
            '[' -> repeat(d.readUnsignedShort()) { elementValue(d, utf8) }
            else -> error("element value tag $tag")
        }
    }
}
