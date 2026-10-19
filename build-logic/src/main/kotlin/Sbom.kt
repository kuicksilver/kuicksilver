// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.DefaultTask
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.component.ProjectComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.artifacts.result.ResolvedComponentResult
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Nested
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.security.MessageDigest
import java.util.UUID

// CycloneDX 1.6 SBOMs of the published modules (docs/release.md, "Supply chain"), written without a third-party plugin: one
// document per publication, from the resolved graph Gradle publishes for it, plus one per module that aggregates them. The
// statically linked native code Gradle cannot see is added as components: the ksl C shim and the pinned OpenSSL (version,
// tarball SHA-256 and configure flags from gradle/openssl.toml), under every publication that embeds or depends on
// kuicksilver-native. Deterministic: the timestamp is the commit's, the serial number a name-based UUID of the content.

/** One platform publication of a Kotlin Multiplatform module: its artifactId and the configuration its consumers resolve. */
abstract class SbomPublication {
    /** The Maven artifactId, `<module>-<target>` in lower case. */
    @get:Input abstract val artifactId: Property<String>

    /** The suffix of sibling Kuicksilver modules in this publication's graph (`jvm`, `android`, `iosarm64`, ...). */
    @get:Input abstract val siblingSuffix: Property<String>

    /** The package-url `type` qualifier of this publication's main artifact (`jar`, `aar`, `klib`). */
    @get:Input abstract val packaging: Property<String>

    /** The resolved graph of the configuration that matches the published variant. */
    @get:Input abstract val graph: Property<ResolvedComponentResult>

    /** The artifacts of the external (non-project) components in [graph], for their SHA-256. */
    @get:Internal abstract val externalArtifacts: SetProperty<ResolvedArtifactResult>

    /** The files of [externalArtifacts], so that the task reruns when one changes. */
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val externalFiles: ConfigurableFileCollection
}

/** Writes `<artifactId>-<version>.cdx.json` for every publication of a module and for the module itself. */
abstract class CyclonedxSbomTask : DefaultTask() {
    @get:Input abstract val mavenGroup: Property<String>

    @get:Input abstract val moduleName: Property<String>

    @get:Input abstract val version: Property<String>

    @get:Input abstract val pomDescription: Property<String>

    /** The commit the publication is built from and its committer date (ISO 8601), the SBOM's timestamp. */
    @get:Input abstract val gitCommit: Property<String>

    @get:Input abstract val gitCommitDate: Property<String>

    @get:Input abstract val opensslVersion: Property<String>

    @get:Input abstract val opensslSha256: Property<String>

    @get:Input abstract val opensslConfigureFlags: ListProperty<String>

    @get:Input abstract val kslAbi: Property<String>

    /** The modules of a BOM (java-platform) publication, which has constraints and no graph. */
    @get:Input @get:Optional abstract val platformConstraints: ListProperty<String>

    @get:Nested abstract val publications: ListProperty<SbomPublication>

    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun write() {
        val out = outputDirectory.get().asFile
        out.listFiles()?.forEach { it.delete() }
        val v = version.get()
        val module = moduleName.get()
        val documents = mutableListOf<Document>()
        for (p in publications.get()) {
            val doc = publicationDocument(p, v)
            documents += doc
            out.resolve("${p.artifactId.get()}-$v.cdx.json").writeText(doc.json())
        }
        // the module itself: the root (Gradle metadata) publication of a KMP module, or the BOM
        val self = component(mavenPurl(mavenGroup.get(), module, v, null), mavenGroup.get(), module, v, pomDescription.get(), own = true)
        val aggregate = Document(self)
        for (d in documents) {
            aggregate.add(d.main)
            d.components.values.forEach(aggregate::add)
            d.dependencies.forEach { (ref, on) -> aggregate.dependencies.getOrPut(ref) { linkedSetOf() } += on }
            aggregate.dependsOn(self.ref, d.main.ref)
        }
        platformConstraints.orNull?.forEach { m ->
            val c = component(mavenPurl(mavenGroup.get(), m, v, null), mavenGroup.get(), m, v, null, own = true)
            aggregate.add(c)
            aggregate.dependsOn(self.ref, c.ref)
        }
        out.resolve("$module-$v.cdx.json").writeText(aggregate.json())
    }

    private fun publicationDocument(p: SbomPublication, v: String): Document {
        val g = mavenGroup.get()
        val pack = p.packaging.get()
        val main = component(mavenPurl(g, p.artifactId.get(), v, pack), g, p.artifactId.get(), v, pomDescription.get(), own = true)
        val doc = Document(main)
        val hashes = p.externalArtifacts.get().groupBy { it.id.componentIdentifier }
        val refs = mutableMapOf<ResolvedComponentResult, String>()
        fun refOf(c: ResolvedComponentResult): String? = refs.getOrPut(c) {
            when (val id = c.id) {
                is ProjectComponentIdentifier ->
                    if (id == p.graph.get().id) main.ref
                    else {
                        val a = "${id.projectName}-${p.siblingSuffix.get()}"
                        doc.add(component(mavenPurl(g, a, v, pack), g, a, v, null, own = true)).ref
                    }
                is ModuleComponentIdentifier -> {
                    val files = hashes[id].orEmpty().map { it.file }
                    // the main artifact <module>-<version>.<ext>; the others (cinterop klibs) are listed in properties
                    // a Kotlin/Native component resolves to its main klib (ktor-io-iosArm64Main-3.6.0.klib) and maybe cinterop klibs
                    val primary = files.firstOrNull { it.name.startsWith("${id.module}-${id.version}.") } ?: files.singleOrNull()
                        ?: files.filter { it.extension == "klib" && !it.name.contains("Cinterop") }.singleOrNull()
                    val ext = primary?.extension?.takeIf { it != "jar" }
                    val c = component(mavenPurl(id.group, id.module, id.version, ext), id.group, id.module, id.version, null, own = false)
                    primary?.let { c.sha256 = sha256(it) }
                    files.filter { it != primary }.sortedBy { it.name }.forEach { c.properties += "kuicksilver:artifact:${it.name}" to "sha256:${sha256(it)}" }
                    doc.add(c).ref
                }
                else -> return null
            }
        }
        val seen = mutableSetOf<ResolvedComponentResult>()
        fun walk(c: ResolvedComponentResult) {
            if (!seen.add(c)) return
            val from = refOf(c) ?: return
            doc.dependencies.getOrPut(from) { linkedSetOf() }
            for (d in c.dependencies) {
                if (d !is ResolvedDependencyResult || d.isConstraint) continue
                val to = refOf(d.selected) ?: continue
                if (to != from) doc.dependsOn(from, to)
                walk(d.selected)
            }
        }
        walk(p.graph.get())
        // statically linked native code: under kuicksilver-native's own publication, or the sibling that brings it in
        val nativeRef = if (moduleName.get() == "kuicksilver-native") main.ref
        else doc.components.values.firstOrNull { it.own && it.name == "kuicksilver-native-${p.siblingSuffix.get()}" }?.ref
        if (nativeRef != null) {
            val ssl = openssl()
            val ksl = ksl(v)
            doc.add(ksl); doc.add(ssl)
            doc.dependsOn(nativeRef, ksl.ref)
            doc.dependsOn(ksl.ref, ssl.ref)
            doc.dependencies.getOrPut(ssl.ref) { linkedSetOf() }
        }
        return doc
    }

    private fun ksl(v: String) = Component(
        ref = "pkg:generic/kuicksilver/ksl@$v",
        group = "io.kuicksilver", name = "ksl", version = v, purl = "pkg:generic/kuicksilver/ksl@$v",
        description = "The ksl C shim over OpenSSL (kuicksilver-native/src/c), statically linked into the JNI, Android and Kotlin/Native libraries",
        own = true,
    ).apply {
        properties += "kuicksilver:ksl:abi" to kslAbi.get()
        properties += "kuicksilver:linkage" to "static"
        vcsRevision = gitCommit.get()
    }

    private fun openssl(): Component {
        val ov = opensslVersion.get()
        val url = "https://github.com/openssl/openssl/releases/download/openssl-$ov/openssl-$ov.tar.gz"
        return Component(
            ref = "pkg:generic/openssl@$ov", group = null, name = "openssl", version = ov,
            purl = "pkg:generic/openssl@$ov?download_url=${url.replace(":", "%3A")}&checksum=sha256%3A${opensslSha256.get()}",
            description = "OpenSSL, built from the pinned release tarball with a reduced configuration and linked statically",
            own = false,
        ).apply {
            sha256 = opensslSha256.get()
            cpe = "cpe:2.3:a:openssl:openssl:$ov:*:*:*:*:*:*:*"
            supplier = "OpenSSL Foundation" to "https://openssl-library.org"
            distribution = url
            properties += "kuicksilver:linkage" to "static"
            properties += "kuicksilver:openssl:configure" to opensslConfigureFlags.get().joinToString(" ")
            // OpenSSL 3 builds its FIPS provider only with enable-fips; the flags leave it at its default (disabled), and no-module
            // rules out any loadable provider (tools/check/openssl-no-fips.sh checks each build's configdata.pm)
            properties += "kuicksilver:openssl:fips-provider" to "not built"
        }
    }

    private fun component(purl: String, g: String?, n: String, v: String, desc: String?, own: Boolean) =
        Component(purl, g, n, v, purl, desc, own).apply { if (own) vcsRevision = gitCommit.get() }

    private fun mavenPurl(g: String, a: String, v: String, type: String?) =
        "pkg:maven/$g/$a@$v" + (type?.takeIf { it != "jar" }?.let { "?type=$it" } ?: "")

    private fun sha256(f: java.io.File): String =
        MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    private class Component(
        val ref: String, val group: String?, val name: String, val version: String, val purl: String, val description: String?,
        val own: Boolean,
    ) {
        var sha256: String? = null
        var cpe: String? = null
        var supplier: Pair<String, String>? = null
        var distribution: String? = null
        var vcsRevision: String? = null
        val properties = mutableListOf<Pair<String, String>>()

        fun toMap(): Map<String, Any?> = linkedMapOf(
            "type" to "library", "bom-ref" to ref,
            "supplier" to (supplier?.let { mapOf("name" to it.first, "url" to listOf(it.second)) }
                ?: if (own) KUICKSILVER else null),
            "group" to group, "name" to name, "version" to version, "description" to description,
            "hashes" to sha256?.let { listOf(mapOf("alg" to "SHA-256", "content" to it)) },
            "licenses" to if (own || name == "openssl") listOf(mapOf("license" to mapOf("id" to "Apache-2.0"))) else null,
            "cpe" to cpe, "purl" to purl,
            "externalReferences" to listOfNotNull(
                distribution?.let { mapOf("type" to "distribution", "url" to it) },
                vcsRevision?.let { mapOf("type" to "vcs", "url" to "https://github.com/kuicksilver/kuicksilver", "comment" to "commit $it") },
            ).ifEmpty { null },
            "properties" to properties.map { mapOf("name" to it.first, "value" to it.second) }.ifEmpty { null },
        )
    }

    private inner class Document(val main: Component) {
        val components = linkedMapOf<String, Component>()
        val dependencies = linkedMapOf<String, MutableSet<String>>()

        fun add(c: Component): Component = if (c.ref == main.ref) main else components.getOrPut(c.ref) { c }

        fun dependsOn(from: String, to: String) { dependencies.getOrPut(from) { linkedSetOf() } += to }

        fun json(): String {
            val body = linkedMapOf(
                "metadata" to linkedMapOf(
                    "timestamp" to gitCommitDate.get(),
                    "tools" to mapOf("components" to listOf(mapOf("type" to "application", "group" to "io.kuicksilver", "name" to "kuicksilver-build-logic-sbom", "version" to version.get()))),
                    "component" to main.toMap(),
                    "manufacturer" to KUICKSILVER,
                    "supplier" to KUICKSILVER,
                    "licenses" to listOf(mapOf("license" to mapOf("id" to "Apache-2.0"))),
                    "properties" to listOf(mapOf("name" to "kuicksilver:git-commit", "value" to gitCommit.get())),
                ),
                "components" to components.values.sortedBy { it.ref }.map { it.toMap() },
                "dependencies" to (dependencies.keys + main.ref).distinct().sorted()
                    .map { r -> linkedMapOf("ref" to r, "dependsOn" to dependencies[r].orEmpty().sorted()) },
            )
            val content = Json.write(body)
            val serial = UUID.nameUUIDFromBytes(content.toByteArray())
            val doc = linkedMapOf<String, Any?>(
                "\$schema" to "http://cyclonedx.org/schema/bom-1.6.schema.json",
                "bomFormat" to "CycloneDX", "specVersion" to "1.6", "serialNumber" to "urn:uuid:$serial", "version" to 1,
            )
            doc.putAll(body)
            return Json.write(doc) + "\n"
        }
    }

    private companion object {
        val KUICKSILVER = mapOf("name" to "The Kuicksilver Authors", "url" to listOf("https://kuicksilver.io"))
    }
}

/** A minimal JSON writer (maps keep their order; null values and empty maps are left out). */
internal object Json {
    fun write(v: Any?, indent: String = ""): String = when (v) {
        null -> "null"
        is String -> quote(v)
        is Number, is Boolean -> v.toString()
        is Map<*, *> -> {
            val e = v.entries.filter { it.value != null }
            if (e.isEmpty()) "{}" else e.joinToString(",\n", "{\n", "\n$indent}") { "$indent  ${quote(it.key.toString())}: ${write(it.value, "$indent  ")}" }
        }
        is Iterable<*> -> {
            val e = v.toList()
            if (e.isEmpty()) "[]" else e.joinToString(",\n", "[\n", "\n$indent]") { "$indent  ${write(it, "$indent  ")}" }
        }
        else -> quote(v.toString())
    }

    private fun quote(s: String): String = buildString {
        append('"')
        for (c in s) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c == '\n' -> append("\\n")
            c == '\r' -> append("\\r")
            c == '\t' -> append("\\t")
            c < ' ' -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
        append('"')
    }
}
