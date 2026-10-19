// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.Classpath
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.workers.WorkAction
import org.gradle.workers.WorkParameters
import org.gradle.workers.WorkerExecutor
import javax.inject.Inject

/**
 * Validates CycloneDX JSON documents against the CycloneDX 1.6 JSON schema with cyclonedx-core-java (the reference library,
 * which carries the schema and its SPDX and JSF parts), in an isolated class loader and by reflection: the library and its
 * Jackson stay off the build-logic class path. Fails on the first document with a schema error and lists every error of it.
 */
abstract class ValidateCyclonedxTask @Inject constructor(private val workers: WorkerExecutor) : DefaultTask() {
    @get:InputFiles @get:PathSensitive(PathSensitivity.NAME_ONLY) abstract val documents: ConfigurableFileCollection

    /** cyclonedx-core-java and its runtime dependencies (the `cyclonedxValidator` configuration). */
    @get:Classpath abstract val validatorClasspath: ConfigurableFileCollection

    /** One line per document: its name and `valid`; written only when all are. */
    @get:OutputFile abstract val report: RegularFileProperty

    @TaskAction
    fun validate() {
        val files = documents.files.filter { it.name.endsWith(".cdx.json") }.sortedBy { it.name }
        if (files.isEmpty()) throw GradleException("no CycloneDX documents to validate")
        val stdlib = java.io.File(KotlinVersion::class.java.protectionDomain.codeSource.location.toURI())
        val queue = workers.classLoaderIsolation { classpath.from(validatorClasspath, stdlib) }
        queue.submit(ValidateCyclonedxAction::class.java) {
            this.documents.from(files)
            this.report.set(this@ValidateCyclonedxTask.report)
        }
        queue.await()
        logger.lifecycle("CycloneDX 1.6 schema: ${files.size} documents valid (${report.get().asFile})")
    }
}

/** The worker side of ValidateCyclonedxTask: runs in the class loader that holds cyclonedx-core-java. */
abstract class ValidateCyclonedxAction : WorkAction<ValidateCyclonedxAction.Parameters> {
    interface Parameters : WorkParameters {
        val documents: ConfigurableFileCollection
        val report: RegularFileProperty
    }

    override fun execute() {
        // by reflection: build-logic does not compile against the library, so it adds nothing to the build class path
        val loader = javaClass.classLoader
        val parser = loader.loadClass("org.cyclonedx.parsers.JsonParser").getConstructor().newInstance()
        val v16 = loader.loadClass("org.cyclonedx.Version").getField("VERSION_16").get(null)
        val validate = parser.javaClass.getMethod("validate", java.io.File::class.java, v16.javaClass)
        val lines = mutableListOf<String>()
        for (f in parameters.documents.files.sortedBy { it.name }) {
            val errors = validate.invoke(parser, f, v16) as List<*>
            if (errors.isNotEmpty()) {
                throw GradleException("${f.name} is not a valid CycloneDX 1.6 document:\n" + errors.joinToString("\n") { "  ${(it as Throwable).message}" })
            }
            lines += "${f.name} valid"
        }
        parameters.report.get().asFile.writeText(lines.joinToString("\n", postfix = "\n"))
    }
}
