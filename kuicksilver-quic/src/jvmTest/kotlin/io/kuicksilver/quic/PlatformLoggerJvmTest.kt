// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.quic

import java.io.File
import java.net.URLClassLoader
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** On the JVM the platform logger is SLF4J; without an SLF4J provider (as in these tests) it writes to standard error instead of nowhere. */
class PlatformLoggerJvmTest {
    @Test fun withoutAnSlf4jProviderTheWarningsGoToStandardError() {
        val provider = org.slf4j.LoggerFactory.getLogger("io.kuicksilver") !is org.slf4j.helpers.NOPLogger
        val name = KuicksilverLogger.platform(LogLevel.Warn).toString()
        assertTrue(if (provider) "SLF4J" in name else name == "KuicksilverLogger.stderr(Warn)", name)
    }

    /**
     * The module compiles against SLF4J only (Ktor's JVM artifacts bring it at run time): without `slf4j-api` on the class
     * path the platform logger is standard error, not a `NoClassDefFoundError` at the first warning. The module's classes are
     * loaded again here in a class loader that has everything of this test's class path but SLF4J.
     */
    @Test fun withoutSlf4jOnTheClassPathTheWarningsGoToStandardError() {
        val path = System.getProperty("java.class.path").split(File.pathSeparator).filter { it.isNotEmpty() }
        val urls = path.filter { "slf4j" !in File(it).name }.map { File(it).toURI().toURL() }
        assertTrue(urls.size < path.size, "SLF4J is on the test class path: $path")
        URLClassLoader(urls.toTypedArray(), ClassLoader.getPlatformClassLoader()).use { loader ->
            assertFailsWith<ClassNotFoundException> { loader.loadClass("org.slf4j.LoggerFactory") }
            val levels = loader.loadClass("io.kuicksilver.quic.LogLevel")
            val warn = levels.enumConstants.single { it.toString() == "Warn" }
            val platform =
                loader
                    .loadClass("io.kuicksilver.quic.PlatformLogger_jvmKt")
                    .declaredMethods
                    .single { it.name.startsWith("platformLogger") }
            assertEquals("KuicksilverLogger.stderr(Warn)", platform.invoke(null, warn).toString())
        }
    }
}
