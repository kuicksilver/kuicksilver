// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import java.util.jar.Manifest
import kotlin.reflect.KClass

private val versions = ConcurrentHashMap<String, Result<String?>>()

/**
 * The manifest of the jar the class was loaded from (not `Package.implementationVersion`, which belongs to whichever jar
 * defined the package first), falling back to the package's version; null on Android (dex), for classes from a directory,
 * and for a jar without the attribute.
 */
internal actual fun ktorArtifactVersion(anchor: KClass<*>): String? =
    versions
        .getOrPut(anchor.java.name) {
            runCatching {
                val cls = anchor.java
                val resource = cls.name.replace('.', '/') + ".class"
                val url = (cls.classLoader ?: ClassLoader.getSystemClassLoader())?.getResource(resource)?.toString()
                val fromJar =
                    url?.takeIf { it.startsWith("jar:") }?.let { u ->
                        val conn = URI(u.substringBefore("!/") + "!/META-INF/MANIFEST.MF").toURL().openConnection()
                        conn.useCaches = false
                        conn.getInputStream().use { Manifest(it).mainAttributes.getValue("Implementation-Version") }
                    }
                // Android defines every package of an app with the versions "0.0" (dalvik's ClassLoader.definePackage): not
                // a Ktor version, so on Android only a jar manifest counts, and dex classes have none
                fromJar ?: cls.`package`?.implementationVersion?.takeUnless { onAndroid }
            }
        }.getOrNull()

@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal actual fun versionCheckDisabled(): Boolean =
    System.getProperty(KtorVersionPolicy.CHECK_PROPERTY).equals("false", ignoreCase = true)

/** ART and Dalvik report `java.vm.name` "Dalvik". */
private val onAndroid: Boolean = System.getProperty("java.vm.name").orEmpty().contains("Dalvik", ignoreCase = true)
