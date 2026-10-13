// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.reflect.KClass

/**
 * The Ktor version the engines are built for, checked when a client engine is created and a server engine starts
 * (docs/guide/ktor.md, "Supported Ktor versions"). The engines use Ktor internals (docs/ktor-internal-api.md), so another
 * minor release of Ktor can fail later with `NoSuchMethodError` or wrong behaviour; this check fails first, with a message
 * that says what to do.
 *
 * On the JVM and Android the version comes from the `Implementation-Version` in the manifest of the jar that holds the
 * given Ktor class; where it cannot be read (Android's dex, a shaded or repackaged jar, classes from a directory) the
 * check passes. Kotlin/Native resolves klibs at link time, so a different Ktor fails the link; nothing is checked there.
 */
@InternalKuicksilverApi
public object KtorVersionPolicy {
    /** Major.minor of the Ktor release the engines are compiled and tested against. */
    public const val SUPPORTED: String = "3.6"

    /** The JVM system property that turns the check off when set to `false` (experts who verified their Ktor). */
    public const val CHECK_PROPERTY: String = "kuicksilver.ktor.versionCheck"

    /**
     * Fails with [IllegalStateException] when the runtime version of one of [artifacts] (artifact name to a class it
     * contains) differs from [SUPPORTED] in major.minor, unless [CHECK_PROPERTY] is `false`.
     */
    public fun check(vararg artifacts: Pair<String, KClass<*>>) {
        if (versionCheckDisabled()) return
        for ((artifact, anchor) in artifacts) {
            mismatch(artifact, ktorArtifactVersion(anchor))?.let { throw IllegalStateException(it) }
        }
    }

    /** The failure message when [found] (null: unknown, accepted) is not a [supported] release; null when it is. */
    public fun mismatch(
        artifact: String,
        found: String?,
        supported: String = SUPPORTED,
    ): String? {
        if (found == null) return null
        val parts = found.split('.', '-')
        if (parts.size >= 2 && "${parts[0]}.${parts[1]}" == supported) return null
        return "Kuicksilver's Ktor engines support Ktor $supported.x, but $artifact $found is on the classpath. Align every " +
            "io.ktor artifact to $supported.x (for example with `platform(\"io.ktor:ktor-bom:$supported.<patch>\")`), or, " +
            "at your own risk, start the JVM with -D$CHECK_PROPERTY=false (docs/guide/ktor.md, \"Supported Ktor versions\")."
    }
}

/** The `Implementation-Version` of the artifact that holds [anchor], or null where it cannot be read. */
internal expect fun ktorArtifactVersion(anchor: KClass<*>): String?

/** Whether [KtorVersionPolicy.CHECK_PROPERTY] is `false`. */
internal expect fun versionCheckDisabled(): Boolean
