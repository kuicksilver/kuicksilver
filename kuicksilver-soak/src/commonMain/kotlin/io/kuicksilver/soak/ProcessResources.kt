// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

/**
 * What the process holds, per platform: `proc.rssKiB` (resident set), `proc.fds` (open descriptors); on the JVM also
 * `jvm.heapAfterGcKiB`, `jvm.directKiB`, `jvm.directBuffers`, `jvm.threads`; on Kotlin/Native `kn.heapAfterGcKiB`.
 * Every sample runs a full GC first, so heap figures are live data, not garbage.
 */
internal expect object ProcessResources {
    fun sample(): Map<String, Long>

    /** A configuration value from the environment (the Gradle build forwards `-Pkuicksilver.soak.*` as `KSL_SOAK_*`). */
    fun env(name: String): String?
}
