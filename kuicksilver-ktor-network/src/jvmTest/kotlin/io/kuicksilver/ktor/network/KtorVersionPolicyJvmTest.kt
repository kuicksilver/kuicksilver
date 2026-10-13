// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.Job
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class KtorVersionPolicyJvmTest {
    /** On the JVM the version is read from the Ktor jar's manifest, not guessed. */
    @Test fun readsTheJarManifest() {
        assertEquals(KtorVersionPolicy.SUPPORTED, ktorArtifactVersion(ByteReadChannel::class)!!.split('.').take(2).joinToString("."))
    }

    /** A class outside any jar (a test class from a directory) has no version: the check passes rather than guessing. */
    @Test fun noManifestIsUnknown() = assertNull(ktorArtifactVersion(KtorVersionPolicyJvmTest::class))

    /** The failing path end to end: a jar whose version is not 3.6.x (kotlinx-coroutines 1.x) stands in for a newer Ktor. */
    @Test fun otherVersionFailsFastUnlessTurnedOff() {
        val e = assertFailsWith<IllegalStateException> { KtorVersionPolicy.check("ktor-client-core" to Job::class) }
        assertContains(e.message!!, "ktor-client-core 1.")
        withProperty("false") { KtorVersionPolicy.check("ktor-client-core" to Job::class) }
    }

    @Test fun propertyTurnsTheCheckOff() {
        val old = System.getProperty(KtorVersionPolicy.CHECK_PROPERTY)
        try {
            System.setProperty(KtorVersionPolicy.CHECK_PROPERTY, "false")
            assertEquals(true, versionCheckDisabled())
            System.setProperty(KtorVersionPolicy.CHECK_PROPERTY, "true")
            assertEquals(false, versionCheckDisabled())
        } finally {
            if (old ==
                null
            ) {
                System.clearProperty(KtorVersionPolicy.CHECK_PROPERTY)
            } else {
                System.setProperty(KtorVersionPolicy.CHECK_PROPERTY, old)
            }
        }
    }

    private fun withProperty(
        value: String,
        block: () -> Unit,
    ) {
        val old = System.getProperty(KtorVersionPolicy.CHECK_PROPERTY)
        try {
            System.setProperty(KtorVersionPolicy.CHECK_PROPERTY, value)
            block()
        } finally {
            if (old ==
                null
            ) {
                System.clearProperty(KtorVersionPolicy.CHECK_PROPERTY)
            } else {
                System.setProperty(KtorVersionPolicy.CHECK_PROPERTY, old)
            }
        }
    }
}
