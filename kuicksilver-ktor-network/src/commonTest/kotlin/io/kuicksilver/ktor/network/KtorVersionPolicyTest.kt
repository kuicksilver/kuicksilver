// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteReadChannel
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class KtorVersionPolicyTest {
    @Test fun sameMinorPasses() {
        assertNull(KtorVersionPolicy.mismatch("ktor-client-core", "3.6.0", "3.6"))
        assertNull(KtorVersionPolicy.mismatch("ktor-client-core", "3.6.12", "3.6"))
        assertNull(KtorVersionPolicy.mismatch("ktor-client-core", "3.6.1-eap-42", "3.6"))
    }

    @Test fun unknownVersionPasses() = assertNull(KtorVersionPolicy.mismatch("ktor-client-core", null, "3.6"))

    @Test fun otherMinorOrMajorFails() {
        for (v in listOf("3.7.0", "3.5.2", "4.0.0", "3", "3.60.0")) {
            val m = assertNotNull(KtorVersionPolicy.mismatch("ktor-client-core", v, "3.6"), v)
            assertContains(m, "ktor-client-core $v")
            assertContains(m, "3.6.x")
            assertContains(m, "-D${KtorVersionPolicy.CHECK_PROPERTY}=false")
        }
    }

    /** The build's own Ktor passes: [KtorVersionPolicy.SUPPORTED] follows `gradle/libs.versions.toml`. */
    @Test fun runtimeKtorIsSupported() {
        KtorVersionPolicy.check("ktor-io" to ByteReadChannel::class)
        ktorArtifactVersion(
            ByteReadChannel::class,
        )?.let { assertEquals(KtorVersionPolicy.SUPPORTED, it.split('.').take(2).joinToString(".")) }
    }
}
