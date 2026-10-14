// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.ktor.network.KtorVersionPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The startup Ktor version check covers every artifact whose internals the engine uses (docs/ktor-internal-api.md). */
class KtorArtifactsTest {
    /** The server core, the HTTP/1.1 parser, the sockets and the I/O channels: a mismatch in any of them fails at startup, not later with NoSuchMethodError. */
    @Test fun everyArtifactTheEngineDependsOnIsChecked() {
        assertEquals(setOf("ktor-server-core", "ktor-http-cio", "ktor-network", "ktor-io"), KTOR_ARTIFACTS.map { it.first }.toSet())
    }

    /** Each anchor class is loaded from the jar of the artifact it stands for, so the check reads that artifact's version. */
    @Test fun eachAnchorComesFromItsArtifact() {
        for ((artifact, anchor) in KTOR_ARTIFACTS) {
            val jar =
                anchor.java.protectionDomain.codeSource.location
                    .toString()
                    .substringAfterLast('/')
            assertTrue(jar.startsWith("$artifact-"), "$artifact is anchored by a class from $jar")
        }
    }

    /** The build's own Ktor passes the check. */
    @OptIn(InternalKuicksilverApi::class)
    @Test
    fun buildKtorPasses() = KtorVersionPolicy.check(*KTOR_ARTIFACTS.toTypedArray())
}
