// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

@OptIn(ExperimentalKuicksilverApi::class)
class VersionUpgradeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val v1v2 = quicConfig { versions = listOf(VersionProfile.V1, VersionProfile.V2) }
    private val v2v1 =
        quicConfig {
            versions =
                listOf(VersionProfile.V2, VersionProfile.V1)
        }

    private fun headerVersion(b: ByteArray): Int =
        if (b[0].toInt() and 0x80 !=
            0
        ) {
            ((b[1].toInt() and 0xff) shl 24) or ((b[2].toInt() and 0xff) shl 16) or ((b[3].toInt() and 0xff) shl 8) or
                (b[4].toInt() and 0xff)
        } else {
            -1
        }

    @Test fun compatibleUpgradeV1ToV2() {
        val serverVersions = ArrayList<Int>()
        val p = CorePair(clientQuic = v1v2, serverQuic = v2v1, crypto = ksl)
        p.filterToClient =
            { _, b ->
                headerVersion(b).takeIf { it >= 0 }?.let { serverVersions += it }
                true
            }
        try {
            assertTrue(p.handshake())
            assertEquals(VersionProfile.V2, p.client.version)
            assertEquals(VersionProfile.V2, p.server!!.version)
            assertTrue(
                serverVersions.isNotEmpty() &&
                    serverVersions.all {
                        it == VersionProfile.V2.version
                    },
                "every server long-header packet is v2: $serverVersions",
            )
        } finally {
            p.close()
        }
    }

    @Test fun clientPreferringV2StartsInV1AndUpgrades() {
        // the interop runner's v2 case and RFC 9368 section 2.3: the first flight is v1, the preference list says v2 first
        val prefersV2 =
            quicConfig {
                versions = listOf(VersionProfile.V2, VersionProfile.V1)
                initialVersion = VersionProfile.V1
            }
        val clientVersions = ArrayList<Int>()
        val p = CorePair(clientQuic = prefersV2, serverQuic = v2v1, crypto = ksl)
        p.filterToServer =
            { _, b ->
                headerVersion(b).takeIf { it >= 0 }?.let { clientVersions += it }
                true
            }
        try {
            assertTrue(p.handshake())
            assertEquals(VersionProfile.V1.version, clientVersions.first(), "the first flight is v1")
            assertEquals(VersionProfile.V2, p.client.version)
            assertEquals(VersionProfile.V2, p.server!!.version)
        } finally {
            p.close()
        }
    }

    @Test fun clientStartingInV2() {
        val p = CorePair(clientQuic = v2v1, serverQuic = v2v1, crypto = ksl)
        try {
            assertTrue(p.handshake())
            assertEquals(VersionProfile.V2, p.client.version)
            assertEquals(VersionProfile.V2, p.server!!.version)
        } finally {
            p.close()
        }
    }

    @Test fun v1OnlyServerKeepsV1() {
        val p = CorePair(clientQuic = v1v2, crypto = ksl)
        try {
            assertTrue(p.handshake())
            assertEquals(VersionProfile.V1, p.client.version)
            assertEquals(VersionProfile.V1, p.server!!.version)
        } finally {
            p.close()
        }
    }

    @Test fun serverOrderV1V2StaysV1() {
        val p = CorePair(clientQuic = v1v2, serverQuic = v1v2, crypto = ksl)
        try {
            assertTrue(p.handshake())
            assertEquals(VersionProfile.V1, p.client.version)
        } finally {
            p.close()
        }
    }

    @Test fun defaultConfigNeverSendsV2() {
        val versions = HashSet<Int>()
        val p = CorePair(serverQuic = v2v1, crypto = ksl)
        p.filterToServer =
            { _, b ->
                headerVersion(b).takeIf { it >= 0 }?.let { versions += it }
                true
            }
        try {
            assertTrue(p.handshake())
            assertEquals(setOf(1), versions)
            assertEquals(VersionProfile.V1, p.server!!.version)
        } finally {
            p.close()
        }
    }

    @Test fun versionInformationCheckedOnBothSides() {
        val p = CorePair(clientQuic = v1v2, serverQuic = v2v1, crypto = ksl)
        p.client.testForgeChosenVersion = true
        try {
            assertFalse(p.handshake())
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(s)
            assertEquals(0x11L, s.code)
        } finally {
            p.close()
        }
    }
}
