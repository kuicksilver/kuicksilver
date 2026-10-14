// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class VersionInformationTest {
    private val v1 = 0x00000001
    private val v2 = 0x6b3343cf

    private fun tp(
        chosen: Int,
        vararg available: Int,
    ) = TransportParameters().apply {
        chosenVersion = chosen
        availableVersions = available
    }

    private fun both() = listOf(VersionProfile.V1, VersionProfile.V2)

    private fun expect11(block: () -> Unit) {
        val e = assertFailsWith<QuicWireException>(block = block)
        assertEquals(0x11L, e.code)
    }

    private fun expect08(block: () -> Unit) {
        val e = assertFailsWith<QuicWireException>(block = block)
        assertEquals(0x08L, e.code)
    }

    @Test fun versionInformationRoundTrip() {
        val back = TransportParametersCodec.decode(TransportParametersCodec.encode(tp(v2, v2, v1), TlsRole.Server, 27), TlsRole.Server)
        assertEquals(v2, back.chosenVersion)
        assertEquals(listOf(v2, v1), back.availableVersions!!.toList())
    }

    @Test fun versionInformationLengthNotMultipleOf4Rejected() =
        expect08 {
            TransportParametersCodec.decode(byteArrayOf(0x11, 6, 0, 0, 0, 1, 0, 0), TlsRole.Server)
        }

    @Test fun chosenVersionZeroRejected() =
        expect08 {
            TransportParametersCodec.decode(byteArrayOf(0x11, 8, 0, 0, 0, 0, 0, 0, 0, 1), TlsRole.Server)
        }

    /** RFC 9368 section 4: "any Available Version equal to zero ... MUST treat it as a parsing failure". */
    @Test fun negative_availableVersionZeroRejected() =
        expect08 {
            TransportParametersCodec.decode(byteArrayOf(0x11, 8, 0, 0, 0, 1, 0, 0, 0, 0), TlsRole.Server)
        }

    /** RFC 9368 section 4: a server treats a client Chosen Version missing from its Available Versions as a parsing failure. */
    @Test fun negative_clientChosenVersionNotInAvailableRejected() {
        expect08 { TransportParametersCodec.decode(byteArrayOf(0x11, 8, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf.toByte()), TlsRole.Client) }
        expect08 { TransportParametersCodec.decode(byteArrayOf(0x11, 4, 0, 0, 0, 1), TlsRole.Client) }
        // a server's list need not contain its Chosen Version and may be empty (section 3)
        TransportParametersCodec.decode(byteArrayOf(0x11, 4, 0, 0, 0, 1), TlsRole.Server)
    }

    /** RFC 9368 section 4: "if the client reacted to a Version Negotiation packet and the server's Available Versions field is empty". */
    @Test fun negative_emptyAvailableVersionsAfterVnRejected() =
        expect11 {
            VersionNegotiationValidator.clientCheck(v2, v1, tp(v1), intArrayOf(v1), both())
        }

    @Test fun chooseVersionServerPreferenceFirst() {
        assertEquals(v2, chooseVersion(intArrayOf(v2, v1), v1, intArrayOf(v1, v2)))
        assertEquals(v1, chooseVersion(intArrayOf(v1, v2), v1, intArrayOf(v1, v2)))
    }

    @Test fun chooseVersionFallsBackToOriginal() {
        assertEquals(v1, chooseVersion(intArrayOf(v2, v1), v1, intArrayOf(v1)))
        assertEquals(v1, chooseVersion(intArrayOf(v2), v1, null))
    }

    @Test fun negative_serverChosenVersionMismatchesPacketVersion() =
        expect11 {
            VersionNegotiationValidator.clientCheck(v1, v1, tp(v2, v2, v1), null, both())
        }

    @Test fun negative_clientChosenVersionMismatchesInitial() = expect11 { VersionNegotiationValidator.serverCheck(v1, v1, tp(v2, v1, v2)) }

    @Test fun negative_downgradeAfterVersionNegotiation() =
        expect11 {
            VersionNegotiationValidator.clientCheck(v2, v1, tp(v1, v1, v2), intArrayOf(v1), both())
        }

    @Test fun missingVersionInformationAfterVnIsError() =
        expect11 {
            VersionNegotiationValidator.clientCheck(v2, v1, TransportParameters(), intArrayOf(v1), both())
        }

    @Test fun validNegotiationPasses() {
        VersionNegotiationValidator.clientCheck(v1, v2, tp(v2, v2, v1), null, both())
        VersionNegotiationValidator.serverCheck(v1, v2, tp(v1, v1, v2))
        VersionNegotiationValidator.clientCheck(v1, v1, TransportParameters(), null, listOf(VersionProfile.V1))
    }
}
