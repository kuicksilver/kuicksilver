// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import kotlin.test.Test
import kotlin.test.assertEquals

class VerifyReasonMessageTest {
    private val objectReasons: Map<VerifyReason, String> =
        mapOf(
            VerifyReason.UnknownIssuer to "UnknownIssuer",
            VerifyReason.Expired to "Expired",
            VerifyReason.NotYetValid to "NotYetValid",
            VerifyReason.Revoked to "Revoked",
            VerifyReason.UnknownRevocationStatus to "UnknownRevocationStatus",
            VerifyReason.BadSignature to "BadSignature",
            VerifyReason.InvalidPurpose to "InvalidPurpose",
            VerifyReason.BadEncoding to "BadEncoding",
            VerifyReason.NoCertificate to "NoCertificate",
            VerifyReason.CertificateTransparency to "CertificateTransparency",
        )

    @Test
    fun objectReasonsPrintTheirName() {
        for ((reason, name) in objectReasons) {
            assertEquals(name, reason.toString())
        }
    }

    @Test
    fun verifyMessageNamesTheReason() {
        for ((reason, name) in objectReasons) {
            val e = TlsException.Verify(reason, emptyList())
            assertEquals("certificate verification failed: $name", e.message)
        }
        val custom = TlsException.Verify(VerifyReason.Custom("pinned elsewhere"), emptyList())
        assertEquals("certificate verification failed: Custom(pinned elsewhere)", custom.message)
    }
}
