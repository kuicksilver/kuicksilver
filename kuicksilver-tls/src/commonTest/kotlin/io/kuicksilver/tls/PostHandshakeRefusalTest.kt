// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslException
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * RFC 9113 section 9.2.3: "HTTP/2 clients MUST treat a TLS post-handshake CertificateRequest message as a connection error
 * (Section 5.4.1) of type PROTOCOL_ERROR." ksl offers no post_handshake_auth, so OpenSSL refuses such a message with
 * unexpected_message before its type is visible; [TlsConnection.postHandshakeMessageRefused] recognises that refusal. No
 * server we can drive sends a CertificateRequest to a client that did not offer post_handshake_auth (OpenSSL's and the
 * JDK's refuse to), so the failure is built as ksl reports it.
 */
class PostHandshakeRefusalTest {
    private fun failure(
        packed: Int,
        alert: Int,
    ) = KslException.Internal(packed, alert, "ksl: TLS error")

    private val unexpectedMessage = (20 shl 16) or 244

    @Test fun tls13UnexpectedMessageWeSentIsARefusedPostHandshakeMessage() {
        assertTrue(TlsConnection.refusedPostHandshakeMessage(TlsVersion.Tls13, failure(unexpectedMessage, 10)))
    }

    @Test fun negative_otherFailuresAreNot() {
        // received from the peer, not sent by us
        assertFalse(TlsConnection.refusedPostHandshakeMessage(TlsVersion.Tls13, failure(unexpectedMessage, 10 or 0x100)))
        // TLS 1.2: a HelloRequest is no refusal (KSL_GET_RENEGOTIATION reports it)
        assertFalse(TlsConnection.refusedPostHandshakeMessage(TlsVersion.Tls12, failure(unexpectedMessage, 10)))
        // a bad record MAC, a decode error
        assertFalse(TlsConnection.refusedPostHandshakeMessage(TlsVersion.Tls13, failure((20 shl 16) or 281, 20)))
        assertFalse(TlsConnection.refusedPostHandshakeMessage(TlsVersion.Tls13, failure((20 shl 16) or 159, 50)))
        // ksl's own codes
        assertFalse(TlsConnection.refusedPostHandshakeMessage(TlsVersion.Tls13, failure(0xff0009, 0)))
    }
}
