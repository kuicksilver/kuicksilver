// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.EchTestKeys
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.EchConfigList
import io.kuicksilver.tls.EchKey
import io.kuicksilver.tls.EchServerKeys
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * RFC 9849 sections 6.1.6 and 6.1.7 over QUIC: a client whose ECH the server rejected completes its handshake for the
 * public_name (an empty Certificate when asked for one, no CertificateVerify, its Finished) and then aborts with
 * ech_required (CRYPTO_ERROR 0x179). The flight goes out with the CONNECTION_CLOSE: the server reads the client's
 * Finished (its handshake completes) before the close.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class EchRejectionFlightTest {
    private fun listOf(pem: String): EchConfigList {
        val body = pem.substringAfter("-----BEGIN ECHCONFIG-----").substringBefore("-----END ECHCONFIG-----")
        return EchConfigList.parseBase64(body.lines().joinToString(""))
    }

    @Test fun aRejectedClientSendsItsFlightThenEchRequired() {
        for (askForCertificate in kotlin.collections.listOf(false, true)) {
            val client =
                CoreFixtures.client(alpn = "hq-interop") {
                    echConfigList = listOf(EchTestKeys.A)
                    identity = TlsIdentity.fromDer(kotlin.collections.listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                }
            val server =
                CoreFixtures.server {
                    echKeys = EchServerKeys(kotlin.collections.listOf(EchKey(EchTestKeys.B)))
                    if (askForCertificate) {
                        clientAuth = ClientAuth.Optional
                        trust = TrustConfig.AnchoredCa(kotlin.collections.listOf(CoreFixtures.testCa))
                    }
                }
            CorePair(client, server, crypto = KslQuicCrypto).use { p ->
                p.runUntil { p.closedReason(p.serverEvents) != null && p.closedReason(p.clientEvents) != null }
                val atServer = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.serverEvents))
                assertEquals(Initiator.Peer, atServer.initiator)
                assertEquals(0x100L + 121, atServer.code, "ech_required (CRYPTO_ERROR 0x179)")
                // the server drains on the CONNECTION_CLOSE and drives its TLS no more; the flight that came with it was
                // handed to its TLS session, which completes on it
                val session = p.server!!.handshake.session
                val r = session.drive()
                assertTrue(r !is io.kuicksilver.tls.DriveResult.Failed, "$r")
                var done = false
                while (true) {
                    val ev = session.nextEvent() ?: break
                    if (ev is io.kuicksilver.tls.TlsEvent.HandshakeDone) done = true
                    if (ev is io.kuicksilver.tls.TlsEvent.Keys) ev.protector.close()
                }
                assertTrue(done, "the server read the client's Finished before the close (askForCertificate=$askForCertificate)")
                assertTrue(session.peerCertificates.isEmpty(), "the client sent an empty Certificate")
            }
        }
    }
}
