// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import io.kuicksilver.tls.tlsConfig
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import platform.posix.getenv
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * TrustConfig.Platform on Windows against the public Internet: a real chain to a root in the Windows store is accepted, and
 * badssl.com's deliberately broken certificates fail with the right reason. Reaches the network, so it runs only with
 * `KUICKSILVER_NETWORK_TESTS=1` in the environment; otherwise every case returns at once.
 */
class WindowsPlatformTrustNetworkTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val enabled = getenv("KUICKSILVER_NETWORK_TESTS")?.toKString() == "1"

    private fun handshake(host: String) =
        runBlocking {
            withTimeout(60.seconds) {
                SelectorManager(Dispatchers.Default).use { selector ->
                    aSocket(selector).tcp().connect(host, 443).use { socket ->
                        val tls =
                            socket.tls(
                                tlsConfig(TlsRole.Client) {
                                    serverName = host
                                    alpn = listOf("http/1.1")
                                    versions = TlsVersions.Tls12And13 // badssl.com speaks TLS 1.2 only
                                    trust = TrustConfig.Platform
                                },
                            )
                        tls.peerCertificates.size.also { tls.close() }
                    }
                }
            }
        }

    private fun rejection(host: String): VerifyReason = assertFailsWith<TlsException.Verify> { handshake(host) }.reason

    @Test fun publicSiteIsTrusted() {
        if (!enabled) return
        assertTrue(handshake("www.google.com") >= 1)
    }

    @Test fun negative_expiredCertificate() {
        if (!enabled) return
        assertIs<VerifyReason.Expired>(rejection("expired.badssl.com"))
    }

    @Test fun negative_wrongHost() {
        if (!enabled) return
        assertIs<VerifyReason.HostnameMismatch>(rejection("wrong.host.badssl.com"))
    }

    @Test fun negative_untrustedRoot() {
        if (!enabled) return
        assertIs<VerifyReason.UnknownIssuer>(rejection("untrusted-root.badssl.com"))
    }

    @Test fun negative_selfSigned() {
        if (!enabled) return
        assertIs<VerifyReason.UnknownIssuer>(rejection("self-signed.badssl.com"))
    }
}
