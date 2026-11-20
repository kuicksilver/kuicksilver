// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import kotlinx.coroutines.runBlocking
import java.io.IOException
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import java.util.Collections
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * RFC 9849 section 10.7 on a device: the Android platform verifier, asked to stay offline (a name an accepted ECH hid),
 * opens no URL while it decides. The leaf carries an OCSP URL, a CRL distribution point and an AIA caIssuers URL
 * (http://127.0.0.1:1/...), and its issuer is not among the device's anchors: a verifier that fetched an intermediate or a
 * revocation status would open one of them, and every URL a process opens goes through the default ProxySelector, which
 * this test records. The verdict is a refusal (UnknownIssuer), reached without the network.
 */
class AndroidOfflineTrustTest {
    @Test fun offlineVerificationOpensNoUrl(): Unit =
        runBlocking {
            val opened = Collections.synchronizedList(ArrayList<URI>())
            val previous = ProxySelector.getDefault()
            ProxySelector.setDefault(
                object : ProxySelector() {
                    override fun select(uri: URI): List<Proxy> {
                        opened += uri
                        return listOf(Proxy.NO_PROXY)
                    }

                    override fun connectFailed(
                        uri: URI,
                        sa: SocketAddress,
                        ioe: IOException,
                    ) {}
                },
            )
            try {
                for (offline in listOf(true, false)) {
                    val verdict =
                        PlatformVerifier.evaluate(
                            Certificate.parsePem(LEAF),
                            HostName.normalize("server.test"),
                            TlsRole.Client,
                            offline,
                        )
                    assertIs<VerifyResult.Rejected>(verdict.result, "offline=$offline")
                }
                assertEquals(emptyList(), opened.toList(), "the platform verifier opened URLs")
            } finally {
                ProxySelector.setDefault(previous)
            }
        }

    private companion object {
        // OfflineTrustCerts.LEAF (tools/certs/gen-offline-trust-certs.sh): server.test, OCSP, CRL and caIssuers at 127.0.0.1:1
        const val LEAF: String = OfflineTrustLeaf.PEM
    }
}
