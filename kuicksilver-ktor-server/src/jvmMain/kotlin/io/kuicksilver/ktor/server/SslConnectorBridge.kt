// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.EngineConnectorConfig
import io.ktor.server.engine.EngineSSLConnectorConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import java.security.PrivateKey

/**
 * Ktor's `sslConnector { keyStore ... }` (and `ktor.security.ssl.*`) on the JVM: the key and chain of [EngineSSLConnectorConfig.keyAlias]
 * become a [TlsIdentity]; a trust store makes client certificates required, as with Ktor's Netty and Jetty engines.
 */
internal actual fun platformTlsConnector(c: EngineConnectorConfig): KuicksilverTlsConnector? {
    if (c !is EngineSSLConnectorConfig) return null
    val key =
        c.keyStore.getKey(c.keyAlias, c.privateKeyPassword()) as? PrivateKey
            ?: throw TlsException.Config("no private key under alias '${c.keyAlias}'")
    val chain =
        c.keyStore.getCertificateChain(c.keyAlias)?.map { it.encoded }
            ?: throw TlsException.Config("no certificate chain under alias '${c.keyAlias}'")
    val identity = TlsIdentity.fromDer(chain, key.encoded) // PKCS#8
    val trust =
        c.trustStore?.let { ts ->
            TrustConfig.AnchoredCa(ts.aliases().toList().mapNotNull { a -> ts.getCertificate(a)?.encoded?.let { Certificate(it) } })
        }
    return KuicksilverTlsConnector
        .Builder(identity)
        .apply {
            host = c.host
            port = c.port
            if (trust != null) {
                this.trust = trust
                clientAuth = ClientAuth.Required
            }
        }.build()
}
