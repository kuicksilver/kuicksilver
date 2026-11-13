// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.EngineConnectorConfig
import io.ktor.server.engine.EngineSSLConnectorConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import java.security.PrivateKey

/**
 * Ktor's `sslConnector { keyStore ... }` (and `ktor.security.ssl.*`) on the JVM: the key and chain of [EngineSSLConnectorConfig.keyAlias]
 * become a [TlsIdentity]; a trust store makes client certificates required, as with Ktor's Netty and Jetty engines; its
 * `enabledProtocols` ([sslVersions]) choose the TLS versions. Ktor's connector has nothing for a stapled OCSP response or a
 * trusted gateway, so such a connector staples nothing and answers `421 Misdirected Request` for a host its certificate does
 * not name; the `EngineMain` keys `kuicksilver.tls.ocspStapling` and `kuicksilver.tls.trustedGateway` are refused next to it
 * (they apply to the port of `kuicksilver.tls.certificateChain`). An application that needs either sets `ocspStapling` or
 * `trustedGateway` on `tlsConnector(identity)` in code, or serves the port with the `kuicksilver.tls` keys.
 */
internal actual fun platformTlsConnector(c: EngineConnectorConfig): KuicksilverTlsConnector? {
    if (c !is EngineSSLConnectorConfig) return null
    val versions = sslVersions(c.enabledProtocols) // before the key is copied into native memory
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
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            this.versions = versions
            if (trust != null) {
                this.trust = trust
                clientAuth = ClientAuth.Required
            }
        }.build()
}

/**
 * Ktor's `enabledProtocols` (`ktor.security.ssl.enabledProtocols`) as [TlsVersions]: null (Ktor's default) or `TLSv1.3` alone is
 * [TlsVersions.Tls13]; `TLSv1.2` and `TLSv1.3` together are [TlsVersions.Tls12And13]. Anything else throws
 * [TlsException.Config]: TLS 1.0 and 1.1 are never negotiated (RFC 9325 section 3.1.1: "Implementations MUST NOT negotiate TLS
 * version 1.0", "1.1"), and TLS 1.2 alone is not offered (the same section: implementations "SHOULD support TLS 1.3 and, if
 * implemented, MUST prefer to negotiate TLS 1.3 over earlier versions of TLS").
 */
internal fun sslVersions(enabled: List<String>?): TlsVersions {
    if (enabled == null) return TlsVersions.Tls13
    return when (enabled.map { it.trim() }.toSet()) {
        setOf("TLSv1.3") -> TlsVersions.Tls13

        setOf("TLSv1.2", "TLSv1.3") -> TlsVersions.Tls12And13

        else -> throw TlsException.Config(
            "enabledProtocols $enabled: the Kuicksilver engine serves [TLSv1.3] or [TLSv1.2, TLSv1.3] (no TLS 1.0 or 1.1, no TLS 1.2 without 1.3)",
        )
    }
}
