// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The test PKI of the C tests (tools/certs/gen-testcerts.sh), read from the DER files on the test class path: a self-signed
 * P-256 test CA and a server leaf for `server.test`, `127.0.0.1` and `::1`. Every peer, ours and the others, uses the same
 * files: our engines through [TlsIdentity] and [TrustConfig], the JDK, Netty and OkHttp through a key store and an
 * [SSLContext].
 */
internal object Pki {
    private fun der(name: String): ByteArray =
        checkNotNull(Pki::class.java.classLoader.getResourceAsStream(name)) { "$name is not on the test class path" }.use { it.readBytes() }

    val caDer: ByteArray by lazy { der("test-ca.der") }
    val otherCaDer: ByteArray by lazy { der("other-ca.der") }
    val serverDer: ByteArray by lazy { der("server.der") }
    private val serverKeyDer: ByteArray by lazy { der("server.key.der") }

    private fun x509(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    val ca: X509Certificate by lazy { x509(caDer) }
    val server: X509Certificate by lazy { x509(serverDer) }
    val serverKey: PrivateKey by lazy { KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(serverKeyDer)) }

    /**
     * Our server's identity (a fresh copy: the engine zeroes the key array it imports): the leaf alone, as most servers
     * send it (RFC 8446 section 4.4.2: "a certificate that specifies a trust anchor MAY be omitted from the chain").
     */
    fun identity(): TlsIdentity = TlsIdentity.fromDer(listOf(serverDer), serverKeyDer.copyOf())

    /** Our client's trust: the test CA as the only anchor. */
    val trust: TrustConfig get() = TrustConfig.AnchoredCa(listOf(Certificate(caDer)))

    /** Trust in an unrelated CA only, for the negative TLS tests. */
    val otherTrust: TrustConfig get() = TrustConfig.AnchoredCa(listOf(Certificate(otherCaDer)))

    const val KEY_ALIAS = "server"
    val password: CharArray get() = "interop".toCharArray()

    /** The server key and chain as a PKCS#12 store in memory, for Ktor's `sslConnector` (Netty) and plain Netty. */
    val serverKeyStore: KeyStore by lazy {
        KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry(KEY_ALIAS, serverKey, password, arrayOf(server, ca))
        }
    }

    /** A trust manager with the test CA (or [other]) as its only anchor, for the JDK and OkHttp clients. */
    fun trustManager(other: Boolean = false): X509TrustManager {
        val store =
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setCertificateEntry("ca", if (other) x509(otherCaDer) else ca)
            }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().single()
    }

    /** A client [SSLContext] (TLS 1.3 and 1.2, the JDK's defaults) that trusts the test CA (or [other]). */
    fun clientContext(other: Boolean = false): SSLContext =
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager(other)), null) }
}
