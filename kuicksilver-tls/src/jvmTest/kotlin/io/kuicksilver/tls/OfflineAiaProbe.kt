// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import java.io.IOException
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import java.security.KeyStore
import java.util.Collections
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The child JVM of [OfflineTrustJvmTest.offlineFetchesNoIntermediateWithAiaOn], started with
 * `-Dcom.sun.security.enableAIAcaIssuers=true` (read once per process by the JDK's path builder): verifies the offline
 * test leaf, whose issuer is not among the system anchors, as [JvmTrust.evaluate] with `offline` from the first argument,
 * and prints every URL the JDK opened (each goes through the default ProxySelector) as `fetched <uri>`, then `done`.
 */
fun main(args: Array<String>) {
    val opened = Collections.synchronizedList(ArrayList<URI>())
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
    val tmf = TrustManagerFactory.getInstance("PKIX")
    tmf.init(null as KeyStore?)
    val base = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    val result = JvmTrust.evaluate(base, Certificate.parsePem(OfflineTrustCerts.LEAF), TlsRole.Client, args[0].toBoolean()).result
    for (u in opened) println("fetched $u")
    println("done ${result::class.simpleName}")
}
