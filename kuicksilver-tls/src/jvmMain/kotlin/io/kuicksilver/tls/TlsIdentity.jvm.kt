// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import java.security.KeyStore
import java.security.cert.X509Certificate

/** JVM: import an identity from a `KeyStore` (migration path from Ktor's `sslConnector { keyStore }`); the key is exported as PKCS#8 and zeroed after import. */
public fun TlsIdentity.Companion.fromKeyStore(
    keyStore: KeyStore,
    alias: String,
    password: CharArray,
): TlsIdentity.InMemory {
    try {
        val key = keyStore.getKey(alias, password) ?: throw TlsException.Config("no key for alias '$alias'")
        if (key.format != "PKCS#8") throw TlsException.Config("key '$alias' is not exportable as PKCS#8 (format ${key.format})")
        val chain =
            keyStore.getCertificateChain(alias)?.map { (it as X509Certificate).encoded }
                ?: throw TlsException.Config("no certificate chain for alias '$alias'")
        return fromDer(chain, key.encoded)
    } finally {
        password.fill('\u0000')
    }
}

/** JVM: PKCS#12 bundles through the JDK keystore provider. */
public fun TlsIdentity.Companion.fromPkcs12(
    bytes: ByteArray,
    password: CharArray,
): TlsIdentity.InMemory {
    val ks = KeyStore.getInstance("PKCS12")
    ks.load(bytes.inputStream(), password)
    val alias = ks.aliases().toList().firstOrNull { ks.isKeyEntry(it) } ?: throw TlsException.Config("no key entry in the PKCS#12 bundle")
    return fromKeyStore(ks, alias, password)
}
