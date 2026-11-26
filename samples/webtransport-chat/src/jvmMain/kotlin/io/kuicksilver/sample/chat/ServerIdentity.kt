// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.chat

import io.kuicksilver.tls.TlsIdentity
import java.io.File

/**
 * The server's certificate chain and key from PEM files, as a deployment gives them: [chainFile] and [keyFile] (an
 * unencrypted PKCS#8 key), or else the environment's `CHAT_TLS_CHAIN` and `CHAT_TLS_KEY`. Without either, the sample's
 * public test identity ([SampleServerPem]), and only for a loopback [host]: anyone has its key, so a server on the
 * network with it can be impersonated to every client that trusts the sample CA.
 */
fun serverIdentity(
    host: String,
    chainFile: String? = System.getenv("CHAT_TLS_CHAIN"),
    keyFile: String? = System.getenv("CHAT_TLS_KEY"),
): TlsIdentity {
    require((chainFile == null) == (keyFile == null)) { "give both the chain and the key file, or neither" }
    if (chainFile != null && keyFile != null) return TlsIdentity.fromPem(File(chainFile).readText(), File(keyFile).readText().toCharArray())
    require(host == "127.0.0.1" || host == "::1" || host == "localhost") {
        "$host is not loopback: give your own certificate and key (CHAT_TLS_CHAIN, CHAT_TLS_KEY), the sample's key is public"
    }
    return sampleServerIdentity()
}

/** The sample's public test identity, for loopback and the tests; the key array is zeroed after import. */
fun sampleServerIdentity(): TlsIdentity = TlsIdentity.fromPem(SampleServerPem.chainPem, SampleServerPem.keyPem.toCharArray())
