// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.chat

import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig

/**
 * The client's side of TLS. Common code ships in every client build, so only what a client may hold is here: the CA it
 * trusts, never a server key (the JVM server's identity is `serverIdentity` in jvmMain).
 */
object ChatTls {
    /**
     * What the client trusts: the CA certificates of [caPem] only (the sample CA by default; pass your own for a server
     * with your own certificate), the URL's host checked against the certificate as always.
     */
    fun clientTrust(caPem: String = SampleCa.caPem): TrustConfig = TrustConfig.AnchoredCa(Certificate.parsePem(caPem))
}
