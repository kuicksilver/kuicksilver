// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import javax.net.ssl.SSLException

/** JVM: an `SSLException` (itself an `IOException`), so Ktor and application code catching `SSLException` keep working. */
public actual sealed class TlsException actual constructor(
    message: String,
    cause: Throwable?,
) : SSLException(message, cause) {
    public actual class AlertReceived actual constructor(
        public actual val code: Int,
        public actual val description: String,
    ) : TlsException("TLS alert received from the peer: $description ($code)", null)

    public actual class Verify actual constructor(
        public actual val reason: VerifyReason,
        chain: List<Certificate>,
    ) : TlsException("certificate verification failed: $reason", null) {
        public actual val chain: List<Certificate> = chain.toList()
    }

    public actual class Protocol actual constructor(
        public actual val openSslCode: Int?,
        message: String,
        cause: Throwable?,
    ) : TlsException(message, cause)

    public actual class Config actual constructor(
        message: String,
    ) : TlsException(message, null)
}
