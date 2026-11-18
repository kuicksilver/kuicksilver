// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.io.IOException

public actual sealed class TlsException actual constructor(
    message: String,
    cause: Throwable?,
) : IOException(message, cause) {
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

    @ExperimentalKuicksilverApi
    public actual class EchRejected actual constructor(
        public actual val retryConfigs: EchConfigList?,
    ) : TlsException(
            if (retryConfigs != null) {
                "the server rejected Encrypted Client Hello (ech_required); it sent retry configurations"
            } else {
                "the server rejected Encrypted Client Hello (ech_required) and sent no retry configurations"
            },
            null,
        )
}
