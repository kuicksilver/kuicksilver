// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

/** Linux Native: the platform store is the OpenSSL default directory (`/etc/ssl/certs`), verified by `ksl` without a pause. */
internal actual val platformTrustViaOpenSsl: Boolean = true

internal actual object PlatformVerifier {
    actual suspend fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): VerifyResult = VerifyResult.Rejected(VerifyReason.Custom("unreachable: Linux platform trust is verified by OpenSSL inside ksl"))
}
