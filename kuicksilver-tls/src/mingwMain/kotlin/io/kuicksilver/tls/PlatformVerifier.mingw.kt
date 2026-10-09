// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

internal actual val platformTrustViaOpenSsl: Boolean = false

/** Windows: `CertGetCertificateChain`/`CertVerifyCertificateChainPolicy` arrive with the mingw toolchain in CI; until then use AnchoredCa. */
internal actual object PlatformVerifier {
    actual suspend fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): VerifyResult = VerifyResult.Rejected(VerifyReason.Custom("TrustConfig.Platform is not available on mingwX64 yet; use AnchoredCa"))
}
