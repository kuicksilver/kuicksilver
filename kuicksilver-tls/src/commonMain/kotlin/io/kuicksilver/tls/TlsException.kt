// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.io.IOException

/** Base of all TLS failures. On the JVM this is an `SSLException`, so existing `catch (e: SSLException)` keeps working. */
public expect sealed class TlsException(
    message: String,
    cause: Throwable?,
) : IOException {
    /** A fatal alert arrived from the peer. */
    public class AlertReceived(
        code: Int,
        description: String,
    ) : TlsException {
        /** The alert description code (RFC 9846 section 6), e.g. 42 for `bad_certificate`, 48 for `unknown_ca`. */
        public val code: Int

        /** The RFC 9846 name of [code][TlsException.AlertReceived.code], e.g. `bad_certificate`, or `alert_<code>` for one without a known name. */
        public val description: String
    }

    /** Peer certificate verification failed; the alert sent is derived from [reason][TlsException.Verify.reason]. */
    public class Verify(
        reason: VerifyReason,
        chain: List<Certificate>,
    ) : TlsException {
        /** Why the peer was rejected; the real reason even when [TlsConfig.genericAlerts] hid it from the peer. */
        public val reason: VerifyReason

        /** The chain the peer presented, leaf first; empty when it sent none. */
        public val chain: List<Certificate>
    }

    /** A protocol error reported by OpenSSL or the shim; [openSslCode][TlsException.Protocol.openSslCode] is `(lib shl 16) or reason` when known. */
    public class Protocol(
        openSslCode: Int?,
        message: String,
        cause: Throwable?,
    ) : TlsException {
        /** OpenSSL's packed error code; null for the shim's own errors and failures outside OpenSSL (a timeout, a closed transport). */
        public val openSslCode: Int?
    }

    /** An invalid configuration, detected when the configuration object is built. */
    public class Config(
        message: String,
    ) : TlsException
}

/**
 * The TLS alert code that [TlsException.Verify] produces (RFC 9846 section 6.2) when the reason comes from a verifier that
 * chooses the alert (a [CertificateVerifier], the platform, pins). Where `ksl` decides, the alert sent follows OpenSSL: a failed
 * stapled OCSP check is always `bad_certificate_status_response` (113, RFC 6066 section 8), whatever the reason ([VerifyReason.Revoked],
 * [VerifyReason.InvalidStatusResponse], [VerifyReason.UnknownRevocationStatus]) and also with [TlsConfig.genericAlerts]; a
 * configured CRL gives the alert OpenSSL maps its error to (`ssl_x509err2alert`): `certificate_revoked` (44) for a revoked
 * certificate, `certificate_expired` (45) for an expired CRL, `bad_certificate` (42) for a CRL not valid yet, with a bad time
 * field or a signature that does not decrypt, `decrypt_error` (51) for a CRL signature that does not verify, `unknown_ca` (48)
 * when no usable CRL or CRL issuer is found, and `certificate_unknown` (46) for a CRL of another scope, an issuer without
 * cRLSign or an unknown critical CRL extension.
 */
@OptIn(ExperimentalKuicksilverApi::class)
public val VerifyReason.alertCode: Int
    get() =
        when (this) {
            is VerifyReason.HostnameMismatch,
            is VerifyReason.PinMismatch,
            is VerifyReason.BadSignature,
            is VerifyReason.BadEncoding,
            is VerifyReason.NoCertificate,
            is VerifyReason.WeakKey,
            is VerifyReason.WeakSignature,
            -> 42

            is VerifyReason.UnknownIssuer, is VerifyReason.UnknownRevocationStatus -> 48

            is VerifyReason.Expired, is VerifyReason.NotYetValid -> 45

            is VerifyReason.Revoked -> 44

            is VerifyReason.InvalidPurpose -> 43

            is VerifyReason.CertificateTransparency, is VerifyReason.Custom -> 46

            is VerifyReason.InvalidStatusResponse -> 113
        }
