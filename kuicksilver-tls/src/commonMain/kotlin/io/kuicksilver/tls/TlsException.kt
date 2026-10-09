// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

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
        /** The alert description code (RFC 8446 section 6), e.g. 42 for `bad_certificate`, 48 for `unknown_ca`. */
        public val code: Int

        /** The RFC 8446 name of [code], e.g. `bad_certificate`, or `alert_<code>` for one without a known name. */
        public val description: String
    }

    /** Peer certificate verification failed; the alert sent is derived from [reason]. */
    public class Verify(
        reason: VerifyReason,
        chain: List<Certificate>,
    ) : TlsException {
        /** Why the peer was rejected; the real reason even when [TlsConfig.genericAlerts] hid it from the peer. */
        public val reason: VerifyReason

        /** The chain the peer presented, leaf first; empty when it sent none. */
        public val chain: List<Certificate>
    }

    /** A protocol error reported by OpenSSL or the shim; [openSslCode] is `(lib shl 16) or reason` when known. */
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

/** The TLS alert code that [TlsException.Verify] produces (RFC 8446 section 6.2). */
public val VerifyReason.alertCode: Int
    get() =
        when (this) {
            is VerifyReason.HostnameMismatch,
            is VerifyReason.PinMismatch,
            is VerifyReason.BadSignature,
            is VerifyReason.BadEncoding,
            is VerifyReason.NoCertificate,
            -> 42

            is VerifyReason.UnknownIssuer, is VerifyReason.UnknownRevocationStatus -> 48

            is VerifyReason.Expired, is VerifyReason.NotYetValid -> 45

            is VerifyReason.Revoked -> 44

            is VerifyReason.InvalidPurpose -> 43

            is VerifyReason.CertificateTransparency, is VerifyReason.Custom -> 46
        }
