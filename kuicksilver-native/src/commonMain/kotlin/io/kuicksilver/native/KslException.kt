// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** Failures of the native layer itself (loading, ABI, OpenSSL internals). Protocol-level failures are reported by the TLS layer. */
public sealed class KslException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    /**
     * The native library could not be loaded on this platform.
     *
     * @property platform the operating system the loader ran on: `osx`, `linux` or `windows` on the JVM, `android`, or `native`
     *   on Kotlin/Native.
     * @property classifier the library variant looked for: the Maven classifier (`osx-aarch_64`) on the JVM, the CPU ABI on
     *   Android, `static` on Kotlin/Native.
     * @property reason what went wrong: a missing file or resource, a SHA-256 mismatch (a tampered or corrupted artifact, which
     *   never loads), or a `ksl_init` failure. [KslLoader.availability] reports the same failure without throwing.
     */
    public class NativeLoad internal constructor(
        public val platform: String,
        public val classifier: String,
        public val reason: String,
        cause: Throwable?,
        /** How [KslLoader.availability] classifies this failure; set by the loader at the throw site. */
        internal val kind: NativeUnavailableReason,
    ) : KslException("cannot load libksl for $platform/$classifier: $reason", cause) {
        /** A load failure of kind [NativeUnavailableReason.LoadFailed]. */
        public constructor(
            platform: String,
            classifier: String,
            reason: String,
            cause: Throwable? = null,
        ) : this(platform, classifier, reason, cause, NativeUnavailableReason.LoadFailed)
    }

    /**
     * A system OpenSSL is too old or too new.
     *
     * @property found the version string the OpenSSL in use reports.
     * @property required the supported range, e.g. `OpenSSL 3.5+ (not 4.x)`.
     */
    public class Version(
        public val found: String,
        public val required: String,
    ) : KslException("OpenSSL $found found, $required required")

    /**
     * A required symbol is missing from the OpenSSL in use.
     *
     * @property name the missing OpenSSL function, e.g. `SSL_set_quic_tls_cbs` (an OpenSSL without the 3.5 QUIC TLS API).
     */
    public class MissingSymbol(
        public val name: String,
    ) : KslException("missing OpenSSL symbol $name")

    /**
     * The native library and the Kotlin side disagree on the ABI.
     *
     * @property native the ABI version the loaded library reports (`ksl_abi_version`).
     * @property kotlin the ABI version this Kotlin code was compiled against (`KSL_ABI_VERSION` of `ksl.h`, 6 in 0.2.0).
     */
    public class AbiMismatch(
        public val native: Int,
        public val kotlin: Int,
    ) : KslException("ksl ABI $native in the native library, $kotlin expected")

    /**
     * An error reported by ksl or OpenSSL: [packed] is `(lib shl 16) or reason`, [alert] is the TLS alert (`or 0x100` when received).
     *
     * @property packed the error code `(lib shl 16) or reason`; split it with [lib] and [reason].
     * @property alert the TLS alert involved (RFC 9846 section 6.2) in bits 0-7, bit 8 (`0x100`) set when the peer sent it, and
     *   bits 16-31 the OpenSSL `X509_V_ERR_*` code of a local certificate verification failure; 0 when none applies.
     */
    public class Internal(
        public val packed: Int,
        public val alert: Int,
        message: String,
    ) : KslException(message) {
        /** The library part of [packed] (OpenSSL's `ERR_GET_LIB`); `0xff` for ksl's own codes, see [isKsl]. */
        public val lib: Int get() = packed ushr 16

        /** The reason part of [packed] (OpenSSL's `ERR_GET_REASON`); a `KSL_E_*` value when [isKsl]. */
        public val reason: Int get() = packed and 0xffff

        /** True for ksl's own codes (`KSL_E_*`). */
        public val isKsl: Boolean get() = lib == 0xff
    }
}
