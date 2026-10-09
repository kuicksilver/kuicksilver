// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * Whether the native library `libksl` can be used in this process, as answered by [KslLoader.availability].
 *
 * An application that must also run on operating systems or CPU architectures Kuicksilver has no build for checks it once
 * at startup and keeps another transport (TCP, the platform's own HTTP stack) when it is [Unavailable], instead of
 * catching [KslException] from the first connection.
 */
@ExperimentalKuicksilverApi
public sealed interface NativeAvailability {
    /** The library is loaded, its ABI matches [KSL_ABI_VERSION] and it is initialized: every Kuicksilver transport works. */
    public data object Available : NativeAvailability

    /**
     * The library cannot be used in this process; Kuicksilver transports would throw [cause] on first use.
     *
     * @property reason the kind of failure, for deciding whether to fall back silently or to report a broken installation.
     * @property detail a human-readable explanation (the message of [cause]) for logs; not meant to be parsed.
     * @property cause the exception the load attempt raised, usually a [KslException]; [KslLoader.ensureLoaded] throws this
     *   same instance. Null only when the failure raised no exception.
     */
    public class Unavailable(
        public val reason: NativeUnavailableReason,
        public val detail: String,
        public val cause: Throwable?,
    ) : NativeAvailability {
        override fun toString(): String = "Unavailable($reason: $detail)"
    }
}

/** Why [KslLoader.availability] answered [NativeAvailability.Unavailable]. */
@ExperimentalKuicksilverApi
public enum class NativeUnavailableReason {
    /**
     * No library is shipped for this platform: on the JVM, no jar resource for the host classifier (e.g. `freebsd-x86_64`)
     * and neither `-Dkuicksilver.native.path` nor `-Dkuicksilver.native.system=true`; on Android, no `libksl.so` for the
     * device's CPU ABI in the APK. The expected case for a fallback transport.
     */
    NoLibraryForPlatform,

    /**
     * A library was found or named but could not be loaded or initialized: `System.load`/`System.loadLibrary` failed (a
     * missing dependency, a `noexec` work directory, a wrong architecture), the file named by `-Dkuicksilver.native.path`
     * does not exist, `ksl_init` failed, or a system OpenSSL is unsupported ([KslException.Version],
     * [KslException.MissingSymbol]).
     */
    LoadFailed,

    /**
     * The jar resource failed the SHA-256 manifest check (a tampered or corrupted artifact, a missing manifest or entry, or
     * several differing copies on the classpath) and was not loaded. Usually worth reporting rather than silently ignoring.
     */
    IntegrityMismatch,

    /** The library loaded but reports a `ksl` ABI version other than [KSL_ABI_VERSION] (a library from another release). */
    AbiMismatch,
}
