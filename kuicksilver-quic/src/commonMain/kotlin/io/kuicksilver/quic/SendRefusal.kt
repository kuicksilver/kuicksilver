// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.io.IOException

/**
 * A socket that reports the datagrams the system refused as too large for the path or link (EMSGSIZE, WSAEMSGSIZE) without
 * throwing: the accelerated `ksl` socket skips such a slot, counts it and still counts it as sent. A CONNECT-UDP proxy, which
 * sends one payload per call on a socket of its own, asks after each send whether that payload went out.
 */
@InternalKuicksilverApi
public interface EmsgsizeReports {
    /**
     * The length of the latest datagram the system refused as too large since the previous call, or 0 when it refused none.
     * One thread at a time, the sender's.
     */
    public fun takeEmsgsize(): Int
}

/**
 * Whether [e], thrown by a send, is the system refusing the datagram as larger than the path or link carries (EMSGSIZE,
 * WSAEMSGSIZE) rather than a socket that failed. Looks through [e]'s causes (at most [MAX_CAUSES]) for:
 * - a [PathMtuRefusedException] (the portable JVM socket's refusal of a datagram of at most 1200 bytes);
 * - an I/O exception whose message [namesEmsgsize]: the system's `strerror(EMSGSIZE)` in the process's locale where `ksl`
 *   tells it ([systemEmsgsizeText]), "Message too long" (Linux and Apple in English), a text naming `EMSGSIZE` (Android), or
 *   the Windows JDK's "larger than the maximum supported by the underlying transport";
 * - on Kotlin/Native, ktor's `PosixException` with errno EMSGSIZE (or WSAEMSGSIZE on Windows) ([isPlatformEmsgsize]).
 *
 * Never a refusal: a [QuicException.DontFragmentUnavailable] anywhere in the chain (the socket has no DF for that family,
 * which ends the tunnel or the path), whatever the causes below it say.
 *
 * Not recognized, so taken as a failed socket: a localized Linux text on the JVM without `ksl`, and a refusal a socket of
 * the caller's own reports some other way.
 */
@InternalKuicksilverApi
public fun isRefusedAsTooLarge(e: Throwable): Boolean {
    // no Don't Fragment for the destination: not a payload too large but a socket that may not be used (no DF, no tunnel)
    if (causes(e).any { it is QuicException.DontFragmentUnavailable }) return false
    return causes(e).any {
        it is PathMtuRefusedException || isPlatformEmsgsize(it) ||
            (it is IOException && it.message?.let { m -> namesEmsgsize(m, systemEmsgsizeText()) } == true)
    }
}

/** [e] and its causes, at most [MAX_CAUSES] (a longer chain, or a cycle, ends there). */
private fun causes(e: Throwable): Sequence<Throwable> = generateSequence(e) { c -> c.cause?.takeIf { it !== c } }.take(MAX_CAUSES)

/** Causes [isRefusedAsTooLarge] looks through at most (a longer chain, or a cycle, ends there). */
private const val MAX_CAUSES = 8

/** WSAEMSGSIZE, the code a Windows socket reports for EMSGSIZE; no POSIX errno is that large. */
internal const val WSAEMSGSIZE = 10040

/**
 * Whether the message [m] of a send's exception names EMSGSIZE / WSAEMSGSIZE: the system's own text [localized] (null or empty
 * when unknown), "Message too long" in any case, `EMSGSIZE` (also in `WSAEMSGSIZE`), or the Windows JDK's text for
 * WSAEMSGSIZE (net_util_md.c: "The message is larger than the maximum supported by the underlying transport").
 */
internal fun namesEmsgsize(
    m: String,
    localized: String?,
): Boolean =
    (!localized.isNullOrEmpty() && m.contains(localized)) || m.contains("Message too long", ignoreCase = true) ||
        m.contains("EMSGSIZE") || m.contains("larger than the maximum supported by the underlying transport", ignoreCase = true)

/** `strerror(EMSGSIZE)` in this process's locale where `ksl` reports it (the JVM on Linux and Apple), else null; read once. */
internal expect fun systemEmsgsizeText(): String?

/** A platform exception that carries EMSGSIZE as its error number (ktor's `PosixException` on Kotlin/Native); false on the JVM. */
internal expect fun isPlatformEmsgsize(e: Throwable): Boolean
