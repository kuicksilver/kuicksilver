// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.util.logging.Logger
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.io.IOException
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Polls the PEM files of a server identity (`kuicksilver.tls.certificateChain`, `kuicksilver.tls.privateKey`) and reloads
 * [target] when the chain file holds another chain.
 *
 * - **Trigger:** the certificates of the chain file differ from those of `target.current`. The chain is not a secret; the
 *   key is read only to build the new identity, never kept or compared in Kotlin. Comparing content rather than a
 *   modification time also sees an atomic swap of a symlinked directory (Kubernetes secrets, as Envoy's file watch does).
 * - **Partial writes:** a new chain is applied only once two reads [settle] apart return the same text, so a chain cut
 *   between two certificates is not served (and the file is read again [settle] after a reload, so a write that paused
 *   longer is corrected then, not an interval later); a key that is not there yet (certbot writes the chain before the key) fails
 *   the pair check of `TlsIdentity.fromPem` and the old identity stays. Every failure is retried, after 1 s and then twice
 *   as long each time up to the polling interval, so a half-written pair is picked up within seconds and a broken one is
 *   not read in a tight loop.
 * - **A chain file holding a private key** (a combined PEM) is refused: the key belongs in its own file.
 * - **Errors** are logged as warnings, a repeated one at debug level only; messages name the file and the reason, never
 *   key material.
 */
internal class IdentityFileWatcher(
    private val chainPath: String,
    private val keyPath: String,
    private val target: TlsIdentity.Reloadable,
    private val log: Logger,
    private val readText: (String) -> String = ::readPemText,
    private val readKey: (String) -> CharArray = ::readPemKey,
    private val settle: Duration = 1.seconds,
) {
    /** What the last [checkOnce] found. */
    internal enum class Outcome { Unchanged, Settling, Reloaded, Failed }

    internal var lastOutcome: Outcome = Outcome.Unchanged
        private set

    /** A changed chain seen once, waiting for a second identical read. */
    private var pending: String? = null
    private var lastFailure: String? = null

    /** One look at the files; true when [target] now serves a new identity. Never throws, except for cancellation. */
    suspend fun checkOnce(): Boolean {
        lastOutcome =
            try {
                check()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                failed("${e::class.simpleName}: ${e.message}")
                Outcome.Failed
            }
        if (lastOutcome != Outcome.Failed) lastFailure = null
        return lastOutcome == Outcome.Reloaded
    }

    private fun check(): Outcome {
        val text = readText(chainPath)
        if ("PRIVATE KEY" in text) {
            // a key in the chain file (a combined PEM): refused, and its text is not kept for the next read
            pending = null
            failed("$chainPath contains a private key; it must hold the certificate chain only")
            return Outcome.Failed
        }
        val chain = Certificate.parsePem(text) // TlsException.Config for a damaged file or one without a certificate
        if (chain == target.current.chain) {
            pending = null
            return Outcome.Unchanged
        }
        if (pending != text) {
            pending = text
            return Outcome.Settling
        }
        val next = TlsIdentity.fromPem(text, readKey(keyPath)) // the pair check; the key array is wiped
        try {
            target.reload(next)
        } catch (e: Throwable) {
            next.close()
            throw e
        }
        pending = null
        log.info(
            "server certificate reloaded from $chainPath: ${chain.size} certificate(s), leaf notAfter ${chain[0].notAfterEpochSeconds}",
        )
        return Outcome.Reloaded
    }

    private fun failed(reason: String) {
        val message = "server certificate not reloaded from $chainPath and $keyPath, the current one stays: $reason"
        if (reason != lastFailure) log.warn(message) else log.debug(message)
        lastFailure = reason
    }

    /**
     * Checks every [interval] until cancelled; a changed chain is read again after [settle] (and once more [settle] after it
     * was applied), a failure retried after 1 s, then twice as long each time, up to [interval].
     */
    suspend fun run(interval: Duration) {
        val firstRetry = minOf(1.seconds, interval)
        var retry = firstRetry
        while (true) {
            checkOnce()
            val wait =
                when (lastOutcome) {
                    Outcome.Failed -> {
                        retry.also { retry = minOf(retry * 2, interval) }
                    }

                    // after a reload too: a chain file still being written when two reads agreed is seen and fixed one settle later
                    Outcome.Settling, Outcome.Reloaded -> {
                        retry = firstRetry
                        minOf(settle, interval)
                    }

                    else -> {
                        retry = firstRetry
                        interval
                    }
                }
            delay(wait)
        }
    }
}

/** The most a PEM file of the identity may hold (a chain of a dozen certificates is a few tens of KiB). */
internal const val MAX_PEM_FILE_BYTES: Long = 1L shl 20

/** Opens [path] and fails with [IOException] when it holds more than [MAX_PEM_FILE_BYTES]: memory stays bounded per check. */
private fun <T> readBounded(
    path: String,
    read: (kotlinx.io.Source) -> T,
): T =
    SystemFileSystem.source(Path(path)).buffered().use { src ->
        if (src.request(MAX_PEM_FILE_BYTES + 1)) throw IOException("$path is larger than $MAX_PEM_FILE_BYTES bytes")
        read(src)
    }

internal fun readPemText(path: String): String = readBounded(path) { it.readString() }

/**
 * The key file as characters, without a `String` of it and without kotlinx-io's pooled segments (never wiped): read by
 * [readSecretFile] into a buffer of its own that is wiped. PEM is ASCII.
 */
internal fun readPemKey(path: String): CharArray = readSecretFile(path, MAX_PEM_FILE_BYTES)

/** The bytes of [path] (at most [maxBytes], else [IOException]) as characters, every intermediate copy wiped. */
internal expect fun readSecretFile(
    path: String,
    maxBytes: Long,
): CharArray
