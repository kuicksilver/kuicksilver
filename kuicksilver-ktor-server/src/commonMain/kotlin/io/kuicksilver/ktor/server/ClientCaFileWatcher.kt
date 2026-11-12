// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.util.logging.Logger
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CancellationException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Polls the PEM file of the client CA bundle (`kuicksilver.tls.clientCa`) and reloads [target] when it holds other
 * certificates, with the rules of [IdentityFileWatcher]:
 *
 * - **Trigger:** the certificates of the file differ from `target.current.roots` (content, not modification time).
 * - **Partial writes:** a new bundle is applied only once two reads [settle] apart return the same text, so a bundle cut
 *   between two certificates is not used (and the file is read again [settle] after a reload). Every failure is retried
 *   after 1 s, then twice as long each time up to the polling interval.
 * - **A file holding a private key** is refused.
 * - **Errors** (an unreadable or damaged file, a bundle with no certificate valid now) keep the bundle in use and are
 *   logged as warnings, a repeated one at debug level only.
 */
internal class ClientCaFileWatcher(
    private val path: String,
    private val target: TrustConfig.ReloadableCa,
    private val log: Logger,
    private val readText: (String) -> String = { readPemText(it, refusePrivateKey = true, holds = CA_FILE_HOLDS) },
    private val settle: Duration = 1.seconds,
) {
    /** What the last [checkOnce] found. */
    internal var lastOutcome: IdentityFileWatcher.Outcome = IdentityFileWatcher.Outcome.Unchanged
        private set

    /** A changed bundle seen once, waiting for a second identical read. */
    private var pending: String? = null
    private var lastFailure: String? = null

    /** One look at the file; true when [target] now holds a new bundle. Never throws, except for cancellation. */
    fun checkOnce(): Boolean {
        lastOutcome =
            try {
                check()
            } catch (e: CancellationException) {
                throw e
            } catch (e: PrivateKeyInPemFile) {
                pending = null
                failed(e.message.orEmpty()) // the same words whether the reader or the check below finds the key
                IdentityFileWatcher.Outcome.Failed
            } catch (e: Throwable) {
                failed("${e::class.simpleName}: ${e.message}")
                IdentityFileWatcher.Outcome.Failed
            }
        if (lastOutcome != IdentityFileWatcher.Outcome.Failed) lastFailure = null
        return lastOutcome == IdentityFileWatcher.Outcome.Reloaded
    }

    private fun check(): IdentityFileWatcher.Outcome {
        val text = readText(path)
        if ("PRIVATE KEY" in text) throw PrivateKeyInPemFile(path, CA_FILE_HOLDS) // a reader that let it through
        val roots = Certificate.parsePem(text) // TlsException.Config for a damaged file or one without a certificate
        if (roots == target.current.roots) {
            pending = null
            return IdentityFileWatcher.Outcome.Unchanged
        }
        if (pending != text) {
            pending = text
            return IdentityFileWatcher.Outcome.Settling
        }
        target.reload(TrustConfig.AnchoredCa(roots)) // refuses a bundle with no certificate valid now
        pending = null
        log.info("client CA bundle reloaded from $path: ${roots.size} certificate(s)")
        warnNonCa(path, roots, log)
        return IdentityFileWatcher.Outcome.Reloaded
    }

    private fun failed(reason: String) {
        val message = "client CA bundle not reloaded from $path, the current one stays: $reason"
        if (reason != lastFailure) log.warn(message) else log.debug(message)
        lastFailure = reason
    }

    /** Checks every [interval] until cancelled, as [IdentityFileWatcher.run] does. */
    suspend fun run(interval: Duration): Unit = pollFiles(interval, settle) { checkOnce().let { lastOutcome } }
}

/** What the client CA file must hold, in the message that refuses a file with a private key. */
internal const val CA_FILE_HOLDS: String = "CA certificates"

/**
 * Warns when [roots] holds certificates that are not CA certificates (no basicConstraints `cA`): every certificate of an
 * AnchoredCa is a trust anchor, so a leaf there admits a client presenting exactly that certificate, which is rarely meant.
 */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal fun warnNonCa(
    path: String,
    roots: List<Certificate>,
    log: Logger,
) {
    val leaves = roots.count { !it.isCa }
    if (leaves > 0) {
        log.warn(
            "client CA file $path holds $leaves certificate(s) that are not CA certificates (no basicConstraints cA); " +
                "each is trusted as an anchor, so a client presenting exactly that certificate is accepted",
        )
    }
}
