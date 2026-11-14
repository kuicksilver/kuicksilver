// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.util.logging.Logger
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.OcspStapling
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlin.time.Duration

/**
 * The OCSP response file of `kuicksilver.tls.ocspStapling` ([target] is the deployment port's stapling).
 *
 * - **Whether it is stapled** ([checkUsable]): RFC 6960 section 3.2 as a handshake checks it ([usable]: for the leaf of
 *   [chain], verified by its issuer or a delegated responder, inside its validity interval). A response that is not, at
 *   startup or later (it expired, the certificate was reloaded and the response is for the old one), is logged once as a
 *   warning, since the server then staples nothing; one that is stapled again is logged once at info. A response larger
 *   than TLS 1.3 can carry (65527 bytes, RFC 8446 section 4.4.2) is named too: it is stapled over TLS 1.2 only.
 * - **Re-reading** ([checkOnce] with [reread]): with `kuicksilver.tls.reloadInterval` the file is read again each interval,
 *   and a changed response replaces the stapled one ([OcspStapling.update]); a file that cannot be read or holds no DER
 *   SEQUENCE leaves the current one, with a warning (a repeated one at debug level only).
 */
internal class OcspFileWatcher(
    private val path: String,
    private val target: OcspStapling,
    private val chain: () -> List<Certificate>,
    private val log: Logger,
    private val reread: Boolean,
    private val read: (String) -> ByteArray = ::readOcspResponseFile,
    private val usable: (OcspStapling, List<Certificate>) -> Boolean = { s, c -> s.isUsableFor(c) },
) {
    private var stapled: Boolean? = null
    private var lastFailure: String? = null

    /** Reads the file again when [reread], then [checkUsable]. Never throws, except for cancellation. */
    fun checkOnce(): IdentityFileWatcher.Outcome {
        var outcome = IdentityFileWatcher.Outcome.Unchanged
        if (reread) {
            try {
                val bytes = read(path)
                if (!bytes.contentEquals(target.current)) {
                    target.update(bytes) // TlsException.Config for a file that holds no DER SEQUENCE; the current one stays
                    log.info("OCSP response reloaded from $path: ${bytes.size} bytes")
                    outcome = IdentityFileWatcher.Outcome.Reloaded
                }
                lastFailure = null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                val reason = "${e::class.simpleName}: ${e.message}"
                val message = "OCSP response not reloaded from $path, the current one stays: $reason"
                if (reason != lastFailure) log.warn(message) else log.debug(message)
                lastFailure = reason
                outcome = IdentityFileWatcher.Outcome.Failed
            }
        }
        checkUsable(reloaded = outcome == IdentityFileWatcher.Outcome.Reloaded)
        return outcome
    }

    /** Logs a change of whether the current response is stapled: the first look and each change after it. */
    fun checkUsable(reloaded: Boolean = false) {
        val now =
            try {
                usable(target, chain())
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                false
            }
        val size = target.current?.size ?: 0
        // a stapled response too large for TLS 1.3: named when it is first stapled and when a reload brings one in
        if (now && size > MAX_TLS13_RESPONSE && (stapled != true || reloaded)) {
            log.warn(
                "the OCSP response in $path is $size bytes: TLS 1.3 and QUIC carry at most $MAX_TLS13_RESPONSE, so only TLS 1.2 staples it",
            )
        }
        if (now == stapled) return
        when {
            !now && stapled == null -> {
                log.warn(
                    "the OCSP response in $path is not stapled: it is not for the server's certificate, does not verify, or is " +
                        "not fresh (RFC 6960 section 3.2); handshakes go on without one",
                )
            }

            !now -> {
                log.warn(
                    "the OCSP response in $path is no longer stapled: it expired or is not for the server's current certificate; " +
                        "handshakes go on without one until a fresh response is in place",
                )
            }

            stapled == false -> {
                log.info("the OCSP response in $path is stapled again")
            }
        }
        stapled = now
    }

    /** [checkOnce] every [interval] until cancelled. */
    suspend fun run(interval: Duration) {
        while (true) {
            delay(interval)
            checkOnce()
        }
    }

    private companion object {
        /** RFC 8446 section 4.4.2: what a CertificateEntry's extensions leave for the response (kuicksilver-tls's limit). */
        const val MAX_TLS13_RESPONSE = 65_527
    }
}

/**
 * `kuicksilver.tls.ocspStapling`: the DER `OCSPResponse` (RFC 6960) in [path], at most 1 MiB (an OCSP response is a few
 * KiB; `OcspStapling` checks the rest).
 */
internal fun readOcspResponseFile(path: String): ByteArray {
    val chars = readSecretFile(path, MAX_PEM_FILE_BYTES) // one char per byte (0..255)
    try {
        return ByteArray(chars.size) { chars[it].code.toByte() }
    } finally {
        chars.fill('\u0000')
    }
}
