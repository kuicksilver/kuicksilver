// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.EndpointStats
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ZeroRttOutcome
import io.kuicksilver.quic.emit

/**
 * One endpoint loop's connection lifecycle as `QuicEndpoint.stats`, the [ConnectionListener] and the [KuicksilverLogger] see
 * it (docs/guide/quic.md, "Observability"). Every method runs on the loop's thread, so the counters are plain fields: a
 * snapshot reads them without a lock, and nothing here allocates per packet.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class LoopObserver(
    val logger: KuicksilverLogger,
    private val listener: ConnectionListener?,
) {
    var accepted = 0L
    var handshakesCompleted = 0L
    var handshakesFailedTimeout = 0L
    var handshakesFailedTls = 0L
    var handshakesFailedOther = 0L
    var zeroRttOffered = 0L
    var zeroRttAccepted = 0L
    var zeroRttRejected = 0L
    var datagramsReceived = 0L
    var datagramsSent = 0L
    var pathValidations = 0L
    var pathValidationFailures = 0L
    var listenerFailures = 0L

    private val debug: Boolean get() = logger.isEnabled(LogLevel.Debug)

    /** Calls the listener when there is one; its exception is logged and counted, never the connection's. */
    private inline fun notify(
        rt: ConnectionRuntime,
        what: String,
        call: ConnectionListener.(ConnectionInfo) -> Unit,
    ) {
        val l = listener ?: return
        try {
            l.call(rt.info)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Throwable) {
            listenerFailures++
            logger.emit(LogLevel.Warn, e) { "connection listener failed in $what for ${rt.info.id}" }
        }
    }

    fun opened(rt: ConnectionRuntime) {
        if (debug) {
            logger.emit(
                LogLevel.Debug,
            ) { "${rt.role.name.lowercase()} connection ${rt.info.id} opened, peer ${rt.core.remoteAddress}" }
        }
        notify(rt, "onOpened") { onOpened(it) }
    }

    fun handshakeCompleted(rt: ConnectionRuntime) {
        handshakesCompleted++
        if (debug) logger.emit(LogLevel.Debug) { "connection ${rt.info.id} handshake complete, ALPN ${rt.core.negotiatedAlpn}" }
        notify(rt, "onHandshakeCompleted") { onHandshakeCompleted(it) }
    }

    fun zeroRtt(
        rt: ConnectionRuntime,
        outcome: ZeroRttOutcome,
    ) {
        if (rt.zeroRttReported) return
        rt.zeroRttReported = true
        if (outcome == ZeroRttOutcome.Accepted) zeroRttAccepted++ else zeroRttRejected++
        if (debug) logger.emit(LogLevel.Debug) { "connection ${rt.info.id} 0-RTT ${outcome.name.lowercase()}" }
        notify(rt, "onZeroRtt") { onZeroRtt(it, outcome) }
    }

    fun pathValidated(
        rt: ConnectionRuntime,
        ok: Boolean,
    ) {
        if (ok) pathValidations++ else pathValidationFailures++
        if (debug) logger.emit(LogLevel.Debug) { "connection ${rt.info.id} path validation ${if (ok) "succeeded" else "failed"}" }
    }

    fun pathChanged(
        rt: ConnectionRuntime,
        change: PathEvent.Changed,
    ) {
        if (debug) {
            logger.emit(LogLevel.Debug) {
                "connection ${rt.info.id} path changed (${change.reason}): ${change.old.remoteAddress} -> ${change.new.remoteAddress}"
            }
        }
        notify(rt, "onPathChanged") { onPathChanged(it, change) }
    }

    /** The connection is over; [handshakeDone] says whether its handshake had completed (else it counts as a failed one). */
    fun closed(
        rt: ConnectionRuntime,
        reason: QuicException.ConnectionLost,
        handshakeDone: Boolean,
    ) {
        if (!handshakeDone) {
            when {
                reason is QuicException.ConnectionLost.Timeout -> handshakesFailedTimeout++
                reason is QuicException.ConnectionLost.TransportClosed && reason.code in TLS_ALERTS -> handshakesFailedTls++
                else -> handshakesFailedOther++
            }
        }
        if (reason is QuicException.ConnectionLost.ZeroRttRejected) zeroRtt(rt, ZeroRttOutcome.Rejected)
        if (debug) {
            logger.emit(LogLevel.Debug) {
                "connection ${rt.info.id} closed${if (handshakeDone) "" else " before its handshake completed"}: ${reason.message}"
            }
        }
        notify(rt, "onClosed") { onClosed(it, reason) }
    }

    /** This loop's share of `QuicEndpoint.stats`, beside the endpoint core's own counters. */
    fun snapshot(
        acceptOverflows: Long,
        uncaughtFailures: Long,
        sendFailures: Long,
        socketDrops: Long,
    ): EndpointStats =
        EndpointStats(
            initialsDropped = 0,
            retriesSent = 0,
            invalidTokens = 0,
            versionNegotiations = 0,
            statelessResets = 0,
            statelessRateLimited = 0,
            admissionContractViolations = 0,
            connectionsAccepted = accepted,
            connectionsRefusedAcceptQueue = acceptOverflows,
            handshakesCompleted = handshakesCompleted,
            handshakesFailedTimeout = handshakesFailedTimeout,
            handshakesFailedTls = handshakesFailedTls,
            handshakesFailedOther = handshakesFailedOther,
            zeroRttOffered = zeroRttOffered,
            zeroRttAccepted = zeroRttAccepted,
            zeroRttRejected = zeroRttRejected,
            datagramsReceived = datagramsReceived,
            datagramsSent = datagramsSent,
            datagramsDroppedSocket = socketDrops,
            pathValidations = pathValidations,
            pathValidationFailures = pathValidationFailures,
            uncaughtFailures = uncaughtFailures,
            sendFailures = sendFailures,
            listenerFailures = listenerFailures,
        )

    private companion object {
        /** CONNECTION_CLOSE codes of TLS alerts (RFC 9001 section 4.8: 0x0100 + alert). */
        val TLS_ALERTS = 0x100L..0x1ffL
    }
}
