// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client.publich3

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.io.ConnectionEndedException
import io.kuicksilver.ktor.client.ConnectStage
import io.kuicksilver.ktor.client.FailureDiagnostics
import io.kuicksilver.ktor.client.ProtocolDiagnostics
import io.kuicksilver.ktor.client.QuicHandshakeProgress
import io.kuicksilver.ktor.client.QuicStalledException
import io.kuicksilver.ktor.client.Transport
import io.kuicksilver.ktor.client.kuicksilverDiagnostics
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.TransportError
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.VerifyReason

/*
 * The verdict policy of the public HTTP/3 check (docs/how-we-verify.md, "Public HTTP/3 servers"): every outcome is one of
 *
 *   Pass           the check held, with the client's own diagnostics as the evidence;
 *   NotApplicable  the server does not offer the feature (no 0-RTT ticket, `disable_active_migration`): nothing to judge;
 *   Warn           the server changed or could not be reached: a name lookup or TCP failure, no QUIC answer at all, a close
 *                  that blames the server (INTERNAL_ERROR, CONNECTION_REFUSED, H3_INTERNAL_ERROR), an expired certificate,
 *                  an Alt-Svc without h3 any more. A warning annotation, never a red build;
 *   Fail           our client is wrong: a server closed with an error code that blames the client (PROTOCOL_VIOLATION,
 *                  FRAME_ENCODING_ERROR, H3_FRAME_UNEXPECTED, a TLS alert like decode_error), our client closed with an
 *                  error of its own (it judged a deployed server's packets invalid), a server that answered but whose
 *                  handshake never completed, a contradiction in our own diagnostics (an H3Only call served over TCP, a
 *                  QUIC version we never offered), or any exception type besides those of the network (a socket's, a
 *                  timeout's): every other exception of this library included.
 *
 * A check that does not pass is run once more on a fresh client; Fail stands only when both attempts fail with a
 * client-blaming outcome (`combine`), so one lost packet cannot turn the build red. And a check that passes on no target
 * while three or more targets are reachable is a Fail for every target (`escalate`): six unrelated deployments changing in
 * the same week is less likely than a regression of ours (no Initial any server answers, an Alt-Svc parser that learns
 * nothing, resumption that never offers 0-RTT).
 */

/** The four outcomes, mildest first. */
internal enum class Verdict { Pass, NotApplicable, Warn, Fail }

/**
 * One judged outcome: [verdict] and why ([reason], one line for the summary table). [offline] marks a failure before any
 * server could answer (name lookup, TCP connect): the runner's network rather than the target, which [escalate] does not
 * count as a reachable target.
 */
internal data class Judged(
    val verdict: Verdict,
    val reason: String,
    val offline: Boolean = false,
) {
    companion object {
        fun pass(reason: String) = Judged(Verdict.Pass, reason)

        fun notApplicable(reason: String) = Judged(Verdict.NotApplicable, reason)

        fun warn(reason: String) = Judged(Verdict.Warn, reason)

        fun fail(reason: String) = Judged(Verdict.Fail, reason)
    }
}

/**
 * What a failed attempt says, as plain values: [evidenceOf] reads it from the exception and the call's diagnostics, the
 * tests build it by hand. [classify] judges it.
 */
internal sealed interface Evidence {
    /** The name lookup failed (the runner's resolver, or the name is gone). */
    data class NameLookup(
        val detail: String,
    ) : Evidence

    /** TCP to the target failed (refused, unreachable, reset) before TLS. */
    data class TcpUnreachable(
        val detail: String,
    ) : Evidence

    /**
     * The connect timeout ran out ([ConnectTimeoutException]); [quicProgress] is how far a QUIC handshake got, null when
     * none was tried.
     */
    data class ConnectTimeout(
        val quicProgress: QuicHandshakeProgress?,
    ) : Evidence

    /** A QUIC timer closed the connection: the handshake timeout ([progress] says whether the server answered) or idle. */
    data class QuicTimeout(
        val kind: TimeoutKind,
        val progress: QuicHandshakeProgress?,
    ) : Evidence

    /** CONNECTION_CLOSE with a transport error [code] (0x0100 + alert for TLS), sent by [initiator]. */
    data class TransportClose(
        val code: Long,
        val initiator: Initiator,
        val reason: String,
    ) : Evidence

    /** CONNECTION_CLOSE with an application (HTTP/3) error [code], or an HTTP/3 connection or stream error. */
    data class Http3Close(
        val code: Long,
        val initiator: Initiator,
    ) : Evidence

    /** A QPACK error (always ours to decode: the server's encoder stream or field sections). */
    data class Qpack(
        val code: Long,
    ) : Evidence

    /** Our client found the response malformed (RFC 9114 section 4.1.2). */
    data class MalformedResponse(
        val reason: String,
    ) : Evidence

    /** A TLS alert from the server over TCP. */
    data class AlertReceived(
        val code: Int,
        val description: String,
    ) : Evidence

    /** Our client rejected the server's certificate. */
    data class CertificateRejected(
        val reason: VerifyReason,
    ) : Evidence

    /** OpenSSL or the shim failed the handshake on our side ([TlsException.Protocol]). */
    data class TlsLocal(
        val detail: String,
    ) : Evidence

    /** The server rejected our Encrypted Client Hello. */
    data class EchRejected(
        val retryConfigs: Boolean,
    ) : Evidence

    /** Version Negotiation: the server's [offered] versions against our [supported] ones. */
    data class VersionNegotiation(
        val offered: List<Int>,
        val supported: List<Int>,
    ) : Evidence

    /** The server said it did not process the request (GOAWAY, H3_REQUEST_REJECTED). */
    data object NotProcessed : Evidence

    /** A Stateless Reset, no viable path, or msquic's handshake connection ID change: the server or the path. */
    data class ServerSide(
        val what: String,
    ) : Evidence

    /**
     * The exchange stopped: the attempt's own deadline ran out, or the engine's stall detection gave up on the path
     * ([io.kuicksilver.ktor.client.QuicStalledException]); [handshakeCompleted] is whether the stalled connection itself had
     * completed its handshake (another connection of the attempt does not count).
     */
    data class Stalled(
        val handshakeCompleted: Boolean,
    ) : Evidence

    /**
     * An HTTP/2 stream reset or connection end ([io.kuicksilver.http2.runtime.Http2Exception]): its [code] (null for a
     * connection that ended without a GOAWAY code), whether the server's side ended it ([byPeer]: its frame, or the
     * transport lost under it), and for a connection without a code whether its cause chain is a transport failure
     * ([transportCause], [isTransportCauseChain]).
     */
    data class Http2(
        val code: Http2ErrorCode?,
        val byPeer: Boolean,
        val transportCause: Boolean = false,
    ) : Evidence

    /**
     * The TLS connection's transport ended under it ([isTlsTransportClosure]: a TCP FIN during the handshake or without
     * close_notify, a socket failure under TLS): the server or the path, not our TLS stack.
     */
    data class TlsTransportClosed(
        val detail: String,
    ) : Evidence

    /**
     * An exception of this library that no rule above names ([QuicException.ConnectionLost.Internal], [TlsException.Config],
     * [Http3Exception.Settings], a field section too large, ...): the client's own failure.
     */
    data class Internal(
        val type: String,
        val message: String?,
    ) : Evidence

    /**
     * Anything else; [transient] for the socket and timeout exceptions a network causes (java.net.SocketException,
     * java.net.SocketTimeoutException, Ktor's HttpRequestTimeoutException), false for every other type.
     */
    data class Other(
        val type: String,
        val message: String?,
        val transient: Boolean,
    ) : Evidence
}

/** TLS alerts (RFC 9846 section 6) a server sends about itself or its policy, not about our ClientHello. */
private val SERVER_SIDE_ALERTS =
    mapOf(
        0 to "close_notify",
        49 to "access_denied",
        80 to "internal_error",
        90 to "user_canceled",
        112 to "unrecognized_name",
        115 to "unknown_psk_identity", // a ticket the server no longer accepts (key rotation): a full handshake follows
        116 to "certificate_required",
        120 to "no_application_protocol",
    )

/**
 * HTTP/3 codes a server sends about itself or the request's fate (RFC 9114 section 8.1), not about our protocol use.
 * H3_EXCESSIVE_LOAD is not one: a server sends it about the peer's behaviour, so from a server it blames us.
 */
private val SERVER_SIDE_H3 =
    setOf(
        Http3ErrorCode.NO_ERROR,
        Http3ErrorCode.INTERNAL_ERROR,
        Http3ErrorCode.REQUEST_REJECTED,
        Http3ErrorCode.REQUEST_CANCELLED,
        0x10fL, // H3_CONNECT_ERROR
        0x110L, // H3_VERSION_FALLBACK
    )

/** The RFC 9114 section 8.1 codes; anything outside them and [QPACK_CODES] (a reserved or private code) reads as H3_NO_ERROR. */
private val KNOWN_H3 = 0x100L..0x110L

/** The QPACK error codes (RFC 9204 section 6), which close the whole connection. */
private val QPACK_CODES = 0x200L..0x202L

private fun qpackName(code: Long) =
    when (code) {
        0x200L -> "QPACK_DECOMPRESSION_FAILED"
        0x201L -> "QPACK_ENCODER_STREAM_ERROR"
        else -> "QPACK_DECODER_STREAM_ERROR"
    }

/**
 * HTTP/2 codes (RFC 9113 section 7) a server sends about itself, its load or the request's fate. ENHANCE_YOUR_CALM is not
 * one: "the endpoint detected that its peer is exhibiting a behavior that might be generating excessive load", so from a
 * server it blames us, as H3_EXCESSIVE_LOAD does.
 */
private val SERVER_SIDE_H2 =
    setOf(
        Http2ErrorCode.NO_ERROR,
        Http2ErrorCode.INTERNAL_ERROR,
        Http2ErrorCode.REFUSED_STREAM,
        Http2ErrorCode.CANCEL,
        Http2ErrorCode.CONNECT_ERROR,
        Http2ErrorCode.HTTP_1_1_REQUIRED,
    )

/** Transport codes (RFC 9000 section 20.1) a server sends about itself or its resources, not about our protocol use. */
private val SERVER_SIDE_TRANSPORT =
    setOf(
        TransportError.NO_ERROR,
        TransportError.INTERNAL_ERROR,
        TransportError.CONNECTION_REFUSED,
        TransportError.INVALID_TOKEN, // a NEW_TOKEN the server no longer accepts (key rotation; RFC 9000 section 8.1.3)
        TransportError.APPLICATION_ERROR,
        TransportError.AEAD_LIMIT_REACHED,
        TransportError.NO_VIABLE_PATH,
    )

/** RFC 9000 section 20.1 and RFC 9368 section 4 names of the transport codes up to 0x11. */
private val TRANSPORT_NAMES =
    listOf(
        "NO_ERROR",
        "INTERNAL_ERROR",
        "CONNECTION_REFUSED",
        "FLOW_CONTROL_ERROR",
        "STREAM_LIMIT_ERROR",
        "STREAM_STATE_ERROR",
        "FINAL_SIZE_ERROR",
        "FRAME_ENCODING_ERROR",
        "TRANSPORT_PARAMETER_ERROR",
        "CONNECTION_ID_LIMIT_ERROR",
        "PROTOCOL_VIOLATION",
        "INVALID_TOKEN",
        "APPLICATION_ERROR",
        "CRYPTO_BUFFER_EXCEEDED",
        "KEY_UPDATE_ERROR",
        "AEAD_LIMIT_REACHED",
        "NO_VIABLE_PATH",
        "VERSION_NEGOTIATION_ERROR",
    )

private fun hex(code: Long) = "0x" + code.toString(16)

private fun transportName(code: Long): String =
    if (code in
        TRANSPORT_NAMES.indices.let { 0L..it.last }
    ) {
        TRANSPORT_NAMES[code.toInt()]
    } else {
        hex(code)
    }

/** The judgement of one failed attempt (the policy above). */
internal fun classify(e: Evidence): Judged =
    when (e) {
        is Evidence.NameLookup -> {
            Judged(Verdict.Warn, "name lookup failed: ${e.detail}", offline = true)
        }

        is Evidence.TcpUnreachable -> {
            Judged(Verdict.Warn, "TCP connect failed: ${e.detail}", offline = true)
        }

        is Evidence.ConnectTimeout -> {
            if (e.quicProgress == QuicHandshakeProgress.HandshakeStarted) {
                Judged.fail("the server answered our Initial but the handshake never completed (connect timeout)")
            } else {
                Judged.warn("connect timeout, no QUIC packet from the server (UDP blocked or server down)")
            }
        }

        is Evidence.QuicTimeout -> {
            when {
                e.kind == TimeoutKind.Idle -> Judged.warn("idle timeout: the server went silent")
                e.progress == QuicHandshakeProgress.HandshakeStarted -> Judged.fail("the server answered but the handshake timed out")
                else -> Judged.warn("handshake timeout, no QUIC packet from the server (UDP blocked or server down)")
            }
        }

        is Evidence.TransportClose -> {
            classifyTransportClose(e)
        }

        is Evidence.Http3Close -> {
            val name = if (e.code in KNOWN_H3) Http3ErrorCode.name(e.code) else "unknown code ${hex(e.code)} (H3_NO_ERROR)"
            when {
                e.code in QPACK_CODES -> {
                    Judged.fail("${qpackName(e.code)} from ${if (e.initiator == Initiator.Peer) "the server" else "our client"}")
                }

                e.initiator == Initiator.Local && e.code in setOf(Http3ErrorCode.NO_ERROR, Http3ErrorCode.REQUEST_CANCELLED) -> {
                    Judged.warn("our client closed with $name")
                }

                e.initiator == Initiator.Local -> {
                    Judged.fail("our client closed the HTTP/3 connection with $name: it judged the server's HTTP/3 invalid")
                }

                e.code !in KNOWN_H3 || e.code in SERVER_SIDE_H3 -> {
                    Judged.warn("the server closed with $name")
                }

                else -> {
                    Judged.fail("the server closed with $name: it blames our HTTP/3")
                }
            }
        }

        is Evidence.Qpack -> {
            Judged.fail("QPACK error ${if (e.code in QPACK_CODES) qpackName(e.code) else hex(e.code)}")
        }

        is Evidence.MalformedResponse -> {
            Judged.fail("our client found the response malformed: ${e.reason}")
        }

        is Evidence.AlertReceived -> {
            if (e.code in SERVER_SIDE_ALERTS) {
                Judged.warn("TLS alert ${e.description} from the server")
            } else {
                Judged.fail("TLS alert ${e.description} (${e.code}) from the server: it rejects our ClientHello")
            }
        }

        is Evidence.CertificateRejected -> {
            when (e.reason) {
                VerifyReason.Expired, VerifyReason.NotYetValid, VerifyReason.Revoked, is VerifyReason.HostnameMismatch -> {
                    Judged.warn("the server's certificate: ${e.reason}")
                }

                // the runner's trust store can lag behind a CA a server just moved to: a known source of false alarms
                VerifyReason.UnknownIssuer -> {
                    Judged.warn("unknown issuer: a CA the runner's trust store does not have yet, or our chain building (see the qlog)")
                }

                else -> {
                    Judged.fail("our client rejected a certificate every browser accepts: ${e.reason}")
                }
            }
        }

        is Evidence.TlsTransportClosed -> {
            Judged.warn("the TLS connection's transport ended: ${e.detail}")
        }

        is Evidence.TlsLocal -> {
            Judged.fail("our TLS stack failed the handshake: ${e.detail}")
        }

        is Evidence.EchRejected -> {
            Judged.fail("the server rejected our ECH with a configuration fresh from its HTTPS record (retry configs: ${e.retryConfigs})")
        }

        is Evidence.VersionNegotiation -> {
            if (e.offered.any { it in e.supported }) {
                Judged.fail("Version Negotiation lists a version we support: ${e.offered.joinToString { "0x" + it.toUInt().toString(16) }}")
            } else {
                Judged.warn("no common QUIC version: the server offers ${e.offered.joinToString { "0x" + it.toUInt().toString(16) }}")
            }
        }

        Evidence.NotProcessed -> {
            Judged.warn("the server did not process the request (GOAWAY or H3_REQUEST_REJECTED)")
        }

        is Evidence.ServerSide -> {
            Judged.warn(e.what)
        }

        is Evidence.Stalled -> {
            if (e.handshakeCompleted) {
                Judged.fail("the exchange stalled on a connection whose handshake had completed")
            } else {
                Judged.warn("stalled before the connection's handshake completed")
            }
        }

        is Evidence.Http2 -> {
            classifyHttp2(e)
        }

        is Evidence.Internal -> {
            Judged.fail("${e.type}: ${e.message}")
        }

        is Evidence.Other -> {
            if (e.transient) {
                Judged.warn("${e.type}: ${e.message}")
            } else {
                Judged.fail("unexpected ${e.type}: ${e.message}")
            }
        }
    }

private fun classifyTransportClose(e: Evidence.TransportClose): Judged {
    // the reason phrase is the server's text: it goes into the job summary and annotations as plain words only
    val phrase = e.reason.take(120).filter { it in ' '..'~' && it !in "<>[]()|`*_%" }
    val what = "${transportName(e.code)}${if (phrase.isEmpty()) "" else " ($phrase)"}"
    if (e.code in 0x100L..0x1ffL) {
        val alert = (e.code - 0x100).toInt()
        val name = SERVER_SIDE_ALERTS[alert]
        return when {
            e.initiator == Initiator.Local -> Judged.fail("our client ended the handshake with TLS alert $alert: $what")
            name != null -> Judged.warn("TLS alert $name from the server")
            else -> Judged.fail("TLS alert $alert from the server: it rejects our ClientHello ($what)")
        }
    }
    return when {
        e.initiator == Initiator.Local && e.code == TransportError.NO_ERROR -> Judged.warn("our client closed with NO_ERROR")
        e.initiator == Initiator.Local -> Judged.fail("our client closed with $what: it judged the server's packets invalid")
        e.code in SERVER_SIDE_TRANSPORT -> Judged.warn("the server closed with $what")
        e.code > TransportError.VERSION_NEGOTIATION_ERROR -> Judged.warn("the server closed with an unknown transport code ${hex(e.code)}")
        else -> Judged.fail("the server closed with $what: it blames our QUIC")
    }
}

private fun classifyHttp2(e: Evidence.Http2): Judged {
    val code = e.code
    return when {
        // RFC 9113 section 6.8: an endpoint SHOULD send GOAWAY before closing, so a server may close without one (a FIN, a
        // PING left unanswered, a TLS truncation are reported as the server's side ending)
        code == null && e.transportCause && e.byPeer -> Judged.warn("the server closed the connection without GOAWAY")

        code == null && e.transportCause -> Judged.warn("the HTTP/2 connection ended when its transport failed")

        code == null -> Judged.fail("the HTTP/2 connection ended without a code, and not because its transport failed")

        !e.byPeer && (code == Http2ErrorCode.NO_ERROR || code == Http2ErrorCode.CANCEL) -> Judged.warn("our client ended HTTP/2 with $code")

        !e.byPeer -> Judged.fail("our client ended HTTP/2 with $code: it judged the server's HTTP/2 invalid")

        code in SERVER_SIDE_H2 -> Judged.warn("the server ended HTTP/2 with $code")

        else -> Judged.fail("the server ended HTTP/2 with $code: it blames our HTTP/2")
    }
}

/**
 * The verdict of a check from its first attempt and, when that did not pass, the second one on a fresh client: Fail only
 * when both failed blaming the client; a pass on the second attempt, or a failure followed by "not applicable", is a
 * warning that names the first failure.
 */
internal fun combine(
    first: Judged,
    second: Judged?,
): Judged =
    when {
        first.verdict == Verdict.Pass || first.verdict == Verdict.NotApplicable || second == null -> {
            first
        }

        second.verdict == Verdict.Pass -> {
            Judged.warn("passed on the second attempt; the first: ${first.reason}")
        }

        // the feature is not offered after all, but the first attempt failed: worth a look, not a red build
        second.verdict == Verdict.NotApplicable && first.verdict == Verdict.Fail -> {
            Judged.warn("not applicable on the second attempt (${second.reason}); the first: ${first.reason}")
        }

        second.verdict == Verdict.NotApplicable -> {
            second
        }

        first.verdict == Verdict.Fail && second.verdict == Verdict.Fail -> {
            Judged.fail(if (first.reason == second.reason) second.reason else "${first.reason}; then ${second.reason}")
        }

        else -> {
            Judged(
                Verdict.Warn,
                if (first.reason == second.reason) second.reason else "${first.reason}; then ${second.reason}",
                offline = first.offline && second.offline,
            )
        }
    }

/** The checks [escalate] applies its rule to: those every target of the list supports. */
internal val UNIVERSAL_CHECKS = setOf(Check.Http3, Check.AltSvc, Check.ZeroRtt)

/** The fewest reachable targets that make "passed on no target" a verdict on the client. */
internal const val ESCALATION_QUORUM = 3

/**
 * The run-wide rule, applied only while [quicPathOpen] (some target answered the Version Negotiation probe,
 * [versionNegotiationFrom]: otherwise the runner's network blocks QUIC and a QUIC check that passed nowhere says nothing
 * about the client), and only to judgements that ran ([Judged.offline] false; a check the run's deadline skipped is offline):
 *
 * - a check of [UNIVERSAL_CHECKS] that ran on at least [ESCALATION_QUORUM] reachable targets (some check of theirs got
 *   beyond the name lookup and TCP) and passed on none of them fails on every reachable target where it ran and did not
 *   pass;
 * - [Check.Migration] fails the same way when at least [ESCALATION_QUORUM] reachable targets did not refuse it (a refusal
 *   is "n/a": `disable_active_migration`, zero-length connection IDs) and it passed on none of them.
 *
 * Takes and returns target name to check to verdict.
 */
internal fun escalate(
    results: Map<String, Map<Check, Judged>>,
    quicPathOpen: Boolean,
): Map<String, Map<Check, Judged>> {
    if (!quicPathOpen) return results
    val reachable = results.filterValues { checks -> checks.values.any { !it.offline } }.keys
    if (reachable.size < ESCALATION_QUORUM) return results

    fun judged(c: Check) = reachable.mapNotNull { t -> results.getValue(t)[c]?.takeIf { !it.offline } }
    val escalated = HashMap<Check, Int>()
    for (c in UNIVERSAL_CHECKS) {
        val j = judged(c)
        if (j.size >= ESCALATION_QUORUM && j.none { it.verdict == Verdict.Pass }) escalated[c] = j.size
    }
    val migrated = judged(Check.Migration).filter { it.verdict != Verdict.NotApplicable }
    if (migrated.size >= ESCALATION_QUORUM && migrated.none { it.verdict == Verdict.Pass }) escalated[Check.Migration] = migrated.size
    if (escalated.isEmpty()) return results
    return results.mapValues { (target, checks) ->
        if (target !in reachable) {
            checks
        } else {
            checks.mapValues { (c, j) ->
                val n = escalated[c]
                if (n != null && !j.offline && j.verdict != Verdict.Fail && j.verdict != Verdict.Pass &&
                    !(c == Check.Migration && j.verdict == Verdict.NotApplicable)
                ) {
                    Judged.fail("passed on none of the $n reachable targets where it ran, so not a server change: ${j.reason}")
                } else {
                    j
                }
            }
        }
    }
}

/** The chain of [t]: itself, its causes and what is attached to each (HTTP/3's failure under a TCP one), at most 32. */
private fun chain(t: Throwable): List<Throwable> {
    val out = ArrayList<Throwable>()
    val todo = ArrayDeque(listOf(t))
    while (todo.isNotEmpty() && out.size < 32) {
        val x = todo.removeFirst()
        if (out.any { it === x }) continue
        out += x
        x.cause?.let { todo += it }
        x.suppressed.forEach { todo += it }
    }
    return out
}

/** The exceptions a network causes (a reset, a timeout, an end of stream, a closed channel), the only types besides the rules above that make a warning. */
private fun isTransient(x: Throwable): Boolean =
    x is java.net.SocketException ||
        x is java.net.SocketTimeoutException ||
        x is java.io.EOFException ||
        x is java.nio.channels.ClosedChannelException ||
        x is io.ktor.client.plugins.HttpRequestTimeoutException

/**
 * A message the library gives a plain `kotlinx.io.IOException` (exactly that class) when the peer or the path ended a
 * connection, at [site] (`path:line`, checked by PublicH3VerdictsTest, which finds [built] in that file); [prefix] when
 * the message continues with a value.
 */
internal data class TransportMessage(
    val text: String,
    val site: String,
    val prefix: Boolean = false,
    val built: String = "IOException(\"$text",
)

/**
 * The peer, path and network closes the library still reports as a plain IOException. The others are typed: the peer's
 * close and its silence are [ConnectionEndedException.PeerClosed] and [ConnectionEndedException.PeerUnresponsive], a
 * transport failure by type; our own close is [ConnectionEndedException.LocalClose], never one. Any other plain
 * IOException message is not a transport failure.
 *
 * TODO: [isTransient]'s java.io.EOFException is accepted from anywhere: a kotlinx-io read past the end inside our own
 * code (a parser's bug) passes as a network end today.
 */
internal val TRANSPORT_MESSAGES =
    listOf(
        // the socket timeout while our own request was still going out: nothing says whose side stalled
        TransportMessage(
            "the socket timeout expired",
            "kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h1/H1Pool.kt:1409",
            built = "fun closeAfterExpiry(what: String = \"the socket timeout expired\")",
        ),
    )

/** Whether [x] is the library's typed end by the peer or the path, or a plain IOException with a [TRANSPORT_MESSAGES] text. */
private fun isTransportMessage(x: Throwable): Boolean {
    if (x is ConnectionEndedException.PeerClosed || x is ConnectionEndedException.PeerUnresponsive) return true
    if (x::class != java.io.IOException::class) return false
    val m = x.message ?: return false
    return TRANSPORT_MESSAGES.any { if (it.prefix) m.startsWith(it.text) else m == it.text }
}

/**
 * Whether the chain from [first] down its causes is a transport failure, link by link: every link is a network exception
 * ([isTransient]), a typed peer end or a plain IOException with a [TRANSPORT_MESSAGES] message ([isTransportMessage]), a TLS
 * transport closure
 * ([isTlsTransportClosure], which judges the rest of the chain itself) or Ktor's ClosedByteChannelException (a channel
 * closed over its cause, which passes the walk on without deciding it); and at least one link is one of the first three.
 * No cause, or any other link (a RuntimeException, another exception of this library, another plain IOException), is not.
 */
internal fun isTransportCauseChain(
    first: Throwable?,
    depth: Int = 0,
): Boolean {
    if (depth > 8) return false // a cycle of TLS wrappers: no transport failure proven
    var proven = false
    val links = generateSequence(first) { it.cause }.take(17).toList()
    if (links.size > 16) return false // a chain longer than 16 links is never proven
    for (x in links) {
        when {
            x is TlsException.Protocol -> return isTlsTransportClosure(x, depth + 1)
            isTransient(x) || isTransportMessage(x) -> proven = true
            x is io.ktor.utils.io.ClosedByteChannelException -> continue
            else -> return false
        }
    }
    return proven
}

/**
 * Whether [e] says the transport under TLS ended rather than our TLS stack failing: no OpenSSL code, and either no cause
 * and a message of TlsConnection's for a closed transport ("transport closed during the TLS handshake", "transport closed
 * without close_notify (truncation)": a real FIN), or a cause chain that is a transport failure ([isTransportCauseChain]).
 * Everything else without an OpenSSL code is our TLS stack's own failure: an unexpected ksl state, a resumed session
 * without a cached chain, refused ciphertext, renegotiation, a shim failure, a "transport closed" over our own close (the
 * connection is closing), the "transport failure" wrapper over anything but a transport failure.
 */
internal fun isTlsTransportClosure(
    e: TlsException.Protocol,
    depth: Int = 0,
): Boolean {
    if (e.openSslCode != null) return false
    val cause = e.cause ?: return e.message.orEmpty().startsWith("transport closed")
    return isTransportCauseChain(cause, depth)
}

/**
 * The evidence of a failed attempt: from [t] (its causes and suppressed exceptions included) and the call's [diagnostics]
 * (taken from [t] when null), the most specific fact first; [stalledAfterHandshake] is whether the connection that was
 * still open when the attempt's deadline ran out had completed its handshake (the probe's connection listener knows).
 */
internal fun evidenceOf(
    t: Throwable,
    diagnostics: ProtocolDiagnostics? = t.kuicksilverDiagnostics,
    stalledAfterHandshake: Boolean = false,
): Evidence {
    val all = chain(t)
    val quicProgress =
        diagnostics
            ?.connectFailures
            ?.lastOrNull { it.transport == Transport.Quic && it.stage == ConnectStage.QuicHandshake }
            ?.quicProgress

    fun <T> first(pick: (Throwable) -> T?): T? = all.firstNotNullOfOrNull(pick)
    first { (it as? TlsException.EchRejected)?.let { r -> Evidence.EchRejected(r.retryConfigs != null) } }?.let { return it }
    first { (it as? TlsException.Verify)?.let { v -> Evidence.CertificateRejected(v.reason) } }?.let { return it }
    first { (it as? TlsException.AlertReceived)?.let { a -> Evidence.AlertReceived(a.code, a.description) } }?.let { return it }
    for (x in all) {
        when (x) {
            is QuicException.ConnectionLost.TransportClosed -> {
                return Evidence.TransportClose(x.code, x.initiator, x.reason)
            }

            is QuicException.ConnectionLost.ApplicationClosed -> {
                return Evidence.Http3Close(x.code, x.initiator)
            }

            is Http3Exception.Protocol -> {
                return Evidence.Http3Close(x.h3Code, x.initiator)
            }

            is Http3Exception.Qpack -> {
                return Evidence.Qpack(x.code)
            }

            is Http3Exception.MessageError -> {
                return Evidence.MalformedResponse(x.reason)
            }

            is Http2Exception.MalformedMessage -> {
                return Evidence.MalformedResponse(x.message ?: "HTTP/2")
            }

            is Http2Exception.StreamReset -> {
                return Evidence.Http2(x.code, x.byPeer)
            }

            is Http2Exception.ConnectionClosed -> {
                return Evidence.Http2(x.code, x.byPeer, transportCause = isTransportCauseChain(x.cause))
            }

            // a stream's reset or stop as the transport reports it: its HTTP/3 meaning (Http3Exception.fromQuic)
            is QuicException.StreamError.Reset, is QuicException.StreamError.Stopped -> {
                when (val h = Http3Exception.fromQuic(x as QuicException)) {
                    is Http3Exception.Protocol -> {
                        return Evidence.Http3Close(h.h3Code, h.initiator)
                    }

                    is Http3Exception.Qpack -> {
                        return Evidence.Qpack(h.code)
                    }

                    is Http3Exception.RequestNotProcessed -> {
                        return Evidence.NotProcessed
                    }

                    else -> {}
                }
            }

            is Http3Exception.RequestNotProcessed -> {
                return Evidence.NotProcessed
            }

            is QuicException.ConnectionLost.VersionNegotiation -> {
                return Evidence.VersionNegotiation(x.offered, x.supported)
            }

            is QuicException.ConnectionLost.StatelessReset -> {
                return Evidence.ServerSide("stateless reset from the server")
            }

            is QuicException.ConnectionLost.NoViablePath -> {
                return Evidence.ServerSide("no viable path")
            }

            is QuicException.ConnectionLost.ServerConnectionIdChanged -> {
                return Evidence.ServerSide("the server changed its connection ID during the handshake (msquic)")
            }

            is QuicException.ConnectionLost.ZeroRttRejected -> {
                return Evidence.ServerSide("the server rejected 0-RTT")
            }

            is QuicException.ConnectionLost.Timeout -> {
                return Evidence.QuicTimeout(x.kind, quicProgress)
            }

            is QuicStalledException -> {
                return Evidence.Stalled(x.stall.handshakeComplete)
            }

            else -> {}
        }
    }
    // only a transport that really ended is the server's or the path's; any other TLS failure is our stack's
    first { it as? TlsException.Protocol }?.let {
        return if (isTlsTransportClosure(it)) {
            Evidence.TlsTransportClosed(it.message ?: "transport closed")
        } else {
            Evidence.TlsLocal(it.message ?: "TLS failure")
        }
    }
    first { x -> x.takeIf { it is java.net.UnknownHostException || it is java.nio.channels.UnresolvedAddressException } }
        ?.let { return Evidence.NameLookup(it::class.simpleName ?: "lookup") }
    if (diagnostics?.connectFailures?.any { it.stage == ConnectStage.NameLookup } == true) return Evidence.NameLookup("no address")
    first { it as? ConnectTimeoutException }?.let { return Evidence.ConnectTimeout(quicProgress) }
    first { x -> x.takeIf { it is java.net.ConnectException || it is java.net.NoRouteToHostException } }
        ?.let { return Evidence.TcpUnreachable(it.message ?: it::class.simpleName ?: "refused") }
    first { it as? kotlinx.coroutines.TimeoutCancellationException }?.let { return Evidence.Stalled(stalledAfterHandshake) }
    // any other exception of this library (the diagnostics carrier aside) is the client's own failure
    first { x -> x.takeIf { it::class.qualifiedName.orEmpty().startsWith("io.kuicksilver.") && it !is FailureDiagnostics } }
        ?.let { return Evidence.Internal(it::class.qualifiedName ?: "io.kuicksilver", it.message?.take(200)) }
    first { x ->
        x.takeIf(::isTransient)
    }?.let { return Evidence.Other(it::class.qualifiedName ?: "Throwable", it.message?.take(200), true) }
    return Evidence.Other(t::class.qualifiedName ?: "Throwable", t.message?.take(200), false)
}
