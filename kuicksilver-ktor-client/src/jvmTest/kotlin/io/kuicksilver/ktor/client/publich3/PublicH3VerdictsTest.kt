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
import io.kuicksilver.ktor.client.QuicHandshakeProgress
import io.kuicksilver.ktor.client.QuicStalledException
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.MigrationRefusal
import io.kuicksilver.quic.MigrationRefusedException
import io.kuicksilver.quic.PathFailureReason
import io.kuicksilver.quic.PathValidationException
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.TransportError
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.VerifyReason
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The verdict policy of the public HTTP/3 check (PublicH3Main, `.github/workflows/public-h3.yml`) on built outcomes
 * (evidence and exceptions made by hand): what blames the server stays a warning, what blames our client fails, a second attempt and the run-wide rule
 * decide as documented in docs/how-we-verify.md, "Public HTTP/3 servers". No network.
 */
class PublicH3VerdictsTest {
    private fun verdict(e: Evidence) = classify(e).verdict

    @Test fun theRunnersNetworkIsAWarningMarkedOffline() {
        for (e in listOf(Evidence.NameLookup("UnknownHostException"), Evidence.TcpUnreachable("refused"))) {
            val j = classify(e)
            assertEquals(Verdict.Warn, j.verdict, "$e")
            assertTrue(j.offline, "$e")
        }
    }

    @Test fun noQuicAnswerIsAWarningButAServerThatAnsweredAndNeverFinishedFails() {
        assertEquals(Verdict.Warn, verdict(Evidence.ConnectTimeout(null)))
        assertEquals(Verdict.Warn, verdict(Evidence.ConnectTimeout(QuicHandshakeProgress.NoPacketReceived)))
        assertEquals(Verdict.Fail, verdict(Evidence.ConnectTimeout(QuicHandshakeProgress.HandshakeStarted)))
        assertEquals(Verdict.Warn, verdict(Evidence.QuicTimeout(TimeoutKind.Handshake, QuicHandshakeProgress.NoPacketReceived)))
        assertEquals(Verdict.Fail, verdict(Evidence.QuicTimeout(TimeoutKind.Handshake, QuicHandshakeProgress.HandshakeStarted)))
        assertEquals(Verdict.Warn, verdict(Evidence.QuicTimeout(TimeoutKind.Idle, QuicHandshakeProgress.HandshakeStarted)))
        assertEquals(Verdict.Warn, verdict(Evidence.Stalled(handshakeCompleted = false)))
        assertEquals(Verdict.Fail, verdict(Evidence.Stalled(handshakeCompleted = true)))
    }

    @Test fun aServerCloseFailsOnlyWithACodeThatBlamesTheClient() {
        val blaming =
            listOf(
                TransportError.FLOW_CONTROL_ERROR,
                TransportError.STREAM_LIMIT_ERROR,
                TransportError.FRAME_ENCODING_ERROR,
                TransportError.TRANSPORT_PARAMETER_ERROR,
                TransportError.PROTOCOL_VIOLATION,
                TransportError.KEY_UPDATE_ERROR,
                TransportError.VERSION_NEGOTIATION_ERROR,
            )
        for (code in blaming) {
            assertEquals(
                Verdict.Fail,
                verdict(Evidence.TransportClose(code, Initiator.Peer, "")),
                "0x${code.toString(16)}",
            )
        }
        val serverSide =
            listOf(
                TransportError.NO_ERROR,
                TransportError.INTERNAL_ERROR,
                TransportError.CONNECTION_REFUSED,
                TransportError.APPLICATION_ERROR,
                TransportError.AEAD_LIMIT_REACHED,
                TransportError.NO_VIABLE_PATH,
                0x1234L, // no RFC code: not a judgement on us
            )
        for (code in serverSide) {
            assertEquals(
                Verdict.Warn,
                verdict(Evidence.TransportClose(code, Initiator.Peer, "")),
                "0x${code.toString(16)}",
            )
        }
    }

    @Test fun ourOwnErrorCloseFailsWhateverTheCode() {
        assertEquals(Verdict.Fail, verdict(Evidence.TransportClose(TransportError.PROTOCOL_VIOLATION, Initiator.Local, "bad frame")))
        assertEquals(Verdict.Fail, verdict(Evidence.TransportClose(TransportError.INTERNAL_ERROR, Initiator.Local, "")))
        assertEquals(Verdict.Fail, verdict(Evidence.TransportClose(TransportError.crypto(42), Initiator.Local, "")))
        assertEquals(Verdict.Warn, verdict(Evidence.TransportClose(TransportError.NO_ERROR, Initiator.Local, "")))
    }

    @Test fun tlsAlertsSplitIntoTheServersPolicyAndOurClientHello() {
        assertEquals(Verdict.Fail, verdict(Evidence.TransportClose(TransportError.crypto(50), Initiator.Peer, ""))) // decode_error
        assertEquals(Verdict.Fail, verdict(Evidence.TransportClose(TransportError.crypto(47), Initiator.Peer, ""))) // illegal_parameter
        // no_application_protocol
        assertEquals(Verdict.Warn, verdict(Evidence.TransportClose(TransportError.crypto(120), Initiator.Peer, "")))
        assertEquals(Verdict.Warn, verdict(Evidence.TransportClose(TransportError.crypto(80), Initiator.Peer, ""))) // internal_error
        assertEquals(Verdict.Fail, verdict(Evidence.AlertReceived(109, "missing_extension")))
        assertEquals(Verdict.Warn, verdict(Evidence.AlertReceived(112, "unrecognized_name")))
    }

    @Test fun http3CodesBlameTheClientOnlyForItsOwnProtocolUse() {
        for (code in listOf(
            Http3ErrorCode.FRAME_UNEXPECTED,
            Http3ErrorCode.SETTINGS_ERROR,
            Http3ErrorCode.MISSING_SETTINGS,
            Http3ErrorCode.ID_ERROR,
            Http3ErrorCode.EXCESSIVE_LOAD, // a server sends it about its peer's behaviour (RFC 9114 section 8.1)
        )) {
            assertEquals(Verdict.Fail, verdict(Evidence.Http3Close(code, Initiator.Peer)), Http3ErrorCode.name(code))
        }
        for (code in listOf(
            Http3ErrorCode.NO_ERROR,
            Http3ErrorCode.INTERNAL_ERROR,
            Http3ErrorCode.REQUEST_REJECTED,
        )) {
            assertEquals(Verdict.Warn, verdict(Evidence.Http3Close(code, Initiator.Peer)), Http3ErrorCode.name(code))
        }
        // a reserved (grease) code reads as H3_NO_ERROR (RFC 9114 section 9)
        assertEquals(Verdict.Warn, verdict(Evidence.Http3Close(0x1f * 7L + 0x21, Initiator.Peer)))
        assertEquals(Verdict.Fail, verdict(Evidence.Http3Close(Http3ErrorCode.FRAME_ERROR, Initiator.Local)))
        assertEquals(Verdict.Warn, verdict(Evidence.Http3Close(Http3ErrorCode.REQUEST_CANCELLED, Initiator.Local)))
        assertEquals(Verdict.Fail, verdict(Evidence.Qpack(0x200)))
        assertEquals(Verdict.Fail, verdict(Evidence.MalformedResponse("uppercase field name")))
    }

    @Test fun aCertificateTheServerLetLapseWarnsOneWeRejectWronglyFails() {
        assertEquals(Verdict.Warn, verdict(Evidence.CertificateRejected(VerifyReason.Expired)))
        assertEquals(Verdict.Warn, verdict(Evidence.CertificateRejected(VerifyReason.Revoked)))
        // the runner's trust store may lag behind a new CA: a warning with a note, not a red build
        val unknownIssuer = classify(Evidence.CertificateRejected(VerifyReason.UnknownIssuer))
        assertEquals(Verdict.Warn, unknownIssuer.verdict)
        assertTrue("trust store" in unknownIssuer.reason, unknownIssuer.reason)
        assertEquals(Verdict.Fail, verdict(Evidence.CertificateRejected(VerifyReason.BadSignature)))
        assertEquals(Verdict.Fail, verdict(Evidence.TlsLocal("record overflow")))
        assertEquals(Verdict.Fail, verdict(Evidence.EchRejected(retryConfigs = true)))
    }

    @Test fun versionNegotiationFailsOnlyWhenItListsAVersionWeSupport() {
        assertEquals(Verdict.Fail, verdict(Evidence.VersionNegotiation(listOf(0x6b3343cf, 1), listOf(1))))
        assertEquals(Verdict.Warn, verdict(Evidence.VersionNegotiation(listOf(0xff00001d.toInt()), listOf(1, 0x6b3343cf))))
    }

    @Test fun otherExceptionsAreSocketTroubleOrOurBug() {
        assertEquals(Verdict.Warn, verdict(Evidence.Other("java.net.SocketException", "reset", transient = true)))
        assertEquals(Verdict.Fail, verdict(Evidence.Other("java.lang.IllegalStateException", "bad state", transient = false)))
        assertEquals(Verdict.Fail, verdict(Evidence.Internal("io.kuicksilver.quic.QuicException.ConnectionLost.Internal", "x")))
        assertEquals(Verdict.Warn, verdict(Evidence.NotProcessed))
        assertEquals(Verdict.Warn, verdict(Evidence.ServerSide("stateless reset from the server")))
    }

    @Test fun theSecondAttemptDecides() {
        val fail = Judged.fail("PROTOCOL_VIOLATION from the server")
        val warn = Judged.warn("no answer")
        assertEquals(Judged.pass("ok"), combine(Judged.pass("ok"), null))
        assertEquals(Verdict.Fail, combine(fail, Judged.fail("PROTOCOL_VIOLATION from the server")).verdict)
        val flaky = combine(fail, Judged.pass("ok"))
        assertEquals(Verdict.Warn, flaky.verdict)
        assertTrue("PROTOCOL_VIOLATION" in flaky.reason, flaky.reason)
        assertEquals(Verdict.Warn, combine(fail, warn).verdict)
        assertEquals(Verdict.Warn, combine(warn, fail).verdict)
        assertEquals(Verdict.NotApplicable, combine(warn, Judged.notApplicable("no ticket")).verdict)
        // a failure, then "not applicable": not a red build, but the failure stays visible
        val thenNa = combine(fail, Judged.notApplicable("the transport refused to migrate: DisabledByPeer"))
        assertEquals(Verdict.Warn, thenNa.verdict)
        assertTrue("PROTOCOL_VIOLATION" in thenNa.reason && "DisabledByPeer" in thenNa.reason, thenNa.reason)
        val offline = Judged(Verdict.Warn, "lookup", offline = true)
        assertTrue(combine(offline, offline).offline)
        assertFalse(combine(offline, warn).offline)
    }

    private fun run(vararg rows: Pair<String, Map<Check, Judged>>) = linkedMapOf(*rows)

    @Test fun aUniversalCheckThatPassedOnNoReachableTargetFailsEverywhere() {
        val noAnswer = Judged.warn("connect timeout, no QUIC packet from the server")
        val tcpFine = Judged.warn("the first answer has no h3 in Alt-Svc any more")
        val results =
            run(
                "A" to mapOf(Check.Http3 to noAnswer, Check.AltSvc to tcpFine),
                "B" to mapOf(Check.Http3 to noAnswer, Check.AltSvc to Judged.pass("h2 first")),
                "C" to mapOf(Check.Http3 to noAnswer, Check.AltSvc to tcpFine),
            )
        val out = escalate(results, quicPathOpen = true)
        for (t in listOf("A", "B", "C")) assertEquals(Verdict.Fail, out.getValue(t).getValue(Check.Http3).verdict, t)
        // Alt-Svc passed somewhere: the other targets' warnings stay warnings
        assertEquals(Verdict.Warn, out.getValue("A").getValue(Check.AltSvc).verdict)
        assertEquals(Verdict.Pass, out.getValue("B").getValue(Check.AltSvc).verdict)
    }

    @Test fun zeroRttOfferedNowhereFailsButMigrationRefusedEverywhereDoesNot() {
        val noTicket = Judged.notApplicable("no 0-RTT attempt")
        val refused = Judged.notApplicable("the transport refused to migrate: DisabledByPeer")
        val ok = Judged.pass("QUIC v1")
        val row = mapOf(Check.Http3 to ok, Check.ZeroRtt to noTicket, Check.Migration to refused)
        val out = escalate(run("A" to row, "B" to row, "C" to row), quicPathOpen = true)
        for (t in listOf("A", "B", "C")) {
            assertEquals(Verdict.Fail, out.getValue(t).getValue(Check.ZeroRtt).verdict, t)
            assertEquals(Verdict.NotApplicable, out.getValue(t).getValue(Check.Migration).verdict, t)
            assertEquals(Verdict.Pass, out.getValue(t).getValue(Check.Http3).verdict, t)
        }
    }

    @Test fun anOfflineRunnerOrTooFewTargetsNeverEscalate() {
        val offline = Judged(Verdict.Warn, "name lookup failed", offline = true)
        val allOffline = mapOf(Check.Http3 to offline, Check.AltSvc to offline, Check.ZeroRtt to offline)
        val results = run("A" to allOffline, "B" to allOffline, "C" to allOffline, "D" to allOffline)
        assertEquals(results, escalate(results, quicPathOpen = true), "no target reachable: the runner's network")
        val warn = Judged.warn("no QUIC answer")
        val two = run("A" to mapOf(Check.Http3 to warn), "B" to mapOf(Check.Http3 to warn), "C" to allOffline)
        assertEquals(two, escalate(two, quicPathOpen = true), "two reachable targets are below the quorum")
        val tcpOnly = mapOf(Check.Http3 to warn, Check.AltSvc to Judged.pass("h2 first"))
        val blocked = run("A" to tcpOnly, "B" to tcpOnly, "C" to tcpOnly)
        assertEquals(Verdict.Fail, escalate(blocked, quicPathOpen = true).getValue("A").getValue(Check.Http3).verdict)
        assertEquals(blocked, escalate(blocked, quicPathOpen = false), "no Version Negotiation from any target: the runner blocks QUIC")
    }

    @Test fun evidenceIsReadFromTheExceptionsTheEngineThrows() {
        val closed =
            QuicException.ConnectionLost.TransportClosed(
                TransportError.PROTOCOL_VIOLATION,
                0x06,
                "bad ack",
                "bad ack".encodeToByteArray(),
                Initiator.Peer,
            )
        assertEquals(
            Evidence.TransportClose(TransportError.PROTOCOL_VIOLATION, Initiator.Peer, "bad ack"),
            evidenceOf(IOException("call failed", closed), null),
        )
        val verify = TlsException.Verify(VerifyReason.UnknownIssuer, emptyList())
        val local = QuicException.ConnectionLost.TransportClosed(TransportError.crypto(48), 0x06, "", ByteArray(0), Initiator.Local, verify)
        assertEquals(
            Evidence.CertificateRejected(VerifyReason.UnknownIssuer),
            evidenceOf(local, null),
            "the certificate is the more specific fact",
        )
        val h1 =
            IOException("TCP side failed").apply {
                addSuppressed(Http3Exception.Protocol(Http3ErrorCode.SETTINGS_ERROR, Initiator.Peer, null))
            }
        assertEquals(
            Evidence.Http3Close(Http3ErrorCode.SETTINGS_ERROR, Initiator.Peer),
            evidenceOf(h1, null),
            "HTTP/3's failure under the TCP one",
        )
        assertIs<Evidence.NameLookup>(evidenceOf(java.net.UnknownHostException("cloudflare-quic.com"), null))
        assertIs<Evidence.TcpUnreachable>(evidenceOf(java.net.ConnectException("Connection refused"), null))
        assertEquals(Evidence.ConnectTimeout(null), evidenceOf(ConnectTimeoutException("Connect timeout has expired"), null))
        assertEquals(Evidence.AlertReceived(70, "protocol_version"), evidenceOf(TlsException.AlertReceived(70, "protocol_version"), null))
        assertEquals(
            Evidence.QuicTimeout(TimeoutKind.Handshake, null),
            evidenceOf(QuicException.ConnectionLost.Timeout(TimeoutKind.Handshake, 15.seconds), null),
        )
        val stalled = runCatching { runBlocking { withTimeout(1) { awaitCancellation() } } }.exceptionOrNull()!!
        assertEquals(Evidence.Stalled(handshakeCompleted = true), evidenceOf(stalled, null, stalledAfterHandshake = true))
        assertEquals(Evidence.Stalled(handshakeCompleted = false), evidenceOf(stalled, null, stalledAfterHandshake = false))
        val bug = evidenceOf(IllegalStateException("unexpected state"), null)
        assertIs<Evidence.Other>(bug)
        assertEquals(Verdict.Fail, classify(bug).verdict)
        assertEquals(Verdict.Warn, classify(evidenceOf(java.net.SocketException("Connection reset"), null)).verdict)
    }

    @Test fun traceAndAltSvcParsing() {
        val trace = "fl=123\nh=cloudflare-quic.com\nhttp=http/3\ntls=TLSv1.3\nsni=encrypted\n"
        assertEquals("http/3", traceField(trace, "http"))
        assertEquals("encrypted", traceField(trace, "sni"))
        assertEquals(null, traceField(trace, "warp"))
        assertTrue(altSvcHasH3("h3=\":443\"; ma=86400"))
        assertTrue(altSvcHasH3("h3-29=\":443\"; ma=2592000, h3=\":443\"; ma=2592000"))
        assertFalse(altSvcHasH3("h3-29=\":443\"; ma=86400"), "a draft version only")
        assertFalse(altSvcHasH3("h2=\"alt.example.com:443\""))
        assertFalse(altSvcHasH3("clear"))
    }

    @Test fun eachTargetTakesTheUniversalChecksAndEchOnlyWhereItsRecordHasOne() {
        for (t in TARGETS) {
            assertTrue(checksOf(t).containsAll(UNIVERSAL_CHECKS + Check.Migration), t.name)
            assertEquals(t.ech, Check.Ech in checksOf(t), t.name)
        }
        assertTrue(TARGETS.size >= ESCALATION_QUORUM, "the run-wide rule needs a quorum of targets")
        assertEquals(TARGETS.size, TARGETS.map { it.stack }.toSet().size, "one target per QUIC implementation")
    }

    @Test fun theSummaryAndTheResultsNameEveryVerdict() {
        val results =
            run(
                "Cloudflare" to
                    mapOf(
                        Check.Http3 to Judged.pass("QUIC v1"),
                        Check.Ech to Judged.fail("ECH configured, but the server saw sni=plaintext"),
                    ),
                "Google" to mapOf(Check.Http3 to Judged.warn("a \"quoted\" | piped reason")),
            )
        val md = summaryMarkdown(results)
        assertTrue(md.startsWith("## Public HTTP/3 servers: FAIL"), md)
        assertTrue("| Cloudflare | Cloudflare quiche | pass | - | - | - | FAIL |" in md, md)
        assertTrue("a \"quoted\" \\| piped reason" in md, "a pipe in a reason does not break the table: $md")
        val json = resultsJson(results)
        assertTrue("\"verdict\":\"Fail\"" in json, json)
        assertTrue("a \\\"quoted\\\" | piped reason" in json, json)
        assertTrue(summaryMarkdown(run("Google" to mapOf(Check.Http3 to Judged.pass("v1")))).startsWith("## Public HTTP/3 servers: pass"))
    }

    /** A server's reason phrase reaches the job summary and the annotations: it must stay one line of plain words. */
    @Test fun aServersTextCannotForgeMarkupOrWorkflowCommands() {
        val hostile = "bye\n::error::forged\r\n<img src=x>[link](http://x) `code` *bold*"
        val shown = plain(hostile)
        assertFalse(shown.any { it < ' ' }, shown)
        assertFalse(shown.any { it in "<>[]`*" }, shown)
        val md = summaryMarkdown(run("Google" to mapOf(Check.Http3 to Judged.warn(hostile))))
        assertFalse(md.lines().any { it.startsWith("::") }, md)
        val reason = classify(Evidence.TransportClose(TransportError.INTERNAL_ERROR, Initiator.Peer, "a\n::warning::x <b>")).reason
        assertFalse(reason.any { it < ' ' || it in "<>" }, reason)
        assertTrue(plain("x".repeat(1000)).length <= 300)
    }

    @Test fun theUdpControlProbeFollowsTheInvariantsAndOnlyItsOwnVersionNegotiationCounts() {
        val dcid = ByteArray(8) { (it + 1).toByte() }
        val scid = ByteArray(8) { (0x40 + it).toByte() }
        val probe = versionNegotiationProbe(dcid, scid)
        assertEquals(1200, probe.size, "padded like an Initial (RFC 9000 section 14.1)")
        assertEquals(0xc0, probe[0].toInt() and 0xc0, "long header")
        assertEquals(
            PROBE_VERSION,
            java.nio.ByteBuffer
                .wrap(probe, 1, 4)
                .int,
        )
        assertEquals(0x0a0a0a0a, PROBE_VERSION and 0x0f0f0f0f, "a version reserved to force Version Negotiation")

        // a server's answer: version 0, our SCID as its DCID, our DCID as its SCID, then v1, v2 and a GREASE version
        fun vn(
            d: ByteArray,
            s: ByteArray,
            versions: List<Int>,
        ): ByteArray {
            val b = java.nio.ByteBuffer.allocate(7 + d.size + s.size + 4 * versions.size)
            b
                .put(0x80.toByte())
                .putInt(0)
                .put(d.size.toByte())
                .put(d)
                .put(s.size.toByte())
                .put(s)
            versions.forEach { b.putInt(it) }
            return b.array()
        }
        assertEquals(
            listOf(1, 0x6b3343cf, 0x5a6a7a8a),
            parseVersionNegotiation(vn(scid, dcid, listOf(1, 0x6b3343cf, 0x5a6a7a8a)), dcid, scid),
        )
        assertEquals(
            null,
            parseVersionNegotiation(vn(dcid, scid, listOf(1)), dcid, scid),
            "connection IDs not swapped: not an answer to us",
        )
        assertEquals(null, parseVersionNegotiation(vn(scid, dcid, listOf(1)).also { it[4] = 1 }, dcid, scid), "a version other than 0")
        assertEquals(null, parseVersionNegotiation(vn(scid, dcid, listOf(1)).also { it[0] = 0x40 }, dcid, scid), "a short header")
        assertEquals(null, parseVersionNegotiation(vn(scid, dcid, listOf(1)).copyOf(7 + 16 + 3), dcid, scid), "a cut version list")
        assertEquals(null, parseVersionNegotiation(vn(scid, dcid, emptyList()), dcid, scid), "no version at all")
        assertEquals(null, parseVersionNegotiation(ByteArray(3), dcid, scid))
    }

    @Test fun qpackCodesInAConnectionCloseFailFromEitherSide() {
        for (side in Initiator.entries) {
            for ((code, name) in listOf(
                0x200L to "QPACK_DECOMPRESSION_FAILED",
                0x201L to "QPACK_ENCODER_STREAM_ERROR",
                0x202L to "QPACK_DECODER_STREAM_ERROR",
            )) {
                val j = classify(Evidence.Http3Close(code, side))
                assertEquals(Verdict.Fail, j.verdict, "$name from $side")
                assertTrue(name in j.reason, j.reason)
            }
        }
        val closed = QuicException.ConnectionLost.ApplicationClosed(0x200, "", Initiator.Peer)
        assertEquals(Verdict.Fail, classify(evidenceOf(closed, null)).verdict)
        assertEquals(Verdict.Fail, classify(evidenceOf(Http3Exception.Qpack(0x201), null)).verdict)
    }

    @Test fun everyOtherExceptionOfTheLibraryIsTheClientsOwnFailure() {
        val ours =
            listOf(
                QuicException.ConnectionLost.Internal("loop failed"),
                TlsException.Config("bad configuration"),
                Http3Exception.Settings("no Extended CONNECT"),
                Http3Exception.FieldSectionTooLarge(4, 16384),
                // wrapped under a plain IOException, as an engine may throw it
                IOException("call failed", QuicException.ConnectionLost.Internal("loop failed")),
            )
        for (e in ours) {
            val ev = evidenceOf(e, null)
            assertIs<Evidence.Internal>(ev, "$e")
            assertEquals(Verdict.Fail, classify(ev).verdict, "$e")
        }
        // only the exceptions a network causes warn
        assertEquals(Verdict.Warn, classify(evidenceOf(java.net.SocketException("Connection reset"), null)).verdict)
        assertEquals(Verdict.Warn, classify(evidenceOf(java.net.SocketTimeoutException("Read timed out"), null)).verdict)
        val requestTimeout =
            io.ktor.client.plugins
                .HttpRequestTimeoutException("https://www.google.com/", 30_000L)
        assertEquals(Verdict.Warn, classify(evidenceOf(requestTimeout, null)).verdict)
        assertEquals(Verdict.Fail, classify(evidenceOf(IOException("something else"), null)).verdict)
        assertEquals(Verdict.Fail, classify(evidenceOf(IllegalArgumentException("bad"), null)).verdict)
    }

    /**
     * The HTTP/2 exceptions' constructors are internal to their module: built through reflection. They mirror
     * `Http2Exception.StreamReset(streamId, code, byPeer, notProcessed, message)` and
     * `Http2Exception.ConnectionClosed(code, byPeer, notProcessed, message, cause)` as H2Runtime calls them (`onReset`,
     * `closedCause`, `sendStep`).
     */
    private fun streamReset(
        code: Http2ErrorCode,
        byPeer: Boolean,
    ): Throwable =
        Http2Exception.StreamReset::class.java.declaredConstructors
            .single { it.parameterCount == 5 }
            .newInstance(1, code, byPeer, false, "reset") as Throwable

    private fun connectionClosed(
        code: Http2ErrorCode?,
        byPeer: Boolean,
        cause: Throwable? = null,
    ): Throwable =
        Http2Exception.ConnectionClosed::class.java.declaredConstructors
            .single { it.parameterCount == 5 }
            .newInstance(code, byPeer, false, "closed", cause) as Throwable

    @Test fun http2ResetsAndClosesAreJudgedByCodeAndSide() {
        val blaming =
            listOf(
                Http2ErrorCode.PROTOCOL_ERROR,
                Http2ErrorCode.COMPRESSION_ERROR,
                Http2ErrorCode.FRAME_SIZE_ERROR,
                Http2ErrorCode.FLOW_CONTROL_ERROR,
                Http2ErrorCode.STREAM_CLOSED,
                // "its peer is exhibiting a behavior that might be generating excessive load" (RFC 9113 section 7)
                Http2ErrorCode.ENHANCE_YOUR_CALM,
            )
        val serverSide =
            listOf(
                Http2ErrorCode.NO_ERROR,
                Http2ErrorCode.INTERNAL_ERROR,
                Http2ErrorCode.REFUSED_STREAM,
                Http2ErrorCode.CANCEL,
            )
        for (code in blaming) {
            assertEquals(Verdict.Fail, classify(evidenceOf(streamReset(code, byPeer = true), null)).verdict, "reset $code")
            assertEquals(Verdict.Fail, classify(evidenceOf(connectionClosed(code, byPeer = true), null)).verdict, "GOAWAY $code")
        }
        for (code in serverSide) {
            assertEquals(Verdict.Warn, classify(evidenceOf(streamReset(code, byPeer = true), null)).verdict, "reset $code")
            assertEquals(Verdict.Warn, classify(evidenceOf(connectionClosed(code, byPeer = true), null)).verdict, "GOAWAY $code")
        }
        // our own error code: we judged the server's HTTP/2 invalid
        assertEquals(Verdict.Fail, classify(evidenceOf(streamReset(Http2ErrorCode.PROTOCOL_ERROR, byPeer = false), null)).verdict)
        assertEquals(Verdict.Fail, classify(evidenceOf(connectionClosed(Http2ErrorCode.INTERNAL_ERROR, byPeer = false), null)).verdict)
        assertEquals(Verdict.Warn, classify(evidenceOf(streamReset(Http2ErrorCode.CANCEL, byPeer = false), null)).verdict)
        // no GOAWAY code from our side: a transport failure under it warns, nothing under it fails
        val reset = connectionClosed(null, byPeer = false, cause = java.net.SocketException("Connection reset"))
        assertEquals(Verdict.Warn, classify(evidenceOf(reset, null)).verdict)
        assertEquals(Verdict.Fail, classify(evidenceOf(connectionClosed(null, byPeer = false), null)).verdict)
    }

    /**
     * The server's side ended the HTTP/2 connection without GOAWAY (RFC 9113 section 6.8: a SHOULD), with the causes
     * H2Runtime reports: `closedCause` after `lost(...)` with byPeer = true and no GOAWAY code, for a TCP FIN (`readLoop`), a
     * PING unanswered when the next is due (`pingLoop`) and a TLS truncation (TlsConnection's close without close_notify).
     */
    @Test fun aServerThatClosesWithoutGoAwayIsAWarning() {
        val causes =
            listOf(
                ConnectionEndedException.PeerClosed("the peer closed the connection"),
                ConnectionEndedException.PeerUnresponsive("no PING acknowledgement within 30000 ms"),
                TlsException.Protocol(null, "transport closed without close_notify (truncation)", null),
            )
        for (c in causes) {
            val closed = connectionClosed(null, byPeer = true, cause = c)
            val ev = evidenceOf(closed, null)
            assertEquals(Evidence.Http2(null, byPeer = true, transportCause = true), ev, "$c")
            val j = classify(ev)
            assertEquals(Verdict.Warn, j.verdict, "$c")
            assertTrue("without GOAWAY" in j.reason, j.reason)
        }
    }

    /** A connection end without GOAWAY whose cause is no transport failure is a bug of ours, whoever's side ended it. */
    @Test fun aConnectionEndWithoutGoAwayOverANonTransportCauseFails() {
        for (c in listOf(
            IllegalStateException("unexpected frame state"),
            QuicException.ConnectionLost.Internal("loop failed"),
            ConnectionEndedException.PeerClosed("the peer closed the connection", IllegalStateException("underneath")),
            // the message without the type: what the library gives no peer end
            IOException("the peer closed the connection"),
            TlsException.Protocol(null, "unexpected ksl state 5", null),
        )) {
            for (byPeer in listOf(true, false)) {
                val ev = evidenceOf(connectionClosed(null, byPeer = byPeer, cause = c), null)
                assertEquals(Evidence.Http2(null, byPeer = byPeer, transportCause = false), ev, "$c")
                assertEquals(Verdict.Fail, classify(ev).verdict, "$c, byPeer $byPeer")
            }
        }
        // the transport-like causes: a network exception, the runtime's typed peer end over one, a TLS transport closure
        assertTrue(isTransportCauseChain(java.io.EOFException("end")))
        assertTrue(
            isTransportCauseChain(ConnectionEndedException.PeerClosed("the peer closed the connection", java.net.SocketException("reset"))),
        )
        assertFalse(isTransportCauseChain(IOException("the connection was lost", java.net.SocketException("reset"))), "an unlisted message")
        assertTrue(isTransportCauseChain(TlsException.Protocol(null, "transport closed during the TLS handshake", null)))
        assertFalse(isTransportCauseChain(null))
        assertFalse(isTransportCauseChain(java.io.InterruptedIOException("not the runtime's own class")))
    }

    @Test fun aTlsFailureWithoutAnOpenSslCodeIsTheTransportEndingOnlyWhenTheTransportEnded() {
        // TlsConnection's closed transport: the message, or a network exception among the causes
        for (closed in listOf(
            TlsException.Protocol(null, "transport closed without close_notify (truncation)", null),
            TlsException.Protocol(null, "transport closed during the TLS handshake", null),
            TlsException.Protocol(null, "Connection reset", java.net.SocketException("Connection reset")),
        )) {
            val j = classify(evidenceOf(closed, null))
            assertEquals(Verdict.Warn, j.verdict, "${closed.message}")
            assertFalse(j.offline, "a server answered: the target was reachable")
        }
        // our TLS stack's own failures without an OpenSSL code
        for (ours in listOf(
            TlsException.Protocol(null, "unexpected ksl state 7", null),
            TlsException.Protocol(null, "resumed session without a cached chain", null),
            TlsException.Protocol(null, "ksl refused ciphertext", null),
            TlsException.Protocol(null, "the peer attempted a TLS renegotiation, which HTTP/2 forbids", null),
            // a shim failure: KslContext maps ksl's own codes (lib 0xff) to a null openSslCode with the KslException as cause
            TlsException.Protocol(
                null,
                "ksl: bad state",
                io.kuicksilver.native.KslException
                    .Internal((0xff shl 16) or 3, 0, "ksl: bad state"),
            ),
            // TlsConnection's "transport failure" wrapper over something that is no network failure
            TlsException.Protocol(null, "transport failure", IllegalStateException("pump state")),
        )) {
            val ev = evidenceOf(ours, null)
            assertIs<Evidence.TlsLocal>(ev, "${ours.message}")
            assertEquals(Verdict.Fail, classify(ev).verdict, "${ours.message}")
        }
        val withCode = evidenceOf(TlsException.Protocol((20 shl 16) or 281, "wrong version number", null), null)
        assertIs<Evidence.TlsLocal>(withCode)
        assertEquals(Verdict.Fail, classify(withCode).verdict)
        for (e in listOf(java.io.EOFException("end of stream"), java.nio.channels.ClosedChannelException())) {
            val j = classify(evidenceOf(e, null))
            assertEquals(Verdict.Warn, j.verdict, "$e")
            assertFalse(j.offline, "$e")
        }
    }

    @Test fun aStreamResetOrStopIsReadThroughItsHttp3Meaning() {
        fun reset(code: Long) = QuicException.StreamError.Reset(4, code, Initiator.Peer)
        assertEquals(
            Evidence.Http3Close(Http3ErrorCode.FRAME_UNEXPECTED, Initiator.Peer),
            evidenceOf(reset(Http3ErrorCode.FRAME_UNEXPECTED), null),
        )
        assertEquals(Verdict.Fail, classify(evidenceOf(reset(Http3ErrorCode.FRAME_UNEXPECTED), null)).verdict)
        assertEquals(Verdict.Warn, classify(evidenceOf(reset(Http3ErrorCode.REQUEST_CANCELLED), null)).verdict)
        assertEquals(Verdict.Fail, classify(evidenceOf(reset(0x200), null)).verdict, "QPACK_DECOMPRESSION_FAILED")
        val stopped = QuicException.StreamError.Stopped(4, Http3ErrorCode.REQUEST_REJECTED, Initiator.Peer)
        assertEquals(Evidence.NotProcessed, evidenceOf(IOException("call failed", stopped), null))
        // a grease code reads as H3_NO_ERROR (RFC 9114 section 9): the server's choice
        assertEquals(Verdict.Warn, classify(evidenceOf(reset(0x21), null)).verdict)
    }

    @Test fun aStallIsJudgedByTheStalledCallsOwnConnectionWhenItsDiagnosticsNameOne() {
        val done = setOf("aa01", "bb02")
        assertTrue(stalledAfterHandshake(CallConnection.Quic("aa01"), done, openAfterHandshake = false))
        assertFalse(
            stalledAfterHandshake(CallConnection.Quic("cc03"), done, openAfterHandshake = true),
            "another connection's handshake does not count",
        )
        assertFalse(stalledAfterHandshake(CallConnection.Tcp, done, openAfterHandshake = true), "a TCP call has no QUIC handshake")
        // no connection named yet: the attempt's open connections are all the listeners can tell
        assertTrue(stalledAfterHandshake(null, done, openAfterHandshake = true))
        assertFalse(stalledAfterHandshake(null, done, openAfterHandshake = false))
    }

    // the Stall a QuicStalledException carries
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun aStallIsJudgedByTheStalledConnectionsOwnHandshake() {
        for (complete in listOf(true, false)) {
            val stalled =
                QuicStalledException(
                    io.kuicksilver.ktor.client.h3
                        .Stall(5.seconds, 3, complete),
                    null,
                )
            // whatever another connection of the attempt did: the stall's own connection decides
            assertEquals(Evidence.Stalled(complete), evidenceOf(stalled, null, stalledAfterHandshake = !complete))
        }
        assertEquals(Verdict.Fail, verdict(Evidence.Stalled(handshakeCompleted = true)))
        assertEquals(Verdict.Warn, verdict(Evidence.Stalled(handshakeCompleted = false)))
    }

    @Test fun aRotatedTokenOrTicketIsTheServersChoice() {
        assertEquals(Verdict.Warn, verdict(Evidence.TransportClose(TransportError.INVALID_TOKEN, Initiator.Peer, "")))
        assertEquals(Verdict.Warn, verdict(Evidence.TransportClose(TransportError.crypto(115), Initiator.Peer, ""))) // unknown_psk_identity
        assertEquals(Verdict.Warn, verdict(Evidence.AlertReceived(115, "unknown_psk_identity")))
    }

    @Test fun cloudflareTraceValuesFailOnlyWhenKnownToContradict() {
        assertEquals(null, judgeTraceHttp("http/3"))
        for (v in listOf("http/1.1", "http/2", "h2", "http/1.0")) assertEquals(Verdict.Fail, judgeTraceHttp(v)?.verdict, v)
        for (v in listOf(null, "h3", "http/3+quic", "")) assertEquals(Verdict.Warn, judgeTraceHttp(v)?.verdict, "$v")
        assertEquals(Verdict.Pass, judgeTraceSni("encrypted").verdict)
        assertEquals(Verdict.Fail, judgeTraceSni("plaintext").verdict)
        for (v in listOf(null, "off", "")) assertEquals(Verdict.Warn, judgeTraceSni(v).verdict, "$v")
        // the ECH check needs both: sni=encrypted with http= missing is a warning
        val trace = "fl=1\nsni=encrypted\n"
        val judged = judgeTraceHttp(traceField(trace, "http")) ?: judgeTraceSni(traceField(trace, "sni"))
        assertEquals(Verdict.Warn, judged.verdict)
    }

    @Test fun migrationFailuresAreTheServersChoiceExceptAnUnexplainedStateError() {
        assertEquals(Verdict.NotApplicable, judgeMigrationFailure(MigrationRefusedException(MigrationRefusal.DisabledByPeer)).verdict)
        assertEquals(
            Verdict.NotApplicable,
            judgeMigrationFailure(MigrationRefusedException(MigrationRefusal.ZeroLengthConnectionId)).verdict,
        )
        assertEquals(Verdict.Warn, judgeMigrationFailure(PathValidationException(PathFailureReason.ValidationTimeout)).verdict)
        assertEquals(Verdict.Warn, judgeMigrationFailure(PathValidationException(PathFailureReason.NoSpareConnectionId)).verdict)
        val noCid = IllegalStateException("no unused connection ID of the peer for path 1 yet (RFC 9000 section 9.5)")
        assertEquals(Verdict.Warn, judgeMigrationFailure(noCid).verdict)
        assertEquals(Verdict.Fail, judgeMigrationFailure(IllegalStateException("more than four paths")).verdict)
        val close = QuicException.ConnectionLost.TransportClosed(TransportError.PROTOCOL_VIOLATION, 0, "", ByteArray(0), Initiator.Peer)
        assertEquals(Verdict.Fail, judgeMigrationFailure(close).verdict)
    }

    @Test fun migrationThatPassedNowhereFailsOnceThreeTargetsAllowedIt() {
        val lost = Judged.warn("the new path did not validate (ValidationTimeout)")
        val refused = Judged.notApplicable("the transport refused to migrate: DisabledByPeer")
        val ok = Judged.pass("QUIC v1")

        fun row(m: Judged) = mapOf(Check.Http3 to ok, Check.AltSvc to ok, Check.ZeroRtt to ok, Check.Migration to m)
        val three = escalate(run("A" to row(lost), "B" to row(lost), "C" to row(lost), "D" to row(refused)), quicPathOpen = true)
        for (t in listOf("A", "B", "C")) assertEquals(Verdict.Fail, three.getValue(t).getValue(Check.Migration).verdict, t)
        assertEquals(Verdict.NotApplicable, three.getValue("D").getValue(Check.Migration).verdict, "a refusal stays n/a")
        val two = escalate(run("A" to row(lost), "B" to row(lost), "C" to row(refused), "D" to row(refused)), quicPathOpen = true)
        assertEquals(Verdict.Warn, two.getValue("A").getValue(Check.Migration).verdict, "two that allowed it are below the quorum")
        val onePassed = escalate(run("A" to row(lost), "B" to row(lost), "C" to row(lost), "D" to row(ok)), quicPathOpen = true)
        assertEquals(Verdict.Warn, onePassed.getValue("A").getValue(Check.Migration).verdict)
    }

    @Test fun checksTheDeadlineSkippedAreNeverEscalated() {
        val ok = Judged.pass("QUIC v1")
        val row = mapOf(Check.Http3 to ok, Check.AltSvc to ok, Check.ZeroRtt to NOT_RUN)
        val out = escalate(run("A" to row, "B" to row, "C" to row), quicPathOpen = true)
        for (t in listOf("A", "B", "C")) assertEquals(NOT_RUN, out.getValue(t).getValue(Check.ZeroRtt), t)
        // the deadline cut the run: 0-RTT ran on two of three reachable targets, below the quorum, so it is not escalated
        val noTicket = Judged.notApplicable("no 0-RTT attempt")
        val ran = mapOf(Check.Http3 to ok, Check.AltSvc to ok, Check.ZeroRtt to noTicket)
        val cut = run("A" to ran, "B" to ran, "C" to row)
        assertEquals(cut, escalate(cut, quicPathOpen = true))
        // on three it ran: escalated, and the reason says on how many it ran
        val full = escalate(run("A" to ran, "B" to ran, "C" to ran, "D" to row), quicPathOpen = true)
        val j = full.getValue("A").getValue(Check.ZeroRtt)
        assertEquals(Verdict.Fail, j.verdict)
        assertTrue("none of the 3 reachable targets where it ran" in j.reason, j.reason)
        assertEquals(NOT_RUN, full.getValue("D").getValue(Check.ZeroRtt))
    }

    @Test fun bareUrlsInAReasonAreNotLinks() {
        val shown = plain("see https://evil.example/x and www.evil.example now")
        assertFalse("https://evil" in shown, shown)
        assertFalse("www.evil" in shown, shown)
        assertTrue(USER_AGENT.startsWith("kuicksilver-public-h3/"), USER_AGENT)
        assertTrue("how-we-verify.md#public-http3-servers" in USER_AGENT, USER_AGENT)
    }

    /** The repository root, found upwards from the test's working directory (the module's). */
    private fun repoRoot(): java.io.File {
        val start = java.io.File(System.getProperty("user.dir")).absoluteFile
        return generateSequence(start) { it.parentFile }.firstOrNull {
            java.io.File(it, "settings.gradle.kts").isFile &&
                java.io.File(it, "tools/check").isDirectory
        }
            ?: throw AssertionError("the repository root is not above $start")
    }

    /** Whether the file of [site] (`path:line`; the line is only a hint) holds [built] somewhere. */
    private fun builtIn(
        site: String,
        built: String,
    ): Boolean =
        java.io
            .File(repoRoot(), site.substringBefore(':'))
            .readText()
            .contains(built)

    /**
     * Every transport message is still one the library gives a plain IOException in its file, and every typed close
     * still has its type there: a renamed or retyped one fails here. The line of each site is a hint for the reader;
     * lines move, the check is on the content.
     */
    @Test fun everyTransportMessageIsStillAtItsSite() {
        for (m in TRANSPORT_MESSAGES) {
            assertTrue(
                builtIn(m.site, m.built) && builtIn(m.site, "kotlinx.io.IOException(what)"),
                "${m.site.substringBefore(':')} no longer builds ${m.built}... (was near line ${m.site.substringAfter(':')})",
            )
        }
        for ((text, site) in peerEnds + ourCloses) {
            assertTrue(
                builtIn(site, text),
                "${site.substringBefore(':')} no longer builds $text... (was near line ${site.substringAfter(':')})",
            )
        }
    }

    /** The typed ends by the peer or the path the library gives: a transport failure by type. */
    private val peerEnds =
        listOf(
            "PeerClosed(\"the peer closed the connection" to
                "kuicksilver-http2/src/commonMain/kotlin/io/kuicksilver/http2/runtime/H2Runtime.kt:751",
            "PeerUnresponsive(\"no PING acknowledgement within " to
                "kuicksilver-http2/src/commonMain/kotlin/io/kuicksilver/http2/runtime/H2Runtime.kt:833",
            "PeerUnresponsive(\"the HTTP/2 connection did not answer a health PING" to
                "kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h1/H1Pool.kt:687",
        )

    /** The typed closes the library gives its own closes: never a transport failure. */
    private val ourCloses =
        listOf(
            "LocalClose(\"the connection is closing" to
                "kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h1/H1Pool.kt:370",
            "LocalClose(\"the HTTP/2 connection was closed by the client" to
                "kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h2/H2Pool.kt:80",
            "LocalClose(\"the TLS socket is closed: nothing more is read" to
                "kuicksilver-ktor-network/src/commonMain/kotlin/io/kuicksilver/ktor/network/SocketTls.kt:198",
        )

    @Test fun onlyTheListedPeerAndPathMessagesAreTransportFailures() {
        for (m in TRANSPORT_MESSAGES) {
            val text = if (m.prefix) m.text + "30000 ms" else m.text
            assertTrue(isTransportCauseChain(IOException(text)), text)
            assertEquals(
                Verdict.Warn,
                classify(evidenceOf(connectionClosed(null, byPeer = true, cause = IOException(text)), null)).verdict,
                text,
            )
        }
        for (typed in listOf(ConnectionEndedException.PeerClosed("x"), ConnectionEndedException.PeerUnresponsive("x"))) {
            assertTrue(isTransportCauseChain(typed), "$typed")
            assertEquals(
                Verdict.Warn,
                classify(evidenceOf(connectionClosed(null, byPeer = true, cause = typed), null)).verdict,
                "$typed",
            )
        }
        for ((built, _) in ourCloses + peerEnds) {
            // the typed message as a plain IOException, as before the types: no transport failure
            val text = built.substringAfter('"')
            assertFalse(isTransportCauseChain(IOException(text)), text)
        }
        for ((built, _) in ourCloses) {
            val text = built.substringAfter('"')
            for (ours in listOf(IOException(text), ConnectionEndedException.LocalClose(text))) {
                assertFalse(isTransportCauseChain(ours), "$ours")
                assertEquals(
                    Verdict.Fail,
                    classify(evidenceOf(connectionClosed(null, byPeer = false, cause = ours), null)).verdict,
                    "$ours",
                )
                val tls = TlsException.Protocol(null, "transport closed without close_notify (truncation)", ours)
                assertEquals(Verdict.Fail, classify(evidenceOf(tls, null)).verdict, "a truncation over our own close: $ours")
            }
        }
        // the class alone is not enough, nor a subclass with a listed message
        assertFalse(isTransportCauseChain(IOException("something else")))
        assertFalse(isTransportCauseChain(java.io.InterruptedIOException("the socket timeout expired")))
        // a typed peer end over our own close is ours: the chain is judged link by link
        assertFalse(
            isTransportCauseChain(
                ConnectionEndedException.PeerClosed("x", IllegalStateException("pump")),
            ),
        )
    }

    @Test fun aTlsTransportFailureNeedsATransportCauseChainLinkByLink() {
        // a socket failure under a programming error is no transport failure
        val wrapped = TlsException.Protocol(null, "transport failure", IllegalStateException("pump", java.net.SocketException("reset")))
        assertIs<Evidence.TlsLocal>(evidenceOf(wrapped, null))
        assertEquals(Verdict.Fail, classify(evidenceOf(wrapped, null)).verdict)
        assertEquals(Verdict.Fail, classify(evidenceOf(connectionClosed(null, byPeer = true, cause = wrapped), null)).verdict)
        // "transport closed" counts without a cause (a real FIN) or over a transport chain only
        assertEquals(
            Verdict.Warn,
            classify(evidenceOf(TlsException.Protocol(null, "transport closed during the TLS handshake", null), null)).verdict,
        )
        val overSocket =
            TlsException.Protocol(
                null,
                "transport closed without close_notify (truncation)",
                java.net.SocketException("reset"),
            )
        assertEquals(Verdict.Warn, classify(evidenceOf(overSocket, null)).verdict)
        val overInternal =
            TlsException.Protocol(
                null,
                "transport closed without close_notify (truncation)",
                QuicException.ConnectionLost.Internal("loop failed"),
            )
        assertEquals(Verdict.Fail, classify(evidenceOf(overInternal, null)).verdict)
    }

    @Test fun aClosedByteChannelPassesTheWalkOnButDecidesNothing() {
        val chain =
            io.ktor.utils.io.ClosedByteChannelException(
                TlsException.Protocol(null, "transport failure", java.net.SocketException("reset")),
            )
        assertTrue(isTransportCauseChain(chain))
        assertEquals(Verdict.Warn, classify(evidenceOf(connectionClosed(null, byPeer = true, cause = chain), null)).verdict)
        assertTrue(
            isTransportCauseChain(
                io.ktor.utils.io
                    .ClosedReadChannelException(java.io.EOFException("end")),
            ),
        )
        assertFalse(
            isTransportCauseChain(
                io.ktor.utils.io
                    .ClosedByteChannelException(),
            ),
            "a closed channel alone proves nothing",
        )
        assertFalse(
            isTransportCauseChain(
                io.ktor.utils.io
                    .ClosedByteChannelException(IllegalStateException("bug")),
            ),
        )
        // a chain longer than 16 links is never proven, however transport-like its links
        var long: Throwable = java.net.SocketException("reset")
        repeat(16) {
            long =
                io.ktor.utils.io
                    .ClosedByteChannelException(long)
        }
        assertFalse(isTransportCauseChain(long), "17 links")
        var short: Throwable = java.net.SocketException("reset")
        repeat(15) {
            short =
                io.ktor.utils.io
                    .ClosedByteChannelException(short)
        }
        assertTrue(isTransportCauseChain(short), "16 links")
    }
}
