// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.runtime.H3Session.AttemptStep
import io.kuicksilver.http3.runtime.H3Session.Companion.CRITICAL
import io.kuicksilver.http3.runtime.H3Session.Companion.transportCause
import io.kuicksilver.http3.runtime.H3Session.Critical
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.awaitSendStopped
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration

// Our critical streams (control, QPACK encoder and decoder; RFC 9114 section 6.2.1): opening them, writing to them, and the zero-RTT attempt they are part of.

/**
 * Writes [b] on our critical stream [pick] once the streams are open, on the session's dispatcher (the bookkeeping
 * below is the dispatcher's alone; callers such as `updatePriority` run on the application's thread). Bytes made for
 * streams a rejected 0-RTT dropped (an older `criticalGen`, or a write the drop failed) never reach the newer ones:
 * QPACK instructions made then can only be about early request streams the server never saw, whose IDs the requests
 * sent again reuse (a Stream Cancellation there would cancel the new request's sections).
 * [again] says whether such a frame is still wanted on the new control stream (a GOAWAY is); one written before the
 * handshake told the 0-RTT's fate is kept for that (`earlyControl`).
 */
internal suspend fun H3Session.writeCritical(
    lock: Mutex,
    pick: (Critical) -> QuicStream,
    b: ByteArray,
    again: (() -> Boolean)? = null,
    madeFor: Int? = null,
): Unit =
    withContext(dispatcher) {
        checkOnDispatcher()
        // bytes made earlier (queued) are for the streams of the generation they were made in
        var gen = madeFor ?: criticalGen
        while (true) {
            awaitCriticalStreams()
            val written =
                lock.withLock {
                    val c = critical
                    if (gen != criticalGen || c == null) return@withLock false
                    try {
                        pick(c).output.writeFully(b)
                        pick(c).output.flush()
                        if (again != null && gen == 0) earlyControl?.add(b to again)
                        true
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Throwable) {
                        val cause = transportCause(e)
                        if (cause is QuicException.StreamError.Stopped || cause is QuicException.StreamError.Reset) {
                            // the peer closed one of our critical streams: RFC 9114 section 6.2.1 ("If either control stream is
                            // closed at any point, this MUST be treated as a connection error of type
                            // H3_CLOSED_CRITICAL_STREAM") and RFC 9204 section 4.2 (the same for the encoder and decoder streams)
                            fail(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "the peer closed our critical stream ${pick(c).id}")
                            throw e
                        }
                        if (cause !is QuicException.StreamError.EarlyDataRejected) throw e
                        criticalWriteFailuresForTest.addAndFetch(1)
                        false
                    }
                }
            if (written) return@withContext
            // the stream it was for is gone with the rejected 0-RTT. The runtime may not have reported the rejection yet
            // (its event waits behind a flush): the handshake's end comes after it, and a connection that ends first
            // leaves nothing to write on. Waiting here also keeps this loop from spinning on a failed stream
            try {
                quic.awaitHandshake()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                return@withContext
            }
            noteRejectedZeroRttHere()
            if (criticalGen == gen || again == null || !again()) return@withContext // no newer streams, or not wanted there
            gen = criticalGen
        }
    }

/**
 * The peer stopping one of our critical streams closes it: RFC 9114 section 6.2.1 ("If either control stream is closed at
 * any point, this MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM") and RFC 9204 section 4.2 for the
 * QPACK streams. Noticed when the STOP_SENDING arrives, not at our next write there, which may never come.
 */
private fun H3Session.watchStopped(st: QuicStream) {
    scope.launch {
        val code = st.awaitSendStopped()
        fail(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "the peer stopped our critical stream ${st.id} (code $code)")
    }
}

/** [st] was dropped by the server's rejection of 0-RTT (RFC 9001 section 4.6.2): the server never saw anything of it. */
internal fun H3Session.droppedByRejectedZeroRtt(st: QuicStream): Boolean {
    val causes = listOf(runCatching { st.output.closedCause }.getOrNull(), runCatching { st.input.closedCause }.getOrNull())
    return causes.any { it != null && transportCause(it) is QuicException.StreamError.EarlyDataRejected }
}

/**
 * RFC 9204 section 2.2.2.2: a stream reset or abandoned before its field sections were all processed gets a Stream
 * Cancellation. Not one the server's rejection of 0-RTT dropped: the server never saw it, so its encoder holds no
 * section of it, and the request sent again reuses its ID (RFC 9001 section 4.6.2).
 */
internal suspend fun H3Session.cancelSections(st: QuicStream) {
    if (droppedByRejectedZeroRtt(st)) return
    // QPACK is the dispatcher's. NonCancellable: the callers are often cancelled already (a body pump in its catch after
    // its own cancellation), and withContext would throw at once without making the cancellation
    withContext(NonCancellable + dispatcher) { qpack.cancelStream(st.id) }
}

/**
 * Client: the server rejected 0-RTT (RFC 9001 section 4.6.2: "The client therefore MUST reset the state of all streams,
 * including application state bound to those streams"). Runs before anything of the server is read (the accept loop and
 * the request sent again call it first), so whatever QPACK holds unsent can only be about the dropped streams: it goes.
 * Critical streams the rejection dropped are given up, and [criticalStreamsLoop] opens new ones and sends SETTINGS again;
 * live ones, opened after the rejection, stay (giving those up would reset a typed control stream).
 * Idempotent; on the session's dispatcher, whoever calls it.
 */
internal suspend fun H3Session.noteRejectedZeroRtt() = withContext(dispatcher) { noteRejectedZeroRttHere() }

/** [noteRejectedZeroRtt], for a caller already on the dispatcher. */
internal suspend fun H3Session.noteRejectedZeroRttHere() {
    checkOnDispatcher()
    if (isServer || zeroRttRejectionNoted || quic.earlyDataAccepted != false) return
    zeroRttRejectionNoted = true
    qpack.onEarlyDataRejected()
    val held = critical?.let { listOf(it.control, it.encoder, it.decoder) } ?: attemptStreams
    if (held.any { droppedByRejectedZeroRtt(it) }) {
        criticalGen++
        critical = null
        if (criticalStreams.isCompleted) criticalStreams = CompletableDeferred()
    }
}

/**
 * Opens our critical streams; a client does so again when the server rejected the 0-RTT that carried them (RFC 9001
 * section 4.6.2 resets every stream the client opened), which it knows for sure once the handshake completed. At most
 * twice: streams opened after the rejection are 1-RTT streams.
 */
internal suspend fun H3Session.criticalStreamsLoop(deadline: Duration) {
    while (true) {
        val gen = criticalGen
        val opened = openCriticalStreams(deadline, gen) ?: return
        if (isServer) return
        try {
            quic.awaitHandshake()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            return // the connection is gone: its closed handler reports it
        }
        noteRejectedZeroRttHere()
        if (opened && gen == criticalGen) {
            earlyControl = null // the 0-RTT's fate is known and these streams stay
            return
        }
    }
}

/**
 * Opens the control and QPACK streams and sends SETTINGS (RFC 9114 section 6.2: the critical streams first, then
 * others, GREASE, as the peer allows): true once done, false when a rejected 0-RTT took them first (generation [gen]
 * passed), null when the connection failed: for want of stream credit, or because the peer closed a critical stream of
 * ours while it was being opened (H3_CLOSED_CRITICAL_STREAM).
 */
internal suspend fun H3Session.openCriticalStreams(
    deadline: Duration,
    gen: Int,
): Boolean? {
    val opened = ArrayList<QuicStream>(3)
    attemptStreams = opened
    typedStreams.clear()
    val hook = criticalAttemptHookForTest
    val done =
        try {
            withTimeoutOrNull(deadline) {
                hook?.invoke(AttemptStep.Started, gen)
                for (i in 0 until 3) {
                    opened += quic.openUni(CRITICAL)
                    if (gen != criticalGen) return@withTimeoutOrNull false
                }
                hook?.invoke(AttemptStep.Opened, gen)
                val (control, encoder, decoder) = opened
                controlLock.withLock {
                    if (gen != criticalGen) return@withTimeoutOrNull false
                    typedStreams += control
                    control.output.writeFully(VarInt.encode(StreamType.CONTROL))
                    control.output.writeFully(FrameHeaders.frame(FrameType.SETTINGS, SettingsCodec.encode(ourSettings())))
                    if (settings.grease) {
                        control.output.writeFully(
                            FrameHeaders.frame(FrameType.grease(Random.nextLong(0, 1000)), Random.nextBytes(Random.nextInt(0, 8))),
                        )
                    }
                    // what went on the dropped control stream before the 0-RTT's fate was known, and is still wanted
                    if (gen > 0) {
                        earlyControl?.forEach { (frame, wanted) -> if (wanted()) control.output.writeFully(frame) }
                        earlyControl = null
                    }
                    control.output.flush()
                }
                hook?.invoke(AttemptStep.ControlWritten, gen)
                encoderLock.withLock {
                    if (gen != criticalGen) return@withTimeoutOrNull false
                    typedStreams += encoder
                    encoder.output.writeFully(VarInt.encode(StreamType.QPACK_ENCODER))
                    encoder.output.flush()
                }
                decoderLock.withLock {
                    if (gen != criticalGen) return@withTimeoutOrNull false
                    typedStreams += decoder
                    decoder.output.writeFully(VarInt.encode(StreamType.QPACK_DECODER))
                    decoder.output.flush()
                }
                if (gen != criticalGen) return@withTimeoutOrNull false
                critical = Critical(control, encoder, decoder)
                for (st in listOf(control, encoder, decoder)) watchStopped(st)
                true
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            val cause = transportCause(e)
            if (cause is QuicException.StreamError.Stopped || cause is QuicException.StreamError.Reset) {
                // the peer closed a critical stream while we set it up (RFC 9114 section 6.2.1, RFC 9204 section 4.2)
                fail(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "the peer closed our critical stream while it was opened")
                return null // the connection is closing: criticalStreamsLoop ends, as after the deadline
            }
            if (cause !is QuicException.StreamError.EarlyDataRejected) throw e
            false
        }
    if (done == null) {
        fail(
            Http3ErrorCode.GENERAL_PROTOCOL_ERROR,
            "control and QPACK streams not open after $deadline: the peer must allow at least three unidirectional streams",
        )
        return null
    }
    if (!done) {
        // only an attempt that holds a stream the rejection dropped gives up ([noteRejectedZeroRttHere]), and the streams
        // are typed in the order they were opened, after all three were: the live 1-RTT ones it opened after the dropped
        // ones carry nothing yet. They are reset before their type, which RFC 9114 section 6.2 allows: "A receiver MUST
        // tolerate unidirectional streams being closed or reset prior to the reception of the unidirectional stream
        // header". A typed one is never reset (section 6.2.1: a closed control stream is H3_CLOSED_CRITICAL_STREAM)
        for (st in opened) {
            if (!droppedByRejectedZeroRtt(st) && typedStreams.none { it === st }) runCatching { st.reset(Http3ErrorCode.NO_ERROR) }
        }
        return false
    }
    criticalStreams.complete(Unit)
    // the peer stops a reserved stream at once (RFC 9114 section 6.2.3), so failures here are expected and never fatal
    if (settings.grease) {
        scope.launch {
            try {
                val g = quic.openUni()
                g.output.writeFully(VarInt.encode(FrameType.grease(Random.nextLong(0, 1000))) + Random.nextBytes(Random.nextInt(0, 8)))
                g.output.flushAndClose()
            } catch (
                e: CancellationException,
            ) {
                throw e
            } catch (_: Throwable) {
            }
        }
    }
    return true
}

/** Waits until our control and QPACK streams exist; throws the connection's error if it closes first. */
internal suspend fun H3Session.awaitCriticalStreams() {
    if (criticalStreams.isCompleted) return
    select {
        criticalStreams.onAwait { }
        closed.onAwait { throw it }
    }
}
