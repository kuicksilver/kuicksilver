// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.fuzz

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.core.H2ConnectionCore
import io.kuicksilver.http2.core.H2Event
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.SettingId

/**
 * What one input of a stateful fuzz target reached, by name: the frames that got to their handler in the core
 * ([H2ConnectionCore.frameHook]), the settings and flow-control changes they made, the events the driver saw and the
 * errors the core answered with (its GOAWAY and RST_STREAM codes, and which flood limit ended the connection). Set only by
 * the reach harness ([H2FuzzReachTest]); null while fuzzing, so a campaign pays one null check per frame.
 */
internal class Reach {
    val features = LinkedHashSet<String>()

    /** How the connection ended, when we ended it (for the per-input listing). */
    var closed: String? = null

    fun hit(name: String) {
        features += name
    }

    /** Watches every frame [core] handles from now on. */
    fun watch(core: H2ConnectionCore) {
        core.frameHook = { f -> frame(f, core) }
    }

    private fun frame(
        f: Frame,
        core: H2ConnectionCore,
    ) {
        when (f) {
            is Frame.Data -> {
                hit(if (f.data.isEmpty() && !f.endStream) "frame DATA (empty)" else "frame DATA")
            }

            is Frame.Headers -> {
                hit("frame HEADERS")
                if (!f.endHeaders) hit("field block split (HEADERS without END_HEADERS)")
            }

            is Frame.Continuation -> {
                hit("frame CONTINUATION")
            }

            is Frame.Priority -> {
                hit("frame PRIORITY")
            }

            is Frame.RstStream -> {
                hit("frame RST_STREAM")
            }

            is Frame.Settings -> {
                if (f.ack) hit("frame SETTINGS ACK") else hit("frame SETTINGS")
                for (i in f.ids.indices) {
                    val v = f.values[i]
                    when (f.ids[i]) {
                        SettingId.HEADER_TABLE_SIZE -> {
                            hit("setting HEADER_TABLE_SIZE")
                        }

                        SettingId.ENABLE_PUSH -> {
                            hit("setting ENABLE_PUSH")
                        }

                        SettingId.MAX_CONCURRENT_STREAMS -> {
                            hit("setting MAX_CONCURRENT_STREAMS")
                        }

                        SettingId.INITIAL_WINDOW_SIZE -> {
                            hit("setting INITIAL_WINDOW_SIZE")
                            if (v < core.peerInitialWindow) hit("flow: initial window shrinks")
                            if (v > core.peerInitialWindow) hit("flow: initial window grows")
                        }

                        SettingId.MAX_FRAME_SIZE -> {
                            hit("setting MAX_FRAME_SIZE")
                        }

                        SettingId.MAX_HEADER_LIST_SIZE -> {
                            hit("setting MAX_HEADER_LIST_SIZE")
                        }

                        SettingId.ENABLE_CONNECT_PROTOCOL -> {
                            hit("setting ENABLE_CONNECT_PROTOCOL")
                        }

                        SettingId.NO_RFC7540_PRIORITIES -> {
                            hit("setting NO_RFC7540_PRIORITIES")
                        }

                        else -> {
                            hit("setting unknown")
                        }
                    }
                }
            }

            is Frame.Ping -> {
                hit(if (f.ack) "frame PING ACK" else "frame PING")
            }

            is Frame.GoAway -> {
                hit("frame GOAWAY")
            }

            is Frame.WindowUpdate -> {
                hit(if (f.streamId == 0) "frame WINDOW_UPDATE (connection)" else "frame WINDOW_UPDATE (stream)")
            }

            is Frame.PriorityUpdate -> {
                hit("frame PRIORITY_UPDATE")
            }

            is Frame.PushPromise -> {
                hit("frame PUSH_PROMISE")
            }

            is Frame.AltSvc -> {
                hit("frame ALTSVC")
            }

            is Frame.Unknown -> {
                hit("frame unknown type")
            }
        }
    }

    /** An event the driver drained. */
    fun event(e: H2Event) {
        when (e) {
            is H2Event.Closed -> {
                if (e.byPeer) return
                closed = "${e.code.name}: ${e.reason}"
                hit("connection error ${e.code.name}")
                if (e.code == Http2ErrorCode.ENHANCE_YOUR_CALM) hit("calm: ${calmCause(e.reason)}")
            }

            is H2Event.HeadersReceived -> {
                if (e.tooLarge) hit("field section too large")
                if (e.fields.any { it.first == ":protocol" }) hit("Extended CONNECT (:protocol)")
            }

            is H2Event.GoAway -> {
                hit("event GOAWAY")
            }

            is H2Event.PingAck -> {
                hit("event PING answered")
            }

            is H2Event.WindowAvailable -> {
                hit("flow: window available again")
            }

            is H2Event.PriorityUpdate -> {
                hit("event PRIORITY_UPDATE")
            }

            is H2Event.AltSvc -> {
                hit("event ALTSVC")
            }

            else -> {}
        }
    }

    /** A frame the core wrote. */
    fun wrote(f: Frame) {
        if (f is Frame.RstStream) hit("stream error ${Http2ErrorCode.of(f.errorCode).name}")
    }

    companion object {
        /** The flood limit an ENHANCE_YOUR_CALM came from, by its debug text. */
        fun calmCause(reason: String): String =
            when {
                "glitches" in reason -> "glitch budget"
                "control frames queued" in reason -> "control frame queue"
                "CONTINUATION" in reason || "field block above" in reason -> "field block limits"
                "field block not finished" in reason -> "field block time"
                "empty DATA" in reason -> "empty DATA in a row"
                "refused streams" in reason -> "refused streams in a row"
                "stream resets" in reason -> "reset budget"
                else -> reason
            }
    }
}

/** The reach harness's collector for the input running now; null while fuzzing. */
@Volatile internal var reach: Reach? = null
