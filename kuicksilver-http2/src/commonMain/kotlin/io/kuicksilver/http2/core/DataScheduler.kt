// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

/**
 * Chooses the stream whose DATA frame goes next (RFC 9218 section 10, as the QUIC transport's scheduler does for HTTP/3):
 * the most urgent level first ("It is RECOMMENDED that, when possible, servers respect the urgency parameter"); within it
 * non-incremental streams in ascending id order ("Non-incremental responses of the same urgency SHOULD be served by
 * prioritizing bandwidth allocation in ascending order of the stream ID") and incremental streams round-robin
 * ("Incremental responses of the same urgency SHOULD be served by sharing bandwidth among them").
 *
 * Two exceptions keep a stream from starving, as on HTTP/3. Within one level the incremental and the non-incremental
 * streams take turns frame by frame (section 10 recommends that servers "avoid such starvation where possible"), and a
 * [tunnel][H2Stream.tunnel] gets one frame in [TUNNEL_TURN] whatever its urgency (section 10.1: "servers SHOULD allocate
 * some amount of bandwidths to streams acting as tunnels").
 *
 * A stream is in the set while it has a DATA frame queued or its writer was just told to hand over its next one (see
 * [H2ConnectionCore]); the set holds at most one entry per stream the peer let us open, so a pass over it per frame (at
 * most `SETTINGS_MAX_CONCURRENT_STREAMS` entries for a 16 KiB frame) costs little and allocates nothing.
 */
internal class DataScheduler {
    private val ready = ArrayList<H2Stream>()

    /** Bit `u` is set when the last frame sent at urgency `u` came from an incremental stream. */
    private var lastIncremental = 0

    /** Frames sent from other streams since a tunnel last sent one while a tunnel was in the set. */
    private var sinceTunnel = 0
    private var tunnels = 0
    private var served = 0L

    val isEmpty: Boolean get() = ready.isEmpty()

    fun add(s: H2Stream) {
        if (s.dataReady) return
        s.dataReady = true
        ready += s
        if (s.tunnel) tunnels++
    }

    fun remove(s: H2Stream) {
        if (!s.dataReady) return
        s.dataReady = false
        ready.remove(s)
        if (s.tunnel && --tunnels == 0) sinceTunnel = 0
    }

    fun clear() {
        for (s in ready) s.dataReady = false
        ready.clear()
        tunnels = 0
        sinceTunnel = 0
    }

    /** The stream that goes next, or null when the set is empty. */
    fun next(): H2Stream? {
        if (ready.isEmpty()) return null
        var urgency = Int.MAX_VALUE
        var tunnel: H2Stream? = null
        for (s in ready) {
            if (s.urgency < urgency) urgency = s.urgency
            if (s.tunnel && (tunnel == null || s.servedAt < tunnel.servedAt)) tunnel = s
        }
        if (tunnel != null && tunnel.urgency != urgency && sinceTunnel >= TUNNEL_TURN - 1) return tunnel
        var nonIncremental: H2Stream? = null
        var incremental: H2Stream? = null
        for (s in ready) {
            if (s.urgency != urgency) continue
            if (s.incremental) {
                if (incremental == null || s.servedAt < incremental.servedAt) incremental = s
            } else if (nonIncremental == null || s.id < nonIncremental.id) {
                nonIncremental = s
            }
        }
        return if (incremental != null &&
            (nonIncremental == null || lastIncremental and (1 shl urgency) == 0)
        ) {
            incremental
        } else {
            nonIncremental
        }
    }

    /** [s], the stream [next] chose, sent a frame: the round-robin and the turns advance. */
    fun onServed(s: H2Stream) {
        s.servedAt = ++served
        lastIncremental = if (s.incremental) lastIncremental or (1 shl s.urgency) else lastIncremental and (1 shl s.urgency).inv()
        if (s.tunnel) {
            sinceTunnel = 0
        } else if (tunnels > 0) {
            sinceTunnel++
        }
    }

    internal companion object {
        /** A tunnel in the set sends at least one frame in this many (about 6 %), as on HTTP/3. */
        const val TUNNEL_TURN = 16
    }
}
