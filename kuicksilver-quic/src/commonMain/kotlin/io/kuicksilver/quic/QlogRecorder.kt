// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * How a layer above QUIC (HTTP/3) adds its own events to a connection's qlog trace (docs/guide/quic.md, "qlog"), so that one
 * file holds the transport's and the application's events, as qlog tools expect.
 *
 * [record] may be called from any thread. It never calls the [QlogSink]: the event is formatted with its time on the caller's
 * thread, queued, and written by the endpoint loop before the next transport event, so a sink is still only ever called on
 * the loop and two records never interleave. The queue is bounded: events beyond it are dropped, never waited for.
 */
@InternalKuicksilverApi
public interface QlogRecorder {
    /**
     * True while the trace takes events: false once it ended (connection released, size cap, failing sink). Check it before
     * building an event, so a connection whose trace is gone formats nothing.
     */
    public val enabled: Boolean

    /** The sink's [QlogSink.logHeaderValues]: HTTP field values may be written; otherwise only their names. */
    public val logHeaderValues: Boolean

    /**
     * Queues one event: [name] is the qlog event name with its category (`http:frame_created`), [data] the members of its
     * `data` object, already JSON (`"stream_id":0,"frame":{...}`), without the braces. Both must be valid JSON as given:
     * nothing is escaped here.
     */
    public fun record(
        name: String,
        data: String,
    )
}

/** The qlog recorder of [this] connection, or null when it is not traced (no sink) or is of another implementation. */
@InternalKuicksilverApi
public val QuicConnection.qlogRecorder: QlogRecorder?
    get() = (this as? io.kuicksilver.quic.runtime.ConnectionRuntime)?.qlogRecorder
