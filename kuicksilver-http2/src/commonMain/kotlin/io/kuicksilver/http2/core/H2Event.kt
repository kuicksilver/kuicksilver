// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode

/** What the connection core reports to its driver ([H2ConnectionCore.nextEvent]). */
internal sealed interface H2Event {
    /**
     * A field section on [streamId]: request or response headers, an interim (1xx) response or trailers. [tooLarge]: the
     * section passed our SETTINGS_MAX_HEADER_LIST_SIZE and [fields] stops at the limit (a server answers 431, a client
     * fails the request; RFC 9113 section 8.2). [opening]: the peer opened [streamId] with this section (a server's new
     * request); any other section belongs to a stream the driver already knows, or released (never a new request).
     */
    class HeadersReceived(
        val streamId: Int,
        val fields: List<Pair<String, String>>,
        val endStream: Boolean,
        val tooLarge: Boolean,
        val opening: Boolean = false,
    ) : H2Event

    /** Content of [streamId]; the driver calls [H2ConnectionCore.consumed] once the application has read it. */
    class Data(
        val streamId: Int,
        val data: ByteArray,
        val endStream: Boolean,
    ) : H2Event

    /**
     * [streamId] ended abnormally: reset by the peer ([byPeer]), or by us after its error. [notProcessed]: the peer's
     * GOAWAY or REFUSED_STREAM says it did not process the request, which is safe to retry (RFC 9113 sections 6.8, 8.7).
     */
    class StreamReset(
        val streamId: Int,
        val code: Http2ErrorCode,
        val byPeer: Boolean,
        val notProcessed: Boolean,
    ) : H2Event

    /** The peer sent GOAWAY: no new streams; ours above [lastStreamId] were reported as not processed. */
    class GoAway(
        val lastStreamId: Int,
        val code: Http2ErrorCode,
        val debug: ByteArray,
    ) : H2Event

    /** The peer's SETTINGS were applied (its limits may have changed). */
    data object SettingsChanged : H2Event

    /** [streamId] can take data again after [H2ConnectionCore.sendData] accepted less than it was offered. */
    class WindowAvailable(
        val streamId: Int,
    ) : H2Event

    /**
     * An ALTSVC frame (RFC 7838 section 4) a client takes: on stream 0 for [origin] (its Origin field), on one of our streams
     * ([streamId]) for that stream's origin ([origin] null). [value] is an `Alt-Svc` field value, "semantically equivalent
     * to receiving an Alt-Svc header field".
     */
    class AltSvc(
        val streamId: Int,
        val origin: String?,
        val value: String,
    ) : H2Event

    /** Our PING was answered after [rttNanos]. */
    class PingAck(
        val payload: Long,
        val rttNanos: Long,
    ) : H2Event

    /** The connection is over: write what [H2ConnectionCore.poll] still gives, then close the transport. */
    class Closed(
        val code: Http2ErrorCode,
        val byPeer: Boolean,
        val reason: String,
    ) : H2Event
}

/** [H2ConnectionCore.openStream] while the peer's SETTINGS_MAX_CONCURRENT_STREAMS is reached: wait or use another connection. */
internal class H2StreamLimit(
    message: String,
) : Exception(message)

/** A new stream cannot be opened on this connection (GOAWAY, closed, identifiers exhausted): use another connection. */
internal class H2ConnectionUnusable(
    message: String,
) : Exception(message)

/** A field section larger than the peer's SETTINGS_MAX_HEADER_LIST_SIZE: it was not sent and the HPACK state is unchanged. */
internal class H2HeaderListTooLarge(
    message: String,
) : Exception(message)
