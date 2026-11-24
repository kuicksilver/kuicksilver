// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.frame.SettingsId

/**
 * The WebTransport over HTTP/3 drafts this library recognises in a peer's SETTINGS, oldest first. The wire format is
 * draft-ietf-webtrans-http3-17; draft-16 is spoken for the libraries that have not moved yet (webtransport-go, picoquic),
 * and the older codepoints are advertised and accepted because browsers still speak them (Chrome and Firefox draft-02,
 * Safari draft-14). Every codepoint and rule that changes between drafts lives here.
 */
internal enum class WtVersion {
    /** `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02 to -06), `:protocol webtransport` with `sec-webtransport-http3-draft02: 1`. */
    Draft02,

    /** `SETTINGS_WT_MAX_SESSIONS` (draft-13, -14), `:protocol webtransport`. */
    Draft14,

    /** `SETTINGS_WT_ENABLED` 0x2c7cf000 (draft-15, -16), `:protocol webtransport-h3`. */
    Draft16,

    /** `SETTINGS_WT_ENABLED` 0x20b8933b (draft-17 section 9.2), `:protocol webtransport-h3`. */
    Draft17,
    ;

    /**
     * This version needs `reset_stream_at` on both sides. draft-14 and draft-16 section 3.1: "both the client and the server
     * enable the extension by sending an empty reset_stream_at transport parameter"; draft-02 predates RESET_STREAM_AT
     * (Chrome and Firefox speak it, and need not send the parameter).
     */
    val needsResetStreamAt: Boolean get() = this != Draft02

    /** The `:protocol` token a client sends to a peer of this version (section 3.2 from draft-15 on; `webtransport` before). */
    val protocolToken: String get() = if (this >= Draft16) WtTokens.H3 else WtTokens.LEGACY

    /**
     * The connection error for a `WT_STREAM` signal anywhere but the first bytes the initiator sends on a bidirectional
     * stream: draft-17 section 4.3, "H3_FRAME_UNEXPECTED"; draft-14 and draft-16 section 4.3, "H3_FRAME_ERROR" (draft-02
     * names none; it keeps the older code).
     */
    val misplacedWtStreamCode: Long get() = if (this >= Draft17) Http3ErrorCode.FRAME_UNEXPECTED else Http3ErrorCode.FRAME_ERROR

    companion object {
        /** The highest version the peer's [settings] announce, or null when they announce none. */
        fun of(settings: Map<Long, Long>): WtVersion? = offeredIn(settings).maxOrNull()

        /**
         * Every version the peer's [settings] announce. A draft-17 `SETTINGS_WT_ENABLED` counts only as 1: a client takes
         * any other value from a server as a connection error, and a server ignores it from a client (draft-17 section
         * 3.1, "a server MUST ignore it"; section 7.1 reads the codepoints a client sends as its versions).
         */
        fun offeredIn(settings: Map<Long, Long>): Set<WtVersion> =
            buildSet {
                if (settings[SettingsId.WT_ENABLED_DRAFT17] == 1L) add(Draft17)
                if (settings[SettingsId.WT_ENABLED_DRAFT16] == 1L) add(Draft16)
                if ((settings[SettingsId.WT_MAX_SESSIONS_DRAFT14] ?: 0L) > 0L) add(Draft14)
                if ((settings[SettingsId.ENABLE_WEBTRANSPORT_DRAFT02] ?: 0L) != 0L) add(Draft02)
            }

        /** The versions we announce ([WtSettings.ours]): a server every one, a client draft-17, draft-16 and draft-02. */
        fun ours(isServer: Boolean): Set<WtVersion> = if (isServer) entries.toSet() else setOf(Draft17, Draft16, Draft02)

        /**
         * The versions a session on this connection may run, highest first: those both sides announce (draft-17 section
         * 7.1, "The highest version supported by both endpoints is selected"; a version only the peer announces is never
         * chosen). A server whose client announces none selects draft-17: section 7.1, "Otherwise, the server selects the
         * version described in this document. For example, a client that supports only the version described in this
         * document does not send SETTINGS_WT_ENABLED, so the server selects that version". A client never assumes one: "A
         * client that supports only draft versions that the server does not support finds none of its codepoints in the
         * server's SETTINGS, so it treats the server as not supporting WebTransport".
         */
        fun common(
            peer: Map<Long, Long>,
            isServer: Boolean,
        ): List<WtVersion> {
            val both = (offeredIn(peer) intersect ours(isServer)).sortedDescending()
            return if (isServer && both.isEmpty()) listOf(Draft17) else both
        }
    }
}

/**
 * Why the peer of [h3] cannot carry a WebTransport session of [version] by its transport parameters (draft-14 to -17
 * section 3.1: `max_datagram_frame_size` above 0 and, from draft-14 on, `reset_stream_at`, both on both sides), or null
 * when it can. The peer's SETTINGS are checked by the callers.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun wtTransportGap(
    h3: io.kuicksilver.http3.runtime.H3Session,
    version: WtVersion,
): String? =
    when {
        !h3.quic.peerSupportsDatagrams -> {
            "the peer did not send max_datagram_frame_size above 0, which WebTransport needs (section 3.1)"
        }

        version.needsResetStreamAt && !h3.quic.resetStreamAtEnabled -> {
            "reset_stream_at is not on both sides (QuicConfig.resetStreamAt and the peer's transport parameter), which " +
                "WebTransport $version needs (section 3.1)"
        }

        else -> {
            null
        }
    }

/**
 * The version a client's session on [h3] runs: the highest that both sides announce ([WtVersion.common]) and that the
 * connection's transport parameters can carry ([wtTransportGap]); null with the reason when none can. A server that
 * announces draft-16 without `reset_stream_at` but also draft-02 gets a draft-02 CONNECT (then a draft-02 request in
 * every respect: `:protocol webtransport` and `sec-webtransport-http3-draft02: 1`). This fallback is our reading of
 * section 7.1, "the highest version supported by both endpoints" taken as the highest both can actually run; the draft
 * does not say it. A server that announces only the newer draft is refused.
 */
internal fun wtClientVersion(h3: io.kuicksilver.http3.runtime.H3Session): Pair<WtVersion?, String?> {
    val common = h3.wtCommonVersions
    if (common.isEmpty()) return null to NO_COMMON_VERSION
    common.firstOrNull { wtTransportGap(h3, it) == null }?.let { return it to null }
    return null to wtTransportGap(h3, common.first())
}

/**
 * The version of the WebTransport request a server accepts on [h3]: draft-02 when the request is a draft-02 request
 * ([draft02Request]: `:protocol webtransport` and `sec-webtransport-http3-draft02: 1`) and both sides announce draft-02,
 * else the highest version both announce (section 7.1); null with the reason when the connection's transport parameters
 * cannot carry it (section 3.1: the request is then malformed). So a client that announces draft-16 or draft-14 without
 * `reset_stream_at` and also draft-02 is served only when its CONNECT is a draft-02 request (our reading of section 7.1,
 * as for [wtClientVersion]); its draft-16 or draft-14 CONNECT is refused, never run as a draft-16 session that broke
 * section 3.1 and could not reset as section 4.4 requires. A request in draft-02 form runs draft-02 even when a higher
 * common version could run, because the client asked for draft-02.
 */
internal fun wtServerVersion(
    h3: io.kuicksilver.http3.runtime.H3Session,
    draft02Request: Boolean,
): Pair<WtVersion?, String?> {
    val common = h3.wtCommonVersions
    if (common.isEmpty()) return null to NO_COMMON_VERSION
    val v = if (draft02Request && WtVersion.Draft02 in common) WtVersion.Draft02 else common.first()
    return wtTransportGap(h3, v)?.let { null to it } ?: (v to null)
}

private const val NO_COMMON_VERSION =
    "the peer announces no WebTransport draft we speak (SETTINGS_WT_ENABLED of draft-17 or draft-16, draft-14 " +
        "SETTINGS_WT_MAX_SESSIONS or draft-02 SETTINGS_ENABLE_WEBTRANSPORT)"

/** The WebTransport settings we interpret and advertise (draft-ietf-webtrans-http3-17 section 3.1); identifiers in [SettingsId]. */
internal object WtSettings {
    /**
     * The codepoints this library interprets; the peer's are taken out of `Http3PeerSettings.unknown`. The flow-control
     * ones are among them, so a client keeps them with its tickets and refuses a resumed connection whose draft-16 or
     * draft-14 server lowered them after 0-RTT (their section 3.2: "A client MUST close the connection with
     * H3_SETTINGS_ERROR if the SETTINGS frame received in the resumed connection reduces any flow control values from the
     * cached previous values"); a draft-17 server's are taken as sent ([discardedOnResumption]).
     */
    val ALL: Set<Long> =
        setOf(
            SettingsId.WT_ENABLED_DRAFT17,
            SettingsId.WT_ENABLED_DRAFT16,
            SettingsId.WT_MAX_SESSIONS_DRAFT14,
            SettingsId.ENABLE_WEBTRANSPORT_DRAFT02,
            SettingsId.WT_INITIAL_MAX_STREAMS_UNI,
            SettingsId.WT_INITIAL_MAX_STREAMS_BIDI,
            SettingsId.WT_INITIAL_MAX_DATA,
        )

    /**
     * The settings a client does not hold a resumed connection to (RFC 9114 section 7.2.4.2), by the SETTINGS [now] that
     * connection's server sent. draft-17 section 3.2: "a client MUST discard any values for the settings defined in this
     * document (Section 9.2) that it retained from a previous connection and use the values received on the current
     * connection. A server can therefore accept 0-RTT regardless of the values it previously sent for these settings, and
     * the requirements in Section 7.2.4.2 of [HTTP3] to treat incompatible or omitted settings as a connection error do
     * not apply to these settings." Draft-17's `SETTINGS_WT_ENABLED` always; the three `SETTINGS_WT_INITIAL_*` when the
     * server speaks draft-17, which our client then selects (it offers draft-17 first, [WtVersion.ours]). A server of
     * draft-16 or draft-14 is held to the values it sent before: their section 3.2, "A client MUST close the connection
     * with H3_SETTINGS_ERROR if the SETTINGS frame received in the resumed connection reduces any flow control values".
     */
    fun discardedOnResumption(now: Map<Long, Long>): Set<Long> =
        if (WtVersion.Draft17 in WtVersion.offeredIn(now)) {
            setOf(
                SettingsId.WT_ENABLED_DRAFT17,
                SettingsId.WT_INITIAL_MAX_STREAMS_UNI,
                SettingsId.WT_INITIAL_MAX_STREAMS_BIDI,
                SettingsId.WT_INITIAL_MAX_DATA,
            )
        } else {
            setOf(SettingsId.WT_ENABLED_DRAFT17)
        }

    /**
     * What we advertise. A server announces every version so each browser and library finds its own; a client announces
     * draft-17, draft-16 and draft-02 (draft-17 section 3.1: "For draft versions of WebTransport only, clients MUST also
     * send SETTINGS_WT_ENABLED for each draft version they support"; section 7.1: "An endpoint that supports multiple draft
     * versions sends SETTINGS_WT_ENABLED once for each distinct codepoint"). Both send their non-zero initial flow-control limits (section 5.5), which declare WebTransport flow
     * control (section 5.1), and a server tells draft-14 clients how many sessions it takes at once
     * (`SETTINGS_WT_MAX_SESSIONS`, [Http3Settings.webTransportMaxSessions] with flow control, else 1: draft-14 section
     * 5.1 counts a value above 1 as declaring flow control).
     */
    fun ours(
        isServer: Boolean,
        settings: Http3Settings,
    ): List<Pair<Long, Long>> =
        buildList {
            add(SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L)
            if (isServer) {
                add(
                    SettingsId.WT_MAX_SESSIONS_DRAFT14 to
                        if (settings.webTransportFlowControl) settings.webTransportMaxSessions.toLong() else 1L,
                )
            }
            add(SettingsId.WT_ENABLED_DRAFT16 to 1L)
            add(SettingsId.WT_ENABLED_DRAFT17 to 1L)
            if (settings.webTransportInitialMaxStreamsUni != 0L) {
                add(SettingsId.WT_INITIAL_MAX_STREAMS_UNI to settings.webTransportInitialMaxStreamsUni)
            }
            if (settings.webTransportInitialMaxStreamsBidi != 0L) {
                add(SettingsId.WT_INITIAL_MAX_STREAMS_BIDI to settings.webTransportInitialMaxStreamsBidi)
            }
            if (settings.webTransportInitialMaxData != 0L) add(SettingsId.WT_INITIAL_MAX_DATA to settings.webTransportInitialMaxData)
        }
}

/** `:protocol` tokens of a WebTransport Extended CONNECT. */
internal object WtTokens {
    /** draft-15 and later (section 3.2), draft-17 included. */
    const val H3: String = "webtransport-h3"

    /** draft-02 to -14, still sent by every browser. */
    const val LEGACY: String = "webtransport"

    /** The request field a draft-02 client sends with [LEGACY]; its value is `1`. */
    const val DRAFT02_REQUEST_FIELD: String = "sec-webtransport-http3-draft02"

    /** The response field a draft-02 client (Chrome) requires, with the value [DRAFT02_RESPONSE_VALUE]. */
    const val DRAFT02_RESPONSE_FIELD: String = "sec-webtransport-http3-draft"
    const val DRAFT02_RESPONSE_VALUE: String = "draft02"

    /**
     * Whether `:protocol` [protocol] names WebTransport, in any case: RFC 9110 section 7.8, "recipients SHOULD use
     * case-insensitive comparison when matching each protocol-name to supported protocols" (RFC 8441 section 4).
     */
    fun isWebTransport(protocol: String?): Boolean = protocol.equals(H3, ignoreCase = true) || protocol.equals(LEGACY, ignoreCase = true)
}
