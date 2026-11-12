// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.frame.SettingsId

/**
 * The WebTransport over HTTP/3 drafts this library recognises in a peer's SETTINGS, oldest first. The wire format is
 * draft-ietf-webtrans-http3-16; the older codepoints are advertised and accepted because browsers still speak them
 * (Chrome and Firefox draft-02, Safari draft-14). Every codepoint that changes between drafts lives here.
 */
internal enum class WtVersion {
    /** `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02 to -06), `:protocol webtransport` with `sec-webtransport-http3-draft02: 1`. */
    Draft02,

    /** `SETTINGS_WT_MAX_SESSIONS` (draft-13, -14), `:protocol webtransport`. */
    Draft14,

    /** `SETTINGS_WT_ENABLED` (draft-15, -16), `:protocol webtransport-h3`. */
    Draft16,
    ;

    /**
     * This version needs `reset_stream_at` on both sides. draft-14 and draft-16 section 3.1: "both the client and the server
     * enable the extension by sending an empty reset_stream_at transport parameter"; draft-02 predates RESET_STREAM_AT
     * (Chrome and Firefox speak it, and need not send the parameter).
     */
    val needsResetStreamAt: Boolean get() = this != Draft02

    /** The `:protocol` token a client sends to a peer of this version (draft-16 section 3.2; `webtransport` before -15). */
    val protocolToken: String get() = if (this == Draft16) WtTokens.H3 else WtTokens.LEGACY

    companion object {
        /** The highest version the peer's [settings] announce, or null when they announce none. */
        fun of(settings: Map<Long, Long>): WtVersion? = offeredIn(settings).maxOrNull()

        /** Every version the peer's [settings] announce. */
        fun offeredIn(settings: Map<Long, Long>): Set<WtVersion> =
            buildSet {
                if (settings[SettingsId.WT_ENABLED] == 1L) add(Draft16)
                if ((settings[SettingsId.WT_MAX_SESSIONS_DRAFT14] ?: 0L) > 0L) add(Draft14)
                if ((settings[SettingsId.ENABLE_WEBTRANSPORT_DRAFT02] ?: 0L) != 0L) add(Draft02)
            }

        /** The versions we announce ([WtSettings.ours]): a server every one, a client draft-16 and draft-02. */
        fun ours(isServer: Boolean): Set<WtVersion> = if (isServer) entries.toSet() else setOf(Draft16, Draft02)

        /**
         * The versions both sides announce, highest first: draft-16 section 7.1, "The highest version supported by both
         * endpoints is selected". A version only the peer announces is never chosen.
         */
        fun common(
            peer: Map<Long, Long>,
            isServer: Boolean,
        ): List<WtVersion> = (offeredIn(peer) intersect ours(isServer)).sortedDescending()
    }
}

/**
 * Why the peer of [h3] cannot carry a WebTransport session of [version] by its transport parameters (draft-16 and draft-14
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
 * The version a session on [h3] runs: the highest that both sides announce ([WtVersion.common]) and that the connection's
 * transport parameters can carry ([wtTransportGap]); null with the reason when none can. A peer that announces a newer
 * draft without its section 3.1 transport parameters (draft-14 and draft-16 need `reset_stream_at`) but also draft-02
 * gets draft-02, the highest version both sides can actually run; one that announces only the newer draft is refused.
 */
internal fun wtSelect(h3: io.kuicksilver.http3.runtime.H3Session): Pair<WtVersion?, String?> {
    val common = h3.wtCommonVersions
    common.firstOrNull { wtTransportGap(h3, it) == null }?.let { return it to null }
    val reason =
        common.firstOrNull()?.let { wtTransportGap(h3, it) }
            ?: "the peer announces no WebTransport draft we speak (SETTINGS_WT_ENABLED, draft-14 SETTINGS_WT_MAX_SESSIONS " +
            "or draft-02 SETTINGS_ENABLE_WEBTRANSPORT)"
    return null to reason
}

/** The WebTransport settings we interpret and advertise (draft-ietf-webtrans-http3-16 section 3.1); identifiers in [SettingsId]. */
internal object WtSettings {
    /** The codepoints this library interprets; the peer's are taken out of `Http3PeerSettings.unknown`. */
    val ALL: Set<Long> = setOf(SettingsId.WT_ENABLED, SettingsId.WT_MAX_SESSIONS_DRAFT14, SettingsId.ENABLE_WEBTRANSPORT_DRAFT02)

    /**
     * What we advertise. A server announces every version so each browser finds its own, and allows one session
     * (`WT_MAX_SESSIONS = 1`): without `SETTINGS_WT_INITIAL_*` there is no WebTransport flow control, and a client then
     * keeps to a single session (section 5.1). A client announces draft-16 and draft-02.
     */
    fun ours(isServer: Boolean): List<Pair<Long, Long>> =
        buildList {
            add(SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L)
            if (isServer) add(SettingsId.WT_MAX_SESSIONS_DRAFT14 to 1L)
            add(SettingsId.WT_ENABLED to 1L)
        }
}

/** `:protocol` tokens of a WebTransport Extended CONNECT. */
internal object WtTokens {
    /** draft-15 and later (section 3.2). */
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
