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

    /** The `:protocol` token a client sends to a peer of this version (draft-16 section 3.2; `webtransport` before -15). */
    val protocolToken: String get() = if (this == Draft16) WtTokens.H3 else WtTokens.LEGACY

    companion object {
        /** The highest version the peer's [settings] announce, or null when they announce none. */
        fun of(settings: Map<Long, Long>): WtVersion? =
            when {
                settings[SettingsId.WT_ENABLED] == 1L -> Draft16
                (settings[SettingsId.WT_MAX_SESSIONS_DRAFT14] ?: 0L) > 0L -> Draft14
                (settings[SettingsId.ENABLE_WEBTRANSPORT_DRAFT02] ?: 0L) != 0L -> Draft02
                else -> null
            }
    }
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

    fun isWebTransport(protocol: String?): Boolean = protocol == H3 || protocol == LEGACY
}
