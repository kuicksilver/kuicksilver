// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.webtransport.WtSettings

/**
 * The server SETTINGS a client keeps with its session tickets and complies with in 0-RTT (RFC 9114 section 7.2.4.2:
 * "Clients SHOULD store the settings the server provided in the HTTP/3 connection where resumption information was
 * provided"; "A client MUST comply with stored settings ... when attempting 0-RTT").
 */
internal object StoredSettings {
    /** The settings this client understands, each with its default; MAX_FIELD_SECTION_SIZE has none (absent: unlimited). */
    private val DEFAULTS: Map<Long, Long?> =
        mapOf(
            SettingsId.QPACK_MAX_TABLE_CAPACITY to 0L,
            SettingsId.QPACK_BLOCKED_STREAMS to 0L,
            SettingsId.MAX_FIELD_SECTION_SIZE to null,
            SettingsId.ENABLE_CONNECT_PROTOCOL to 0L,
            SettingsId.H3_DATAGRAM to 0L,
        ) + WtSettings.ALL.associateWith { 0L }

    /** What is stored: the server's SETTINGS without reserved (GREASE) identifiers, which carry no meaning. */
    fun kept(received: Map<Long, Long>): List<Pair<Long, Long>> = received.filterKeys { !FrameType.isGrease(it) }.toList()

    /**
     * Why the SETTINGS a server sent after accepting 0-RTT are not compatible with the [stored] ones, or null. Section
     * 7.2.4.2: settings "not compatible with the previously specified settings", and a SETTINGS frame "that omits a setting
     * value that the client understands (apart from reserved setting identifiers) that was previously specified to have a
     * non-default value", are a connection error of type H3_SETTINGS_ERROR. Compatible: a client that complied with the
     * stored values complies with the new ones, so no limit is lower and no feature turned off; a non-zero
     * SETTINGS_QPACK_MAX_TABLE_CAPACITY must be sent again unchanged (RFC 9204 section 3.2.3).
     */
    fun incompatibility(
        stored: Map<Long, Long>,
        now: Map<Long, Long>,
    ): String? {
        for ((id, was) in stored) {
            if (id !in DEFAULTS) continue
            val name = "0x${id.toString(16)}"
            val v = now[id]
            if (v == null) {
                if (DEFAULTS[id] != was) return "setting $name ($was in 0-RTT) omitted"
                continue
            }
            if (id == SettingsId.QPACK_MAX_TABLE_CAPACITY) {
                if (was != 0L && v != was) return "QPACK table capacity $v instead of $was used in 0-RTT"
            } else if (v < was) {
                return "setting $name lowered from $was to $v after 0-RTT"
            }
        }
        return null
    }
}
