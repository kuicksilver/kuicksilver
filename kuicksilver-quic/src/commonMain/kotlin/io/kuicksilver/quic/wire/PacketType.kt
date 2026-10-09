// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

/** Long-header packet types plus the 1-RTT short header (RFC 9000 section 17). */
internal enum class PacketType { Initial, ZeroRtt, Handshake, Retry, OneRtt }
