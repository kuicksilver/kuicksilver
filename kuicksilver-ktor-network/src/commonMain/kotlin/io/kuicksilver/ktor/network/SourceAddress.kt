// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * The local address the system would send from to reach [destination] (port 0), or null when it has none: no address of
 * that family, or no route to it. A UDP socket is connected to [destination], which only selects the route and the source
 * address, and closed again: no packet is sent. RFC 6724 section 6 sorts destinations by such candidate source addresses
 * (Source(D) in its rules: Rule 1, an undefined one; Rule 2, its scope; Rule 5, its label), which this answers for one
 * destination.
 */
@InternalKuicksilverApi
public fun sourceAddressFor(destination: TcpAddress): TcpAddress? =
    try {
        platformSourceAddress(destination)?.takeUnless { a -> a.bytes.all { it.toInt() == 0 } }
    } catch (_: Exception) {
        null
    }

internal expect fun platformSourceAddress(destination: TcpAddress): TcpAddress?
