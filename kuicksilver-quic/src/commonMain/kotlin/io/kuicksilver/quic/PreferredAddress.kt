// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.core.AddressClass

/**
 * A server's preferred address (RFC 9000 sections 9.6 and 18.2): where it asks clients to move after the handshake, one address
 * per family it offers. The endpoint opens a socket on each (with every loop of a group sharing the port, as for the main
 * socket) and advertises them with its sequence-1 connection ID. A client moves only to the address of the family it already
 * uses, only after it validated the path, and only from a server whose own address is public when the preferred one is local
 * (threat-model 3.14).
 *
 * @property ipv4 The IPv4 address and port, or null when none is offered.
 * @property ipv6 The IPv6 address and port, or null when none is offered.
 */
@ExperimentalKuicksilverApi
public class PreferredAddress internal constructor(
    public val ipv4: InetSocketAddress?,
    public val ipv6: InetSocketAddress?,
    check: Boolean,
) {
    /** A preferred address of [ipv4] and/or [ipv6]: IP literals with a port, not unspecified, multicast or broadcast. */
    public constructor(ipv4: InetSocketAddress?, ipv6: InetSocketAddress?) : this(ipv4, ipv6, true)

    init {
        // tests build a hostile server's addresses with check = false
        if (check) validate()
    }

    private fun validate() {
        require(ipv4 != null || ipv6 != null) { "a preferred address needs IPv4 or IPv6" }
        ipv4?.let {
            require(AddressClass.ipBytes(it).size == 4) { "ipv4 is not an IPv4 literal: ${it.hostname}" }
            require(it.port in 1..65535) { "ipv4 needs a port" }
            require(!AddressClass.isUnsafeDestination(it, originLocal = true)) { "ipv4 is unspecified, multicast or broadcast" }
        }
        ipv6?.let {
            require(AddressClass.ipBytes(it).size == 16) { "ipv6 is not an IPv6 literal: ${it.hostname}" }
            require(it.port in 1..65535) { "ipv6 needs a port" }
            require(!AddressClass.isUnsafeDestination(it, originLocal = true)) { "ipv6 is unspecified or multicast" }
        }
    }

    override fun toString(): String = "PreferredAddress(ipv4=$ipv4, ipv6=$ipv6)"
}
