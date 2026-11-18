// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import java.net.Inet6Address
import java.net.InetAddress

/**
 * [address] as an [IpAddress], with the scope id of an IPv6 address; no lookup. For a resolver that answers with
 * `InetAddress`, such as an OkHttp `Dns`: `Dns.blocking { name -> okHttpDns.lookup(name).map { IpAddress.of(it) } }`.
 */
@ExperimentalKuicksilverApi
public fun IpAddress.Companion.of(address: InetAddress): IpAddress = of(address.address, (address as? Inet6Address)?.scopeId ?: 0)
