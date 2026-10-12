// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

/**
 * [host] as a socket address takes it: an IPv6 literal without its URL brackets. Ktor keeps the brackets in `Url.host`
 * ("[::1]"); the JVM resolver accepts them, but Kotlin/Native resolves through `getaddrinfo`, which rejects them
 * (EAI_NONAME, surfaced by ktor-network as "POSIX error 0").
 */
internal fun socketHost(host: String): String =
    if (host.length > 2 && host.startsWith('[') && host.endsWith(']')) host.substring(1, host.length - 1) else host
