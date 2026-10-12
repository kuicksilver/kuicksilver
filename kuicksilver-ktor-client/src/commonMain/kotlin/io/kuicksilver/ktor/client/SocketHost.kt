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

/**
 * [host] as an RFC 3986 `uri-host` (used in `Alt-Used`, RFC 7838 section 5): an IPv6 literal gets its brackets, a name or
 * an IPv4 address stays as it is.
 */
internal fun uriHost(host: String): String = if (':' in host && !host.startsWith('[')) "[$host]" else host
