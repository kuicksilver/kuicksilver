// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import java.net.BindException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.test.fail

/**
 * Fails when another socket can still take 127.0.0.1:[port] while the test server listens on it, so that a test reaching
 * the server over 127.0.0.1 might reach that socket instead. That is the case for a server bound to the wildcard address
 * (a connector without `host`) on macOS: BSD sockets let a listener bound to 127.0.0.1 share the port of a wildcard one,
 * and a connection to 127.0.0.1 goes to the more specific listener. The kernel even hands a wildcard `port = 0` bind a
 * port that such a listener already holds (a Gradle daemon keeps dozens on 127.0.0.1, a local proxy a few): the request
 * then went to that process, and the test saw a TLS handshake time out after 10 s, a transport closed during the
 * handshake, or "wrong version number". A test server reached over 127.0.0.1 binds 127.0.0.1; this checks it, with the
 * socket options other processes get by default.
 */
internal fun assertNoLoopbackSquatter(port: Int) {
    ServerSocket().use { squatter ->
        try {
            squatter.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port))
        } catch (_: BindException) {
            return // the port is the server's alone on 127.0.0.1
        }
        fail("another process could take 127.0.0.1:$port from the test server: bind the server to 127.0.0.1 (host = \"127.0.0.1\")")
    }
}
