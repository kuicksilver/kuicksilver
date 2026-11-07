// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress

/**
 * The port is held by the local end of a connection: no listener matches it, so a SYN to it is answered with a reset, and
 * no connect takes a port in use as its own. (A socket bound without listening does not do here: Apple drops a SYN to it,
 * and the connect times out instead of being refused.)
 */
internal actual suspend fun <T> withRefusedLoopbackPort(
    selector: SelectorManager,
    use: suspend (port: Int) -> T,
): T {
    val server = bindTcp(selector, "127.0.0.1", 0)
    try {
        val client = connectTcp(selector, InetSocketAddress("127.0.0.1", (server.localAddress as InetSocketAddress).port))
        try {
            val accepted = server.accept()
            try {
                return use((client.localAddress as InetSocketAddress).port)
            } finally {
                accepted.close()
            }
        } finally {
            client.close()
        }
    } finally {
        server.close()
    }
}
