// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.activePath
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** A request's `remoteAddress` is the client's address now, whatever path events the session saw. */
class RemoteAddressTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun requestRemoteAddressFollowsAMigrationTheSessionMissed() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                // the session sees no path event at all: as if its PathEvent.Changed was dropped (a hot flow without replay)
                val deaf =
                    object : QuicConnection by s {
                        override val pathEvents: Flow<PathEvent> = emptyFlow()
                    }
                val server = async { Http3Connection.server(deaf) }
                val client = Http3Connection.client(c)
                val h3 = server.await()
                val newAddr = InetSocketAddress("10.0.0.3", 3333)
                c.migrate(q.net.open(newAddr))
                val response = async { client.request(http3Request("GET", "server.test", "/")) }
                val req = withTimeout(5.seconds) { h3.acceptRequest() }
                // the server moves its end once a non-probing packet came from the new address
                withTimeout(5.seconds) { while (s.activePath?.remoteAddress != newAddr) delay(10) }
                assertEquals(newAddr, req.remoteAddress)
                response.cancel()
                client.close()
                h3.close()
            }
        }
}
