// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.PathMtuRefusedException
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9000 section 14.2.1 where the socket's DF is in DO mode (probe mode refused, or the JVM's portable socket without `ksl`):
 * a forged ICMP message claiming less than 1200 makes the system refuse every datagram to the peer (EMSGSIZE / WSAEMSGSIZE). A
 * refusal of a datagram of at most 1200 bytes ([PathMtuRefusedException]) ends the connection at once with no viable path (an
 * HTTP/3 client then falls back to TCP) instead of losing datagrams until the idle timeout; a larger one stays a lost datagram.
 * Fault injection on the in-memory socket.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class PathMtuRefusedTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun ping(
        c: QuicConnection,
        s: QuicConnection,
    ) = coroutineScope {
        val server =
            launch {
                val st = s.acceptStream()
                val got = st.input.readExactly(4)
                st.output.writeFully(got, 0, 4)
                st.output.flushAndClose()
            }
        val st = c.openBidi()
        st.output.writeFully(byteArrayOf(1, 2, 3, 4), 0, 4)
        st.output.flushAndClose()
        assertTrue(st.input.readExactly(4).contentEquals(byteArrayOf(1, 2, 3, 4)))
        server.join()
    }

    @Test fun negative_aRefusalAtOrBelow1200EndsTheClientConnection() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, _) = p.connect()
                    p.clientIo.sendFailure = PathMtuRefusedException(1200)
                    val st = c.openBidi()
                    // the flush may already meet the closed connection
                    runCatching {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    }
                    assertIs<QuicException.ConnectionLost.NoViablePath>(c.closed.await())
                }
            }
        }

    @Test fun negative_aRefusalOnTheServersSocketEndsThatConnectionOnly() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    p.serverIo.sendFailure = PathMtuRefusedException(800)
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(1), 0, 1)
                    st.output.flush() // the server acknowledges: its send is refused
                    assertIs<QuicException.ConnectionLost.NoViablePath>(s.closed.await())
                    p.serverIo.sendFailure = null
                    val (c2, s2) = p.connect() // the server's endpoint stays up
                    ping(c2, s2)
                    assertFalse(c2.closed.isCompleted)
                    c.close()
                }
            }
        }

    @Test fun aRefusalAbove1200IsALostDatagram() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    p.clientIo.sendFailuresLeft = 1
                    p.clientIo.sendFailure = PathMtuRefusedException(1300)
                    ping(c, s) // its first datagram is refused and sent again
                    assertTrue(p.clientIo.sendFailure == null, "the refusal happened")
                    assertFalse(c.closed.isCompleted, "a refusal above QUIC's floor is a lost datagram, not a failed path")
                }
            }
        }
}
