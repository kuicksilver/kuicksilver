// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    kotlinx.coroutines.DelicateCoroutinesApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.ktor.client

import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.runBlocking
import java.net.Inet6Address
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals

/** The application resolver on the JVM and Android: `InetAddress` answers (an OkHttp `Dns`) and the blocking adapter's threads. */
class DnsJvmTest {
    /** An `InetAddress` (as an OkHttp `Dns` answers) converts without a lookup, its scope kept. */
    @Test fun inetAddressesConvert() {
        assertEquals(IpAddress.parse("192.0.2.1"), IpAddress.of(InetAddress.getByAddress("h.test", byteArrayOf(192.toByte(), 0, 2, 1))))
        val scoped = Inet6Address.getByAddress("h.test", IpAddress.parse("fe80::1").bytes, 4)
        assertEquals(IpAddress.parse("fe80::1%4"), IpAddress.of(scoped))
        // an IPv4-mapped literal is an Inet4Address to the JDK already
        assertEquals(IpAddress.parse("192.0.2.1"), IpAddress.of(InetAddress.getByName("::ffff:192.0.2.1")))
    }

    /** [Dns.blocking] runs the blocking lookup on the dispatcher it is given, not on the caller's thread. */
    @Test fun aBlockingDnsRunsOnItsDispatcher() =
        newSingleThreadContext("dns-test-lookups").use { lookups ->
            runBlocking {
                var thread = ""
                val dns =
                    Dns.blocking(lookups) {
                        thread = Thread.currentThread().name
                        listOf(IpAddress.parse("192.0.2.1"))
                    }
                assertEquals(listOf(IpAddress.parse("192.0.2.1")), dns.lookup("h.test"))
                // with the coroutines' debug mode the thread's name carries the coroutine's (" @coroutine#2")
                assertEquals("dns-test-lookups", thread.substringBefore(" @"))
            }
        }
}
