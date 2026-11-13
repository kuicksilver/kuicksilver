// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [matchesHost]: the RFC 9525 section 6.3 name check (RFC 9110 section 4.3.4). The server leaf names `server.test`,
 * `*.wild.test`, 127.0.0.1 and ::1.
 */
class HostMatchTest {
    private val server = Certificate(TestCerts.server)

    private fun Certificate.matches(host: String) = matchesHost(HostName.normalize(host))

    @Test fun namesAndAddressesOfTheLeaf() {
        for (h in listOf(
            "server.test",
            "SERVER.TEST",
            "server.test.",
            "a.wild.test",
            "x-1.Wild.Test.",
            "127.0.0.1",
            "::1",
            "[::1]",
            "0:0:0:0:0:0:0:1",
        )) {
            assertTrue(server.matches(h), h)
        }
    }

    @Test fun negative_namesAndAddressesTheLeafDoesNotCarry() {
        for (h in listOf(
            "other.test",
            "wild.test",
            "a.b.wild.test",
            "server.test.evil",
            "evil.server.test",
            "127.0.0.2",
            "::2",
            "::ffff:127.0.0.1",
        )) {
            assertFalse(server.matches(h), h)
        }
    }

    /** RFC 9525 section 6.3: no partial wildcards (OpenSSL's NO_PARTIAL_WILDCARDS, as the client verifier). */
    @Test fun negative_partialWildcardMatchesNothing() {
        val partial = Certificate(TestCerts.serverPartialWildcard)
        for (h in listOf("f.wild.test", "fab.wild.test", "x.wild.test")) assertFalse(partial.matches(h), h)
    }

    /** An IP-ID matches iPAddress entries only: a dNSName that spells an address is not one (RFC 9525 section 6.2). */
    @Test fun negative_dnsNameSpellingAnAddressIsNoIpId() {
        assertFalse(Certificate(TestCerts.serverDnsIp).matches("127.0.0.1"))
    }

    /** RFC 9110 section 4.3.4: "A reference identity of type CN-ID MUST NOT be used". */
    @Test fun negative_commonNameIsNeverUsed() {
        assertFalse(Certificate(TestCerts.serverCnOnly).matches("cn.test")) // its subject CN
    }
}
