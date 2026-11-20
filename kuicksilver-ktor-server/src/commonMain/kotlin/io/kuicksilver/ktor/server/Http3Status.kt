// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.IpFamily

/**
 * Whether a TLS connector serves HTTP/3, and why not ([KuicksilverApplicationEngine.http3Status]): the server keeps serving
 * HTTP/1.1 and HTTP/2 on the connector's TCP port either way.
 *
 * @property port the connector's port (TCP, and UDP where HTTP/3 is served).
 * @property served whether HTTP/3 is served there (for both address families unless
 *   [notServedFamily][Http3Status.notServedFamily] says otherwise).
 * @property notServedFamily the address family HTTP/3 is not served for while it is for the other: its UDP socket
 *   cannot set Don't Fragment for it (no DF, no QUIC: RFC 9000 section 14); connections from that family get no
 *   `Alt-Svc`. Null when [served][Http3Status.served] is false (nothing is served) or when HTTP/3 is served for every
 *   family.
 * @property reason why HTTP/3 is not served, or not for [notServedFamily][Http3Status.notServedFamily]: an
 *   `io.kuicksilver.quic.QuicException.DontFragmentUnavailable` (its `family`), or an `UnsupportedOperationException`
 *   (no QUIC server on this platform); null when it is served for both families.
 */
@ExperimentalKuicksilverApi
public class Http3Status(
    public val port: Int,
    public val served: Boolean,
    public val notServedFamily: IpFamily?,
    public val reason: Throwable?,
) {
    /** The status on one line, for a log: the port, whether HTTP/3 is served, and the family and reason when set. */
    override fun toString(): String =
        "Http3Status(port=$port, served=$served" + (notServedFamily?.let { ", notServedFamily=$it" } ?: "") +
            (reason?.let { ", reason=${it.message}" } ?: "") + ")"
}
