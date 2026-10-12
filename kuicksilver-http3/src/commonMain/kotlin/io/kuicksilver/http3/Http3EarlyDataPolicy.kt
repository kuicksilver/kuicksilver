// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * What an HTTP/3 server does with a request that arrived in 0-RTT before the handshake completed (RFC 8470, ADR-0015).
 * Early data can be replayed by an attacker (RFC 8446 section 8): only requests [replayable] says are safe to execute
 * twice run at once. Every other one waits for the handshake ([WaitForHandshake], the default; a replayed connection
 * never completes it, so the request never runs) or is answered with `425 Too Early` ([Reject425]), which a client
 * repeats after its handshake (RFC 8470 section 5.2).
 *
 * @property replayable the requests that may run before the handshake completes; by default GET, HEAD and OPTIONS.
 */
@ExperimentalKuicksilverApi
public sealed class Http3EarlyDataPolicy(
    public val replayable: (Http3ServerRequest) -> Boolean,
) {
    /** Non-replayable early requests reach the application once the handshake completed. */
    public class WaitForHandshake(
        replayable: (Http3ServerRequest) -> Boolean = SafeMethods,
    ) : Http3EarlyDataPolicy(replayable)

    /** Non-replayable early requests are answered with 425 Too Early and never reach the application. */
    public class Reject425(
        replayable: (Http3ServerRequest) -> Boolean = SafeMethods,
    ) : Http3EarlyDataPolicy(replayable)

    /** Holds [SafeMethods]. */
    public companion object {
        /** The safe methods (RFC 9110 section 9.2.1) a client may send early: GET, HEAD, OPTIONS. */
        public val SAFE_METHODS: Set<String> = setOf("GET", "HEAD", "OPTIONS")

        /** Replayable when the method is safe; the handler must still be free of side effects for such requests. */
        public val SafeMethods: (Http3ServerRequest) -> Boolean = { it.method in SAFE_METHODS }
    }
}
