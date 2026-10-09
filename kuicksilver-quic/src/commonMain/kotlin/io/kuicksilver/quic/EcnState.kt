// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** ECN validation state of a path (RFC 9000 section 13.4.2 and appendix A.4), as reported by [ConnectionStats.ecnState]. */
public enum class EcnState {
    /** ECN is off: the socket cannot mark, or validation failed earlier and marking stopped. */
    Disabled,

    /** The first ten packets go out marked ECT(0); the peer's counts decide. */
    Testing,

    /** The test packets were sent; waiting for ACKs that carry the ECN counts. */
    Unknown,

    /** The peer reported the marks: ECN works on this path. */
    Capable,

    /** Marks were bleached or the counts were inconsistent: ECN is off on this path. */
    Failed,
}
