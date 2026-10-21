// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.swift

/**
 * The umbrella of Kuicksilver.xcframework. It adds no API of its own: the framework exports the public API of
 * kuicksilver-tls, kuicksilver-quic and kuicksilver-http3, and Swift calls their suspend functions as `async` methods
 * (or with completion handlers). This object only names the build so a Swift app can log what it ships.
 */
public object KuicksilverInfo {
    /** The Kuicksilver version this framework was built from. */
    public const val VERSION: String = "0.3.0-SNAPSHOT"
}
