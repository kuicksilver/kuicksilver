// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.contract

import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Ignore
import kotlin.test.Test

// The vendored Ktor 3.6.0 server engine suites against embeddedServer(Kuicksilver), over HTTP/1.1 and over HTTP/3.

private typealias E = KuicksilverApplicationEngine
private typealias C = KuicksilverApplicationEngine.Configuration

class KuicksilverH1HttpServerCommonTest : HttpServerCommonTestSuite<E, C>(Kuicksilver) {
    @BeforeTest fun load() = KslLoader.ensureLoaded()
}

class KuicksilverH3HttpServerCommonTest : HttpServerCommonTestSuite<E, C>(Kuicksilver) {
    override val protocol = ContractProtocol.H3

    @BeforeTest fun load() = KslLoader.ensureLoaded()
}

class KuicksilverH1PortableContentTest : PortableContentTestSuite<E, C>(Kuicksilver) {
    @BeforeTest fun load() = KslLoader.ensureLoaded()
}

class KuicksilverH3PortableContentTest : PortableContentTestSuite<E, C>(Kuicksilver) {
    override val protocol = ContractProtocol.H3

    @BeforeTest fun load() = KslLoader.ensureLoaded()
}

class KuicksilverH1WebSocketTest : WebSocketEngineSuite<E, C>(Kuicksilver) {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * Ktor's test sends RSV1 without negotiating an extension and expects the server to take it. The engine fails such a
     * connection with 1002 (RFC 6455 section 5.2, threat model 3.20.1): `ServerWebSocketGuardTest` covers that, and
     * the RSV1 of a negotiated extension reaching the session is covered by `ClientDeflateKtorTest` (both directions).
     */
    @Test
    @Ignore
    override fun testFragmentedFlagsFromTheFirstFrame() {}
}
