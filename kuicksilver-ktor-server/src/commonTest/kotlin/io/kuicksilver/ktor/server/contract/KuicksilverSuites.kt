// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.contract

import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest

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
}
