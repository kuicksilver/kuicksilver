// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.contract

import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest

// The vendored Ktor 3.6.0 ContentTestSuite (JVM: files, class-path resources, streams) against embeddedServer(Kuicksilver).

private typealias ContentE = KuicksilverApplicationEngine
private typealias ContentC = KuicksilverApplicationEngine.Configuration

class KuicksilverH1ContentTest : ContentTestSuite<ContentE, ContentC>(Kuicksilver) {
    @BeforeTest fun load() = KslLoader.ensureLoaded()
}

class KuicksilverH3ContentTest : ContentTestSuite<ContentE, ContentC>(Kuicksilver) {
    override val protocol = ContractProtocol.H3

    @BeforeTest fun load() = KslLoader.ensureLoaded()
}
