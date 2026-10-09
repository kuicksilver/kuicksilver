// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.events.Events
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationEnvironment
import io.ktor.server.engine.ApplicationEngineFactory

/** `embeddedServer(Kuicksilver) { ... }`: HTTP/1.1 over TLS and HTTP/3 on one port (docs/guide/ktor.md). */
public object Kuicksilver : ApplicationEngineFactory<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration> {
    override fun configuration(
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit,
    ): KuicksilverApplicationEngine.Configuration = KuicksilverApplicationEngine.Configuration().apply(configure)

    override fun create(
        environment: ApplicationEnvironment,
        monitor: Events,
        developmentMode: Boolean,
        configuration: KuicksilverApplicationEngine.Configuration,
        applicationProvider: () -> Application,
    ): KuicksilverApplicationEngine =
        KuicksilverApplicationEngine(environment, monitor, developmentMode, configuration, applicationProvider)
}
