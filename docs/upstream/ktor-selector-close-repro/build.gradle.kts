// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
plugins {
    kotlin("jvm") version "2.4.20"
    application
}

// -PktorVersion=2.3.13 (or 3.0.3, 3.6.0, an EAP build such as 3.6.0-eap-1684) picks the Ktor under test
val ktorVersion = providers.gradleProperty("ktorVersion").getOrElse("3.6.0")

repositories {
    mavenCentral()
    maven("https://redirector.kotlinlang.org/maven/ktor-eap") // EAP builds of Ktor's main branch only
}

dependencies {
    implementation("io.ktor:ktor-network:$ktorVersion")
}

kotlin { jvmToolchain(21) }

application { mainClass.set("ReproKt") }
