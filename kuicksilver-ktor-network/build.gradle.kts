// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("kuicksilver.kmp")
    id("kuicksilver.publish")
}
kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":kuicksilver-tls"))
            api(libs.ktor.network)
        }
    }
}


// Linux and Apple share the POSIX system calls of the native TCP sockets (TcpSys.posix.kt); Windows has its own (mingwMain).
kotlin.sourceSets {
    val posixMain = create("posixMain") { dependsOn(getByName("nativeMain")) }
    getByName("appleMain").dependsOn(posixMain)
    getByName("linuxMain").dependsOn(posixMain)
}
