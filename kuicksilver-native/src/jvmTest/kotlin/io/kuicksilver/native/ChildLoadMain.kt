// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.native

/** Entry point of the child JVM in `KslLoaderTest.sharedLibrarySurvivesOtherJvmExit`: loads the library from the given work directory and exits. */
object ChildLoadMain {
    @JvmStatic
    fun main(args: Array<String>) {
        KslLoader.ensureLoaded()
        println("loaded abi " + Ksl.abiVersion())
    }
}
