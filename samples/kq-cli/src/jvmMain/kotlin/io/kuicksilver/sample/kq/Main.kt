// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

import kotlinx.coroutines.runBlocking
import kotlin.system.exitProcess

/** kq on the JVM (`./gradlew -p samples/kq-cli jvmRun --args="get -v https://..."`): the same code as the native executable. */
fun main(args: Array<String>) {
    val code = runBlocking { kq(args.toList(), JvmConsole) }
    exitProcess(code)
}

private object JvmConsole : Console {
    override fun out(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) = System.out.write(bytes, offset, length)

    override fun err(line: String) {
        System.out.flush() // the body so far before the line, as on a terminal
        System.err.println(line)
    }

    override fun flush(): Boolean {
        System.out.flush()
        return !System.out.checkError() // PrintStream keeps a write failure as a flag, never an exception
    }
}
