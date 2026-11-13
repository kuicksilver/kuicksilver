// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import org.junit.jupiter.api.TestInfo
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.PrintStream

/** The test JVM's own standard error, past the test framework's capture of System.err. */
private val console = PrintStream(FileOutputStream(FileDescriptor.err), true)

/**
 * Names the fuzz case about to run on the console, one line: its target and its input (a file of the regression corpus,
 * or Jazzer's empty input; one line for a whole fuzzing run). A test JVM out of heap exits at once
 * (-XX:+ExitOnOutOfMemoryError, the kuicksilver.test-jvm plugin) and leaves no test report: this line names the case.
 */
internal fun fuzzCase(case: TestInfo) {
    val target = case.testClass.map { it.simpleName }.orElse("?") + "." + case.testMethod.map { it.name }.orElse("?")
    console.println("fuzz case: $target ${case.displayName}")
}
