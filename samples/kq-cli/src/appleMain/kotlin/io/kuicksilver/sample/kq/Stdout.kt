// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

/** POSIX stdout takes bytes as they are. */
internal actual fun prepareStdout() {}

/** Nothing to undo. */
internal actual fun restoreStdout() {}
