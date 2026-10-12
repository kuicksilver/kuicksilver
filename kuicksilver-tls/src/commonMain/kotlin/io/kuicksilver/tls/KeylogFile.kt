// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi

/**
 * A [KeylogSink] appending RFC 9850 lines to [path]; the file is created with mode 0600 (docs/guide/tls.md, Key logging).
 * The path is checked here, before any secret exists: a symlink, a file that is not a regular file or belongs to another
 * user, or a file system without POSIX permissions throws [IllegalArgumentException]; an existing file readable by the
 * group or others is tightened to 0600 (Windows only creates the file). On the JVM the file is opened once, here, and every
 * line goes through that descriptor, so a file removed and recreated at the path later receives nothing; the JVM sink is
 * also `java.io.Closeable` and keeps the descriptor until it is closed (or collected, or the process exits). Kotlin/Native
 * reopens the file for every line without following links and repeats the checks on the new descriptor.
 * A line that cannot be written is dropped, not retried. `SSLKEYLOGFILE` is never consulted by the library;
 * [keylogFromEnvironment] reads it explicitly when you ask.
 */
@DelicateKuicksilverApi
public expect fun keylogFile(path: String): KeylogSink

/** The value of `SSLKEYLOGFILE` in this process, or null. Only for explicit, deliberate use in debug builds. */
@DelicateKuicksilverApi
public expect fun keylogFromEnvironment(): KeylogSink?
