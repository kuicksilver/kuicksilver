// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi

/**
 * A [KeylogSink] appending RFC 9850 lines to [path]; the file is created with mode 0600 (docs/guide/tls.md, Key logging).
 * The path is checked here, before any secret exists: a symlink, a file that is not a regular file or belongs to another
 * user, or a file system without POSIX permissions throws [IllegalArgumentException]; an existing file readable by the
 * group or others is tightened to 0600. Every line reopens the file without following links (Windows only creates the file).
 * A line that cannot be written is dropped, not retried. `SSLKEYLOGFILE` is never consulted by the library;
 * [keylogFromEnvironment] reads it explicitly when you ask.
 */
@DelicateKuicksilverApi
public expect fun keylogFile(path: String): KeylogSink

/** The value of `SSLKEYLOGFILE` in this process, or null. Only for explicit, deliberate use in debug builds. */
@DelicateKuicksilverApi
public expect fun keylogFromEnvironment(): KeylogSink?
