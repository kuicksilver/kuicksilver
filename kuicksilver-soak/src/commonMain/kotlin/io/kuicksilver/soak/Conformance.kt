// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

/**
 * The entry point of the conformance executable that `tools/interop/h3spec.sh` and `tools/interop/autobahn.sh` run (one
 * binary for both, so the gate links one more executable, not three): the first argument names the program, the rest
 * are its own. `h3spec-server` is [h3specServerMain], `autobahn-server` [autobahnServerMain], `autobahn-client`
 * [autobahnClientMain].
 */
public fun conformanceMain(args: Array<String>) {
    val rest = args.drop(1).toTypedArray()
    when (args.firstOrNull()) {
        "h3spec-server" -> h3specServerMain(rest)
        "autobahn-server" -> autobahnServerMain(rest)
        "autobahn-client" -> autobahnClientMain(rest)
        else -> throw IllegalArgumentException("usage: conformance <h3spec-server|autobahn-server|autobahn-client> [argument]...")
    }
}
