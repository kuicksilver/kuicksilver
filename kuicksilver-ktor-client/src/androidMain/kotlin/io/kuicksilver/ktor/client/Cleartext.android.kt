// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.security.NetworkSecurityPolicy

// API 24 (minSdk): the per-host check honours <domain-config cleartextTrafficPermitted> as well as the base config. A host
// the policy throws on (IllegalArgumentException for one beginning with a dot, which cleartextPolicyHost refuses first) is
// not permitted: the caller refuses it with the cleartext IOException, never with an unchecked exception.
internal actual fun platformCleartextPermitted(host: String): Boolean =
    try {
        NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(host)
    } catch (_: IllegalArgumentException) {
        false
    }
