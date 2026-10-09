// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult

/**
 * Trust for the interop runner: its certificates are self-signed test material, so the chain is accepted as is and
 * only the host name is checked by `ksl`. `KSL_INTEROP_EXPECTED_NAME` names the SAN to check instead of the URL host
 * when the runner's certificate does not cover `server4`/`server6`.
 */
@OptIn(DelicateKuicksilverApi::class)
internal object InteropTrust {
    private val acceptChain = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) }
    fun config(env: Map<String, String>): TrustConfig = env["KSL_INTEROP_EXPECTED_NAME"]?.let { TrustConfig.ExpectedName(it, base = acceptChain) } ?: acceptChain
}
