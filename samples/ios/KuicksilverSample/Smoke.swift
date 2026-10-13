// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Shared

/// `-smoke`: the in-app server, a QUIC echo and an HTTP/3 GET over loopback, then one `KSL-SMOKE` line on stdout.
enum Smoke {
    static let facade = SampleFacade()

    static func run() {
        func say(_ s: String) { print(s); fflush(stdout) }
        facade.startServer(port: 0, onLog: { say("  \($0)") }) { port, error in
            guard let port else { say("KSL-SMOKE FAIL server: \(error ?? "?")"); return }
            facade.quicEcho(host: "::1", port: port.int32Value, message: "smoke", rounds: 3, intervalMs: 0, trust: .sampleCa,
                            followNetwork: false, onLog: { say("  \($0)") }) { echo, error in
                guard let echo else { say("KSL-SMOKE FAIL echo: \(error ?? "?")"); return }
                facade.http3Get(url: "https://127.0.0.1:\(port)/smoke", trust: .sampleCa) { page, error in
                    guard let page, page.status == 200 else { say("KSL-SMOKE FAIL h3: \(error ?? "status \(page?.status ?? 0)")"); return }
                    say(String(format: "KSL-SMOKE OK echo %d rounds avg %.1f ms, h3 %d %lld bytes in %lld ms",
                               echo.rounds, echo.avgMs, page.status, page.bodyBytes, page.elapsedMs))
                }
            }
        }
    }
}
