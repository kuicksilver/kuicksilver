// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import Shared
import SwiftUI

/// One executable, two OpenSSL copies: Kuicksilver's (prefixed ksl_ossl_, inside the Kotlin framework) and an
/// unprefixed one linked next to it (CollisionProbe.xcconfig). Both complete a TLS 1.3 handshake; the result is one
/// `KSL-PROBE` line on stdout, which tools/check/ios-symbols.sh greps. The app exits when done.
@main
struct ProbeApp: App {

    init() { Probe.run() }

    var body: some Scene {
        WindowGroup { Text("Collision probe: see the console").padding() }
    }
}

enum Probe {
    static let facade = SampleFacade()

    static func run() {
        func say(_ s: String) { print(s); fflush(stdout) }
        var buf = [CChar](repeating: 0, count: 256)
        let rc = probe_unprefixed_openssl_handshake(&buf, Int32(buf.count))
        let plain = String(cString: buf)
        say("unprefixed OpenSSL: \(plain)")
        guard rc == 0 else { say("KSL-PROBE FAIL unprefixed: \(plain)"); exit(1) }
        _ = facade.startServer(port: 0, onLog: { say("  \($0)") }) { port, error in
            guard let port else { say("KSL-PROBE FAIL kuicksilver server: \(error ?? "?")"); exit(1) }
            _ = facade.http3Get(url: "https://127.0.0.1:\(port)/probe", trust: .sampleCa) { page, error in
                guard let page, page.status == 200 else { say("KSL-PROBE FAIL kuicksilver h3: \(error ?? "?")"); exit(1) }
                // a second handshake of the plain stack after Kuicksilver ran: neither copy disturbed the other's state
                var again = [CChar](repeating: 0, count: 256)
                guard probe_unprefixed_openssl_handshake(&again, Int32(again.count)) == 0 else {
                    say("KSL-PROBE FAIL unprefixed after kuicksilver: \(String(cString: again))"); exit(1)
                }
                say("KSL-PROBE OK unprefixed [\(plain)] + kuicksilver [QUIC TLS 1.3, h3 \(page.status) in \(page.elapsedMs) ms]")
                exit(0)
            }
        }
    }
}
