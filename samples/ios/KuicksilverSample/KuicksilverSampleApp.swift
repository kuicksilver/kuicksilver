// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import Shared
import SwiftUI

/// The SwiftUI shell around the Kotlin facade (`SampleFacade` in samples/ios/shared).
@main
struct KuicksilverSampleApp: App {
    @StateObject private var model = AppModel()

    init() {
        // `-smoke` (xcrun simctl launch <device> io.kuicksilver.sample.KuicksilverSample -smoke): a UI-free self check
        // whose result tools/check/ios-sample-smoke.sh greps from the console.
        if CommandLine.arguments.contains("-smoke") { Smoke.run() }
    }

    var body: some Scene {
        WindowGroup {
            TabView {
                Http3View().tabItem { Label("HTTP/3", systemImage: "globe") }
                EchoView().tabItem { Label("QUIC echo", systemImage: "arrow.left.arrow.right") }
                ServerView().tabItem { Label("Server", systemImage: "antenna.radiowaves.left.and.right") }
                TrustView().tabItem { Label("Trust", systemImage: "lock.shield") }
            }
            .environmentObject(model)
        }
    }
}

/// App-wide state: the one facade instance (one Kotlin runtime, one endpoint set) and the trust toggle.
@MainActor
final class AppModel: ObservableObject {
    let facade = SampleFacade()
    @Published var trust: TrustMode = .platform
}
