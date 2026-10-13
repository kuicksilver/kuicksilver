// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import Shared
import SwiftUI

/// The trust toggle every client screen uses.
struct TrustView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationStack {
            Form {
                Picker("Trust", selection: $model.trust) {
                    Text("System (SecTrust)").tag(TrustMode.platform)
                    Text("Sample CA").tag(TrustMode.sampleCa)
                    Text("Trust on first use").tag(TrustMode.tofu)
                }
                .pickerStyle(.inline)
                Section {
                    Text("System: the iOS trust store, for public sites (HTTP/3 tab).")
                    Text("Sample CA: only the sample's private CA (samples/ios/certs/gen.sh). Use it against this app's server, on this phone or another one.")
                    Text("Trust on first use: remembers the first key a host presents, for this run of the app.")
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
            .navigationTitle("Trust")
        }
    }
}
