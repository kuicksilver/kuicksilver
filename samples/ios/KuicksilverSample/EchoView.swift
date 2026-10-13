// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import Shared
import SwiftUI

/// A raw QUIC echo session against a host (this app's server, on this phone or another one) with an RTT and path log.
struct EchoView: View {
    @EnvironmentObject private var model: AppModel
    @State private var host = "::1"
    @State private var port = "4433"
    @State private var rounds = 30
    @State private var intervalMs = 1000
    @State private var followNetwork = false
    @State private var running: SampleTask?
    @State private var log: [String] = []

    var body: some View {
        NavigationStack {
            Form {
                Section("Peer") {
                    TextField("host or IP", text: $host).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("port", text: $port).keyboardType(.numberPad)
                    Stepper("Rounds: \(rounds)", value: $rounds, in: 1...600)
                    Stepper("Every \(intervalMs) ms", value: $intervalMs, in: 0...10_000, step: 250)
                }
                Section {
                    // Wired to SampleFacade.followDefaultNetworkAvailable: enabled once the library ships
                    // QuicConnection.followDefaultNetwork for Apple (k7/ios-lib), with no change here.
                    Toggle("Follow the default network", isOn: $followNetwork)
                        .disabled(!model.facade.followDefaultNetworkAvailable)
                    if !model.facade.followDefaultNetworkAvailable {
                        Text("Not in this build yet. Use Rebind to move the session to a new socket by hand.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                Section {
                    Button(running == nil ? "Start echo" : "Stop") { running == nil ? start() : stop() }
                    Button("Rebind (migrate to a new socket)") { model.facade.rebindEcho { append($0) } }
                        .disabled(running == nil)
                }
                Section("Log") {
                    ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption.monospaced())
                    }
                }
            }
            .navigationTitle("QUIC echo")
        }
    }

    private func start() {
        log = []
        guard let p = Int32(port) else { append("bad port"); return }
        running = model.facade.quicEcho(
            host: host, port: p, message: "ping from \(UIDevice.current.name)", rounds: Int32(rounds),
            intervalMs: Int64(intervalMs), trust: model.trust, followNetwork: followNetwork,
            onLog: { append($0) },
            onResult: { r, e in
                if let r {
                    append(String(format: "done: %d rounds, min %.1f / avg %.1f / max %.1f ms, srtt %.1f ms, %d path changes",
                                  r.rounds, r.minMs, r.avgMs, r.maxMs, r.smoothedRttMs, r.pathChanges))
                }
                if let e { append("error: \(e)") }
                running = nil
            })
    }

    private func stop() { running?.cancel(); running = nil; append("stopped") }

    private func append(_ line: String) { log.append(line); if log.count > 500 { log.removeFirst(log.count - 500) } }
}
