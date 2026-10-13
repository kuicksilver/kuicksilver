<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# iOS sample

A SwiftUI app on top of Kuicksilver, built the way an iOS team would: a Kotlin Multiplatform `shared` module with a thin
facade, one static framework, and an Xcode project that builds it in a Run Script phase. It is not published. The
guide for iOS users is [docs/guide/ios.md](../../docs/guide/ios.md).

| Screen | What it does |
|---|---|
| HTTP/3 | GET of any `https://` URL over HTTP/3 (default `https://cloudflare-quic.com/`): status, headers, body, RTT |
| QUIC echo | a raw QUIC session (ALPN `kuicksilver-echo`) with a line per round (time, smoothed and min RTT) and per path event; Rebind moves it to a new socket; "Follow the default network" switches itself on once the library has it |
| Server | QUIC on `[::]:4433` serving an HTTP/3 page and the echo protocol on one port, advertised over Bonjour as `_kuicksilver._udp` |
| Trust | System (SecTrust), the sample CA (`certs/gen.sh`), or trust on first use |

| Path | What |
|---|---|
| `shared/` | the Kotlin side: `SampleFacade` (callbacks to Swift, no SKIE), `ClientOps.kt`, `SampleServer.kt`, `NetworkFollowing.kt` (the hook for `followDefaultNetwork`), a simulator test of the operations |
| `kuicksilver-swift/` | the umbrella that produces `Kuicksilver.xcframework` (+ dSYMs, privacy manifest) and its SwiftPM zip for Swift-only apps |
| `KuicksilverSample.xcodeproj`, `KuicksilverSample/` | the app; `Config/` holds the xcconfigs, Info.plists and the Run Script |
| `KuicksilverSampleTests/` | XCTest calling the facade from Swift on the simulator |
| `CollisionProbe/` | an app that links the framework next to an unprefixed OpenSSL (`tools/check/ios-symbols.sh`) |

Like `samples/realtime-telemetry`, it is a separate Gradle build that depends on `io.kuicksilver:*` by coordinates;
the composite build in `settings.gradle.kts` substitutes this repository's modules.

## Build and test

From the repository root:

```sh
./gradlew --max-workers=2 -p samples/ios :shared:iosSimulatorArm64Test   # the operations over loopback, in the simulator
bash tools/check/ios-sample-smoke.sh                                     # app build, -smoke launch, XCTest
bash tools/check/ios-symbols.sh                                          # symbol-collision proof
bash tools/check/ios-size.sh                                             # size budget (Release, arm64)
```

Or open `KuicksilverSample.xcodeproj` in Xcode and run on a simulator; the Run Script builds the Kotlin framework.

## On an iPhone

Select your team for the `KuicksilverSample` target (Signing & Capabilities; a free Apple ID works), choose the phone,
press Run. If Xcode reports that the bundle identifier is not available, change `KUICKSILVER_BUNDLE_PREFIX` in
`Config/Project.xcconfig`. The checklist of what to try on the device is in the guide.
