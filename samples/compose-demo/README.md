<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Compose Multiplatform demo

An Android and iOS app, one Compose Multiplatform UI, that shows what HTTP/3 changes for a mobile client: a download
over Kuicksilver's HTTP/3 carries on when the phone switches from Wi-Fi to the mobile network, while the same download
over TCP, next to it, breaks. It also compares the two under packet loss and shows why a request did not use HTTP/3.
It is not published. The guide behind it is [docs/guide/ktor.md, "Connection migration"](../../docs/guide/ktor.md#connection-migration).

| Screen | What it does |
|---|---|
| Migration | Downloads 20 or 50 MiB at once over Kuicksilver HTTP/3 (`connectionMigration = followDefaultNetwork(...)`) and over a TCP engine: OkHttp on Android; CIO and Darwin (URLSession) in two columns on iOS. Progress per engine, the current network, the response's `kuicksilverDiagnostics`, and a log of network changes and `connectionMigrated` events. "Resume TCP" makes a broken TCP download go on with `Range`, to show what that workaround costs. |
| Lossy network | Lab mode: 20 downloads of 1 or 10 MiB per engine from the demo server running behind `tc netem`; median and p90 of the time to the last byte and to the response head. Links to [Why QUIC](../../docs/why-quic.md) for measured numbers. |
| Diagnostics | Any URL with Kuicksilver in `Auto` discovery: the protocol, the reason, the `FallbackReason` with what to check, and a switch for the `http3Allowed` kill switch. |

| Path | What |
|---|---|
| `composeApp/` | the shared code: the UI (`App.kt`), the screen models without UI (`Models.kt`, `Download.kt`, `Diagnostics.kt`), the engines per platform (`androidMain`, `iosMain`), `DemoLogicTest` |
| `androidApp/` | the Android application (AGP 9 keeps it out of the multiplatform module) and `MigrationDemoAndroidTest` |
| `iosApp/` | the Xcode project: a SwiftUI shell around `MainViewController()`; its Run Script builds the `ComposeApp` framework |
| `server/` | the demo server: Kuicksilver's Ktor engine with `/bytes/{n}` (with `Range`) and `/stream`; `netem.sh` runs it behind netem |
| `certs/gen.sh` | the demo's private CA and server certificate (a copy of `samples/ios/certs/gen.sh` that also names 10.0.2.2) |

Like `samples/ios`, it is a separate Gradle build that depends on `io.kuicksilver:*` by coordinates; the composite build
in `settings.gradle.kts` substitutes this repository's modules. Kotlin and AGP are the repository's versions; Compose
Multiplatform is 1.12.2 with Material 3 1.9.0, which only this demo uses.

## Run it

The demo server, on your computer (from the repository root):

```sh
./gradlew -p samples/compose-demo :server:run                       # https://0.0.0.0:8443 (HTTP/1.1 and HTTP/3), http://0.0.0.0:8080
./gradlew -p samples/compose-demo :server:run --args="--no-alt-svc" # the same without Alt-Svc (see "Darwin" below)
```

`/bytes/{n}?rate=<bytes per second>` sends `n` bytes of a fixed pattern, at that rate when given (the Migration screen
asks for 2 or 4 MiB/s, so that there is time to switch the network by hand); `Range: bytes=<first>-` gets a 206 from
that byte on. `/stream?seconds=30&rate=1048576` sends the same pattern without a length. Every client checks every byte
against the pattern, so a download resumed with `Range` is proven whole.

The Android app: `./gradlew -p samples/compose-demo :androidApp:installDebug`, or open `samples/compose-demo` in Android
Studio. On an emulator the server is at 10.0.2.2, the default host. On a phone, enter the server's address (see
[On a phone](#on-a-phone-the-manual-check) for where to run it).

The iOS app (iOS 18.5 or later: Compose Multiplatform 1.12.2 links objects built for it): open
`iosApp/ComposeDemo.xcodeproj` in Xcode and run it; the Run Script builds the Kotlin framework. In the
simulator the server is at 127.0.0.1, the default host. On an iPhone, select your team for the `ComposeDemo` target
(Signing & Capabilities), and enter the server's address.

Every engine trusts only the demo CA (`certs/gen.sh`) for the demo server and checks the certificate for the name
`kuicksilver.local`, whatever address the URL has: Kuicksilver with `TrustConfig.ExpectedName` over
`TrustConfig.AnchoredCa`, OkHttp with a trust manager and a host name check of its own, Darwin with `SecTrust` anchors.

## What to look at

**Migration.** Start the download, then turn Wi-Fi off (on a phone: Control Center or Settings, with mobile data on; on
an emulator: `adb shell svc wifi disable`). Expected:

- the network line changes; the log shows `connectionMigrated: Migrated(<old> -> <new>, ...)`; the HTTP/3 download goes
  on and completes on the new network, over the same connection (its diagnostics still say `HTTP/3`);
- the TCP download stops with an error (or, on some systems, stalls until its read timeout and then fails): its
  connection belongs to the address of the network that went away;
- with "Resume TCP" on, the TCP download goes on with `Range` from the byte where it broke, after a new TCP and TLS
  handshake on the new network; the lane says how many times it resumed. That is the workaround an app needs for every
  TCP transfer it wants to survive a network change, and it only works for resumable requests.

**Lossy network.** Start the server behind netem on a machine with Docker, point the app at it, and run the series:

```sh
bash tools/interop/build-image.sh                          # once: the image with java and tc, and the Linux libksl
./gradlew -p samples/compose-demo :server:installDist
samples/compose-demo/server/netem.sh 50 1                  # +50 ms round trip, 1 % of the server's packets lost
```

**Diagnostics.** With the default URL (the demo server's `/`) the first request goes over HTTP/1.1 with
`NoAlternative` and learns `Alt-Svc`; the second goes over HTTP/3. Turn `http3Allowed` off: the next one says
`Http3Disabled`. Point it at a public site with the system trust to see how that origin is served.

## How the comparison is kept fair, and where it is not

- Both sides download the same bytes from the same server process at the same time, with the same certificate checks.
  The Kuicksilver lane is never resumed: what it shows is the connection surviving, not a retry.
- The TCP side is HTTP/1.1. The demo server does not offer HTTP/2; HTTP/2 runs over TCP too and would not move either.
- **CIO on iOS uses plain `http://`** (port 8080): Ktor's CIO engine has no TLS on Kotlin/Native. That makes its
  connection setup cheaper than a real HTTPS client's, which flatters it in the time to the first byte.
- **Darwin (URLSession) may itself use HTTP/3**: iOS's URLSession speaks HTTP/3 and takes it when the server announces
  it with `Alt-Svc`, and Ktor's Darwin engine reports `HTTP/1.1` whatever URLSession used. Its column is the closest to
  what a real iOS app gets, but it is not a guaranteed TCP baseline: start the server with `--no-alt-svc` to keep it on
  TCP. URLSession also has its own ways to recover from a network change, so its outcome on a switch is URLSession's,
  not TCP's.
- OkHttp runs with its defaults, `retryOnConnectionFailure` included: it retries a request that failed before its
  response, not a body that broke halfway.
- **An emulator or a simulator switches networks unlike a phone.** On the Android emulator, Wi-Fi and mobile data are
  two NATs on the same host, and turning Wi-Fi off removes an interface without a radio handover; the iOS simulator
  uses the Mac's network and has no mobile data at all, so the switch cannot be shown there. The emulator test below is
  necessary but not sufficient: the claim "survives a Wi-Fi to mobile switch" holds for a phone only after it was checked
  on a phone (see below).
- **Lab mode is not a measurement.** netem drops and delays the server's packets only, the client's go through as they
  are; Docker Desktop on macOS forwards the published ports through its own proxy in a Linux VM; and a phone on Wi-Fi
  adds its own losses and delay. Use it to see the effect, and [docs/why-quic.md](../../docs/why-quic.md) (a script, a
  Linux host, every number from a CSV) for the numbers. The series uses warm connections, so it compares transfers, not
  connection setup.

## Tests

From the repository root:

```sh
./gradlew -p samples/compose-demo :composeApp:allTests         # DemoLogicTest on the JVM (Android host) and the iOS simulator
./gradlew -p samples/compose-demo :composeApp:assembleAndroidMain :androidApp:assembleDebug :composeApp:linkDebugFrameworkIosSimulatorArm64
./gradlew -p samples/compose-demo :server:compileKotlin
xcodebuild -project samples/compose-demo/iosApp/ComposeDemo.xcodeproj -scheme ComposeDemo \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build   # the app, with the framework
```

`DemoLogicTest` checks the screen models without UI: a download resumed with `Range` continues from the byte where it
broke (and starts over when the server ignores `Range`, and refuses a `Content-Range` from another offset), the
Migration screen resumes the TCP lane only, the diagnostics text for a fallback and for HTTP/3, and the median and p90.

`MigrationDemoAndroidTest` (`androidApp/src/androidTest`) is the release gate's emulator check: 20 MiB from the demo
server on the host over HTTP/3 with connection migration and over OkHttp at once, the default network switched off at
30 % (`svc wifi disable`, or `svc data disable` when mobile data is the default); the HTTP/3 download must complete after
a `connectionMigrated(Migrated)` and the OkHttp one must fail. It needs an emulator with Wi-Fi and mobile data, the
server on the host and its port:

```sh
./gradlew -p samples/compose-demo :server:run &
./gradlew -p samples/compose-demo :androidApp:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.demoServerPort=8443
```

Without the port it is skipped. It switches the network back on at the end.

## On a phone (the manual check)

1. Run the server where the phone reaches it over Wi-Fi and over the mobile network: a machine with a public address
   (UDP 8443, TCP 8443 and 8080 open). A server on the home LAN is out of reach once Wi-Fi is off, and every download
   then fails, HTTP/3 too. Enter its address in the app.
2. Mobile data on, Wi-Fi on. Migration, 50 MiB at 2 MiB/s, Download.
3. At about a third, turn Wi-Fi off. The HTTP/3 lane completes, the log has `connectionMigrated: Migrated`; the TCP lane
   fails (Android: OkHttp; iOS: CIO, and Darwin as URLSession decides).
4. Again with "Resume TCP": the TCP lane resumes with `Range` after a pause, and says so.
5. Turn Wi-Fi back on during a download: the HTTP/3 lane moves back (another `Migrated`) and completes.
