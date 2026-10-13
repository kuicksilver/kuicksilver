<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Kuicksilver on iOS

Kuicksilver runs on iOS through Kotlin/Native (`iosArm64`, `iosSimulatorArm64`). OpenSSL 3.5 and the `ksl` C shim are
linked statically into your app with every OpenSSL symbol renamed to `ksl_ossl_*` (ADR-0007), so another OpenSSL or
BoringSSL in the same app does not clash with it. The QUIC socket is the accelerated `ksl` socket (ECN, DF; no GSO/GRO
on Darwin). Certificates are checked by SecTrust when you use `TrustConfig.Platform`.

The working example is [`samples/ios`](../../samples/ios/README.md): a SwiftUI app over a small Kotlin facade, with
HTTP/3 GET, a raw QUIC echo with an RTT and path-event log, and a server mode advertised over Bonjour.

## Choosing how to consume it

| Your app | Use | What you ship |
|---|---|---|
| Kotlin Multiplatform (a `shared` module) | the klibs: `implementation("io.kuicksilver:kuicksilver-http3:…")` | one Kotlin framework (yours), Kuicksilver inside it |
| Swift only | `Kuicksilver.xcframework` (dynamic) through SwiftPM `binaryTarget` | the xcframework, with its own privacy manifest and dSYMs |

### Kotlin Multiplatform: klibs and one framework

Depend on the Kuicksilver modules from your shared module like any KMP library. The klibs carry the prefixed OpenSSL
and `libksl` as static libraries; Kotlin/Native links them into the framework your app already builds:

```kotlin
kotlin {
    listOf(iosArm64(), iosSimulatorArm64()).forEach {
        it.binaries.framework { baseName = "Shared"; isStatic = true }
    }
    sourceSets.commonMain.dependencies {
        implementation("io.kuicksilver:kuicksilver-http3:0.1.0-SNAPSHOT")   // or -quic, -ktor-client
    }
}
```

Hook the framework into Xcode the KMP way (direct integration): a Run Script phase before Compile Sources that runs
`./gradlew :shared:embedAndSignAppleFrameworkForXcode`, User Script Sandboxing off (`ENABLE_USER_SCRIPT_SANDBOXING =
NO`), and `FRAMEWORK_SEARCH_PATHS = $(SRCROOT)/shared/build/xcode-frameworks/$(CONFIGURATION)/$(SDK_NAME)` with
`OTHER_LDFLAGS = -framework Shared`. `samples/ios/Config/Project.xcconfig` and `build-kotlin-framework.sh` show the
complete setup.

> **One Kotlin/Native framework per app.** Every Kotlin/Native framework carries its own Kotlin runtime, stdlib and
> copies of every library it uses: two frameworks mean two garbage collectors, two copies of Kuicksilver (and of
> OpenSSL) and types that do not cross between them (a `QuicConnection` from one is not one in the other). Put
> everything Kotlin into one umbrella framework. In particular do not combine your own KMP framework with
> `Kuicksilver.xcframework`: depend on the klibs instead.

Expose a thin facade to Swift rather than the library API: Kotlin `suspend` functions become Swift `async` functions or
completion handlers in the generated header, but `Flow`, `ByteReadChannel` and Kotlin generics translate poorly. The
sample's `SampleFacade` runs every operation on a background dispatcher and calls back on the main thread with
`(result, error)`, with no SKIE or other compiler plugin.

### Swift only: Kuicksilver.xcframework and SwiftPM

`samples/ios/kuicksilver-swift` is a small umbrella module that exports the public API of `kuicksilver-tls`,
`kuicksilver-quic` and `kuicksilver-http3` through the Kotlin `XCFramework` DSL:

```sh
./gradlew -p samples/ios :kuicksilver-swift:assembleKuicksilverReleaseXCFramework
#   samples/ios/kuicksilver-swift/build/XCFrameworks/release/Kuicksilver.xcframework
#     ios-arm64/Kuicksilver.framework (+ PrivacyInfo.xcprivacy)   ios-arm64/dSYMs/Kuicksilver.framework.dSYM
#     ios-arm64-simulator/…                                       ios-arm64-simulator/dSYMs/…
./gradlew -p samples/ios :kuicksilver-swift:zipKuicksilverXCFramework
#   build/spm/Kuicksilver.xcframework.zip and checksum.txt (the same value `swift package compute-checksum` prints)
```

The framework is dynamic, so its dSYMs travel with it and Apple finds its privacy manifest in its own bundle. Publish
the zip (a release asset) and describe it in a `Package.swift`:

```swift
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Kuicksilver",
    platforms: [.iOS(.v15)]   // the OpenSSL build floor,
    products: [.library(name: "Kuicksilver", targets: ["Kuicksilver"])],
    targets: [
        .binaryTarget(
            name: "Kuicksilver",
            url: "https://example.com/releases/0.1.0/Kuicksilver.xcframework.zip",
            checksum: "<contents of checksum.txt>"
        ),
    ]
)
```

Swift then calls the API directly (`import Kuicksilver`; suspend functions are `async`). The project does not publish
this xcframework yet; the Gradle setup is there so a release can.

## Privacy manifest

Apple requires a privacy manifest that declares every "required reason" API an app or SDK uses. Kuicksilver's is
[`kuicksilver-native/apple/PrivacyInfo.xcprivacy`](../../kuicksilver-native/apple/PrivacyInfo.xcprivacy): no tracking,
no collected data, one API category.

| Category | Symbols in a Release arm64 link | Where from | Reason |
|---|---|---|---|
| File timestamp | `stat`, `fstat`, `lstat` | OpenSSL's file loaders (`X509_STORE_load_file/path`, which `libksl` links for a file-based trust store; `conf_def.c`, `ssl_cert.c`, `file_store.c`), the `/dev/urandom` fallback of `rand_unix.c`, and `fstat` in the key log file check when you enable `keylog` | `C617.1`: metadata of files inside the app container that the app points Kuicksilver at; Kuicksilver reads the file type, owner and link count, never sends anything |
| System boot time | none | Kotlin/Native measures time with libc++ `steady_clock` and `gettimeofday`, not `mach_absolute_time` or `systemUptime` | not declared |
| Disk space, active keyboards, user defaults | none | | not declared |

`sysctlbyname` (OpenSSL reads the `hw.optional.arm.*` CPU features) is not on Apple's list. Check your own build with
`tools/check/ios-private-api.py` (below): it prints a `required-reason` line per category it finds. Debug builds of a
Kotlin framework import far more (`getattrlist`, `clock_gettime`, …) because they link the per-library caches with
every platform binding; only the Release link is what you ship.

How to include it:

- **Kuicksilver.xcframework** carries the file in each framework; nothing to do.
- **A KMP app** (Kuicksilver is linked statically into your framework, and a static framework has no bundle of its
  own): merge the entries into your app's `PrivacyInfo.xcprivacy`. If your app has none, add Kuicksilver's file to the
  app target's Copy Bundle Resources, as the sample does. If you have one, add the `NSPrivacyAccessedAPICategoryFileTimestamp`
  entry with `C617.1` (keep your own reasons next to it).
- If your app persists TOFU pins in user defaults or reads timestamps for its own purposes, that is your code's use:
  declare it with your own reason.

## Export compliance

Kuicksilver contains encryption (OpenSSL: TLS 1.3, AES-GCM, ChaCha20-Poly1305, X25519, ML-KEM) and implements it in
the app rather than using the operating system's. Apple's guidance is that encryption built into the OS (for example
HTTPS through `URLSession`) is typically exempt from export documentation, and other encryption is not. The sample
therefore sets `ITSAppUsesNonExemptEncryption` to `true`:

- Under the U.S. Export Administration Regulations, an app that uses standard cryptography to secure its own
  communication is usually a mass-market item exported under License Exception ENC, 15 CFR 740.17(b)(1), and
  classified 5D992.c after self-classification. Since the 2021 amendment, the annual self-classification report of
  740.17(e)(3) covers mass-market *components* and certain executable software rather than end-user apps, but the
  recordkeeping of part 762 applies.
- App Store Connect asks about encryption for every build unless the Info.plist answers it, and may ask for
  documentation (then add `ITSEncryptionExportComplianceCode`), including a declaration for distribution in France.
- The step-by-step version, with the App Store Connect questions, Info.plist and review-note templates, is
  [app-store.md](app-store.md).
- **The classification and the answers are the app owner's decision and responsibility**, not the library's, and this
  section is not legal advice. Changing what the app encrypts (for example adding end-to-end encryption of user data
  on top) can change the answer.

## Networking rules on iOS

- **App Transport Security does not apply.** ATS governs `URLSession` and other URL-loading APIs. Kuicksilver opens its
  own UDP and TCP sockets, so `NSAppTransportSecurity` settings neither allow nor block it. Your TLS policy is
  Kuicksilver's: `TrustConfig.Platform` (SecTrust, the system and MDM roots), pins, or a private CA; host names are
  always checked.
- **Local network permission.** Talking to a device on the LAN (a server on another phone, an echo peer, a printer)
  triggers the iOS local network prompt. Declare `NSLocalNetworkUsageDescription`, and `NSBonjourServices` for every
  service type you browse or advertise (`_kuicksilver._udp` in the sample). Loopback and Internet traffic need neither.
- **Servers are foreground only.** A QUIC server on iOS works (bind `::` for dual-stack), but the system suspends the
  app, and with it the socket, shortly after it leaves the screen. Use `loops = 1`.
- **IPv6-only networks.** App Review tests on a NAT64 network. Bind `::` and connect by host name: the endpoint
  resolves the name once, and on NAT64 the system resolver synthesises an IPv6 address for an IPv4-only host. Do not
  hard-code IPv4 literals.
- **Network changes.** A QUIC connection survives a move to another socket (`QuicConnection.migrate`, `rebind`).
  `QuicConnection.followDefaultNetwork(scope)` (experimental) follows the default network automatically (Wi-Fi to
  cellular and back) through one shared `NWPathMonitor`, and also replaces a socket iOS reclaimed while the app was
  suspended ([QUIC: Network changes](quic.md#network-changes)). The sample's echo screen has a "Follow the default
  network" toggle for it and a manual Rebind button.

## Checks

| Script | What it proves |
|---|---|
| `tools/check/ios-sample-smoke.sh` | the sample builds for the simulator, `-smoke` launch passes (server, echo, HTTP/3 over loopback), and the XCTest bundle calling the facade from Swift passes |
| `tools/check/ios-symbols.sh` | no global symbol is defined both by the Kotlin framework and by an unprefixed OpenSSL of the same release (7148 would be without the prefix); both copies are linked into one executable and both complete a TLS 1.3 handshake on the simulator |
| `tools/check/ios-private-api.py <sdk> <binary>` | every undefined symbol is exported by a public `.tbd` of the SDK (no private API), plus the required-reason report |
| `tools/check/ios-size.sh` | the size budget below, from the linker map of a Release arm64 build |

Results of 2026-10-13 (Xcode 27.0, iOS 27.0 SDK and simulator): all pass. Size and imports re-measured on 2026-10-14
after the 0.2.0 merges (`ios-size.sh`, `ios-private-api.py`): the Release arm64 app imports 647 symbols, all from
public SDK libraries; the Release Kotlin framework 354, likewise.

## Size

Linked bytes of `samples/ios` (Release, arm64, `-dead_strip`), from the linker map:

| Part | MB |
|---|---|
| OpenSSL (libssl + libcrypto, prefixed) | 1.98 |
| `ksl` C shim | 0.03 |
| Kotlin: Kuicksilver | 1.43 |
| Kotlin: stdlib | 0.73 |
| Kotlin/Native runtime, glue and data | 0.72 |
| kotlinx-coroutines | 0.48 |
| ktor-io / ktor-network | 0.18 |
| kotlinx-io, atomicfu, platform interop | 0.06 |
| **Kuicksilver's contribution** | **5.60** |
| the sample's Swift code and the rest | 0.10 |

Measured on 2026-10-14 (the 0.2.0 code, Xcode 27.0). The whole executable is 8316 KiB (8.1 MiB) before stripping and
5955 KiB (5.8 MiB) after (`strip -x`, as an App Store build does). A KMP app that already ships Kotlin pays only for the
OpenSSL, `ksl` and Kuicksilver rows (about 3.4 MB); the runtime, stdlib and coroutines are shared with the rest of its
Kotlin code. The App Store applies app thinning and compression on top.

## Device checklist

The simulator shares the Mac's network stack, so these need an iPhone. Open `samples/ios/KuicksilverSample.xcodeproj`,
select your team in Signing & Capabilities (a free Apple ID works; if the bundle ID is taken, change
`KUICKSILVER_BUNDLE_PREFIX` in `samples/ios/Config/Project.xcconfig`), pick the phone and press Run. For a server and a
client, run the app on two devices, or point the echo screen at `samples/realtime-telemetry`-style peers on a Mac.

1. **Wi-Fi and cellular, separately**: HTTP/3 GET of a public site with System trust; echo to a server on the LAN
   (Wi-Fi only).
2. **Handover under load**: an echo session with 300 rounds every 250 ms, then walk out of Wi-Fi range (or turn Wi-Fi
   off), once with "Follow the default network" on and once with Rebind by hand; the log must show `path changed`
   without a new handshake.
3. **Backgrounding**: start an echo session, background the app for 5 s, 60 s and 5 min, return; note whether the
   session survives (the idle timeout is 30 s) and that a new one works.
4. **Low Power Mode**: repeat 1 and 2.
5. **IPv6-only through NAT64**: share the Mac's connection over Wi-Fi with "Create NAT64 Network" (System Settings >
   General > Sharing > Internet Sharing, Option-click for the NAT64 choice); HTTP/3 GET of an IPv4-only host name must
   work.
6. **Captive portal**: join a network before signing in; requests must fail cleanly (a handshake timeout, no hang).
7. **VPN**: with a VPN on, HTTP/3 and echo; the smaller MTU must not stall the transfer (PMTUD falls back to 1200).
8. **iCloud Private Relay**: on; Private Relay covers Safari, DNS and unencrypted HTTP, not an app's own QUIC, so
   the results must match 1 (name resolution may take a different route).
9. **LAN server**: Server tab, Start; accept the local network prompt; from another phone, echo to the shown address
   with Sample CA trust, and open the `https://` address with the HTTP/3 screen. The service is visible as
   `_kuicksilver._udp` to a Bonjour browser.

Beta needs items 1, 2, 3 and 5.
