<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# API stability and support

What Kuicksilver 0.2.0 promises: which API you can build on, what may still change, how the promise is checked, and
which platforms, Ktor versions and OpenSSL releases are covered. Kuicksilver is pre-1.0 ([README](../README.md),
[CHANGELOG](../CHANGELOG.md): Semantic Versioning, "before 1.0, any 0.x release may contain breaking changes"); this
page says how far below that ceiling each part of the API stays.

## Stability levels

Every public declaration of a published module is at exactly one of these levels. The level is visible in the code:
the opt-in annotations live in `io.kuicksilver.annotations` (module `kuicksilver-native`, available to every module
above it).

| Level | How you recognise it | Patch release (0.2.x) | Minor release (0.3.0, …) |
|---|---|---|---|
| **Stable** | public, no opt-in annotation | binary and source compatible; behaviour changes only as bug fixes | may change before 1.0, but a removal goes through the deprecation cycle below where the change allows it, and every incompatible change is listed in the CHANGELOG |
| **Experimental** | `@ExperimentalKuicksilverApi` (opt-in, warning: "This API is experimental and may change.") | kept compatible unless a defect needs a change, which the CHANGELOG then lists | may change or be removed without a deprecation cycle |
| **Delicate** | `@DelicateKuicksilverApi` (opt-in, warning: "This API is delicate; read its documentation before use.") | as its stability level | as its stability level |
| **Internal** | `@InternalKuicksilverApi` (opt-in, **error**: "This API is internal to Kuicksilver.") | no promise | no promise |
| **Unpublished** | modules `kuicksilver-testing`, `kuicksilver-interop`, `kuicksilver-bench`, `kuicksilver-soak`; `samples/` | not released | not released |

- **Stable** is the default for public API. `explicitApi()` is on in every module, so nothing becomes public by
  accident, and every public declaration carries KDoc that states its contract.
- **Experimental** is where new API starts ([CONTRIBUTING](../CONTRIBUTING.md): "it becomes stable after it has been
  used, in a later minor release"). Opt in per use site with `@OptIn(ExperimentalKuicksilverApi::class)` or for a
  module with `languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi")`. Some interfaces are
  stable to *use* but experimental to *implement* (`@SubclassOptInRequired`): `DatagramIo`, `CongestionController`,
  `DatagramSender`.
- **Delicate** is not a stability level of its own: it marks API that can weaken security when misused (a custom
  verifier, key logging, external signers). It combines with the others: `keylogFile` and `TrustConfig.Custom` are
  stable and delicate, `TlsIdentity.Signer` is experimental and delicate.
- **Internal** declarations are public only because another Kuicksilver module needs them (the `Ksl` FFI facade,
  `KslUdpSocket`, the TCP session cache, `KtorVersionPolicy`, the soak probes). The opt-in is an error, they are left
  out of the ABI dumps, and they can change in any release.
- **Interfaces the library implements** (`QuicConnection`, `QuicStream`, `Http3Connection`, `Http3Stream`, …) are
  meant to be called, not implemented; a minor release may add members to them. Implement them only in test fakes.

**Deprecation cycle** (from [CONTRIBUTING](../CONTRIBUTING.md)): a stable declaration that goes away is first
`@Deprecated` at level `WARNING` with a `ReplaceWith`, then `ERROR`, then removed, with at least one minor release
between the steps. A change that cannot be expressed that way (a type that changes, a sealed hierarchy that gains a
member) is made in a minor release and listed under **Changed** in the CHANGELOG with "breaking". 0.2.0 has such
changes; see the CHANGELOG's "QUIC API (breaking, before 1.0)" entry and the new `PathEvent.SocketLost`, which an
exhaustive `when` over `PathEvent` must now handle.

Deprecated in 0.2.0 and still present: the type aliases `io.kuicksilver.quic.PathChanged` (use `PathEvent.Changed`)
and `io.kuicksilver.quic.wire.VersionProfile` (use `io.kuicksilver.quic.VersionProfile`), both at level `WARNING`.

**Security fixes** go to the latest 0.x release only ([SECURITY](../SECURITY.md), "Supported versions").

## How the promise is checked

- **Kotlin ABI dumps.** The Kotlin Gradle plugin's ABI validation (`abiValidation` in
  `build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts`) keeps a dump of the public ABI of every library module in
  `<module>/api/`: `api/jvm/<module>.api` (JVM), `api/android/<module>.api` (Android) and `api/<module>.klib.api` (the
  Kotlin/Native klibs of `iosArm64`, `iosSimulatorArm64`, `linuxArm64`, `linuxX64`, `macosArm64` and `mingwX64`,
  with Apple-only declarations in their own sections). The one filter excludes declarations annotated
  `@InternalKuicksilverApi`; experimental and delicate API is in the dumps, so its changes are reviewed too.
  `checkKotlinAbi` compares the build against the dumps and is part of each module's `check`; the CI matrix
  (`tools/ci/matrix.sh`, the `apple` job, and `tools/ci/local-matrix.sh`) runs it over every module, which needs the
  Apple, Android and Kotlin/Native toolchains together. An intended API change regenerates the dumps with
  `updateKotlinAbi` in the same commit, and reviewers read the `api/` diff. Before a release, `./gradlew
  checkKotlinAbi` must be green: the dumps are the contract of the version ([release.md](release.md)).
- **What the dumps do not catch**: behaviour, defaults and KDoc contracts. Those are covered by the module tests, the
  guides' code samples (`GuideSamplesTest`, kept in step by `tools/check/guide-sync.sh`) and the CHANGELOG entry every
  user-visible change needs.

## The native library ABI (`ksl`)

The C shim `ksl` (`kuicksilver-native/src/c/ksl.h`) has its own version, `KSL_ABI_VERSION`, **6 in 0.2.0** (ABI 5 kept
identity keys in OpenSSL, ABI 6 added the early-data controls for 0-RTT and the live-object counters). It is bumped on
any incompatible change of the C interface. The Kotlin side expects one exact value (`KSL_ABI_VERSION` in
`io.kuicksilver.native`), and the loader refuses any other: `KslException.AbiMismatch(native, kotlin)` with the message
"ksl ABI <n> in the native library, <m> expected", older or newer alike. On the JVM the check runs right after the
library is loaded and before `ksl_init`; on Android after `System.loadLibrary("ksl")`; on Kotlin/Native `ksl` is linked
statically, so a mismatch cannot normally happen. The outcome is cached for the process: `KslLoader.ensureLoaded()`
throws the same exception again and `KslLoader.availability()` reports
`NativeAvailability.Unavailable(NativeUnavailableReason.AbiMismatch, …)`.

The JVM library carries the ABI in its file name (`libksl_<abi>_<os>_<arch>`), and the jar manifest records it as
`Ksl-ABI`, so libraries of different releases never overwrite each other in the extraction directory. A mismatch in
practice means a library supplied from outside the jar (`-Dkuicksilver.native.path`, `-Dkuicksilver.native.system=true`)
that belongs to another release. `ksl` is not an API for applications: always take the native library from the
`kuicksilver-native` artifact of the same version.

## Ktor versions

Kuicksilver 0.2.0 supports **Ktor 3.6.x** (built and tested against 3.6.0). The engines use some Ktor internals and
vendor parts of Ktor CIO ([ktor-internal-api.md](ktor-internal-api.md)), so another major.minor is unsupported even
when it links. The check (in `kuicksilver-ktor-network`):

- **When.** Creating a client engine (`HttpClient(Kuicksilver)`, also when found through `ServiceLoader`) checks
  `ktor-client-core` and `ktor-http-cio`; starting a server engine (`start()`, not its construction) checks
  `ktor-server-core` and `ktor-server-cio`.
- **How, on the JVM and Android.** For a class of each artifact it reads `Implementation-Version` from the manifest
  of the jar that holds the class (falling back to the package's implementation version) and compares the first two
  components with `3.6`; patch and qualifier are ignored. A version that cannot be read (Android after dexing, shaded
  or repackaged jars, classes from a directory) passes silently.
- **On a mismatch** the engine fails with an `IllegalStateException`: "Kuicksilver's Ktor engines support Ktor 3.6.x,
  but <artifact> <version> is on the classpath. Align every io.ktor artifact to 3.6.x (for example with
  `platform("io.ktor:ktor-bom:3.6.<patch>")`), or, at your own risk, start the JVM with
  -Dkuicksilver.ktor.versionCheck=false (docs/guide/ktor.md, "Supported Ktor versions")."
- **Opting out.** The system property `kuicksilver.ktor.versionCheck=false` (case-insensitive; set it on the command
  line or with `System.setProperty` before the engine is created) skips the check. A real mismatch then fails later,
  if at all, with `NoSuchMethodError` or `AbstractMethodError`.
- **Kotlin/Native** has no runtime check: klibs are resolved at link time, and a Ktor with another ABI fails the link.
- **Upgrades.** A new Ktor minor is adopted in a Kuicksilver minor release; Ktor patch releases are accepted at once
  ([ktor.md, Supported Ktor versions](guide/ktor.md#supported-ktor-versions)).

## OpenSSL

Every artifact links OpenSSL statically; applications get OpenSSL fixes from Kuicksilver releases, not from their
operating system.

- **Branch.** OpenSSL 3.5 LTS only; OpenSSL 4.x is out of scope for now. 0.2.0 pins **3.5.9** in
  `gradle/openssl.toml` together with the tarball's SHA-256 and the fingerprint of the OpenSSL release signing key; the
  build verifies both before compiling (`tools/openssl/fetch.sh`).
- **Updates** follow the commitments in [SECURITY.md, OpenSSL](../SECURITY.md#openssl): a Kuicksilver release with the
  fixed OpenSSL within 72 hours of an OpenSSL release fixing a Critical or High issue, within 14 days for Moderate, in
  the next planned release for Low or unreachable issues, and within 30 days for a non-security 3.5.x patch release.
  Such a release is a patch release (0.2.x) when nothing else changes.
- **Visibility.** The version stays visible in the native libraries; the JVM jar's manifest names it as
  `OpenSSL-Version` and `OpenSSL-SHA256`.
- **Symbols.** On Kotlin/Native and in the JNI libraries the OpenSSL inside cannot clash with another OpenSSL or
  BoringSSL in the same process (prefixed symbols on Kotlin/Native, a version script for JNI; ADR-0007).

## Platforms

Targets of every published module (`kuicksilver.kmp` convention plugin): `jvm`, Android (KMP Android library),
`linuxX64`, `linuxArm64`, `macosArm64`, `iosArm64`, `iosSimulatorArm64`, `mingwX64`. JS and Wasm are not targets;
`macosX64` was dropped (Intel Macs are served by the JVM and its JNI library).

| Platform | Requirements | How 0.2.0 was verified |
|---|---|---|
| JVM | JVM 17 or newer (bytecode 17; built with JDK 21). JNI libraries for Linux x86_64 and aarch64 (glibc 2.17+, manylinux2014; not musl), macOS arm64 and x86_64 (macOS 11+), Windows x86_64 | the JVM suites on macOS, on Linux in Docker, and on Windows in a local Windows 11 VM (Parallels) |
| Android | `minSdk` 24, `compileSdk` 35; arm64-v8a, armeabi-v7a, x86_64; libraries aligned for 16 KiB pages | device tests on the emulator (`androidConnectedCheck`), the AAR's size and 16 KiB page checks |
| `linuxX64`, `linuxArm64` | glibc of the Kotlin/Native sysroot (2.19 on x64, 2.25 on arm64) | the native suites in Docker; the interop runner's native image (`linuxArm64`) |
| `macosArm64` | macOS 11 or newer | the native suites on the macOS host |
| `iosSimulatorArm64` | | the suites of every module on the simulator, and `iosHostInteropTest` against a peer on the host |
| `iosArm64` | | compiled, linked and size-checked (`tools/check/ios-size.sh`, `ios-private-api.py`); **not yet run on a physical device** ([ios.md, Device checklist](guide/ios.md#device-checklist)) |
| `mingwX64` | ECN needs Windows 10 2004 or Server 2022 | the native suites in a local Windows 11 VM (Parallels) |

There is no hosted CI run in 0.2.0: GitHub Actions is paused, and the matrix (`tools/ci/local-matrix.sh`) runs on the
maintainers' machines. Platform limits that are part of the contract (one endpoint loop per port outside Linux and
Android, no GSO/GRO on Darwin, the Windows exclusive bind) are in the [README](../README.md#platforms) and the
[QUIC guide](guide/quic.md#binding-an-endpoint-and-connecting).

## What is experimental in 0.2.0

Everything not listed here (and not internal) is stable. The list follows the annotations in the code; where a whole
type is experimental, so are its members.

### `kuicksilver-native`

| API | Feature |
|---|---|
| `KslLoader.availability()`, `KslLoader.isAvailable()`, `NativeAvailability`, `NativeUnavailableReason` | checking for the native library without catching exceptions |

### `kuicksilver-tls`

| API | Feature |
|---|---|
| `QuicSessionTicket`, `EarlyDataAdmission`, `TlsEvent.SessionTicket`, `QuicTlsSession.earlyDataAccepted`, `resume`, `enableEarlyData`, `QuicCrypto.newSession(config, earlyData)` | 0-RTT plumbing between TLS and QUIC (ADR-0015) |
| `TlsIdentity.Signer` (also delicate) | external signers; **not available in 0.2.0**: its constructor throws `UnsupportedOperationException` |

`EarlyDataState` (`Disabled`, `Allowed`, `Required`) is stable.

### `kuicksilver-quic`

| API | Feature |
|---|---|
| `QuicClientConfig.earlyData`, `QuicServerConfig.earlyData`, `earlyDataContext`, `QuicEndpoint.connectEarly`, `QuicConnection.awaitHandshake`, `earlyDataAccepted`, `isHandshakeComplete`, `QuicStream.receivedEarly`, `ConnectionEvent.EarlyDataAccepted` / `EarlyDataRejected` / `SessionTicket`, `ConnectionCore.earlyDataAccepted` / `streamReceivedEarly`, `QuicException.ConnectionLost.ZeroRttRejected`, `ZeroRttOutcome` | 0-RTT |
| `CongestionController` (to implement), `Bbr` | pluggable congestion control and BBRv3 (`Cubic` and `NewReno` are stable) |
| `ConnectionCore`, `EndpointCore`, `QuicConnection.core`, `QuicConfig.toBuilder()`, `QuicEndpointConfig.toBuilder()` | the sans-IO core used directly |
| `NetworkMigrator`, `MigrationEvent`, `QuicConnection.rebind` | automatic migration (`QuicConnection.migrate`, `addPath`, `probe`, `switchTo` are stable) |
| Android: `QuicConnection.followDefaultNetwork(connectivityManager, scope)`, `ConnectivityManager.defaultNetworks()`, `DatagramIo.open(local, network, prefer)` | following the default network on Android |
| Apple: `QuicConnection.followDefaultNetwork(scope)`, `nwPathUpdates()`, `NwPathKey`, `NwInterfaceType`, `DatagramIo.open(local, interfaceIndex, prefer)` | following the default network on iOS and macOS |
| `PathFailureReason`, `PathValidationException`, the `reason` of `PathEvent.Failed` and `ConnectionEvent.PathFailed` | why a path failed (`NoSpareConnectionId`, …) |
| `PathEvent.SocketLost`, `SocketDefunctException` | sockets the system took away (suspended iOS apps) |
| `DatagramIo` (to implement), `DatagramSender`, `DatagramPacketWriter`, `ConnectionStats.datagramsDroppedSocket` | custom socket and datagram plumbing |
| `QuicEndpoint.stats`, 24 `EndpointStats` counters from `connectionsActive` to `listenerFailures`, `KuicksilverLogger`, `LogLevel`, `ConnectionListener`, `ConnectionInfo`, `QuicEndpointConfig.logger` / `listener`, `AsyncQlogSink` | observability (`QlogSink`, `DirectoryQlogSink`, `QuicConfig.qlog`, `QuicConnection.stats` and the first `EndpointStats` counters, `initialsDropped` to `connectionsCreated`, are stable) |
| `QuicEndpoint.shutdown(grace, code, reason)` | graceful shutdown |
| `ConnectionCore.glitchByFrameType` (delicate) | glitch accounting per frame type |

### `kuicksilver-http3`

| API | Feature |
|---|---|
| `Http3Endpoint.connectEarly`, `Http3Request.allowEarlyData`, `Http3Settings.earlyData`, `Http3EarlyDataPolicy`, `Http3ServerRequest.receivedEarly` | 0-RTT |
| `Http3Endpoint.stats`, `Http3Endpoint.shutdown` | observability, graceful shutdown |

### `kuicksilver-ktor-client`

| API | Feature |
|---|---|
| `http3 { earlyData }` | 0-RTT |
| `maxConnectionsCount`, `maxConnectionsPerRoute`, `idleTimeout`, `maxConnectionLifetime` | connection limits and idle cleanup |
| `logger`, `eventListener`, `KuicksilverEventListener`, `ProtocolReason`, `http3 { qlog; connectionListener }` | observability |

### `kuicksilver-ktor-server`

| API | Feature |
|---|---|
| `quicEarlyData`, `ApplicationRequest.receivedEarly` | 0-RTT |
| `logger`, `qlog`, `connectionListener`, `eventListener`, `KuicksilverServerEventListener` | observability |

### `kuicksilver-ktor-network`

No experimental API. `TlsSocket`, `Socket.tls()` and `Socket.tlsServer()` are stable; `bindTcp`, `connectTcp` and
`KtorVersionPolicy` are internal.

### Stable API with a stated limit

These are stable, but read their KDoc before relying on them:

- `TimeoutKind.PathValidation` is reserved and not produced: a failed path validation ends in
  `ConnectionLost.NoViablePath`.
- `Http3ClientConfig.softDelay` is accepted but not acted on ([ktor.md, Racing and fallback](guide/ktor.md#racing-and-fallback)).
- `QuicEndpointConfig.loops > 1` throws `UnsupportedOperationException` outside Linux and Android, and a QUIC server on
  Kotlin/Native needs the accelerated socket.
