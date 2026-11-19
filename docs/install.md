<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Install

How to add Kuicksilver to a JVM, Android, Kotlin Multiplatform, Swift or Kotlin/Native project, which module to pick,
and which Ktor versions it works with. The [README](../README.md) has the three-line version.

## Versions

0.2.0 and 0.2.1 are withdrawn (their Kotlin/Native artifacts contain a local build path; their removal from Maven
Central has been requested): use 0.3.0. The guides, the API reference and the snippets here describe **0.3.0**, the
release in preparation: every guide says "version `0.3.0` or newer", and features the guides mark as 0.3.0 (the HTTP/3
kill switch and `Http3Advertising`, certificate reload, the QUIC connection limits of the server engine, HTTP/2,
WebTransport, among others; see the [CHANGELOG](../CHANGELOG.md)) are not in 0.2.1.

**Before 0.3.0 is published**, build it from a checkout of `main` and use `0.3.0-SNAPSHOT` as the BOM version below,
with `mavenLocal()` in your repositories. `./gradlew publishToMavenLocal` publishes every target, so it needs everything
in [CONTRIBUTING.md](../CONTRIBUTING.md#building): Docker (OpenSSL and `libksl` for Linux and Windows), the Android NDK
and, on macOS, Xcode. For a JVM application,

```sh
./gradlew publishJvmPublicationToMavenLocal publishKotlinMultiplatformPublicationToMavenLocal :kuicksilver-bom:publishToMavenLocal
```

publishes only the JVM jars, the multiplatform metadata and the BOM: no Android AAR (no NDK) and no Kotlin/Native
klibs. The metadata still runs the C interop of every native target, so OpenSSL is still built for each of them (Docker,
and Xcode on macOS), and the jar carries the native library of the machine that built it only (on an Apple Silicon Mac,
macOS arm64), so the application runs on that kind of machine alone. [Building from source](guide/building.md) covers
your own compiler and flags.

## Gradle

Each block pins every Kuicksilver module with the bill of materials (`kuicksilver-bom`) and every Ktor module with
Ktor's (Kuicksilver needs Ktor 3.6.x, [below](#supported-ktor-versions)). A module brings the modules it is built on;
the native library (OpenSSL 3.5 and `ksl`) comes with `kuicksilver-native`, nothing needs to be installed on the
system. The imports of every snippet are at the top of each guide (for example
[Ktor engines: Imports](guide/ktor.md#imports)).

A JVM server (JVM 17 or newer; Kotlin 2.3 or newer):

```kotlin
// build.gradle.kts
plugins {
    kotlin("jvm") version "2.4.20"
    application
}
repositories { mavenCentral() }
dependencies {
    implementation(platform("io.kuicksilver:kuicksilver-bom:0.3.0"))
    implementation(platform("io.ktor:ktor-bom:3.6.1"))
    implementation("io.kuicksilver:kuicksilver-ktor-server")
    implementation("io.ktor:ktor-server-core")
}
// your main(), or io.kuicksilver.ktor.server.EngineMain with an application.conf (docs/guide/ktor.md)
application { mainClass.set("com.example.MainKt") }
```

An Android app with the Ktor client (`minSdk` 24; the AAR carries the native libraries for arm64-v8a, armeabi-v7a and
x86_64, the `INTERNET` and `ACCESS_NETWORK_STATE` permissions and its R8 rules):

```kotlin
// app/build.gradle.kts
dependencies {
    implementation(platform("io.kuicksilver:kuicksilver-bom:0.3.0"))
    implementation(platform("io.ktor:ktor-bom:3.6.1"))
    implementation("io.kuicksilver:kuicksilver-ktor-client")
    implementation("io.ktor:ktor-client-core")
}
```

Kotlin Multiplatform with iOS (Kotlin 2.4.x for Kotlin/Native; one static framework for all the app's Kotlin code,
[iOS guide](guide/ios.md)):

```kotlin
// shared/build.gradle.kts
kotlin {
    listOf(iosArm64(), iosSimulatorArm64()).forEach {
        it.binaries.framework { baseName = "Shared"; isStatic = true }
    }
    sourceSets.commonMain.dependencies {
        implementation(project.dependencies.platform("io.kuicksilver:kuicksilver-bom:0.3.0"))
        implementation(project.dependencies.platform("io.ktor:ktor-bom:3.6.1"))
        implementation("io.kuicksilver:kuicksilver-ktor-client")   // or kuicksilver-http3, kuicksilver-quic
    }
}
```

A Kotlin/Native program (`linuxX64`, `linuxArm64`, `macosArm64`, `mingwX64`; Kotlin 2.4.x), here with raw QUIC
([QUIC: A complete example](guide/quic.md#a-complete-example-custom-alpn-streams-and-datagrams)):

```kotlin
// build.gradle.kts
plugins { kotlin("multiplatform") version "2.4.20" }
repositories { mavenCentral() }
kotlin {
    linuxX64 { binaries.executable { entryPoint = "com.example.main" } }
    sourceSets.commonMain.dependencies {
        implementation(project.dependencies.platform("io.kuicksilver:kuicksilver-bom:0.3.0"))
        implementation("io.kuicksilver:kuicksilver-quic")
    }
}
```

## Swift only

An app with no Kotlin of its own uses the Swift package
[kuicksilver-swift](https://github.com/kuicksilver/kuicksilver-swift), whose binary target is
`Kuicksilver.xcframework` of the GitHub release, from 0.3.0
([iOS guide, Swift only](guide/ios.md#swift-only-kuicksilverxcframework-and-swiftpm)):

```swift
.package(url: "https://github.com/kuicksilver/kuicksilver-swift", .upToNextMinor(from: "0.3.0")),
```

## Modules

| Artifact (`io.kuicksilver:`) | What it is | Guide |
|---|---|---|
| `kuicksilver-native` | the `ksl` C shim with OpenSSL 3.5 inside, its JNI and cinterop bindings, the native loader | [architecture](architecture.md) |
| `kuicksilver-tls` | TLS 1.3 configuration, trust (platform, private CA, SPKI pins, TOFU), TLS over any byte channel | [tls.md](guide/tls.md) |
| `kuicksilver-ktor-network` | `Socket.tls()` / `Socket.tlsServer()` for ktor-network sockets | [tls.md](guide/tls.md) |
| `kuicksilver-quic` | QUIC transport: streams, datagrams, migration, coroutine API and sans-IO core | [quic.md](guide/quic.md) |
| `kuicksilver-http3` | HTTP/3 and QPACK over `kuicksilver-quic` | [http3.md](guide/http3.md) |
| `kuicksilver-http2` | HTTP/2 and HPACK: a sans-IO core over any byte stream and its coroutine runtime (experimental, for the engines) | [architecture](architecture.md) |
| `kuicksilver-ktor-client` | `HttpClient(Kuicksilver)`: HTTP/3, and HTTP/2 or HTTP/1.1 over TLS, Alt-Svc discovery, racing, fallback | [ktor.md](guide/ktor.md) |
| `kuicksilver-ktor-server` | `embeddedServer(Kuicksilver)`: HTTP/1.1 (and opt-in HTTP/2) over TLS on TCP and HTTP/3 on UDP, same port | [ktor.md](guide/ktor.md) |

Each module depends only on the layer directly below it (ADR-0005). `kuicksilver-testing` (network simulator and
in-memory UDP), `kuicksilver-bench`, `kuicksilver-interop` and `kuicksilver-engine-interop` live in this repository but
are not published.

## Supported Ktor versions

**Ktor 3.6.x.** The engines use a few Ktor internals, so they check the Ktor version when a client engine is created
or a server engine starts (JVM and Android) and fail with a clear message on another major.minor;
`-Dkuicksilver.ktor.versionCheck=false` skips the check. On Kotlin/Native a mismatch fails at link time. New Ktor
minors are adopted in Kuicksilver releases; see [Supported Ktor versions](guide/ktor.md#supported-ktor-versions).

## Next

- The Ktor client: discovery modes (`Auto`, `Preferred`, `H3Only`, `H1Only`), trust and pins, timeouts:
  [Ktor engines](guide/ktor.md).
- The Ktor server: one TLS connector serves HTTP/1.1 over TLS on TCP and HTTP/3 on UDP on the same port number, and
  advertises HTTP/3 with `Alt-Svc`; open and forward both `443/tcp` and `443/udp`:
  [deploying the HTTP/3 server](guide/deployment.md).
- Raw QUIC (your own protocol, streams and datagrams): [QUIC](guide/quic.md); HTTP/3 without Ktor: [HTTP/3](guide/http3.md).
- Every option with its default: the [configuration reference](guide/configuration.md).
