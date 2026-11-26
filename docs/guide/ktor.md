<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Ktor engines

**What this page is for.** The start of the Ktor engine guides: the production first screen of each engine, the imports
every engine page uses, a map of the [engine pages](#the-engine-pages) by task, and the Ktor versions the engines work
with. New to Kuicksilver? Start with the [Quickstart](quickstart.md).

**Before you start**

- Dependencies: `io.kuicksilver:kuicksilver-ktor-server` and/or `io.kuicksilver:kuicksilver-ktor-client`, version
  `0.3.0` or newer. Ktor 3.6.x, with all `io.ktor` artifacts on the same version
  ([Supported Ktor versions](#supported-ktor-versions)).
- Built with Kotlin 2.4.20: JVM and Android need Kotlin 2.3 or newer, Kotlin/Native 2.4.x
  ([Kotlin version](../stability.md#kotlin-version)).
- Platforms: JVM 17 or newer, Android `minSdk` 24, iOS 15, macOS 12 (macOS 11 on the JVM), Linux, Windows
  ([Platforms](../stability.md#platforms)).
- A server needs a certificate chain and private key (PEM). A client needs none: it trusts the platform's store unless you
  set `tls { trust }`.

<a id="minimal-example"></a>
**Minimal example.** The first screen of each engine: the few options most applications set, every one of them stable
(no opt-in; the [configuration reference](configuration.md#first-screen) lists them). A server with a certificate from
files, renewals picked up, on one port for TCP and UDP:

```kotlin
// guide:ktor:first-screen-server
fun main() {
    embeddedServer(Kuicksilver, configure = {
        tls {
            pemFiles(
                "/etc/letsencrypt/live/example.com/fullchain.pem", // the key must be unencrypted PKCS#8
                "/etc/letsencrypt/live/example.com/privkey.pem", // (-----BEGIN PRIVATE KEY-----)
            )
            reloadInterval = 1.hours // pick up certbot renewals
        }
        tlsConnector { port = 443 } // TCP 443: HTTP/2 and HTTP/1.1; UDP 443: HTTP/3, announced with Alt-Svc
    }, module = Application::module).start(wait = true)
}
// Open 443/tcp AND 443/udp. Check: curl -sI https://example.com | grep -i alt-svc; curl --http3-only -sI https://example.com
```

The same server from `application.conf`, with `mainClass = io.kuicksilver.ktor.server.EngineMain` (the keys follow the
DSL: [EngineMain and configuration keys](server-config-file.md#enginemain-and-configuration-keys)):

```hocon
ktor.deployment.port = 443
ktor.application.modules = [ com.example.ApplicationKt.module ]
kuicksilver.tls {
    certificateChain = "/etc/letsencrypt/live/example.com/fullchain.pem"
    privateKey       = "/etc/letsencrypt/live/example.com/privkey.pem"
    reloadInterval   = 1h
}
```

The most common client configures nothing; the first request to a host goes over TCP (HTTP/2 or HTTP/1.1), HTTP/3 from
the next one once the server sent `Alt-Svc` (run it inside a coroutine, for example `runBlocking { }`):

```kotlin
// guide:ktor:first-screen-client
val client = HttpClient(Kuicksilver) // explicit engine: HttpClient() may pick OkHttp/Android first (ServiceLoader)
println(client.get("https://example.com/").bodyAsText())
client.close()
```

A mobile app with its own API (HTTP/3 from the first request, a remote kill switch, connection migration) is the first
screen of [Client](client.md); recipes for common deployments open [Server](server.md). Client certificates on both sides are
under [Mutual TLS](engine-tls.md#mutual-tls-client-certificates), pinning under [Certificate pinning](engine-tls.md#certificate-pinning).

<a id="imports"></a>
**Imports.** The code blocks of the engine pages start after their imports; these are the imports they use, and the
test that compiles them fails when a name moves. The server engine and the client engine are two objects with the same name,
`Kuicksilver`: `io.kuicksilver.ktor.server.Kuicksilver` for `embeddedServer(Kuicksilver)` and
`io.kuicksilver.ktor.client.Kuicksilver` for `HttpClient(Kuicksilver)`. Experimental API (`@ExperimentalKuicksilverApi`)
needs an opt-in: `@file:OptIn(ExperimentalKuicksilverApi::class)` at the top of the file, as the blocks show, or
`languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi")` for the whole module
([stability](../stability.md#stability-levels)).

```kotlin
// guide:ktor:server-imports
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.utils.io.copyTo
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.http2Settings
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.UdpProxy
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.server.H2cMode
import io.kuicksilver.ktor.server.Http3Advertising
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverServerEventListener
import io.kuicksilver.ktor.server.connectUdp
import io.kuicksilver.ktor.server.peerCertificates
import io.kuicksilver.ktor.server.priority
import io.kuicksilver.ktor.server.receivedEarly
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.EchKey
import io.kuicksilver.tls.EchServerKeys
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
```

```kotlin
// guide:ktor:client-imports
import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.http
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.discard
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.http2Settings
import io.kuicksilver.http3.UdpProxyTemplate
import io.kuicksilver.ktor.client.ConnectFailure
import io.kuicksilver.ktor.client.ConnectUdpProxy
import io.kuicksilver.ktor.client.Dns
import io.kuicksilver.ktor.client.FileAltSvcStore
import io.kuicksilver.ktor.client.HostPort
import io.kuicksilver.ktor.client.Http3ConnectionMigration
import io.kuicksilver.ktor.client.Http3Discovery
import io.kuicksilver.ktor.client.HttpsRecordSource
import io.kuicksilver.ktor.client.IpAddress
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.ktor.client.ProtocolReason
import io.kuicksilver.ktor.client.ProxyCredentials
import io.kuicksilver.ktor.client.ProxyResolver
import io.kuicksilver.ktor.client.ProxyResolvers
import io.kuicksilver.ktor.client.QuicConnectionSnapshot
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.TcpConnectionSnapshot
import io.kuicksilver.ktor.client.Transport
import io.kuicksilver.ktor.client.closeHttp3Connections
import io.kuicksilver.ktor.client.kuicksilverDiagnostics
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.updatePriority
import io.kuicksilver.ktor.client.webTransport
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.EchConfigList
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.io.readString
import java.io.File
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
```

The Android samples (the mobile first screen, [Connection migration](client-http3.md#connection-migration)) also need
`android.net.ConnectivityManager` and `io.kuicksilver.ktor.client.followDefaultNetwork` (an Android-only extension; the
iOS and macOS one, without arguments, has the same name). A file that uses both engines (a
test, a gateway) imports at least one of them under another name:

```kotlin
// guide:ktor:both-engines-aliases
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer
// guide:ktor:both-engines
val server = embeddedServer(KuicksilverServer, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 8443
    }
}, module = Application::module)
val client = HttpClient(KuicksilverClient)
```

Kuicksilver plugs into Ktor 3.6 as a server engine (`io.kuicksilver:kuicksilver-ktor-server`) and a client engine
(`io.kuicksilver:kuicksilver-ktor-client`). Both speak HTTP/1.1 over TLS 1.3 (`kuicksilver-ktor-network`) and HTTP/3
(`kuicksilver-http3`); both also speak HTTP/2 over TLS (`kuicksilver-http2`, ADR-0017), on by default on both since
0.3.0 ([HTTP/2 on the server](server.md#http2-on-the-server)): one port serves HTTP/1.1, HTTP/2 and HTTP/3. The code blocks of the engine pages compile and run as `GuideSamplesTest`
(`kuicksilver-ktor-server/src/jvmTest` and `kuicksilver-ktor-client/src/jvmTest`), and the first screens compile in a
source set that opts in to nothing and fails on a warning (`src/jvmFirstScreenTest`), so they stay free of experimental
API; the engines' other tests run on every
target (see "Compatibility"). Every engine option with its default is in the [configuration
reference](configuration.md); common failures are in [troubleshooting](troubleshooting.md).

## The engine pages

| Task | Page |
|---|---|
| A first client and server, with a local test certificate | [Quickstart](quickstart.md) |
| The client engine: timeouts, HTTP/2, the connection pool, name resolution | [Ktor client engine](client.md) |
| How the client finds and uses HTTP/3: `Alt-Svc`, the race and the fallback, the kill switch, connection migration | [HTTP/3 in the Ktor client](client-http3.md) |
| HTTP, HTTPS and SOCKS proxies, CONNECT-UDP | [Proxies in the Ktor client](client-proxies.md) |
| The server engine: connectors, limits, HTTP/3 and HTTP/2, graceful stop | [Ktor server engine](server.md) |
| A load balancer or proxy in front: the PROXY protocol, misdirected requests | [Behind a proxy or load balancer](server-proxies.md) |
| `application.conf` and `EngineMain` | [Configuration file (EngineMain)](server-config-file.md) |
| Certificate pinning, client certificates, certificate reload, SNI, TLS 1.2, ECH | [TLS in the Ktor engines](engine-tls.md) |
| WebSockets, WebTransport, priorities | [WebSockets, WebTransport and priorities](realtime.md) |
| Logs, metrics, qlog; why a request did not use HTTP/3; why a call failed | [Observability and diagnostics](observability.md) |
| 0-RTT | [0-RTT](zero-rtt.md) |
| Ports, firewalls, Docker, Kubernetes, load balancers | [Deploying the HTTP/3 server](deployment.md) |
| Coming from OkHttp, Retrofit or another Ktor engine | [Migrating from OkHttp and Retrofit](migrating-from-okhttp.md), [Migrating from another Ktor engine](migrating-ktor-engines.md) |
| Every option with its default | [Configuration reference](configuration.md) |
| An error message or a symptom | [Troubleshooting](troubleshooting.md) |

## Where the sections of this page went

This page used to hold every section below; links to them land here and lead on.

| Section | Now on |
|---|---|
| <a id="server"></a>Server | [Ktor server engine](server.md) |
| <a id="connection-limits"></a>Connection limits | [Ktor server engine](server.md#connection-limits) |
| <a id="tls-12-on-the-server"></a>TLS 1.2 on the server | [TLS in the Ktor engines](engine-tls.md#tls-12-on-the-server) |
| <a id="http3-on-the-server"></a>HTTP/3 on the server | [Ktor server engine](server.md#http3-on-the-server) |
| <a id="encrypted-client-hello-on-the-server"></a>Encrypted Client Hello on the server | [TLS in the Ktor engines](engine-tls.md#encrypted-client-hello-on-the-server) |
| <a id="http2-on-the-server"></a>HTTP/2 on the server | [Ktor server engine](server.md#http2-on-the-server) |
| <a id="h2c-on-the-server"></a>h2c on the server | [Ktor server engine](server.md#h2c-on-the-server) |
| <a id="turning-http3-off-on-the-server"></a>Turning HTTP/3 off on the server | [Ktor server engine](server.md#turning-http3-off-on-the-server) |
| <a id="websockets-on-the-server"></a>WebSockets on the server | [WebSockets, WebTransport and priorities](realtime.md#websockets-on-the-server) |
| <a id="websockets-over-http3"></a>WebSockets over HTTP/3 | [WebSockets, WebTransport and priorities](realtime.md#websockets-over-http3) |
| <a id="websockets-over-http2"></a>WebSockets over HTTP/2 | [WebSockets, WebTransport and priorities](realtime.md#websockets-over-http2) |
| <a id="webtransport-over-http3-experimental"></a>WebTransport over HTTP/3 (experimental) | [WebSockets, WebTransport and priorities](realtime.md#webtransport-over-http3-experimental) |
| <a id="connect-udp-over-http3-experimental"></a>CONNECT-UDP over HTTP/3 (experimental) | [Ktor server engine](server.md#connect-udp-over-http3-experimental) |
| <a id="misdirected-requests"></a>Misdirected requests | [Behind a proxy or load balancer](server-proxies.md#misdirected-requests) |
| <a id="proxy-protocol"></a>PROXY protocol | [Behind a proxy or load balancer](server-proxies.md#proxy-protocol) |
| <a id="certificate-per-name-sni"></a>Certificate per name (SNI) | [TLS in the Ktor engines](engine-tls.md#certificate-per-name-sni) |
| <a id="certificate-rotation"></a>Certificate rotation | [TLS in the Ktor engines](engine-tls.md#certificate-rotation) |
| <a id="enginemain-and-configuration-keys"></a>EngineMain and configuration keys | [Configuration file (EngineMain)](server-config-file.md#enginemain-and-configuration-keys) |
| <a id="client"></a>Client | [Ktor client engine](client.md) |
| <a id="http2-on-the-client"></a>HTTP/2 on the client | [Ktor client engine](client.md#http2-on-the-client) |
| <a id="h2c-on-the-client"></a>h2c on the client | [Ktor client engine](client.md#h2c-on-the-client) |
| <a id="connection-pool"></a>Connection pool | [Ktor client engine](client.md#connection-pool) |
| <a id="connection-coalescing-experimental"></a>Connection coalescing (experimental) | [Ktor client engine](client.md#connection-coalescing-experimental) |
| <a id="http3-on-the-client"></a>HTTP/3 on the client | [HTTP/3 in the Ktor client](client-http3.md#http3-on-the-client) |
| <a id="discovery-and-alt-svc"></a>Discovery and Alt-Svc | [HTTP/3 in the Ktor client](client-http3.md#discovery-and-alt-svc) |
| <a id="https-records-experimental"></a>HTTPS records (experimental) | [HTTP/3 in the Ktor client](client-http3.md#https-records-experimental) |
| <a id="happy-eyeballs"></a>Happy Eyeballs | [Ktor client engine](client.md#happy-eyeballs) |
| <a id="encrypted-client-hello-experimental"></a>Encrypted Client Hello (experimental) | [TLS in the Ktor engines](engine-tls.md#encrypted-client-hello-experimental) |
| <a id="name-resolution-experimental"></a>Name resolution (experimental) | [Ktor client engine](client.md#name-resolution-experimental) |
| <a id="racing-and-fallback"></a>Racing and fallback | [HTTP/3 in the Ktor client](client-http3.md#racing-and-fallback) |
| <a id="stalled-http3-connections"></a>Stalled HTTP/3 connections | [HTTP/3 in the Ktor client](client-http3.md#stalled-http3-connections) |
| <a id="turning-http3-off-remotely"></a>Turning HTTP/3 off remotely | [HTTP/3 in the Ktor client](client-http3.md#turning-http3-off-remotely) |
| <a id="connection-migration"></a>Connection migration | [HTTP/3 in the Ktor client](client-http3.md#connection-migration) |
| <a id="proxies"></a>Proxies | [Proxies in the Ktor client](client-proxies.md#proxies) |
| <a id="http3-through-a-connect-udp-proxy-experimental"></a>HTTP/3 through a CONNECT-UDP proxy (experimental) | [Proxies in the Ktor client](client-proxies.md#http3-through-a-connect-udp-proxy-experimental) |
| <a id="webtransport-on-the-client-experimental"></a>WebTransport on the client (experimental) | [WebSockets, WebTransport and priorities](realtime.md#webtransport-on-the-client-experimental) |
| <a id="mutual-tls-client-certificates"></a>Mutual TLS (client certificates) | [TLS in the Ktor engines](engine-tls.md#mutual-tls-client-certificates) |
| <a id="certificate-pinning"></a>Certificate pinning | [TLS in the Ktor engines](engine-tls.md#certificate-pinning) |
| <a id="priorities-experimental"></a>Priorities (experimental) | [WebSockets, WebTransport and priorities](realtime.md#priorities-experimental) |
| <a id="websocket-compression-experimental"></a>WebSocket compression (experimental) | [WebSockets, WebTransport and priorities](realtime.md#websocket-compression-experimental) |
| <a id="observability"></a><a id="observability-experimental"></a>Observability | [Observability and diagnostics](observability.md) |
| <a id="why-did-this-request-not-use-http3"></a>Why did this request not use HTTP/3? | [Observability and diagnostics](observability.md#why-did-this-request-not-use-http3) |
| <a id="which-connection-served-this-call"></a>Which connection served this call? | [Observability and diagnostics](observability.md#which-connection-served-this-call) |
| <a id="why-did-this-call-fail"></a>Why did this call fail? | [Observability and diagnostics](observability.md#why-did-this-call-fail) |
| <a id="graceful-stop"></a>Graceful stop | [Ktor server engine](server.md#graceful-stop) |
| <a id="0-rtt-opt-in-experimental"></a>0-RTT (opt-in, experimental) | [0-RTT](zero-rtt.md) |
| <a id="what-must-not-run-early"></a>What must not run early | [0-RTT](zero-rtt.md#what-must-not-run-early) |
| <a id="how-the-server-limits-replays"></a>How the server limits replays | [0-RTT](zero-rtt.md#how-the-server-limits-replays) |

## Supported Ktor versions

Kuicksilver 0.x supports **Ktor 3.6.x** (built and tested against 3.6.1). The engines use a few Ktor internals and
vendor parts of Ktor CIO (`docs/ktor-internal-api.md`), which Ktor may change in any minor release, so another
major.minor is not supported even when it happens to link.

- **At startup.** Creating a client engine (`HttpClient(Kuicksilver)`, also through `ServiceLoader`) checks
  `ktor-client-core`, `ktor-http-cio`, `ktor-network`, `ktor-io` and `ktor-websockets`; starting a server engine checks
  `ktor-server-core`, `ktor-http-cio`, `ktor-network` and `ktor-io` (every artifact whose internals the engines use or
  whose code they adapt). On the JVM and Android the version is the `Implementation-Version` in the manifest of the jar
  that holds each class; when the major.minor is not 3.6, the engine fails with an `IllegalStateException` naming the
  artifact, its version and the fix. Where no version can be read (Android after dexing, shaded or repackaged jars, classes from a directory) the check
  passes silently.
- **Opting out.** `-Dkuicksilver.ktor.versionCheck=false` (or `System.setProperty` before the engine is created) skips
  the check, for experts who verified their Ktor themselves; a mismatch then fails later, if at all, with
  `NoSuchMethodError` or `AbstractMethodError`.
- **Kotlin/Native.** klibs are resolved when the binary is linked: a Ktor whose ABI differs fails the link (unresolved
  symbols), so there is no runtime check. Keep every `io.ktor` dependency on the same 3.6.x, best with
  `platform("io.ktor:ktor-bom:3.6.1")`.
- **Upgrades.** A new Ktor minor is adopted in a Kuicksilver release: the version catalog moves, every entry of
  `docs/ktor-internal-api.md` is re-checked, the vendored CIO code and contract tests are re-vendored from the new tag,
  and `KtorVersionPolicy.SUPPORTED` moves with them. Ktor patch releases (3.6.x) need nothing and are accepted at once.

## Compatibility

Both engines run Ktor 3.6.0's own engine contract tests, vendored under `src/commonTest/kotlin/.../contract` (and
`src/jvmTest` for the JVM-only `ContentTestSuite`; attribution in `NOTICE`), over HTTP/1.1 and over HTTP/3, on every target:
the JVM, Android, Linux, macOS, iOS and Windows. The HTTP/3 runs, like the engines' own HTTP/3 tests in `commonTest`,
need a QUIC server peer and run where one can bind, which since 0.2.0 is every target with the accelerated socket: the
JVM, Android, Linux, macOS, the iOS simulator and Windows (where a probe finds no server, they pass without running). iOS
runs them on the simulator (`iosSimulatorArm64Test`), not yet on a device. Windows (Kotlin/Native and the JVM) was
verified in a local Windows 11 VM (Parallels) and runs in the hosted CI's Windows jobs; the release gate runs locally
(`tools/ci/local-matrix.sh --with-windows`).

**Client** (`kuicksilver-ktor-client`): `ContentTest`, `PostTest`, `UploadTest`, `DownloadTest`, `HttpRedirectTest`,
`HttpTimeoutTest` and `WebSocketTest` against Ktor's test-server routes hosted on the Kuicksilver server engine; every
test runs twice — `Kuicksilver-h1` (cleartext HTTP/1.1, `http3 { enabled = false }`) and `Kuicksilver-h3` (HTTPS, `H3Only`). 93 tests,
90 pass in both modes, 3 are `@Ignore`d upstream. Adapted: the `HttpTimeoutTest` success budgets are widened, room
for a fresh client's handshake on a loaded host (comments in the file). Left out:

- tests that need modules this project does not depend on: JSON content negotiation (`testJsonPostWithEmptyBody`),
  `ktor-client-auth` (three bearer-token WebSocket tests), kotlinx-serialization (`testWebSocketHeaders`, which over
  HTTP/3 would also have no `Connection`/`Upgrade`/`Sec-WebSocket-Key` to compare — RFC 9220 drops them);
- `testWebsocketWithDefaultRequest` over HTTP/3 only: `defaultRequest` sets host and port, so the URL stays `ws://`;
- `ServerSentEventsTest` and `HeadersTest`: they need serialization, logging and auth plugins (SSE is covered by the
  engine's own tests over all three protocols).

The contract found and fixed: a closed client kept its UDP socket (the engine's cleanup waited for its own parent
job), the socket timeout did not cover response bodies, an HTTP/3 body cancelled by the call reported the stream reset
instead of the call's cause (request timeout, caller's exception), and the `Sec-WebSocket-Protocol` of a WebSocket over
HTTP/3 did not reach the client.

**Server** (`kuicksilver-ktor-server`): `HttpServerCommonTestSuite` and `ContentTestSuite` run over HTTP/1.1
(`KuicksilverH1*`: each request once in cleartext and once over TLS, as Ktor's own engines do) and over HTTP/3
(`KuicksilverH3*`, `H3Only` client); `WebSocketEngineSuite` runs over HTTP/1.1 (`KuicksilverH1WebSocketTest`) — its
tests drive raw TCP sockets, so an HTTP/3 run would repeat them unchanged; WebSockets over HTTP/3 are covered by the
engine's tests and by the client contract's `WebSocketTest` in `Kuicksilver-h3` mode. The test client is
`HttpClient(Kuicksilver)` (a test-only dependency on `kuicksilver-ktor-client`), the plugins the suites install are
Ktor 3.6.0's (test scope only). On the JVM: 143 tests, 135 pass, 8 skip: `@Http2Only` (HTTP/2 server push, which Kuicksilver does not implement),
`@Http1Only` over HTTP/3 (the two keep-alive tests and chunked encoding), two tests `@Ignore`d upstream, and `testFragmentedFlagsFromTheFirstFrame` (it sends RSV1 without a negotiated extension, which the engine refuses with 1002). The
multipart uploads (streamed bodies of unknown length, chunked over HTTP/1.1) run over HTTP/3 too. Adapted: the test base (ports from the engine's resolved
connectors, the TLS identity from the test CA, real time instead of virtual time), the paths of the local-file and
static-resource tests (this module's layout and package), and `funkyChunked`, which expects a CRLF inside a quoted
chunk extension to be part of it: RFC 9110 section 5.6.4 allows neither CR nor LF in a quoted-string, so the server
answers 400. The WebSocket suite's test client masks its frames (RFC 6455 section 5.1; the engine fails an unmasked
one), and `testFragmentedFlagsFromTheFirstFrame` is `@Ignore`d: it sends RSV1 without negotiating an extension and
expects the server to take it, which the engine refuses with 1002 (threat model 3.20.1). Not vendored: `HttpServerJvmTestSuite`,
`SustainabilityTestSuite`, `ClientCertTestSuite` and the other JVM suites — they rely on `HttpURLConnection`, JKS key
stores and the Apache/OkHttp clients. Off the JVM, `PortableContentTestSuite` carries the 13 `ContentTestSuite` tests
that need no `java.io` (with `respondBytesWriter` and `ChannelWriterContent` for the JVM writers) in its place.

The suites found and fixed: a query parameter without a value (`?auto`) read as `null` instead of `""` over HTTP/3,
and the HTTP/1.1 client sent a streamed request body completely before reading the response (a server that answers
first, then reads the body, deadlocked). On Linux Native the client contract found that a failed HTTP/3 request (a peer
resetting a WebSocket stream) escaped as an uncaught coroutine exception, which aborts a Kotlin/Native process; each
request now contains its own failure.

**Other HTTP implementations.** The engine interop bench runs both engines against Ktor's Netty and CIO engines,
OkHttp, the JDK's HttpClient and Netty's HTTP/2 and HTTP/3 codecs on the JVM; its pairs, scenarios and the peers'
deviations are in [interop.md](../spec/interop.md#engine-interop-the-ktor-engines-against-other-http-stacks-jvm-2026-11-13).

**Other WebSocket peers.** The engines check every frame against the handshake (RFC 6455 sections 5.1 and 5.2, RFC
7692 section 6.1), stricter than Ktor's own engines:

- Ktor's `WebSocketDeflateExtension` compresses each fragment of a message on its own and sets RSV1 on every fragment,
  not only the first. A peer that uses it and fragments a compressed message is closed with 1002 by Kuicksilver's
  engines; unfragmented messages, the common case, pass. When Ktor's extension runs in Kuicksilver's engines, they send
  such a message as an RFC 7692 one (RSV1 on the first frame only, the fragments one DEFLATE stream); a message in which
  Ktor's `compressCondition` left a fragment uncompressed cannot be, and fails with `ProtocolViolationException`.
- A client that does not mask its frames, or a server that masks them, is closed with 1002, as the RFC requires; Ktor's
  own frame readers accept either.
- Ktor 3.6.1's WebSocket writer on Kotlin/Native (its common `RawWebSocket`) sends every fragment of a message with the
  message's opcode instead of 0 (continuation), so a fragmented message sent from Kotlin/Native through another engine
  is refused by the peer as a new message inside an unfinished one. Kuicksilver's engines send the later fragments as
  continuations on every platform (0.3.0); with another engine on Kotlin/Native, send whole messages. Its JVM writer is
  right.
- Ktor 3.6.1's `WebSocketDeflateExtension` fails (`IllegalArgumentException: byteCount: -5 < 0`, the session closes
  with 1011) when it compresses an empty message after an earlier one; it reads an empty message from
  `PerMessageDeflate` (a single 0x00 byte, RFC 7692 section 7.2.3.6) correctly. Otherwise the two interoperate in both
  directions over HTTP/1.1 and HTTP/3, context takeover included (`ClientDeflateKtorTest`).

### IPv6 over TCP on Kotlin/Native

On Kotlin/Native (Linux, Apple, Windows) Kuicksilver binds and connects its TCP sockets itself instead of through Ktor
3.6's `ktor-network`, because of a Ktor issue reported as
[KTOR-10017](https://youtrack.jetbrains.com/issue/KTOR-10017) (security, under coordinated disclosure).

Both engines therefore open their HTTP/1.1 TCP sockets through `kuicksilver-ktor-network` (`bindTcp`, `connectTcp`): on
the JVM and Android that is `ktor-network` as before; on Kotlin/Native it is a TCP socket of Kuicksilver on Ktor's selector
that binds and connects the address `getaddrinfo` returned. So on every platform:

- a server connector with a specific `host` (`::1`, `127.0.0.1`, a global address) listens on that address only; `::` and
  `0.0.0.0` stay the wildcards, and a connector without a `host` binds `::` with `IPV6_V6ONLY` off, one dual-stack socket
  that IPv4 clients reach as IPv4-mapped addresses;
- the client's HTTP/1.1 connection (and its connection to an HTTP proxy) goes to the address in the URL; an
  IPv4-mapped literal (`[::ffff:127.0.0.1]`) is connected over IPv4, as the JVM does. A host name is resolved to all its
  addresses and connected with Happy Eyeballs ([Happy Eyeballs](client.md#happy-eyeballs)); HTTP/3 races the same addresses over
  QUIC.
- Name lookups block a thread (`getaddrinfo`): at most 8 of each address family run at once, on their own share of
  `Dispatchers.IO`, and a name has one lookup per address family in flight however many requests wait for it, so a stalled resolver cannot take the
  threads the sockets run on (threat model 3.21). An address literal is never looked up.

HTTP/3 uses the accelerated `ksl` UDP socket, which carries the full address on every platform (the Ktor client's endpoint
is dual-stack, ADR-0006). The portable Kotlin/Native UDP socket (`IoPreference.Portable`, or a sandbox that refuses the
accelerated one) still uses `ktor-network`: it refuses to bind a specific IPv6 address (`UnsupportedOperationException`)
and to send to an IPv6 address (`IOException`), for the same reason. Tests:
`ServerH1Test.negative_ipv6ConnectorListensOnItsAddressOnly`,
`ClientH1Test.negative_h1ToIpv6LiteralReachesThatAddressOnly`, `ClientH1Test.plainHttpToIpv6Literal`,
`ClientH3Test.h1ToIpv6Loopback`, `TcpSocketsTest`, `KtorDatagramIoTest`.
