<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Migrating from another Ktor engine

**What this page is for.** Swapping a Ktor client engine (CIO, OkHttp, Android, Darwin, Java) or a Ktor server engine
(Netty, CIO, Jetty, Tomcat) for Kuicksilver: what changes in the engine's configuration and what stays the same. Your
routes, plugins and client calls do not change. Apps that call OkHttp directly, or through Retrofit:
[Migrating from OkHttp and Retrofit](migrating-from-okhttp.md).

**Before you start**

- Kuicksilver needs Ktor 3.6.x, with every `io.ktor` artifact on the same version: an application on another Ktor
  version moves to 3.6 first ([Install: Supported Ktor versions](../install.md#supported-ktor-versions)).
- Dependencies as in the [Quickstart](quickstart.md#1-add-the-dependencies). Remove the old engine's artifact
  (`ktor-client-okhttp`, `ktor-server-netty`...) when nothing else uses it.
- Every Kotlin block on this page that shows Kuicksilver compiles with no opt-in (stable API only). The engines are
  `io.kuicksilver.ktor.client.Kuicksilver` and `io.kuicksilver.ktor.server.Kuicksilver`: two objects with the same name.

## The client engine

<!-- guide-sync: not compiled (other engines, for comparison) -->
```kotlin
// CIO here (requestTimeout is CIO's own setting); the OkHttp, Android, Darwin and Java engines swap the same way
val client = HttpClient(CIO) { engine { requestTimeout = 15_000 } }
```

becomes

```kotlin
// guide:engines:client
val client = HttpClient(Kuicksilver) {
    install(HttpTimeout) { requestTimeoutMillis = 15_000 }
}
```

- **Name the engine.** `HttpClient()` without an argument picks the OkHttp, Android, Java, Apache or Jetty engine over
  Kuicksilver when one of them is on the class path. Pass `Kuicksilver` everywhere a client is created, and drop the other engine's dependency if
  nothing else needs it.
- **Timeouts** go through Ktor's `HttpTimeout` plugin, as with every engine; without it the engine's own
  `connectTimeout` (10 s) applies and nothing else. CIO's engine has a `requestTimeout` of its own, 15 s by default, that
  is lost in the swap: set `HttpTimeout`'s `requestTimeoutMillis` to keep it;
  the Android engine's `connectTimeout` and `socketTimeout` are `connectTimeoutMillis` and `socketTimeoutMillis`.
- **The engine's own settings** move to blocks of `engine { }`:

| Old engine setting | Kuicksilver |
|---|---|
| CIO `maxConnectionsCount`, `endpoint { maxConnectionsPerRoute; keepAliveTime }` | `pool { maxConnections; maxConnectionsPerRoute; idleTimeout }`: the limits have CIO's defaults (1000, 100); an idle connection stays 5 min, where CIO keeps it 5 s |
| CIO `endpoint { connectTimeout }`, `https { trustManager }` | `connectTimeout`; `tls { trust }` |
| OkHttp `config { }`, `preconfigured` | the settings themselves: [Migrating from OkHttp](migrating-from-okhttp.md#setting-by-setting) |
| Android `sslManager` | `tls { trust }`; the platform's trust, including the Network Security Config, is the default |
| Darwin `handleChallenge` (pinning) | `tls { trust = TrustConfig.Pinned(...) }` ([Certificate pinning](engine-tls.md#certificate-pinning)) |
| Darwin `configureSession` | none: Kuicksilver does not use `URLSession` ([iOS](ios.md)) |
| Darwin and App Transport Security | ATS governs `URLSession`, not Kuicksilver's own sockets: its `Info.plist` exceptions do nothing here, and an `http://` URL is not blocked by ATS ([App Store](app-store.md)) |
| TLS versions | the client offers TLS 1.2 and 1.3 by default (`TlsVersions.Tls12And13`), TLS 1.2 with ECDHE and AEAD suites only; `tls { versions = TlsVersions.Tls13 }` for TLS 1.3 only |
| `proxy` | the same Ktor `proxy`; HTTP/3 never goes through an HTTP proxy |
| `pipelining`, `threadsCount` | not used |

- **What you gain:** HTTP/3 once a server announces it (the first request to a host stays on TCP), HTTP/2, and the same
  engine on the JVM, Android, iOS, macOS, Linux and Windows. What each option does, by block:
  [configuration: Ktor client](configuration.md#ktor-client).

## The server engine

<!-- guide-sync: not compiled (other engines, for comparison) -->
```kotlin
embeddedServer(Netty, port = 8443, module = Application::module).start(wait = true)   // or CIO, Jetty, Tomcat
```

becomes, with TLS and HTTP/3 on the same port:

```kotlin
// guide:engines:server
embeddedServer(Kuicksilver, configure = {
    tls { pemFiles("/etc/tls/fullchain.pem", "/etc/tls/privkey.pem") } // the key unencrypted PKCS#8
    tlsConnector { port = 8443 } // HTTP/1.1, HTTP/2 and HTTP/3 on one port
}, module = Application::module).start(wait = true)
```

- **Cleartext as before.** `embeddedServer(Kuicksilver, port = 8080, module = ...)` serves plain HTTP/1.1, as Netty and
  CIO do: behind a TLS-terminating proxy, for instance. HTTP/3 needs TLS on the server itself, so it needs a
  `tlsConnector` or an identity in `tls { }`.
- **TLS.** `tls { pemFiles(...) }` reads the chain and the key (unencrypted PKCS#8, `-----BEGIN PRIVATE KEY-----`;
  [Quickstart](quickstart.md#2-a-server) converts another key format), and `tls { reloadInterval }` picks up renewed
  files. On the JVM, Ktor's `sslConnector(keyStore, ...)` and the `ktor.security.ssl.*` keys still work, as in the Netty
  and Jetty engines, TLS 1.3 only unless its `enabledProtocols` names `TLSv1.2` and `TLSv1.3`
  ([Ktor server engine](server.md)).
- **`EngineMain`.** Set `mainClass` to `io.kuicksilver.ktor.server.EngineMain`. The `ktor.deployment.*` keys keep their
  meaning, with two differences: a port without `ktor.deployment.host` listens on every interface, IPv6 and IPv4 (Netty
  and CIO: IPv4 `0.0.0.0`), and `ktor.deployment.connectionIdleTimeoutSeconds` is the engine's `tcp { idleTimeout }`
  (45 s). The engine's own keys are under `kuicksilver.` and follow the DSL, and an unknown key under `kuicksilver.`
  fails the start ([Configuration file (EngineMain)](server-config-file.md)).
- **Open UDP.** HTTP/3 needs the port open for UDP next to TCP, in the firewall, the security group and the container's
  port mappings ([Deploying the HTTP/3 server](deployment.md)).
- **What does not change:** the application, its routes and plugins (`StatusPages`, `CallLogging`, `WebSockets`,
  `ContentNegotiation`...). Ktor's engine contract tests run against Kuicksilver ([Ktor engines:
  Compatibility](ktor.md#compatibility)).
- **What differs:**
  - TLS 1.3 only by default on the server: `tls { versions = TlsVersions.Tls12And13 }` for old clients.
  - Limits the other engines do not set: a 30 s deadline for a complete request head (`requestHeaderTimeout`), at
    most 256 QUIC connections per client address (`http3 { endpoint { maxConnectionsPerIp } }`, `null` behind a NAT
    or kube-proxy) ([configuration: first screen](configuration.md#first-screen-ktor-server)).
  - `call.request.local.remoteHost` is an IP literal: the engine makes no reverse DNS lookup.
  - The engine cannot be a CONNECT proxy for TCP tunnels; it can be a CONNECT-UDP proxy for HTTP/3
    ([CONNECT-UDP over HTTP/3](server.md#connect-udp-over-http3-experimental)).
