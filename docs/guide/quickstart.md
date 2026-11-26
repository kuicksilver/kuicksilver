<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Quickstart

**What this page is for.** A first HTTP/3 server with the Ktor server engine and a first HTTP/3 request with the Ktor
client engine, on your machine: the dependencies, a local test certificate, the server, the client, and what each does
without configuring anything. Every Kotlin block on this page compiles with no opt-in (stable API only).

## 1. Add the dependencies

You need Kotlin 2.3 or newer (Kotlin/Native: 2.4.x), JVM 17 or newer (Android: `minSdk` 24; iOS 15) and Ktor 3.6.x:
another Ktor version fails when the engine is created ([Install: Supported Ktor
versions](../install.md#supported-ktor-versions)).

**0.3.0 is the release in preparation and not published yet.** A release candidate, 0.3.0-rc1, will be on Maven
Central first. Until then the block below does not resolve: build the library from a checkout and depend on
`0.3.0-SNAPSHOT` with `mavenLocal()`, which needs Docker (and Xcode on macOS) even for a JVM application
([Install: Versions](../install.md#versions) has the commands).

<!-- guide-sync: not compiled (a Gradle build script) -->
```kotlin
// build.gradle.kts
dependencies {
    implementation(platform("io.kuicksilver:kuicksilver-bom:0.3.0"))
    implementation(platform("io.ktor:ktor-bom:3.6.1"))
    implementation("io.kuicksilver:kuicksilver-ktor-client") // the client engine
    implementation("io.kuicksilver:kuicksilver-ktor-server") // the server engine
    implementation("io.ktor:ktor-server-core")
}
```

Android, Kotlin Multiplatform with iOS and Kotlin/Native setups: [Install: Gradle](../install.md#gradle).

## 2. A server

The server needs a certificate chain and its private key as PEM files. To try it locally, make a test CA and a
certificate for `localhost` with an OpenSSL 3 command line (on macOS `/usr/bin/openssl` is LibreSSL, which lacks
`-copy_extensions`: use Homebrew's `openssl`):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 30 \
  -subj "/CN=Local test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout privkey.pem -out server.csr \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" -addext "extendedKeyUsage=serverAuth"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -days 30 -copy_extensions copy -out fullchain.pem
```

**The key must be unencrypted PKCS#8**: its file starts with `-----BEGIN PRIVATE KEY-----`, as the commands above write
it. A key that starts with `BEGIN EC PRIVATE KEY` or `BEGIN RSA PRIVATE KEY` fails the start with `TlsException.Config`
("expected exactly one PKCS#8 PRIVATE KEY block"); convert it once with
`openssl pkcs8 -topk8 -nocrypt -in key.pem -out privkey.pem`.

The imports of this page's server code, then the server:

```kotlin
// guide:quickstart:server-imports
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.server.Kuicksilver
```

```kotlin
// guide:quickstart:server
fun main() {
    embeddedServer(Kuicksilver, configure = {
        tls { pemFiles("fullchain.pem", "privkey.pem") } // the key: unencrypted PKCS#8, "BEGIN PRIVATE KEY"
        tlsConnector { port = 8443 } // TCP 8443: HTTP/2 and HTTP/1.1; UDP 8443: HTTP/3
    }) {
        routing {
            get("/") { call.respondText("Hello over ${call.request.httpVersion}\n") }
        }
    }.start(wait = true)
}
```

Check it with curl (`--http3-only` needs a curl built with HTTP/3: `curl --version` lists `HTTP3`):

```sh
curl --cacert ca.pem -i https://localhost:8443/              # Hello over HTTP/2, and alt-svc: h3=":8443"; ma=86400
curl --cacert ca.pem --http3-only https://localhost:8443/    # Hello over HTTP/3
```

Without configuring anything, the server speaks HTTP/2 and HTTP/1.1 on TCP and HTTP/3 on UDP of the same port, announces
HTTP/3 with `Alt-Svc`, allows TLS 1.3 only (TLS 1.2 for old clients: `tls { versions }`), logs through Ktor's application
log, and keeps 0-RTT and WebTransport off. A `tlsConnector` without a `host` listens on every interface, IPv6 and IPv4;
Ktor's own `embeddedServer(..., port = ...)` connector listens on IPv4 `0.0.0.0` only.

**On a real host**, certbot's `fullchain.pem` and `privkey.pem` take the place of the test files, with port 443:

- Open the port for **both TCP and UDP** in the firewall and the cloud security group: with UDP closed, clients
  quietly stay on HTTP/2.
- Port 443 needs root, or the capability to bind it: run the server as its own user with `CAP_NET_BIND_SERVICE`
  (systemd: `AmbientCapabilities=CAP_NET_BIND_SERVICE`).
- certbot's `privkey.pem` is readable by root only. Give the server's user read access (a group with read access to
  `/etc/letsencrypt/live` and `/etc/letsencrypt/archive`, or an ACL), or copy the files where it can read them from a
  certbot deploy hook; `tls { reloadInterval }` picks up each renewal.

More in [Deploying the HTTP/3 server](deployment.md) (Docker, Kubernetes, load balancers) and, for the same server from
`application.conf`, [Configuration file (EngineMain)](server-config-file.md).

## 3. A client

The imports of this page's client code:

```kotlin
// guide:quickstart:client-imports
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.seconds
```

The client below talks to the server of step 2, which surely announces HTTP/3, and trusts the test CA:

```kotlin
// guide:quickstart:client
suspend fun main() {
    val client = HttpClient(Kuicksilver) { // name the engine: HttpClient() alone may pick another one
        engine { tls { trust = TrustConfig.fromPemFile("ca.pem") } }
    }
    repeat(3) {
        println(client.get("https://localhost:8443/").version) // HTTP/2.0, then HTTP/3.0 from about the third request
        delay(1.seconds)
    }
    client.close()
}
```

- **Name the engine.** `HttpClient()` without an argument takes the engine Ktor finds first, and the OkHttp, Android, Java,
  Apache and Jetty engines come before Kuicksilver on the JVM and Android. In an app that already has `ktor-client-okhttp`,
  it is OkHttp that answers, silently ([troubleshooting](troubleshooting.md#httpclient-uses-another-engine)).
- **HTTP/3 starts after the first request.** The first request to a host goes over TCP, and its response announces
  HTTP/3 in an `Alt-Svc` header field. The second request races HTTP/3 against the TCP connection that is already open,
  and TCP usually wins that one; from about the third request on, the HTTP/3 connection serves the requests. Your own API
  can skip the TCP-only start with `engine { http3 { hints = setOf(HostPort("api.example.com", 443)) } }` (`HostPort` is
  `io.kuicksilver.ktor.client.HostPort`; [configuration: first screen](configuration.md#first-screen-ktor-client)).
- **A public host.** Drop the `engine { }` block, which trusts only the test CA: the client then trusts the platform's
  store. If every response stays `HTTP/2.0`, the host does not announce HTTP/3 or UDP does not get through:
  [troubleshooting](troubleshooting.md#the-ktor-client-never-uses-http3-or-stops-using-it) tells which.
- **Keep one client.** Create the `HttpClient` once and share it: it holds the connections, what it learned from `Alt-Svc`
  and the TLS session tickets.

Without configuring anything, the client falls back to TCP when HTTP/3 fails, speaks HTTP/2 or HTTP/1.1 over TCP, offers
TLS 1.2 and 1.3 with the platform's trust store (TLS 1.2 with ECDHE key exchange and AEAD ciphers only; TLS 1.3 only is
`tls { versions = TlsVersions.Tls13 }`), tries IPv6 and IPv4 addresses (Happy Eyeballs), logs warnings and up through the platform's
logger (SLF4J on the JVM, standard error when no SLF4J binding is on the class path; Logcat on Android; `NSLog` on
Apple platforms),
and keeps 0-RTT and connection migration off.

## Next steps

- The options most applications set, one table per engine: [configuration: first screen](configuration.md#first-screen),
  and which setting controls what: [Which setting controls what](configuration.md#which-setting-controls-what).
- The client in an app: timeouts, a private CA, Android and iOS: [Ktor client engine](client.md); pins and client
  certificates: [TLS in the Ktor engines](engine-tls.md).
- Coming from OkHttp or Retrofit: [Migrating from OkHttp and Retrofit](migrating-from-okhttp.md); from another Ktor engine:
  [Migrating from another Ktor engine](migrating-ktor-engines.md).
- Words such as origin, alternative and route: the [glossary](glossary.md).
