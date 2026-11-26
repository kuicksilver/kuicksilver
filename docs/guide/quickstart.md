<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Quickstart

**What this page is for.** The shortest path to a first HTTP/3 request with the Ktor client engine and a first HTTP/3
server with the Ktor server engine: the dependencies, one client, one server with a local test certificate, and what
you get without configuring anything. Every Kotlin block on this page compiles with no opt-in (stable API only).

## 1. Add the dependencies

Kuicksilver needs Ktor 3.6.x (another Ktor version fails when the engine is created: [Install: Supported Ktor
versions](../install.md#supported-ktor-versions)), JVM 17 or newer, Android `minSdk` 24 or iOS 15.

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

0.3.0 is the release in preparation and is not on Maven Central yet: [Install: Versions](../install.md#versions) says
how to build it and which version to use until then. Android, Kotlin Multiplatform with iOS and Kotlin/Native setups:
[Install: Gradle](../install.md#gradle).

## 2. A client

The imports of this page's client code:

```kotlin
// guide:quickstart:client-imports
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.delay
import java.io.File
import kotlin.time.Duration.Companion.seconds
```

```kotlin
// guide:quickstart:client
suspend fun main() {
    val client = HttpClient(Kuicksilver) // name the engine: HttpClient() alone may pick another one
    repeat(3) {
        val response = client.get("https://example.com/")
        println(response.version) // HTTP/2.0 (or HTTP/1.1) first; HTTP/3.0 once the server announced it
        delay(1.seconds)
    }
    client.close()
}
```

- **Name the engine.** `HttpClient()` without an argument takes the engine Ktor finds first, and the OkHttp and Android
  engines come before Kuicksilver on the JVM and Android. In an app that already has `ktor-client-okhttp`, it is OkHttp
  that answers, silently ([troubleshooting](troubleshooting.md#httpclient-uses-another-engine)).
- **The first request to a host goes over TCP.** The server announces HTTP/3 in an `Alt-Svc` header field of that
  response. The next request races HTTP/3 against the TCP connection already open, which usually wins this once; from
  then on the client's HTTP/3 connection to the host serves the requests. Your own API can skip the TCP-only start:
  `engine { http3 { hints = setOf(HostPort("api.example.com", 443)) } }` ([configuration: first
  screen](configuration.md#first-screen-ktor-client)).
- **Keep one client.** Create the `HttpClient` once and share it: it holds the connections, what it learned from `Alt-Svc`
  and the TLS session tickets.

## 3. A server

The server needs a certificate chain and its private key as PEM files. On a real host they are usually certbot's
`fullchain.pem` and `privkey.pem`. To try it locally, make a test CA and a certificate for `localhost` with an OpenSSL 3
command line (on macOS `/usr/bin/openssl` is LibreSSL, which lacks `-copy_extensions`: use Homebrew's `openssl`):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 30 \
  -subj "/CN=Local test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout privkey.pem -out server.csr \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" -addext "extendedKeyUsage=serverAuth"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -days 30 -copy_extensions copy -out fullchain.pem
```

**The key must be unencrypted PKCS#8**: its file starts with `-----BEGIN PRIVATE KEY-----`, as the commands above write
it. A key that starts with `BEGIN EC PRIVATE KEY` or `BEGIN RSA PRIVATE KEY` fails the start with `TlsException.Config`
("expected exactly one PKCS#8 PRIVATE KEY block"); convert it once:

```sh
openssl pkcs8 -topk8 -nocrypt -in key.pem -out privkey.pem
```

The imports of this page's server code:

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

or with the client from step 2, trusting the test CA instead of the platform's store:

```kotlin
// guide:quickstart:local-client
val client = HttpClient(Kuicksilver) {
    engine { tls { trust = TrustConfig.AnchoredCa(Certificate.parsePem(File("ca.pem").readText())) } }
}
```

On a server, open the port for **both TCP and UDP** in the firewall and the cloud security group: with UDP closed,
clients quietly stay on HTTP/2 ([Deploying the HTTP/3 server](deployment.md)). The same server from an
`application.conf` with `EngineMain`: [Ktor: Minimal example](ktor.md#minimal-example).

## What you get by default

- **HTTP/3 with a fallback.** The client starts on TCP, moves to HTTP/3 after `Alt-Svc`, and goes back to TCP when HTTP/3
  fails (UDP blocked, a handshake timeout); the server announces HTTP/3 on its HTTP/2 and HTTP/1.1 responses.
- **HTTP/2 on both sides**, chosen in the TLS handshake (ALPN), and HTTP/1.1 for peers without it.
- **TLS 1.3 and the platform's trust store** on the client; TLS 1.3 only on the server (TLS 1.2: `tls { versions }`).
- **Dual stack.** The server listens on every interface, IPv6 and IPv4; the client tries both address families
  (Happy Eyeballs).
- **Logging** through the platform's logger on the client (SLF4J on the JVM, Logcat on Android, `NSLog` on Apple
  platforms), warnings and up, and through Ktor's application log on the server.
- **Off until you opt in:** 0-RTT, connection migration on the client, WebTransport.

## Next steps

- The options most applications set, one table per engine: [configuration: first screen](configuration.md#first-screen).
- The client in an app: trust and pins, timeouts, Android and iOS: [Ktor: Client](client.md).
- A request that should use HTTP/3 and does not:
  [troubleshooting](troubleshooting.md#the-ktor-client-never-uses-http3-or-stops-using-it).
- Putting the server on the internet (ports, Docker, Kubernetes, load balancers): [Deploying the HTTP/3
  server](deployment.md).
- Coming from OkHttp or Retrofit: [Migrating from OkHttp and Retrofit](migrating-from-okhttp.md); from another Ktor engine:
  [Migrating from another Ktor engine](migrating-ktor-engines.md).
- 0-RTT, and whether it is safe for your requests: [0-RTT](zero-rtt.md).
