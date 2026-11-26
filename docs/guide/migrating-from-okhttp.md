<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Migrating from OkHttp and Retrofit

**What this page is for.** Moving an Android or JVM app that calls OkHttp directly, or through Retrofit, to the Ktor
client with the Kuicksilver engine: what replaces each OkHttp setting, pinning, timeouts, interceptors, and what is
different. Coming from Ktor's own OkHttp engine (`HttpClient(OkHttp)`) is only an engine swap: [Migrating from another
Ktor engine](migrating-ktor-engines.md).

**Before you start**

- Kuicksilver is an engine for the **Ktor client**, not a transport for OkHttp. There is no adapter in either direction:
  OkHttp cannot send its calls through Kuicksilver, and Kuicksilver does not implement OkHttp's `Call.Factory`,
  `Interceptor` or `EventListener`. Moving means moving your calls to `HttpClient`. Code that keeps an `OkHttpClient`
  keeps working as before, without HTTP/3, so both can live in one app while you move it piece by piece. An OkHttp and
  Retrofit bridge is planned for 0.4.0 ([Retrofit](#retrofit)).
- Dependencies as in the [Quickstart](quickstart.md#1-add-the-dependencies) (the client engine and Ktor 3.6.x). The
  Ktor plugins below (`HttpTimeout`, `HttpRequestRetry`, `HttpCookies`, `HttpCache`) are in `ktor-client-core`.
- Every Kuicksilver block on this page compiles with no opt-in (stable API only). `currentPin`, `backupPin` and `token()` stand
  for your own values: the pins of your server's keys (made as in [Certificate pinning](#certificate-pinning)) and your
  access token.

## The same client, side by side

An OkHttp client as many apps build it:

<!-- guide-sync: not compiled (OkHttp code, for comparison) -->
```kotlin
val client = OkHttpClient.Builder()
    .connectTimeout(10, TimeUnit.SECONDS)
    .readTimeout(15, TimeUnit.SECONDS)
    .writeTimeout(15, TimeUnit.SECONDS)
    .callTimeout(60, TimeUnit.SECONDS)
    .certificatePinner(CertificatePinner.Builder().add("api.example.com", currentPin, backupPin).build())
    .connectionPool(ConnectionPool(5, 5, TimeUnit.MINUTES))
    .cookieJar(cookieJar)
    .cache(Cache(cacheDir, 10L * 1024 * 1024))
    .addInterceptor { chain ->
        chain.proceed(chain.request().newBuilder().header("Authorization", "Bearer ${token()}").build())
    }
    .build()
```

The same with Kuicksilver. The imports:

```kotlin
// guide:okhttp:imports
import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpRequestRetry
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.cache.HttpCache
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.kuicksilver.ktor.client.Kuicksilver
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
```

```kotlin
// guide:okhttp:client
val client = HttpClient(Kuicksilver) {
    engine {
        connectTimeout = 10.seconds   // connectTimeout
        socketTimeout = 15.seconds    // readTimeout and writeTimeout: time without progress
        tls {
            pins { add("api.example.com", currentPin, backupPin) }   // certificatePinner: same patterns, same "sha256/..." text
        }
        pool {
            maxIdleConnectionsPerRoute = 5   // connectionPool(ConnectionPool(5, 5, MINUTES))
            idleTimeout = 5.minutes
        }
    }
    install(HttpTimeout) {
        requestTimeoutMillis = 60_000   // callTimeout
    }
    install(HttpRequestRetry) {   // your own retries: GET only, a POST is never sent twice
        retryOnExceptionIf(maxRetries = 2) { request, _ -> request.method == HttpMethod.Get }
    }
    install(HttpCookies)   // cookieJar
    install(HttpCache)     // cache, in memory
    install(createClientPlugin("BearerHeader") {
        // addInterceptor: an application interceptor that sets a header
        onRequest { request, _ -> request.headers[HttpHeaders.Authorization] = "Bearer ${token()}" }
    })
}
```

A call is a `suspend` function instead of `execute()` or `enqueue()`; cancel it by cancelling its coroutine:

```kotlin
// guide:okhttp:call
val body = client.get("https://api.example.com/users/42").bodyAsText()   // a non-2xx status does not throw
```

As with OkHttp, a 404 or 500 is a response, not an exception; `expectSuccess = true` in the `HttpClient { }` block makes
Ktor throw for them. Create the client once and share it, as with OkHttp.

## Setting by setting

| OkHttp | Kuicksilver and Ktor | Notes |
|---|---|---|
| `connectTimeout` | `HttpTimeout`'s `connectTimeoutMillis`, else `engine { connectTimeout }` | `HttpTimeout`'s wins when set; covers DNS, the pool wait, TCP and TLS or the QUIC handshake; 10 s by default, as OkHttp's |
| `readTimeout`, `writeTimeout` | `engine { socketTimeout }`, or `HttpTimeout`'s `socketTimeoutMillis`, which wins | one inactivity timeout for both directions, 10 s by default, as OkHttp's; `null` for none; not applied to WebSocket sessions and SSE by default ([Timeouts](client.md#timeouts)) |
| `callTimeout` | `HttpTimeout`'s `requestTimeoutMillis`, or `withTimeout { }` around the call | `requestTimeoutMillis` holds for each request sent (a redirect or a retry starts it again); OkHttp's covers the whole call, as `withTimeout` does |
| `connectionSpecs` (TLS versions, suites) | `engine { tls { versions; cipherSuites } }` | TLS 1.2 and 1.3 by default, as OkHttp's; TLS 1.2 only with ECDHE key exchange and AEAD suites (OkHttp's default also takes some CBC suites); `versions = TlsVersions.Tls13` for TLS 1.3 only (the default is `TlsVersions.Tls12And13`); HTTP/3 is always TLS 1.3 |
| `certificatePinner` | `tls { pins { add("api.example.com", pin1, pin2) } }` | the same patterns (`*.`, `**.`) and `sha256/<base64>` text, per host; see [Certificate pinning](#certificate-pinning) for the differences |
| `sslSocketFactory` with your own `X509TrustManager` | `tls { trust = TrustConfig.fromPemFile(caPath) }` (or `fromPem(caPem)`); on the JVM `TrustConfig.fromTrustManager(trustManager)` | a private CA, which replaces the platform's roots; [Your own CA](engine-tls.md#your-own-ca), and [TLS: Trust](tls.md#trust) for every variant |
| `sslSocketFactory` with a `KeyManager` (a client certificate) | `tls { identity = TlsIdentity.fromPem(…) }`; on the JVM `TlsIdentity.fromKeyStore` or `fromPkcs12` | [Mutual TLS](engine-tls.md#mutual-tls-client-certificates) |
| `hostnameVerifier` | none | the host name is always checked (RFC 9525); `TrustConfig.ExpectedName` checks another name |
| `connectionPool` | `engine { pool { } }` | the pool belongs to one `HttpClient`: two clients never share connections, where OkHttp clients made with `newBuilder()` share one pool; [Connection pool](client.md#connection-pool) compares the defaults |
| `dispatcher.maxRequests`, `maxRequestsPerHost` | `pool { maxConnections; maxConnectionsPerRoute }` | these limit connections, not requests; HTTP/2 and HTTP/3 carry many requests on one |
| `protocols(listOf(Protocol.HTTP_1_1))` | `engine { http2 { enabled = false }; http3 { enabled = false } }` | HTTP/2 and HTTP/3 are both on by default; `http2 { enabled = false }` alone still lets HTTP/3 in |
| `retryOnConnectionFailure` | built in | the engine repeats an idempotent request once when a pooled connection turns out closed; a request HTTP/3 failed goes over TCP when it cannot have reached the server, or when it is idempotent and its body can be sent again; anything else: `HttpRequestRetry`, whose `retryOnException` repeats every method, POST included |
| `followRedirects`, `followSslRedirects` | `followRedirects` in `HttpClient { }` (Ktor's `HttpRedirect`) | on by default; Ktor follows redirects of GET and HEAD only and never from `https` to `http`, where OkHttp turns a POST into a GET on 301, 302 and 303 |
| `addInterceptor` | a client plugin: `createClientPlugin` (`onRequest`, `onResponse`), or `plugin(HttpSend).intercept` to send again | Ktor's custom client plugins; give yours a name of its own (Ktor's `Auth` plugin exists) |
| `HttpLoggingInterceptor` | Ktor's `Logging` plugin (`ktor-client-logging`) | |
| `addNetworkInterceptor` | none | there is no hook between the engine and the wire; to observe, use the event listener (next row) |
| `eventListener` | `engine { observability { eventListener } }` (experimental) | `KuicksilverEventListener`: `callStart`, `callEnd`, `callFailed`, `dnsStart`, `dnsEnd`, `connectionAcquired` and more ([Observability](observability.md)) |
| `authenticator` (answers 401) | Ktor's `Auth` plugin (`ktor-client-auth`) | |
| `proxy`, `proxySelector` | Ktor's `proxy`; `engine { proxies { resolver } }` (experimental) | the system proxy settings are used by default; HTTP/3 never goes through an HTTP or SOCKS proxy, only through a CONNECT-UDP one ([Proxies](client-proxies.md#proxies)) |
| `proxyAuthenticator` | `engine { proxies { credentials } }` (experimental) | Basic credentials sent with the first request to the proxy; a 407 challenge is not answered, and Digest and NTLM are not supported |
| `dns` | `engine { network { dns } }` (experimental) | |
| `cookieJar` | `install(HttpCookies)` | in memory by default; your own `CookiesStorage` to keep them |
| `cache` | `install(HttpCache)` | in memory and without a size limit by default (OkHttp's `Cache` is on disk, with a maximum size); give it a storage of your own for anything large |
| `pingInterval` | `install(WebSockets) { pingIntervalMillis }` for WebSockets; `engine { http2 { pingInterval } }` for HTTP/2 connections | |
| `MockWebServer` in tests | Ktor's `MockEngine`, or a local Kuicksilver server | a `MockEngine` test does not run Kuicksilver |
| Android Network Security Config | honoured with the default trust | cleartext rules for `http://`; with `TrustConfig.Platform` (the default) its trust anchors and `<pin-set>` through the platform's `TrustManager` ([TLS: Platform trust](tls.md#platform-trust)); another trust, `AnchoredCa` say, does not read them |
| Android `minSdk` | 24 | the AAR brings its native library for three ABIs, its R8 rules (applied as consumer rules) and the `INTERNET` and `ACCESS_NETWORK_STATE` permissions (merged into your manifest) |
| app size | | OkHttp is pure Kotlin; Kuicksilver brings a native library with OpenSSL inside: under 3,550,000 bytes for arm64-v8a (the release gate's limit), one per ABI ([Install: Gradle](../install.md#gradle)) |

## Certificate pinning

The pins are the same text as OkHttp's: `sha256/` and the base64 SHA-256 of the server's public key (SPKI). From the
certificate file:

```sh
echo "sha256/$(openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64)"
```

`CertificatePinner.Builder().add(pattern, pins…)` is `tls { pins { add(pattern, pins…) } }`: the same patterns (a host,
`*.` for one label, `**.` for any number of labels), the same text, one match among the matching patterns' pins is
enough, and the pins hold for HTTP/3 and the TCP fallback alike. The differences:

- **The leaf's key by default.** OkHttp accepts a pin that matches any certificate of the chain; Kuicksilver matches the
  server's own certificate unless `scope = PinScope.AnyInValidatedChain` is set inside `pins { }`
  (`io.kuicksilver.tls.PinScope`), which gives OkHttp's behaviour (your intermediate CA's key, say).
- **`sha1/` pins are refused** when the client is built; use the `sha256/` pin of the same key (OkHttp's failure message
  lists both).
- **A request to `api.example.com.`** (with the trailing dot) is pinned as `api.example.com`; OkHttp would not pin it.
- **Connection coalescing** (`pool { coalescing }`, off by default) shares a connection only between hosts with the same
  pins.

The chain is still verified against `trust`, the pins come on top ([Certificate pinning](engine-tls.md#certificate-pinning)).
Pin a backup key you hold offline, or a key change locks the app out until it is updated. `TrustConfig.Pinned` pins
every host of a client instead; it cannot be combined with `pins { }`.

## What is different

- **HTTP/3.** The first request to a host goes over TCP (HTTP/2 or HTTP/1.1); once the server announced HTTP/3 with
  `Alt-Svc`, the next request races it against TCP, and the HTTP/3 connection serves the requests after that. `engine { http3 { hints } }` names your own API's hosts to use
  HTTP/3 from the first request ([configuration: first screen](configuration.md#first-screen-ktor-client)).
- **Timeouts.** 10 s to connect and 10 s without progress, as OkHttp's, and no call timeout. The socket timeout leaves
  WebSocket sessions, SSE and WebTransport alone by default; a long poll that waits longer sets its own per request
  ([Timeouts](client.md#timeouts)).
- **Name the engine.** `HttpClient()` without an argument picks the OkHttp, Android, Java, Apache or Jetty engine when
  one of them is on the class path. Write `HttpClient(Kuicksilver)`.
- **TLS.** TLS 1.2 and 1.3, as with OkHttp, but TLS 1.2 only with ECDHE and AEAD suites: a server that offers only CBC
  or RSA key exchange suites fails the handshake ([troubleshooting](troubleshooting.md#a-ktor-client-call-failed-over-which-transport)).
- **Ktor's version.** Kuicksilver needs Ktor 3.6.x ([Install: Supported Ktor versions](../install.md#supported-ktor-versions)).

## Retrofit

Retrofit builds its calls on OkHttp, and Kuicksilver cannot be put under it today. A bridge that serves an
`OkHttpClient`'s calls (and so Retrofit's) through Kuicksilver, `kuicksilver-okhttp`, is planned for 0.4.0; its shape is
not final. Until then, three ways to go:

1. **Keep Retrofit on OkHttp.** Nothing changes and nothing breaks, and those calls get no HTTP/3. Move the calls that
   gain most (large downloads, calls on mobile networks) to a Ktor client first.
2. **Ktorfit**, a separate open-source project (not part of Kuicksilver, not tested by it): Retrofit-style annotated
   interfaces whose implementation is generated at compile time on top of a Ktor `HttpClient`, which can be
   `HttpClient(Kuicksilver)`. Your interfaces change little; check that the Ktorfit version you pick works with Ktor
   3.6.x.
3. **Plain Ktor calls.** Each interface method becomes a `suspend` function that calls the client; Retrofit's converters
   become Ktor's `ContentNegotiation` plugin (`ktor-client-content-negotiation` with `ktor-serialization-kotlinx-json`,
   say), `Call<T>` becomes a suspend call, `Response<T>` an `HttpResponse`.

Not supported in 0.3.0: a Retrofit `callFactory` backed by Kuicksilver. None exists, and writing one means implementing
OkHttp's `Call` on top of Ktor; we do not recommend it, and the 0.4.0 bridge is the planned way. Libraries that take an `OkHttpClient` (image loaders, SDKs)
keep their own OkHttp; some image loaders can fetch through a Ktor client instead (Coil 3, for one, documents a Ktor-based network fetcher; check its current documentation).
