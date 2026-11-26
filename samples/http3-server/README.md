<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# http3-server

An HTTP/3 Ktor server in about twenty lines: [`Main.kt`](src/main/kotlin/io/kuicksilver/sample/http3/Main.kt) is a
plain Ktor module and `main` hands over to Kuicksilver's `EngineMain`; everything else is
[`application.conf`](src/main/resources/application.conf). Like `samples/realtime-telemetry`, it is a separate Gradle
build that depends on `io.kuicksilver:*` by coordinates (the composite build in `settings.gradle.kts` substitutes this
repository's modules; with published artifacts you would drop `includeBuild`), and it verifies every dependency against
the repository's `gradle/verification-metadata.xml`. It is not published.

One port, every protocol a client may speak:

- **HTTP/3 on UDP** and **HTTP/2 and HTTP/1.1 over TLS on TCP**, with the same number (`kuicksilver.http2 = true`
  offers `h2` before `http/1.1` in ALPN, so an old client still gets HTTP/1.1);
- **Alt-Svc**: every TCP response says `Alt-Svc: h3=":8443"; ma=86400` (and an ALTSVC frame on HTTP/2), so browsers,
  curl and the Kuicksilver client move to HTTP/3 for their next requests;
- **TLS from PEM files**, reloaded when they are renewed (`reloadInterval = 1h`): certbot's `fullchain.pem` and
  `privkey.pem` as they are;
- **the PROXY protocol** (HAProxy's, v1 and v2) behind an L4 proxy, switched on by one environment variable.

The module reports which protocol carried the request and who sent it:
`Hello over HTTP/3 from 192.0.2.7`.

| File | What it shows |
|---|---|
| `src/main/kotlin/.../Main.kt` | `EngineMain.main(args)` and a Ktor module that knows nothing of the protocols |
| `src/main/resources/application.conf` | the `kuicksilver.*` keys: TLS files, `http2`, `altSvc`, `proxyProtocol.trustedSources`, each with an environment variable |
| `src/test/kotlin/.../Http3ServerTest.kt` | `EngineMain` with this `application.conf`, and Kuicksilver's Ktor client against it |
| `certs/gen.sh` | a development CA and certificate in `build/dev-certs`; `--test` regenerates `TestCerts.kt` |

## Run it

From the repository root (`certs/gen.sh` needs an OpenSSL 3 or 4 CLI; `OPENSSL=...` picks one):

```sh
samples/http3-server/certs/gen.sh                  # build/dev-certs: ca.pem, chain.pem, key.pem for localhost (30 days)
./gradlew -p samples/http3-server run              # https://localhost:8443, TCP and UDP
```

With a curl built with HTTP/3 (`curl -V` lists `HTTP3`):

```sh
CA=samples/http3-server/build/dev-certs/ca.pem
curl --cacert $CA -si https://localhost:8443/                 # HTTP/2 over TCP; note the alt-svc header
curl --cacert $CA --http3 https://localhost:8443/             # HTTP/3, falling back to TCP if UDP does not get through
curl --cacert $CA --http3-only https://localhost:8443/        # HTTP/3 or nothing: tells a blocked UDP path apart
curl --cacert $CA --http1.1 https://localhost:8443/           # an old client: HTTP/1.1 on the same port
```

`Hello over HTTP/3 from ::1` (or `127.0.0.1`) is the answer to look for. A browser goes the same way, HTTP/2 first and
HTTP/3 from a later request, once it trusts the certificate (with the development CA: import `ca.pem`, or start it
with a flag that accepts it; do not do either with a CA you did not make yourself).

## Configuration

Every key of `application.conf` takes an environment variable, so a container or a systemd unit configures the server
without a rebuild; any other key of the [`EngineMain` table](../../docs/guide/ktor.md#enginemain-and-configuration-keys)
can be added there, or passed as `-P:<key>=<value>`.

| Variable | Key | Default |
|---|---|---|
| `PORT` | `ktor.deployment.port` | `8443`, TCP and UDP |
| `TLS_CHAIN`, `TLS_KEY` | `kuicksilver.tls.certificateChain`, `privateKey` | `build/dev-certs/chain.pem`, `key.pem` (an unencrypted PKCS#8 key) |
| `ALT_SVC` | `kuicksilver.altSvc` | `true` |
| `PROXY_TRUSTED_SOURCES` | `kuicksilver.proxyProtocol.trustedSources` | unset: no PROXY protocol |

## Deploying it

The [deployment guide](../../docs/guide/deployment.md) has the details; for this server:

- **Open both `8443/tcp` and `8443/udp`** (or whatever `PORT` is) in every firewall, security group, `docker run -p` and
  Kubernetes Service on the way. `Alt-Svc` names the port the server bound: map the same number outside and inside,
  or clients try the wrong one ([Ports and Alt-Svc](../../docs/guide/deployment.md#ports-and-alt-svc)).
- **Certificates**: `TLS_CHAIN=/etc/letsencrypt/live/<name>/fullchain.pem TLS_KEY=/etc/letsencrypt/live/<name>/privkey.pem`;
  renewals are picked up within the hour.
- **Behind HAProxy or nginx, PROXY protocol on.** As an L4 proxy (HAProxy `mode tcp` with `send-proxy-v2` on the
  server line; nginx `stream` with `proxy_protocol on;`) the proxy passes TLS through and sends the client's address
  first. Start the server with `PROXY_TRUSTED_SOURCES=<the proxies' addresses>` (a comma-separated list of addresses
  and CIDR blocks): only they may connect over TCP, every connection must start with the header (HAProxy's health
  checks too: give the server line `check check-send-proxy`, or the checks are reset and the server marked down), and
  `call.request.origin.remoteAddress` is the client. The header is TCP only; HTTP/3 reports its UDP peer. Unless the
  proxy also forwards UDP on the same port number (nginx `stream` with `listen 8443 udp`, which then sends from its
  own address), set `ALT_SVC=false`: otherwise `Alt-Svc` points clients at a UDP port nobody serves
  ([PROXY protocol](../../docs/guide/ktor.md#proxy-protocol)).
- **Behind an L7 proxy that terminates TLS and HTTP/3 itself** (nginx `http`, a CDN), the server only ever sees that
  proxy's TCP requests: set `ALT_SVC=false`, and the proxy's own HTTP/3 serves the clients
  ([What can sit in front of the server](../../docs/guide/deployment.md#what-can-sit-in-front-of-the-server)).
- **Check it from outside** with the three commands of [Checking a deployment](../../docs/guide/deployment.md#checking-a-deployment).

## Tests

From the repository root:

```sh
./gradlew --max-workers=2 -p samples/http3-server test
```

`Http3ServerTest` starts the server with this `application.conf` (only the TLS files and a free port of 127.0.0.1 are
passed as `-P:` arguments), then: Kuicksilver's client in `Auto` mode gets HTTP/2 with `Alt-Svc`, then HTTP/3; in
`H3Only` mode HTTP/3 at once; without HTTP/2 and HTTP/3, HTTP/1.1 on the same port. With `trustedSources` set, a TCP
connection that starts with a PROXY v1 header for 203.0.113.7 (the JDK's TLS client after it) gets
`Hello over HTTP/1.1 from 203.0.113.7`, one without a header is refused, and HTTP/3 still answers.

The certificates in `TestCerts.kt` are public test material, and the development pair of `certs/gen.sh` is for your
machine only.
