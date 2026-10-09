# Ktor internals the engines depend on

This is the list of the Ktor 3.6.0 APIs the engines use although Ktor marks them internal or does not
publish them, kept because each is a compatibility risk on a Ktor upgrade. Re-check every entry when the Ktor version moves.

## Server engine (`kuicksilver-ktor-server`)

| What | Where | Why | Risk |
|---|---|---|---|
| `startServerConnectionPipeline(ServerIncomingConnection, timeout, handler)` | `ktor-server-cio`, `io.ktor.server.cio.backend`, `@InternalAPI` | HTTP/1.1 parsing, keep-alive, pipelining and upgrades over our TLS channels (a conscious compromise: reusing it beats maintaining our own HTTP/1.1 server parser) | signature or semantics change in a minor release |
| `ServerIncomingConnection`, `ServerRequestScope` | same, `@InternalAPI` | the connection and per-request scope the pipeline works with | same |
| `CIOApplicationCall`, `CIOApplicationRequest`, `CIOApplicationResponse` | `ktor-server-cio`, `internal` | vendored as `h1/H1Call.kt`, `H1Request.kt`, `H1Response.kt` (Apache-2.0, JetBrains copyright kept) with the TLS scheme, peer certificates and `Alt-Svc` added | fixes upstream do not reach us automatically: diff them on every Ktor upgrade |
| `BaseApplicationCall.putResponseAttribute()` | `ktor-server-core`, `protected` | wiring the response into the call, as CIO does | low |
| `encodeParameters(Parameters)` | `ktor-server-core`, `io.ktor.server.request`, `@InternalAPI` | query parameters of HTTP/3 requests decoded exactly as the CIO request does (`?auto` gives `""`; found by the vendored `ContentTestSuite`) | renamed or moved |

Not used: `HttpRequestCloseHandlerKey` (Ktor's request-close hook needs an internal field of `ServerRequestScope`), so
the `HttpRequestLifecycle` plugin's close notification does not fire over HTTP/1.1 with this engine.

## Client engine (`kuicksilver-ktor-client`)

| What | Where | Why | Risk |
|---|---|---|---|
| `writeHeaders`, `writeBody`, `readResponse`, `startTunnel` of `utils.kt` | `ktor-client-cio`, `internal` | vendored as `h1/H1Exchange.kt` (keep-alive release hook added, Unix sockets removed) | upstream fixes must be merged by hand on Ktor upgrades |
| `WEBSOCKETS_KEY` | `ktor-client-core`, `@InternalAPI` | the WebSocket plugin's channel configuration for the session of a 101 | renamed or moved |
| `ResponseAdapterAttributeKey`, `ResponseAdapter` | `ktor-client-core`, `@InternalAPI` | SSE bodies (the plugin installs an adapter the engine must call) | without it SSE does not work |
| `engines.append(...)` with `@EagerInitialization` | `ktor-client-core` (Native), `@InternalAPI` | engine registration for `HttpClient()` on Kotlin/Native | API change breaks default-engine lookup on Native only |
| `HttpClientEngineBase`, `callContext()` | `ktor-client-core`, public | the engine base class, as every Ktor engine | low |
| `ByteReadChannel.readBuffer` | `ktor-io`, `@InternalAPI` member of a public interface | `SocketTimeoutChannel` wraps a body channel to put the socket timeout on every wait for data and delegates reads to the wrapped buffer | the `ByteReadChannel` interface changing shape |

The vendored engine contract tests (`src/jvmTest/.../contract` of both engine modules, `NOTICE`) are re-vendored from
the same Ktor tag on every upgrade; their exclusions are listed in `docs/guide/ktor.md`, "Compatibility".
