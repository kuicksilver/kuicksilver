# Ktor internals the engines depend on

This is the list of the Ktor 3.6.0 APIs the engines use although Ktor marks them internal or does not
publish them, kept because each is a compatibility risk on a Ktor upgrade. Re-check every entry when the Ktor version moves,
then move `KtorVersionPolicy.SUPPORTED` (`kuicksilver-ktor-network`), the major.minor the engines check at startup
(docs/guide/ktor.md, "Supported Ktor versions").

## Server engine (`kuicksilver-ktor-server`)

| What | Where | Why | Risk |
|---|---|---|---|
| `EnginePipeline.Call`, `handleFailure`, `mdcProvider` | `ktor-server-core`, public | `h1/H1CallPhase.kt` runs the application for HTTP/1.1 calls in a phase before Ktor's default one and follows it (failure logging and status through `handleFailure`, the MDC block, no answer to a `ChannelIOException`), so that a request body that timed out is answered 408 per call and an unread body is left to the pipeline's 256 KiB cap instead of Ktor's unbounded discard | Ktor's default phase gaining behaviour this one then lacks: compare `defaultEnginePipeline` on Ktor upgrades |
| `startServerConnectionPipeline` | `ktor-server-cio`, `io.ktor.server.cio.backend`, `@InternalAPI` | vendored as `h1/ServerPipeline.kt` (keep-alive, pipelining and upgrades over our TLS channels) with a deadline (408) and a 64 KiB size limit (431) per request head, request framing per RFC 9112 section 6 (Content-Length with Transfer-Encoding refused with 400 and close, no framing means no body, chunked trailers accepted — `h1/ChunkedBody.kt`, vendored from `ktor-http-cio`'s `decodeChunked`) and its own connection and request scope types (`ServerRequestScope`'s constructor is internal); `ktor-server-cio` is no longer a dependency | upstream fixes must be merged by hand on Ktor upgrades |
| `parseRequest`, `Request`, `ConnectionOptions`, `expectHttpUpgrade`, `RequestResponseBuilder` | `ktor-http-cio`, public | the HTTP/1.1 request parser and response writer (a conscious compromise: reusing the parser beats maintaining our own) | low |
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
| `ByteReadChannel.readBuffer` | `ktor-io`, `@InternalAPI` member of a public interface | `SocketTimeoutChannel` wraps a body channel to put the socket timeout on every wait for data and delegates reads to the wrapped buffer; the server's `h1/HeadLimitedInput` implements the interface over its own buffer to cap each request head at 64 KiB before Ktor's parser sees it | the `ByteReadChannel` interface changing shape |

## Both engines (`kuicksilver-ktor-network`)

| What | Where | Why | Risk |
|---|---|---|---|
| `Selectable`, `InterestSuspensionsMap`, `SelectorManager.select` on a selectable of our own | `ktor-network` (JVM), public but meant for Ktor's own sockets | `engineSelector()` keeps a pipe registered on the engines' `SelectorManager` so it never goes idle: an idle `ActorSelectorManager` never deregisters the key of a closed socket and NIO then never closes its descriptor (reported to Ktor as [KTOR-10016](https://youtrack.jetbrains.com/issue/KTOR-10016)) | relies on `ActorSelectorManager` selecting while an interest is pending and resuming suspensions with an error when it closes; `EngineSelectorTest` checks the effect, and the workaround goes once Ktor is fixed |

The vendored engine contract tests (`src/jvmTest/.../contract` of both engine modules, `NOTICE`) are re-vendored from
the same Ktor tag on every upgrade; their exclusions are listed in `docs/guide/ktor.md`, "Compatibility".
