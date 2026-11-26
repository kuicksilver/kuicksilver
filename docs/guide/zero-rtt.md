<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# 0-RTT

**What this page is for.** Everything an application needs to decide whether to turn on 0-RTT, turn it on in the Ktor
client and server engines, and check that it works. It is the one page about 0-RTT; the QUIC and HTTP/3 guides only
name their own switches ([Without Ktor](#without-ktor)).

**Before you start**

- 0-RTT is experimental (`@ExperimentalKuicksilverApi`): the code on this page needs
  `@file:OptIn(ExperimentalKuicksilverApi::class)` ([stability](../stability.md#stability-levels)). The design is in
  [ADR-0015](../adr/0015-0rtt-implementation.md).
- It exists only over HTTP/3 (QUIC). HTTP/2 and HTTP/1.1 over TCP never send or accept early data.

## What it buys and what it costs

A client that connected to a server before holds a session ticket from it. With 0-RTT, the next connection carries the
first requests in its first flight, one round trip earlier than a full handshake. Off by default on both sides.

The price is **replay**: an attacker who recorded the client's first flight can send it to the server again (RFC 9846
section 8), and the server runs the early requests a second time. So the server decides which requests may run early,
and only requests that are safe to run twice may.

0-RTT gains nothing when:

- the server has not turned it on (without it, a Kuicksilver server issues no QUIC session tickets at all);
- the client has no ticket yet: tickets live in memory in the `HttpClient` and are used once, so after an app start
  (or with a new `HttpClient`) the first connection to each server is a full handshake, and 0-RTT starts from the next
  connection. Keep one `HttpClient` for the life of the process;
- the requests are not GET, HEAD or OPTIONS without a body: everything else waits for the handshake anyway;
- the server asks for client certificates (mutual TLS), which 0-RTT cannot carry;
- the server's configuration changed since the ticket was issued (ALPN, transport limits, HTTP/3 SETTINGS, its
  certificate): the next handshake is a full one.

## The client

```kotlin
// guide:zero-rtt:client
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val client = HttpClient(Kuicksilver) {
    engine { http3 { earlyData { enabled = true } } }
}
```

- On a new HTTP/3 connection to a server it has a ticket for, the engine sends GET, HEAD and OPTIONS requests without a
  body in 0-RTT; other requests wait for the handshake.
- A `425 Too Early` is retried once after the handshake; when the server rejects 0-RTT as a whole, the early requests
  are repeated once on the same connection after its handshake. Neither counts in the diagnostics' `attempts`.
- The fallback stays intact. A 0-RTT connection wins the race against TCP at once only on a network where QUIC was
  already seen working; elsewhere it must complete its handshake first, so a network that drops UDP loses nothing. The
  connect timeout bounds its handshake: a request sent early on a path that went dark fails then and goes over TCP. A
  request that waited for the handshake was never sent when the handshake fails, and goes over TCP like any other.
- Each ticket is checked against the current `tls { trust }` before use, and all of them are dropped when the client
  closes. Nothing is written to disk.

## The server

```kotlin
// guide:zero-rtt:server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
    http3 { earlyData { enabled = true } }
}) {
    routing {
        get("/") { call.respondText("early: ${call.request.receivedEarly}") }
    }
}
```

With `EngineMain`: `kuicksilver.http3.earlyData.enabled = true`. What happens to an early request depends on the
early-data policy, `http3 { earlyData { policy } }`:

- Requests the policy calls **replayable** (GET, HEAD and OPTIONS by default) run at once, before the handshake
  completes, and `call.request.receivedEarly` is true for them.
- Every other early request waits for the handshake under the default policy, `Http3EarlyDataPolicy.WaitForHandshake()`.
  A replayed copy never completes the handshake (the attacker lacks the key), so it never runs.
- `Http3EarlyDataPolicy.Reject425()` answers those with `425 Too Early` instead, without running the handler; the client
  repeats them after its handshake (RFC 8470 section 5.2). Replayable requests still run early under both policies.
- A server that asks for client certificates cannot accept 0-RTT: `earlyData { enabled = true }` with a
  `tls { clientAuth }` other than `None` fails the start.

### What must not run early

Turn 0-RTT on only when every request the policy calls replayable is safe to execute twice. Check the handlers of
GET, HEAD and OPTIONS (and of anything you add to `replayable`) for:

- state they change: counters, rate limits and quotas, "mark as read", a cart, a vote;
- one-time things a GET consumes: a sign-in or password-reset link, an e-mail confirmation, a download token, a nonce;
- actions behind a GET: sign-in or sign-out, sending a message or a push notification, starting a job, a payment;
- records that must be exact: billing or audit entries written per request.

An early request carries the same cookies and `Authorization` header as the original, so a replay is authorized too:
authentication does not make a state-changing request safe. Reads are fine. When some GETs change state, narrow the
policy instead of turning 0-RTT off, and check `receivedEarly` in handlers that cannot be moved:

```kotlin
// guide:zero-rtt:replayable
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val policy = Http3EarlyDataPolicy.WaitForHandshake(replayable = { request ->
    request.method == "GET" && request.path.orEmpty().startsWith("/static/")   // only these may run early
})
val narrowed = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
    http3 {
        earlyData {
            enabled = true
            this.policy = policy
        }
    }
}) {
    routing {
        get("/feed") {
            if (call.request.receivedEarly) { /* a replay is possible here: no side effects */ }
            call.respondText("feed")
        }
    }
}
```

### Behind a gateway

A CDN or reverse proxy that forwards a request it received in early data marks it `Early-Data: 1` (RFC 8470 section
5.1), and such a request may be a replay whatever the state of the connection it arrives on. This holds with or
without `earlyData { enabled }`: over HTTP/1.1 and HTTP/3 the engine sets `call.request.receivedEarly` for it and
answers `425 Too Early` to any such request the policy does not call replayable (over HTTP/1.1: anything but GET, HEAD
and OPTIONS), without running the handler; the gateway forwards the 425 and its client retries after its handshake.
Gate side effects on `receivedEarly`, not on the TLS state of your own connection.

### How the server limits replays

A replay can only repeat requests the policy runs early, and the server also limits how often and where:

1. **A short window.** A ticket's 0-RTT is accepted only while the ticket's age by the server's clock lies within
   [claimed − 1 s, claimed + 9 s] of the age the client claims (OpenSSL's fixed window, 10 s wide; RFC 9846 section 8.3),
   so a recorded flight is useless at most 10 s after the original.
2. **Once per ticket, per process.** A process-wide replay register remembers every ticket whose 0-RTT it accepted,
   for at least 20 seconds (longer than the window), and refuses that ticket's 0-RTT a second time. Every listener and
   every `http3 { endpoint { loops } }` loop of the process shares it. When it is full (it uses at most 1 MiB), 0-RTT is
   refused and the handshake goes on in 1-RTT: it fails closed.
3. **The configuration that issued the ticket.** A ticket allows 0-RTT only for the same ALPN, transport parameters and
   HTTP/3 SETTINGS, and only under the certificate it was issued with, so after a [certificate
   reload](ktor.md#certificate-rotation) old tickets resume nothing.
4. **The handshake.** A replayed flight never completes the handshake, so what waits for it, or got a 425, never runs
   from a replay.

**Several processes.** The register is per process. Session ticket keys are generated per process by default, so a
ticket issued by one instance resumes nothing on another (the client just runs a full handshake there), and a replay
sent to another instance gets no 0-RTT. With ticket keys shared between processes (`SessionTicketConfig.keys` in a
`TlsConfig` of the QUIC API; the Ktor server engine always uses the keys its process generated), or a server restarted
within the 10-second window with the same keys, a replayed flight can be accepted once per process: a replayable
request may then run once more on each. Keep that in mind before calling a request replayable on a multi-instance
deployment ([threat model 3.8](../spec/threat-model.md#38-0-rtt-and-replay)).

## Check that it works

On the client, a connection listener hears the outcome of every connection that tried 0-RTT:

```kotlin
// guide:zero-rtt:client-check
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
observability {
    connectionListener = object : ConnectionListener {
        override fun onZeroRtt(connection: ConnectionInfo, outcome: ZeroRttOutcome) {
            println("0-RTT to ${connection.remoteAddress}: $outcome")   // Accepted or Rejected
        }
    }
}
```

(inside `engine { }`, next to `http3 { earlyData { } }`; the imports are `io.kuicksilver.quic.ConnectionListener`,
`ConnectionInfo` and `ZeroRttOutcome`). No call means 0-RTT was not tried: the client had no ticket yet, or the server
issues none. On the server, `call.request.receivedEarly` is true for a request that ran before the handshake completed.
When it never happens, or is rejected: [troubleshooting: 0-RTT is rejected](troubleshooting.md#0-rtt-is-rejected).

## Without Ktor

The same feature under the names of the lower layers; the rules above (replay, what must not run early, the server's
limits) are the same:

| Layer | Client | Server | Guide |
|---|---|---|---|
| Ktor engines | `engine { http3 { earlyData { enabled = true } } }` | `http3 { earlyData { enabled = true; policy } }` | this page |
| HTTP/3 API | `Http3Endpoint.connectEarly`, a request with `allowEarlyData = true` | `quicServerConfig(tls) { acceptEarlyData = true }`, `Http3Settings.earlyData` (the policy) | [HTTP/3: 0-RTT](http3.md#0-rtt-opt-in-experimental) |
| QUIC API | `quicClientConfig(tls) { earlyData = EarlyDataState.Allowed }`, `QuicEndpoint.connectEarly` | `quicServerConfig(tls) { acceptEarlyData = true }` | [QUIC: 0-RTT](quic.md#0-rtt-opt-in-experimental) |
