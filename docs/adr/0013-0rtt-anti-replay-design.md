# ADR-0013. Anti-replay design for 0-RTT

Date: 2026-10-08. Status: **proposed** — a design only; nothing in this ADR is implemented in v1, where 0-RTT stays disabled (ADR-0008). Implementation is planned after v1 (owner decision 2026-10-08: designed now, implemented after v1).

## Context

ADR-0008: 0-RTT is disabled in v1 — `early_data` is not enabled, incoming 0-RTT packets are dropped, `EarlyDataState.Disabled`. The design requires that a later version can enable 0-RTT without breaking the API, and that the application itself decides which requests may be replayed. Replay is the only property of 0-RTT that the transport cannot hide from the application: an on-path attacker replays the client's first flight, and the server executes the early data twice (RFC 8446 §8, RFC 9001 §9.2). References: quic-go and quinn accept 0-RTT by default and leave protection to the application; rustls and Go limit tickets by time; OpenSSL 3.5 offers `SSL_set_quic_tls_early_data_enabled` and, in the TLS layer, an acceptance window with a ticket age check (`SSL_CTX_set_recv_max_early_data`, RFC 8446 §8.2 "freshness"), but keeps no state across processes.

## Decision

Protection in three layers, all on the server; the client only marks what may be replayed.

1. **Ticket freshness** (RFC 8446 §8.3) is checked by `ksl` when it receives a ClientHello with `early_data`: `ticket_age` is compared with the issue time (the ticket keys already live in `ksl`), the window is `maxEarlyDataAge` (10 s by default, as for the Retry token). Too old — reject the early data but continue the handshake (`early_data` is not sent in EncryptedExtensions). Not a single new function in `ksl.h` for K3: the flag goes into `ksl_ctx_set_option` (`KSL_OPT_EARLY_DATA_MAX_AGE`), the early secret into the existing `KSL_EV_KEY` events with a new level `KSL_LEVEL_EARLY` (levels are 0–3 today; level 1 — 0-RTT — is already reserved in `ksl_quic_provide`/`KslEvent`).
2. **Single use within the window** (RFC 8446 §8.2 "single-use tickets" in a soft form): `EndpointCore` keeps a window of accepted ClientHellos keyed by `(hash(ticket nonce), time)` — a ring sized `maxEarlyDataAge × expected rate`, by default 65 536 entries in a Bloom filter with two rotating halves (as in RFC 8446 §8.2 and Go `crypto/tls`): a repeated ClientHello with the same ticket inside the window → the early data is rejected. The filter is per endpoint loop (like the Retry and reset keys, ADR-0003); with `loops > 1` a client replayed into another loop passes only the freshness check — an accepted residue that the application closes with idempotency (item 3). Memory, within the per-connection resource ceilings (threat-model 3.2): ≤ 1 MiB per loop.
3. **Idempotency decided by the application**: the client marks requests `EarlyDataState.Allowed` only for what is safe to replay; a `QuicStream`/HTTP/3 request gets a `sentEarly` flag; the server exposes `receivedEarly` on the stream to the application, and the HTTP/3 layer answers `425 Too Early` to everything the application has not declared idempotent (RFC 8470), as quic-go/nghttp3 do.

What is rejected and how: early data rejected by the server is retransmitted by the client itself in 1-RTT (RFC 9001 §4.6.2); the application sees `QuicException.ZeroRttRejected` only if it asked for `EarlyDataState.Required`; a rejected 0-RTT packet is silently dropped by the server (as in v1), 0-RTT keys are not installed.

## API consequences that must not be broken later

- `EarlyDataState` stays a closed enumeration `Disabled | Allowed | Required` (only `Disabled` is available in v1); `QuicClientConfig.Builder.earlyData`, `QuicConfig.maxEarlyDataAge` and `QuicException.ZeroRttRejected` are already declared or reserved (the configuration and error model).
- `ConnectionEvent.HandshakeCompleted` keeps the meaning "1-RTT keys are available"; early data arrives before it through the same `StreamReadable`, with the stream flag `receivedEarly` — a new field, not a new event.
- `TransportParameters` in v1 already keeps the `early_data`-dependent parameters separate from the "remembered" ones (RFC 9000 §7.4.1), so enabling 0-RTT does not change the codec.
- TLS tickets are issued by `ksl` (`ksl_ssl_new_session_ticket`); their format and keys do not change.

## Tests that will be needed

`negative_zeroRttReplay` (the same ClientHello with early data twice within the window → the second is rejected, the application sees one request), `negative_zeroRttAcrossRestart` (after a server restart, tickets of the old process give no 0-RTT: the ticket key is random per process), `negative_zeroRttStaleTicket` (`ticket_age` older than the window → 1-RTT only), `zeroRttRejectedRetransmitsIn1Rtt` (the client retransmits the data itself), `earlyDataLoopsFallBackToFreshness` (a second endpoint loop accepts a replay only within freshness — the documented residue), the interop case `zerortt` against quic-go/ngtcp2/quinn.

## Open questions

Whether a filter shared between loops is needed (threading model, docs/architecture.md): to be decided from measurements after v1. Encoding `425` in HTTP/3 — together with K5.

## Review 2026-10 for a later minor

Reviewed against RFC 9001 §4.6 and §9.2, RFC 8446 §8, RFC 8470, RFC 9000 §7.4.1, RFC 9114 §7.2.4.2 and §10.9, the
OpenSSL 3.5 sources we pin (`ssl/statem/extensions_srvr.c`, `SSL_read_early_data(3)`), and the current quic-go, quiche
and ngtcp2 trees. Verdict: the three-layer shape stands, and 0-RTT is a good headline for the next minor; layers 1 and
2 move, and the API sketch below replaces the "already declared or reserved" claim, which was not true: only
`EarlyDataState.Disabled` exists today.

### What the references do

- **quic-go** accepts 0-RTT only with `Config.Allow0RTT` on an `EarlyListener`. The server gates on two things: the
  transport parameters remembered in the ticket must not exceed the current ones (`ValidFor0RTT`, RFC 9000 §7.4.1), and
  `http3` stores its SETTINGS in the ticket and clears `EarlyData` when they are no longer compatible
  (`settings_0rtt.go`, RFC 9114 §7.2.4.2). It has no replay register of its own: Go `crypto/tls` checks ticket age only.
  It buffers 0-RTT packets that arrive before their Initial: 100 ms, 32 connections, 31 packets each. The HTTP/3 client
  sends a request in 0-RTT only for the opt-in methods `GET_0RTT`/`HEAD_0RTT`. Every other request waits for the
  handshake. The server does not send 425 and leaves replay to the handler.
- **quiche** turns early data on in BoringSSL and passes a constant early-data context (`"quiche"`, with a TODO to put
  the transport parameters and SETTINGS there). It has no server-side anti-replay or 425, so the application has to
  handle replay.
- **ngtcp2** examples pass the encoded transport parameters as BoringSSL's early-data context. With OpenSSL they set
  `SSL_OP_NO_ANTI_REPLAY`, and with GnuTLS they install an anti-replay database whose add callback is a no-op.
  `ngtcp2_conn_tls_early_data_rejected` drops the 0-RTT state, and the client retransmits.
- **OpenSSL 3.5**: (a) It checks freshness on its own. With a ticket that is not expired and whose
  `obfuscated_ticket_age` is within `TICKET_AGE_ALLOWANCE` (10 s, a compile-time constant) of the server's age,
  `early_data_ok` is set. (b) When `max_early_data > 0`, which `SSL_set_quic_tls_early_data_enabled` implies, its
  built-in anti-replay makes tickets stateful and single-use through the internal server session cache. ksl turns that
  cache off (`SSL_SESS_CACHE_OFF`), creates an `SSL_CTX` per QUIC session (`KslQuicCrypto.newSession`), and encrypts
  stateless tickets with keys supplied from Kotlin. So the built-in mode would reject every early data.

### What stands

- Anti-replay is only enforced on the server. The application decides idempotency (layer 3), and HTTP/3 maps that
  decision to RFC 8470.
- The closed set `Disabled | Allowed | Required`, `receivedEarly` as a stream flag rather than a new event, and
  `HandshakeCompleted` still meaning "1-RTT keys".
- Rejected early data is retransmitted by our transport in 1-RTT (RFC 9001 §4.6.2), and `ZeroRttRejected` is raised
  only for `Required`.
- The transport-parameter codec does not change. The early-data key arrives as a `KSL_EV_KEY` at the reserved level 1.
- All the tests listed above. Add `negative_zeroRttTransportParamsShrunk` and `negative_zeroRttH3SettingsChanged`.

### What changes

1. **Freshness (layer 1) uses OpenSSL's check.** Drop `KSL_OPT_EARLY_DATA_MAX_AGE` as a new knob: OpenSSL already
   enforces ±10 s on the ticket age and the session timeout. ksl installs `SSL_CTX_set_allow_early_data_cb`. That
   callback (i) can only narrow the window to `maxEarlyDataAge` (`SSL_SESSION_get_time`), (ii) checks the remembered
   transport parameters and the ALPN-level blob, and (iii) asks the replay register (item 2). ksl sets
   `SSL_OP_NO_ANTI_REPLAY`, as ngtcp2 does, because the built-in mode needs the server cache that ksl keeps off.
2. **The replay register is per server, not per loop, and is keyed by the ticket's identity.** Our tickets are stateless
   and each carries a fresh random IV (`ticket_cb`). The pair `(key_name, iv)` therefore identifies one issued ticket
   exactly and is available in the decrypt path. That is better than "hash(ticket nonce)", which the server cannot see
   before decryption. Store `SipHash(key_name‖iv)` in two rotating halves of a time-bucketed set (RFC 8446 §8.2), where
   one half spans `maxEarlyDataAge + 10 s` of allowance. A Bloom false positive only costs one round trip, because it
   only downgrades to 1-RTT. The register belongs to the `QuicServer` and is shared by all `LoopGroup` loops through a
   striped lock (one CAS per 0-RTT ClientHello). This closes the cross-loop residue of the original item 2 and replaces
   `earlyDataLoopsFallBackToFreshness` with `negative_zeroRttReplayAcrossLoops`. Cap: ≤ 1 MiB per server. Across
   processes or hosts, the ticket keys must be per process (the default random key), or the operator must accept the
   documented residue. A pluggable `ReplayRegister` interface is out of scope.
3. **Client tickets are single-use.** The per-engine `SessionCache` from F4.5 (LRU, 256) takes a ticket out when it is
   used for 0-RTT (RFC 8446 §C.4) instead of reading it. The server issues two tickets per handshake
   (`ksl_ssl_new_session_ticket` ×2 after the pin verdict) so the next connection still has one. The cache entry gains
   the remembered transport parameters and the opaque application blob (HTTP/3 SETTINGS), and it is keyed by
   (server name, port, ALPN, `TlsConfig` trust fingerprint). Because the cache is per engine, a fresh engine starts with
   1-RTT. That is the intended privacy boundary, and the guide documents it.
4. **The context binds the configuration.** Like the ngtcp2 examples, the server stores its encoded transport
   parameters plus the HTTP/3 SETTINGS in the ticket's app data. It rejects 0-RTT when any remembered limit exceeds the
   current one (the `ValidFor0RTT` rule, RFC 9000 §7.4.1) or when SETTINGS are incompatible (RFC 9114 §7.2.4.2).
5. **HTTP/3 gating.** The client sends a request in 0-RTT only when its method is safe (GET, HEAD, OPTIONS) and the
   caller opts in per request. A request that is idempotent but unsafe (PUT, DELETE) is never sent early by default. On
   the server, a request that arrives on an early stream with an unsafe method, or with a safe method the application
   did not declare replayable, waits until the handshake is confirmed by default (RFC 8470 §5.1 allows this). With
   `earlyData = Reject425` it gets `425 Too Early` instead. A client that receives 425 retries once after the handshake
   (RFC 8470 §5.2). The Ktor engines expose `receivedEarly` on the call and never forward `Early-Data: 1` themselves
   (we are an origin, not an intermediary).
6. **Packet handling.** 0-RTT packets that arrive before their Initial are buffered per destination CID, bounded as in
   quic-go (100 ms, 32 CIDs, 31 packets), and count toward the amplification limit until the address is validated
   (RFC 9000 §8.1). After a Retry the client keeps sending 0-RTT, and the server accepts it only for the retried
   connection.

### API surface sketch (all `@ExperimentalKuicksilverApi`)

```kotlin
enum class EarlyDataState { Disabled, Allowed, Required }            // entries added; document `else ->` in when-expressions
QuicClientConfig.Builder.earlyData(state: EarlyDataState)
QuicServerConfig.Builder.earlyData(enabled: Boolean, maxAge: Duration = 10.seconds)  // maxAge ≤ 10 s (OpenSSL allowance)
QuicStream.receivedEarly: Boolean;  QuicConnection.earlyDataAccepted: Boolean?      // null until known
class QuicException.ZeroRttRejected : QuicException
Http3RequestOptions.allowEarlyData: Boolean                          // client, per request, safe methods only
Http3ServerConfig.earlyData: EarlyDataPolicy                         // WaitForHandshake (default) | Reject425 | Accept(predicate)
```

### Test plan

- **Unit (sans-IO):** the register's rotation, cap and false-positive bound; the `ValidFor0RTT` table.
- **`MemoryNetwork` and the simulator:** `negative_zeroRttReplay`, `negative_zeroRttReplayAcrossLoops`,
  `negative_zeroRttStaleTicket` (virtual time 11 s), `negative_zeroRttAcrossRestart`,
  `negative_zeroRttTransportParamsShrunk`, `zeroRttRejectedRetransmitsIn1Rtt`, `zeroRttBeforeInitialIsBuffered`,
  `clientTicketIsSingleUse`.
- **HTTP/3:** `negative_unsafeMethodEarlyWaitsForHandshake`, `reject425PolicyAnd425Retry`,
  `negative_h3SettingsChangedRejects0Rtt`.
- **C (`tools/c-test.sh`):** the early-data callback and `SSL_OP_NO_ANTI_REPLAY`.
- **Interop:** `zerortt` against quic-go, ngtcp2, quinn and quiche, as a required cell.

### Size

About 14 tasks, one minor's main item:

- ksl, 3 tasks: early-data enable, callback and option, key level 1, ABI bump.
- tls, 2 tasks: session cache entry and single-use take; ticket app data.
- quic core, 4 tasks: 0-RTT packet space send/receive; rejection and retransmit; pre-Initial buffer; register.
- runtime and config, 2 tasks.
- HTTP/3 and Ktor, 2 tasks.
- Interop and docs, 1 task.
