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
