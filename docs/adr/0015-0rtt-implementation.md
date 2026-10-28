# ADR-0015. 0-RTT implementation (0.2.0)

Date: 2026-10-13. Status: accepted. Supersedes ADR-0008 for 0.2.0; implements ADR-0013 together with its
["Review 2026-10, implemented in 0.2.0"](0013-0rtt-anti-replay-design.md#review-2026-10-implemented-in-020) section (the owner moved 0-RTT from the next minor into 0.2.0 on 2026-10-12).

## Context

ADR-0013 designed anti-replay for 0-RTT in three layers: freshness, single use within a window, and idempotency
decided by the application. Its review (2026-10) checked the design against OpenSSL 3.5, quic-go, quiche and ngtcp2 and
moved two layers: freshness is OpenSSL's own ticket-age check, and the replay register is per server and keyed by the
ticket. Before this ADR, QUIC connections did not resume at all. A QUIC server context had no ticket keys, the client
had no ticket cache, and incoming 0-RTT packets were dropped. So 0-RTT needs QUIC session resumption first.

Facts of the pinned OpenSSL 3.5.9 that fix the design:

- `SSL_set_quic_tls_early_data_enabled(ssl, 1)` must be called before the handshake starts. On a server it sets
  `max_early_data = 0xffffffff`, the only value QUIC allows (RFC 9001 §4.6.1). Every ticket the connection issues then
  carries `early_data`. On a client it fails unless the resumed session's ticket allowed early data.
- With `max_early_data > 0` and without `SSL_OP_NO_ANTI_REPLAY`, OpenSSL switches to stateful single-use tickets in its
  server session cache. ksl keeps that cache off and creates an `SSL_CTX` per QUIC session, so this mode would reject
  every early data. ksl therefore sets `SSL_OP_NO_ANTI_REPLAY`, as the ngtcp2 examples do.
- With stateless tickets, OpenSSL accepts early data only for the first PSK identity, only when the ticket has not
  expired, and only when the client's `obfuscated_ticket_age` lies within `TICKET_AGE_ALLOWANCE` (10 s) of the
  server's age. This is RFC 9846 §8.3 freshness.
- `SSL_CTX_set_allow_early_data_cb` makes the final decision, and `SSL_CTX_set_session_ticket_cb` can store app data
  in a ticket and read it back when the ticket is decrypted. Neither callback may call back into Kotlin (ksl contract:
  no upcalls). Any per-connection verdict must therefore be stored in the `ksl_ssl` before the ClientHello is
  processed.

## Decision

### ksl (ABI 6)

- `KSL_OPT_EARLY_DATA` (server context): each QUIC session enables early data at creation. The context sets
  `SSL_OP_NO_ANTI_REPLAY` and installs the allow-early-data callback. (0.2.0: every server context installs the ticket
  app-data callbacks, since every ticket carries its QUIC version.)
- `KSL_SET_EARLY_CONTEXT` (server session): bytes that are written into every ticket the session issues and compared
  with the app data of the ticket being resumed. A mismatch rejects early data but keeps the resumption. (0.2.0: the app
  data starts with the negotiated QUIC version of the issuing connection; a ticket whose version is not the client's
  original version is not resumed at all, RFC 9369 section 5. The client checks the same with the version it keeps
  in the ticket's `remembered` blob, and sends 0-RTT in its original version across a compatible upgrade, RFC 9369
  section 4.1.)
- `KSL_SET_EARLY_DATA`: on a client, `[1]` requests 0-RTT with the resumed session (`KSL_E_NOT_SUPPORTED` when the
  ticket does not allow it). On a server, `[1]` is the transport's verdict for this ClientHello (the replay register
  admitted it). Without it the callback rejects.
- `KSL_GET_EARLY_DATA`: one byte, 0 none, 1 rejected, 2 accepted (`SSL_get_early_data_status`).
- The 0-RTT secret arrives as `KSL_EV_KEY` at the reserved level 1, as ADR-0013 planned: write on the client, read on
  the server.

### Anti-replay (server only)

1. **Freshness:** OpenSSL's ±10 s ticket-age check. ADR-0013's `maxEarlyDataAge` knob is dropped. The allowance is a
   compile-time constant in OpenSSL, and the client's claimed age is not exposed to a callback, so a narrower window
   would need an OpenSSL patch, which was rejected.
2. **Replay register:** there is one `ZeroRttReplayRegister` per process (`ProcessReplayRegister`), shared by every
   server endpoint, `LoopGroup` loop and configuration, and kept across endpoint restarts. Its scope is the ticket key:
   any endpoint of the process holding a key decrypts every ticket issued under it. The generated keys are process-wide,
   one `Http3Endpoint.bind` or Ktor connector builds its own `QuicServerConfig`, equal `SessionTicketConfig.keys` may sit
   in several configurations, and a rotated key set keeps the previous key. A register per endpoint or per configuration
   therefore let a replay to a second listener of the same process through (the 0-RTT security review), and a register
   per key-set instance would too (equal keys in two instances, a key shared by the old and the new set). The register's
   key begins with the ticket's key name, so one register per process is exactly one register per ticket key. It runs on
   the process's monotonic clock, not a loop's. It is keyed by SipHash-64 (random key per register) of the first PSK identity's
   `key_name ‖ iv`, the first 32 bytes of our stateless ticket. These bytes identify one issued ticket exactly. The
   register reads them from the ClientHello itself, because the server must decide before ksl processes the hello:
   `KslQuicTlsSession` scans the complete ClientHello for `early_data` and `pre_shared_key`, which is about 60 lines
   of bounded parsing over CRYPTO data that ksl reads anyway. The register has 64 lock-striped buckets, each holding
   two rotating halves of 1024 64-bit fingerprints. A half spans 20 s, which is more than the 10 s allowance plus
   slack. The register uses at most 1 MiB. A full half fails closed: early data is rejected and the handshake goes
   on in 1-RTT. The scan runs before OpenSSL decrypts the ticket, so `admit` only reserves the identity (two concurrent
   hellos with one ticket: the second finds the reservation and gets no early data). The reservation stays only if TLS
   accepts the early data: OpenSSL 3.5 calls the allow-early-data callback in `final_early_data` only after the ticket
   decrypted, the binder verified and the age passed, and `SSL_get_early_data_status` records the verdict. Any other
   outcome (forged identity, bad binder, stale age, context mismatch, a session closed before the decision) releases the
   reservation within the same `ksl` call. A released slot leaves the load count at once (live entries and tombstones are
   counted apart; tombstones are compacted away), so forged hellos never fill the register: only tickets this process
   issued and a client completed a resumption with take room. A false positive only downgrades to 1-RTT.
   OpenSSL judges freshness by the wall clock (a hello passes when the server's ticket age lies in [claimed − 1 s,
   claimed + 9 s], so a replay is fresh at most 10 s of wall time after the original), while the register forgets after
   at least 20 s of monotonic time. A backward wall-clock step could make a forgotten hello fresh again, so each stripe
   tracks the wall-minus-monotonic offset it saw: when it falls by more than 5 s (smaller steps cannot reopen a replay),
   the stripe refuses early data until the wall clock passes its latest admission plus 20 s, then takes the new offset.
3. **Configuration binding (RFC 9000 §7.4.1, RFC 9001 §4.6.3, RFC 9114 §7.2.4.2):** the early context is SHA-256 of
   the ALPN list, the server's §7.4.1 transport parameters (initial windows, stream limits, `active_connection_id_limit`,
   `max_datagram_frame_size`, idle timeout, `max_udp_payload_size`, `disable_active_migration`) and the application
   blob (`Http3Endpoint` passes its encoded SETTINGS). We require equality instead of quic-go's "not lower" comparison
   (decided: equality is simpler and stricter). Any configuration change only costs one 1-RTT handshake, and C does not have to parse transport
   parameters.
4. **Idempotency:** the application decides (layer 3, below).

Residue (threat model): the register is per process per ticket key. Ticket keys shared between processes
(`SessionTicketConfig.keys`) let a replay into another process (or into a restarted one, within the freshness window)
pass the freshness check only. The HTTP/3 server's default policy still never runs an unsafe early request on
a connection whose handshake does not complete. A replayer cannot complete the handshake because it lacks the PSK.

### Resumption and tickets

- A QUIC server issues tickets only when `QuicServerConfig.earlyData` is on. They are two per handshake, as the review
  asks (`KSL_OPT_NUM_TICKETS` 2), and use the same process-wide rotating keys (or `SessionTicketConfig.keys`) and the
  same session context as TCP, prefixed `quic|`. Early data with client authentication is a configuration error in
  0.2.0.
- A QUIC client resumes only when `QuicClientConfig.earlyData` is not `Disabled`. Tickets live in the endpoint's own
  `SessionCache`, which is per engine (shared by all loops of a `LoopGroup`, since `connect` picks loops round-robin)
  and cleared on close. The cache key is the same as for TCP plus the ALPN list,
  and tickets are taken for single use. Before a cached ticket is used, the cached chain is verified again with the
  current trust (the TCP path does the same after the handshake). Each entry keeps the server's encoded transport
  parameters (RFC 9000 §7.4.1). The client does not store HTTP/3 SETTINGS: RFC 9114 §7.2.4.2 lets it use the defaults,
  which our encoder already complies with (no dynamic table).

### Transport

- Client: the remembered parameters (except those §7.4.1 forbids) set the stream and connection send limits before
  the handshake. Stream data, stream control frames and PING go in 0-RTT long-header packets of the Application space
  until 1-RTT keys exist. ACK, CRYPTO, NEW_TOKEN, HANDSHAKE_DONE, connection-ID and path frames never do. The 0-RTT
  write key is discarded when the 1-RTT write key is installed (RFC 9001 §4.9.3).
- Acceptance (`EncryptedExtensions` with `early_data`): new server values below the remembered ones close the
  connection with PROTOCOL_VIOLATION, as quic-go's client does.
- Rejection: 0-RTT packets leave the bytes in flight without a congestion signal. If the ALPN did not change and the
  new limits cover what was already sent, their stream frames are queued again and travel in 1-RTT, and the server's
  new limits (connection and per-stream credit, stream counts) replace the remembered ones even where they are lower
  (RFC 9000 section 7.4.1); this is the one place a send limit may shrink. The stream state
  stays because the server never saw those streams (RFC 9001 §4.6.2 retransmission, as msquic does). Otherwise the
  connection closes with `ZeroRttRejected`. `EarlyDataState.Required` also turns a rejection into `ZeroRttRejected`.
  Superseded in 0.2.1: RFC 9001 §4.6.2 says the client "MUST reset the state of all streams", so a rejection of 0-RTT
  that carried anything always closes the connection with `ZeroRttRejected`, and the Ktor client repeats the requests
  once on a new connection without 0-RTT.
- Server: 0-RTT packets that arrive before their keys are buffered with the other undecryptable packets. They are
  dropped when the handshake shows that 0-RTT was rejected. 0-RTT packets for a connection that does not exist yet
  wait at the endpoint (quic-go's bounds: 100 ms, 32 connection IDs, 31 packets each) for the Initial that creates it.
  0-RTT read keys are discarded 3 × PTO after the first 1-RTT packet (RFC 9001 §4.9.3). Streams that any STREAM frame
  reached in a 0-RTT packet are flagged `receivedEarly`.

### API (all `@ExperimentalKuicksilverApi`)

```kotlin
enum class EarlyDataState { Disabled, Allowed, Required }        // kuicksilver-tls; entries added
QuicTlsSession.enableEarlyData(context: ByteArray?, admission: EarlyDataAdmission?): Boolean
QuicTlsSession.earlyDataAccepted: Boolean?                       // replaces `earlyData`
QuicClientConfig.Builder.earlyData: EarlyDataState = Disabled
QuicServerConfig.Builder.earlyData: Boolean = false;  .earlyDataContext: ByteArray?
QuicEndpoint.connectEarly(remote, config): QuicConnection       // returns at 0-RTT keys, or at completion when no 0-RTT
QuicConnection.earlyDataAccepted: Boolean?;  suspend fun awaitHandshake()
QuicStream.receivedEarly: Boolean
QuicException.ConnectionLost.ZeroRttRejected
Http3Endpoint.connectEarly(...);  Http3Request.allowEarlyData = false   // safe methods only
Http3Settings.earlyData: Http3EarlyDataPolicy = WaitForHandshake()       // | Reject425(); `replayable` predicate, default safe methods
Http3ServerRequest.receivedEarly: Boolean
```

A server endpoint with `earlyData` hands a connection to `accept()` as soon as its 0-RTT is accepted, before the
handshake completes, so the application can answer in 0.5-RTT. A handler must call `awaitHandshake()` before acting
on non-replayable input. HTTP/3 does this for it: by default, a request on a `receivedEarly` stream runs at once only
when `replayable` (default GET, HEAD, OPTIONS). Any other request waits for the handshake, or is answered with 425 under
`Reject425`. An HTTP/3 client sends a request early only when `allowEarlyData` is set and the method is safe. Every
other request waits for the handshake. On 425 the client retries once after the handshake (RFC 8470 §5.2). The Ktor
engines are opt-in: client `earlyData`, server `quicEarlyData`. 0-RTT is never on by default.

## Consequences

- Resumption and 0-RTT are one opt-in. With every option at its default, nothing changes on the wire.
- ADR-0013's planned tests become `negative_0rttReplayRejected`, `negative_0rttTransportParamsReduced`,
  `zeroRttRejectedClosesTheConnection`, `clientTicketIsSingleUse` and the HTTP/3 cases
  (`negative_unsafeMethodNotProcessedInEarlyData`, `reject425PolicyAndOneRetry`).
- The interop `zerortt` and `resumption` cases are required and green against all six peers in both roles (0.2.0),
  except quinn's client against our server in `zerortt` (`tools/interop/required.json`).

## Alternatives rejected

- Keying the register by the ClientHello random: it catches an exact replay but not a second hello that reuses the
  ticket, which the ticket identity does catch.
- A pause in ksl at the ClientHello (`KSL_WANT_EARLY`): the decision would sit closer to OpenSSL, but the pause would
  touch the drive loop shared with TCP. The bounded Kotlin scan needs no C state machine.
- Transparent replay at the HTTP/3 layer only: the transport already holds the unacknowledged bytes, and keeping
  retransmission there matches RFC 9001 §4.6.2 and msquic.
