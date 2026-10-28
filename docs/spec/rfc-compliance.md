# Kuicksilver — RFC compliance

Date: 2026-10-02; as of 0.2.1 (2026-10-21); split into this summary and one details file per RFC on 2026-10-28. Status: living document, updated with each change it describes.

0.2.0 is the first release (TLS, QUIC v1/v2, HTTP/3, the Ktor engines and the 0.2.0 work). One row per requirement or topic:

- **Status**: ✅ met · 🔶 feature subset (what is left is in the details, under "Open items") · ⬜ planned (see [the roadmap](../roadmap.md)) · ❌ not planned (the reason is in the details).
- **Since**: the release from which the current behaviour holds; for ⬜ the release it is planned for, or — when it is not scheduled; for ❌ —. Earlier behaviour is in the details ("History") and in [CHANGELOG.md](../../CHANGELOG.md).
- **Summary**: one sentence; the tests that pin a row are in its details.
- **Details**: the row's section in `docs/spec/rfc/<rfc>.md`: the requirement, how it is met (files), the tests that pin it, history, notes on peers, open items.

Interop results (QUIC Interop Runner matrices, the analyses of red cells, WebTransport with browsers) are in [interop.md](interop.md). `tools/check/rfc-table.sh` checks the format of the tables below.

## QUIC

| RFC | Section / topic | Status | Since | Summary | Details |
|---|---|---|---|---|---|
| RFC 9000 | §5–§6 — versions, connections, Version Negotiation | ✅ | 0.2.0 | Client and server negotiate QUIC versions, including the compatible upgrade from v1 to v2. | [details](rfc/9000.md#s5-versions-connections-version-negotiation) |
| RFC 9000 | §7 — handshake, transport parameters | ✅ | 0.3.0 | The handshake exchanges and validates transport parameters, including `version_information`. | [details](rfc/9000.md#s7-handshake-transport-parameters) |
| RFC 9000 | §7.2 — the server's Source Connection ID is fixed by the first Initial | ✅ | 0.2.1 | The client adopts the SCID of the first Initial it takes and discards later long-header packets with another SCID. | [details](rfc/9000.md#s7-2-the-servers-source-connection-id-is) |
| RFC 9000 | §8 — address validation, Retry, amplification limit | ✅ | 0.3.0 | The server keeps the 3x amplification limit and sends Retry as its admission policy decides. | [details](rfc/9000.md#s8-address-validation-retry-amplification-limit) |
| RFC 9000 | §8.1.3, §8.1.4, §19.7 — NEW_TOKEN, server side | ✅ | 0.3.0 | Once the handshake is confirmed the server issues address-bound NEW_TOKEN tokens and admits their holders without a Retry. | [details](rfc/9000.md#s8-1-3-new-token-server-side) |
| RFC 9000 | §8.1.3, §17.2.5.3, §19.7 — NEW_TOKEN, client side | ✅ | 0.3.0 | An opt-in token store keeps NEW_TOKEN tokens per server name and presents each one once. | [details](rfc/9000.md#s8-1-3-new-token-client-side) |
| RFC 9000 | §8.1.2–§8.1.4, §17.2.5.3 — Retry tokens bind the Retry SCID | ✅ | 0.2.0 | A Retry token carries the Retry SCID, and an Initial with another DCID is refused with INVALID_TOKEN. | [details](rfc/9000.md#s8-1-2-retry-tokens-bind-the-retry-scid) |
| RFC 9000 | §5.2.2, §10.2.3 — refusing a connection the server cannot take | ✅ | 0.2.0 | With a full accept queue a new Initial is refused statelessly with CONNECTION_REFUSED. | [details](rfc/9000.md#s5-2-2-refusing-a-connection-the-server-cannot) |
| RFC 9000 | §21.7 — reassembly memory of a stream | ✅ | 0.2.1 | An internal limit bounds the gaps a stream may hold; a frame that would open one more is dropped unacknowledged. | [details](rfc/9000.md#s21-7-reassembly-memory-of-a-stream) |
| RFC 9000 | §9 — migration, PATH_CHALLENGE, passive and active | ✅ | 0.2.0 | Up to four paths with their own congestion state support passive migration, NAT rebinding and path validation. | [details](rfc/9000.md#s9-migration-path-challenge-passive-and-active) |
| RFC 9000 | §9.1, §9.4 — PATH_CHALLENGE outside the congestion window; congestion state on NAT rebind | ✅ | 0.2.0 | Probes of the active path go out with a full window, and a NAT rebind keeps the congestion state on the new path. | [details](rfc/9000.md#s9-1-path-challenge-outside-the-congestion-window) |
| RFC 9000 | §8.2.1, §8.2.4; RFC 9002 §6.2.1 — PATH_CHALLENGE repeats back off exponentially | ✅ | 0.2.0 | An unanswered PATH_CHALLENGE is repeated with exponential backoff until the validation timeout. | [details](rfc/9000.md#s8-2-1-path-challenge-repeats-back-off-exponentially) |
| RFC 9000 | §5.1 — CID format | ✅ | 0.2.0 | Every connection ID the server issues carries the server's format and routing byte. | [details](rfc/9000.md#s5-1-cid-format) |
| RFC 9000 | §9, §8.1 — rebind during the handshake | ✅ | 0.2.1 | A server still in the handshake follows a new client address, with the same restrictions as migration. | [details](rfc/9000.md#s9-rebind-during-the-handshake) |
| RFC 9000 | §9 (active) — client-initiated (active) migration | ✅ | 0.2.0 | The client can add, probe, switch and close paths, each on its own socket, after confirmation. | [details](rfc/9000.md#s9-client-initiated-active-migration) |
| RFC 9000 | §9.6, §18.2 — preferred address | ✅ | 0.3.0 | An experimental server option advertises preferred addresses and accepts the client's move to them. | [details](rfc/9000.md#s9-6-preferred-address) |
| RFC 9000 | §10 — closing, idle timeout, stateless reset | ✅ | 0.2.1 | Idle timeout, closing and draining follow §10, and stateless resets are generated and detected with HMAC tokens. | [details](rfc/9000.md#s10-closing-idle-timeout-stateless-reset) |
| RFC 9000 | §2–§4 — streams, states, flow control | ✅ | 0.2.0 | Stream states, reassembly, scheduling and connection and stream flow control follow §2–§4. | [details](rfc/9000.md#s2-streams-states-flow-control) |
| RFC 9000 | §5.1 — Connection ID: issuing, retiring, limit | ✅ | 0.2.0 | Connection IDs are issued up to the peer's limit, rotated every 10 000 packets and on a path change, and retired safely. | [details](rfc/9000.md#s5-1-connection-id-issuing-retiring-limit) |
| RFC 9000 | §5.1.1 — issuing spare CIDs promptly | ✅ | 0.2.0 | Each side issues its spare connection IDs as soon as it holds the peer's transport parameters. | [details](rfc/9000.md#s5-1-1-issuing-spare-cids-promptly) |
| RFC 9000 | §5.1.2, §19.15 — a lost NEW_CONNECTION_ID below our own retire_prior_to is not resent | ✅ | 0.2.0 | A lost NEW_CONNECTION_ID that the peer must retire anyway is dropped instead of retransmitted. | [details](rfc/9000.md#s5-1-2-a-lost-new-connection-id-below) |
| RFC 9000 | §12–§19 — packets and frames | ✅ | 0.2.1 | Every QUIC v1 packet and frame type is encoded and decoded as §12–§19 define. | [details](rfc/9000.md#s12-packets-and-frames) |
| RFC 9000 | §21.9 — peer denial of service | ✅ | 0.2.0 | A per-connection glitch bucket closes connections that make us do useless work on demand. | [details](rfc/9000.md#s21-9-peer-denial-of-service) |
| RFC 9000 | §14, RFC 8899 — DPLPMTUD, MTU 1200 minimum | ✅ | 0.3.0 | Each path searches its MTU from 1200 bytes with PADDING probes and reacts to Packet Too Big. | [details](rfc/9000.md#s14-dplpmtud-mtu-1200-minimum) |
| RFC 9000 | §13.4 — ECN | ✅ | 0.2.0 | Packets are marked ECT(0) per path once ECN validation succeeds, and CE marks count as congestion. | [details](rfc/9000.md#s13-4-ecn) |
| RFC 9000 | §13.4.1; RFC 9001 §4.1.4 — packets buffered for their keys keep their datagram | ✅ | 0.2.0 | A packet held until its keys arrive is processed with the address, ECN mark and length of its own datagram. | [details](rfc/9000.md#s13-4-1-packets-buffered-for-their-keys-keep) |
| RFC 9000 | §13.4.2, §13.4.2.1 — ECN validation ignores stale ACKs; counts per space, marks per path | ✅ | 0.2.0 | Only an ACK that raises the largest acknowledged packet validates ECN counts, kept per packet number space. | [details](rfc/9000.md#s13-4-2-ecn-validation-ignores-stale-acks-counts) |
| RFC 9000 | §21.6; RFC 9002 appendix A.7 — peer-chosen ACKs, MAX_DATA and stream counts cost no linear pass | ✅ | 0.2.0 | ACK processing and credit updates run in sublinear time whatever the peer sends. | [details](rfc/9000.md#s21-6-peer-chosen-acks-max-data-and) |
| RFC 9000 | §4.1, §4.6 — flow-control and stream-limit credit is signalled | ✅ | 0.2.0 | New stream data, connection data and stream-count credit wake the writer or opener that waited for it. | [details](rfc/9000.md#s4-1-flow-control-and-stream-limit-credit) |
| RFC 9000 | §4.1, §10.1, §13.3, §19.12–§19.14 — a blocked sender asks again, a receiver answers a stale report | ✅ | 0.2.0 | Blocked frames are repeated while the sender stays blocked, and the receiver answers a stale one with fresh credit. | [details](rfc/9000.md#s4-1-a-blocked-sender-asks-again-a) |
| RFC 9001 | TLS 1.3 in QUIC, keys, header protection, key update, Retry tag | ✅ | 0.2.1 | Packet protection, header protection, key update and the Retry tag run over `ksl` and match the RFC vectors. | [details](rfc/9001.md#tls-1-3-in-quic-keys) |
| RFC 9001 | §4.6, §4.6.1–4.6.3 — 0-RTT | ✅ | 0.2.1 | Opt-in 0-RTT sends and accepts early data, and a rejection resets the early streams. | [details](rfc/9001.md#s4-6-0-rtt) |
| RFC 9000 | §7.4.1 — remembered transport parameters for 0-RTT | ✅ | 0.2.1 | 0-RTT packets use the remembered server parameters, and the new values apply only from 1-RTT on. | [details](rfc/9000.md#s7-4-1-remembered-transport-parameters-for-0-rtt) |
| RFC 9001 | §4.9.3 — discarding 0-RTT keys | ✅ | 0.2.0 | The client drops its 0-RTT key with the 1-RTT key and the server 3 PTO after the first 1-RTT packet. | [details](rfc/9001.md#s4-9-3-discarding-0-rtt-keys) |
| RFC 9846 | §8, §4.3.10 — 0-RTT anti-replay | ✅ | 0.2.0 | A per-server replay register and OpenSSL's ticket-age check refuse replayed 0-RTT. | [details](rfc/9846.md#s8-0-rtt-anti-replay) |
| RFC 8470 | RFC 9114 §7.2.4.2 — HTTP/3 over 0-RTT | ✅ | 0.2.1 | The HTTP/3 client sends SETTINGS in 0-RTT and early only safe opted-in requests; the server binds SETTINGS into tickets. | [details](rfc/8470.md#http-3-over-0-rtt) |
| RFC 9002 | loss detection, PTO, NewReno | ✅ | 0.2.0 | Loss detection, PTO and NewReno follow RFC 9002, with a configurable initial RTT. | [details](rfc/9002.md#loss-detection-pto-newreno) |
| RFC 9438 | CUBIC | ✅ | 0.2.0 | CUBIC is the default congestion controller. | [details](rfc/9438.md#cubic) |
| draft-ietf-ccwg-bbr | BBR (BBRv3) | ✅ | 0.2.0 | An experimental, opt-in BBRv3 controller follows draft-06. | [details](rfc/draft-ietf-ccwg-bbr.md#bbr-bbrv3) |
| RFC 9221 | DATAGRAM frames | ✅ | 0.2.0 | DATAGRAM frames are advertised by default and sent and received within the peer's size limit. | [details](rfc/9221.md#datagram-frames) |
| RFC 8899 | §3, §4.1 — DF on the socket for PMTUD probes | ✅ | 0.3.0 | The native UDP socket sets Don't Fragment for MTU probes on every platform that offers it. | [details](rfc/8899.md#s3-df-on-the-socket-for-pmtud) |
| draft-ietf-quic-reliable-stream-reset | RESET_STREAM_AT | 🔶 | 0.3.0 | An experimental, off-by-default RESET_STREAM_AT delivers a reliable prefix of a reset stream. | [details](rfc/draft-ietf-quic-reliable-stream-reset.md#reset-stream-at) |
| RFC 9287 | grease bit | ✅ | 0.2.0 | The QUIC bit is greased only towards a peer that advertised `grease_quic_bit`. | [details](rfc/9287.md#grease-bit) |
| RFC 9218 | priorities (transport part: the scheduler) | ✅ | 0.2.0 | The stream scheduler orders streams by urgency and the incremental flag. | [details](rfc/9218.md#priorities-transport-part-the-scheduler) |
| draft-ietf-quic-qlog | qlog | ✅ | 0.2.0 | The endpoint writes qlog version 0.3 as JSON-SEQ. | [details](rfc/draft-ietf-quic-qlog.md#qlog) |
| RFC 9368/9369 | compatible version negotiation, QUIC v2 | ✅ | 0.2.0 | QUIC v2 is opt-in on the wire, with compatible version negotiation and a downgrade check. | [details](rfc/9368-9369.md#compatible-version-negotiation-quic-v2) |
| draft-ietf-quic-multipath | multipath | ⬜ | — | Multipath QUIC is planned after 0.3.x. | [details](rfc/draft-ietf-quic-multipath.md#multipath) |
| draft-ietf-quic-load-balancers | QUIC-LB | ⬜ | 0.3.x | QUIC-LB connection ID encoding is planned for 0.3.x. | [details](rfc/draft-ietf-quic-load-balancers.md#quic-lb) |

## TLS

| RFC | Section / topic | Status | Since | Summary | Details |
|---|---|---|---|---|---|
| RFC 9846 | (obsoletes RFC 8446) — TLS 1.3 | ✅ | 0.2.1 | TLS 1.3 over OpenSSL 3.5 is the protocol of every connection, checked against RFC 9846. | [details](rfc/9846.md#tls-1-3) |
| RFC 5246 | (obsoleted by RFC 9846; TLS 1.2 itself stays as written there) — TLS 1.2 (TCP, explicit only) | ✅ | 0.2.1 | TLS 1.2 is offered only over TCP when configured explicitly, with ECDHE, AEAD and Extended Main Secret. | [details](rfc/5246.md#tls-1-2-tcp-explicit-only) |
| RFC 6066 | (updated by RFC 9846 §4.5.1.1, OCSP) — SNI | ✅ | 0.2.1 | The client sends SNI for names only, and the server selects its identity by SNI over TCP. | [details](rfc/6066.md#sni) |
| RFC 7301 | RFC 9001 §8.1 — ALPN | ✅ | 0.2.0 | ALPN is mandatory in QUIC, and a missing or mismatched protocol closes the connection. | [details](rfc/7301.md#alpn) |
| RFC 7301 | §3.1 — protocol name lengths | ✅ | 0.2.0 | Protocol names are checked as 1..255 bytes and the list fits the native wire buffer. | [details](rfc/7301.md#s3-1-protocol-name-lengths) |
| RFC 5705 | (updated by RFC 9846 §7.5) — keying material exporter | ✅ | 0.2.0 | Both sessions export keying material. | [details](rfc/5705.md#keying-material-exporter) |
| RFC 9266 | `tls-exporter` channel binding | ✅ | 0.2.0 | TCP connections expose the `tls-exporter` channel binding. | [details](rfc/9266.md#tls-exporter-channel-binding) |
| RFC 9846 | §4.7.1; RFC 5077 (obsoleted by RFC 9846) — session tickets (TCP server), key rotation | ✅ | 0.2.0 | The TCP server issues session tickets with rotating keys. | [details](rfc/9846.md#s4-7-1-session-tickets-tcp-server-key-rotation) |
| RFC 9525 | (obsoletes RFC 6125) — hostname verification | ✅ | 0.2.0 | One native matcher checks DNS-IDs and IP-IDs on every platform, and it cannot be disabled. | [details](rfc/9525.md#hostname-verification) |
| RFC 9852 | (BCP 195) — TLS 1.3 as every protocol's default | ✅ | 0.2.0 | TLS 1.3 is the default, and QUIC accepts nothing else. | [details](rfc/9852.md#tls-1-3-as-every-protocols) |
| RFC 10015 | TLS 1.2 key exchange | ✅ | 0.3.0 | TLS 1.2 offers only ECDHE suites with AEAD: no static RSA, no FFDH(E), no static ECDH. | [details](rfc/10015.md#tls-1-2-key-exchange) |
| RFC 7469 | (the idea) — SPKI pins | ✅ | 0.2.0 | SPKI SHA-256 pins are matched against the validated chain. | [details](rfc/7469.md#spki-pins) |
| RFC 6960 | / 6961 (6961 obsoleted by RFC 9846: `status_request_v2` is `ocsp_multi_RESERVED`) — OCSP, stapling | ⬜ | — | Revocation checking (OCSP, stapling) is planned for later, behind a flag. | [details](rfc/6960.md#ocsp-stapling) |
| RFC 8879 | certificate compression | ❌ | — | Certificate compression is not planned for 0.x. | [details](rfc/8879.md#certificate-compression) |
| RFC 7627 | §5.2 — Extended Master Secret required for TLS 1.2 | ✅ | 0.2.1 | A TLS 1.2 peer without Extended Master Secret is refused. | [details](rfc/7627.md#s5-2-ems-required) |
| RFC 9325 | §3.5 — TLS 1.2 implementations support Extended Master Secret | ✅ | 0.2.1 | TLS 1.2 is offered only with Extended Master Secret. | [details](rfc/9325.md#s3-5-ems) |
| RFC 9325 | §4.4 — AEAD record limits | ✅ | 0.2.0 | Without KeyUpdate or renegotiation a TLS 1.2 or 1.3 TCP connection ends before its keys reach the AEAD limit. | [details](rfc/9325.md#s4-4-aead-limits) |
| RFC 9325 | §7.5 — certificate revocation | ⬜ | — | Revocation checking is planned with the OCSP row; today it depends on the platform verifier. | [details](rfc/9325.md#s7-5-revocation) |

## HTTP

| RFC | Section / topic | Status | Since | Summary | Details |
|---|---|---|---|---|---|
| RFC 9114 | HTTP/3 | ✅ | 0.2.0 | HTTP/3 client and server are implemented section by section, without server push. | [details](rfc/9114.md#http-3) |
| RFC 9114 | §7.1, §7.2 — frames | ✅ | 0.2.1 | Frames are parsed with GREASE types skipped and HTTP/2 types refused, and a declared length never sets a buffer size. | [details](rfc/9114.md#s7-1-frames) |
| RFC 9114 | §7.2.4, §6.2.1 — SETTINGS | ✅ | 0.2.0 | SETTINGS must come first on the control stream and only once. | [details](rfc/9114.md#s7-2-4-settings) |
| RFC 9114 | §3.1 — engine client | ✅ | 0.2.0 | The Ktor client uses h3 by prior knowledge with one connection per origin and an HTTP/1.1 fallback. | [details](rfc/9114.md#s3-1-engine-client) |
| RFC 9114 | §5.2 — engine server | ✅ | 0.2.0 | The Ktor server's stop sends a two-phase GOAWAY to all HTTP/3 connections at once. | [details](rfc/9114.md#s5-2-engine-server) |
| RFC 9114 | §3.1–3.2 — ALPN `h3` | ✅ | 0.2.0 | Endpoints negotiate ALPN `h3` only and close connections with another protocol. | [details](rfc/9114.md#s3-1-alpn-h3) |
| RFC 9114 | §4.1, §4.1.2 — request/response | ✅ | 0.2.1 | Requests and responses run on bidirectional streams with DATA frames, trailers and interim responses. | [details](rfc/9114.md#s4-1-request-response) |
| RFC 9114 | §4.2.2; RFC 9204 §7.4 — field section size | ✅ | 0.2.0 | Field sections above 64 KiB decoded size are refused on both sides. | [details](rfc/9114.md#s4-2-2-field-section-size) |
| RFC 9114 | §6.1–6.2, §6.2.1–6.2.3 — control and QPACK streams | ✅ | 0.2.1 | The control and QPACK streams are opened and SETTINGS sent at once. | [details](rfc/9114.md#s6-1-control-and-qpack-streams) |
| RFC 9114 | §5.2–5.4 — GOAWAY | ✅ | 0.2.0 | The server sends a two-phase GOAWAY, rejects later requests and closes with H3_NO_ERROR. | [details](rfc/9114.md#s5-2-goaway) |
| RFC 9114 | §4.2.2 (sending) — field section size (sending) | ✅ | 0.2.0 | The peer's field section size limit is honoured when sending. | [details](rfc/9114.md#s4-2-2-field-section-size-sending) |
| RFC 9114 | §5.2 — idle close after GOAWAY | ✅ | 0.2.0 | A request stream counts as in flight from its first byte when the idle close after GOAWAY is decided. | [details](rfc/9114.md#s5-2-idle-close-after-goaway) |
| RFC 9114 | §7.2.8, §8.1 (request streams) — unknown frames on request streams | ✅ | 0.2.0 | Unknown and reserved frames on a request stream are skipped without buffering and spend a glitch token. | [details](rfc/9114.md#s7-2-8-unknown-frames-on-request-streams) |
| RFC 9114 | §4.1.2; RFC 9110 §9.3.2, §15.3.5, §15.4.5 — responses without content | ✅ | 0.2.0 | A response to HEAD or with status 204 or 304 that carries DATA is a malformed message. | [details](rfc/9114.md#s4-1-2-responses-without-content) |
| RFC 9114 | §4.2; RFC 9110 §10.1.4 — `te` | ✅ | 0.2.0 | `te` is accepted only as a request field with the value `trailers`. | [details](rfc/9114.md#s4-2-te) |
| RFC 9114 | §4.2, §4.3 — field validation | ✅ | 0.2.1 | Field names, values and pseudo-header fields are validated as §4.2 and §4.3 require. | [details](rfc/9114.md#s4-2-field-validation) |
| RFC 9114 | §8 (codes), §9 — error codes | ✅ | 0.2.0 | Error codes map to exceptions, an unknown code counts as H3_NO_ERROR, and a rejected request is retry-safe. | [details](rfc/9114.md#s8-error-codes) |
| RFC 9114 | §4.6, §7.2.3, §7.2.5, §7.2.7 — server push | ❌ | — | Server push is not planned; push frames are refused with the error codes of each role. | [details](rfc/9114.md#s4-6-server-push) |
| RFC 9204 | QPACK | ✅ | 0.2.0 | QPACK encoder and decoder are implemented section by section. | [details](rfc/9204.md#qpack) |
| RFC 9204 | §4.1, app. A; RFC 7541 §5.1–5.2, app. B — primitives and static table | ✅ | 0.2.0 | Prefixed integers, string literals, Huffman and the static table are generated from the RFC text. | [details](rfc/9204.md#s4-1-primitives-and-static-table) |
| RFC 9204 | §2.2, §3.2, §4.3–4.5 — decoder | ✅ | 0.2.0 | The decoder keeps the dynamic table and decodes every field line representation and encoder instruction. | [details](rfc/9204.md#s2-2-decoder) |
| RFC 9204 | §7.4 — split encoder-stream instructions | ✅ | 0.2.0 | An encoder-stream instruction split by the transport is reassembled in linear time. | [details](rfc/9204.md#s7-4-split-encoder-stream-instructions) |
| RFC 9204 | §2.1.2, §4.2, §4.4 (in the connection) — streams in the connection | ✅ | 0.2.0 | Encoder instructions precede the blocks that use them, and blocked sections wait for their inserts. | [details](rfc/9204.md#s2-1-2-streams-in-the-connection) |
| RFC 9204 | §2.1, §4.3, §4.5, §7.1 — encoder | ✅ | 0.2.0 | The encoder uses the dynamic table only within the peer's limits and its own bounds. | [details](rfc/9204.md#s2-1-encoder) |
| RFC 9218 | priorities (HTTP part) | ✅ | 0.3.0 | HTTP/3 streams are scheduled by RFC 9218 urgency and incremental parameters. | [details](rfc/9218.md#priorities-http-part) |
| RFC 9218 | §7–8 — PRIORITY_UPDATE | ✅ | 0.2.0 | The server applies the client's PRIORITY_UPDATE, and a server-set priority wins. | [details](rfc/9218.md#s7-priority-update) |
| RFC 9218 | §4–5 — the `Priority` field | ✅ | 0.2.0 | The `Priority` field is parsed strictly as a Structured Fields dictionary. | [details](rfc/9218.md#s4-the-priority-field) |
| RFC 9218 | §8, §10.1, §11 — local scheduling | 🔶 | 0.3.0 | The client schedules its streams by its own signal, and the server merges the client's field with its own. | [details](rfc/9218.md#s8-local-scheduling) |
| RFC 9218 | Ktor server | 🔶 | 0.3.0 | The Ktor server exposes the client's priority signal and its updates to the application. | [details](rfc/9218.md#ktor-server) |
| RFC 9218 | Ktor client | 🔶 | 0.3.0 | The Ktor client sets a request's priority over h3 and h1. | [details](rfc/9218.md#ktor-client) |
| RFC 6455 | §4.1, §5.1, §5.2, §9.1; RFC 7692 §6.1; RFC 9220 §3 — WebSocket extensions in the Ktor engines | ✅ | 0.3.0 | The Ktor client engine negotiates WebSocket extensions over HTTP/1.1 and HTTP/3. | [details](rfc/6455.md#s4-1-websocket-extensions-in-the-ktor-engines) |
| RFC 9220 | Extended CONNECT / WebSocket over h3 | ✅ | 0.2.0 | Extended CONNECT and WebSocket over HTTP/3 work at the HTTP/3 level. | [details](rfc/9220.md#extended-connect-websocket-over-h3) |
| RFC 9297 | HTTP datagrams | ✅ | 0.3.0 | HTTP/3 datagrams and the Capsule Protocol on Extended CONNECT streams are supported. | [details](rfc/9297.md#http-datagrams) |
| RFC 7838 | Alt-Svc | ✅ | 0.2.0 | The client caches Alt-Svc alternatives and the server can announce h3. | [details](rfc/7838.md#alt-svc) |
| RFC 7838 | §2.2, §3, §9.4 — cache bounds | ✅ | 0.2.0 | The Alt-Svc cache keeps at most 8 alternatives per origin and 1000 origins. | [details](rfc/7838.md#s2-2-cache-bounds) |
| RFC 7838 | §2.4; RFC 8305 §5 — race and fallback | ✅ | 0.2.0 | The h3/h1 race makes exactly one HTTP/1.1 attempt. | [details](rfc/7838.md#s2-4-race-and-fallback) |
| RFC 8470 | §4; RFC 7838 §2.4; RFC 8305 §5 — client 0-RTT, race and fallback | ✅ | 0.2.0 | A 0-RTT connection wins the h3/h1 race before its handshake only where QUIC was confirmed. | [details](rfc/8470.md#s4-client-0-rtt-race-and-fallback) |
| RFC 7838 | §3, §3.1 (Alt-Svc on HTTP/3 responses, quoted-string, `ma`) — Alt-Svc on HTTP/3 responses | ✅ | 0.2.1 | The client processes Alt-Svc on every verified response, HTTP/3 ones included. | [details](rfc/7838.md#s3-alt-svc-on-http-3-responses) |
| RFC 7838 | §2.2 — network change | ✅ | 0.2.1 | A network change drops every alternative without `persist`. | [details](rfc/7838.md#s2-2-network-change) |
| RFC 8305 | §4–§6 (TCP) — TCP address race | 🔶 | 0.3.0 | The TCP connection race interleaves address families with a 250 ms attempt delay. | [details](rfc/8305.md#s4-tcp-address-race) |
| RFC 8305 | Happy Eyeballs | 🔶 | 0.2.1 | The h3/h1 race is a feature subset of Happy Eyeballs; the TCP race is its own row. | [details](rfc/8305.md#happy-eyeballs) |
| RFC 9460 | HTTPS RR as a source of h3 | ⬜ | 0.3.0 | HTTPS resource records as a source of h3 are planned for 0.3.0, off by default. | [details](rfc/9460.md#https-rr-as-a-source-of) |
| RFC 9850 | SSLKEYLOGFILE format | ✅ | 0.2.0 | Key logs are written in the SSLKEYLOGFILE format. | [details](rfc/9850.md#sslkeylogfile-format) |
| draft-ietf-webtrans-http3 | WebTransport | 🔶 | 0.3.0 | Experimental WebTransport over HTTP/3 is in progress. | [details](rfc/draft-ietf-webtrans-http3.md#webtransport) |
| draft-ietf-webtrans-http3 | §3.1, §7.1 — SETTINGS | 🔶 | 0.3.0 | WebTransport SETTINGS are sent and checked only with the settings it needs. | [details](rfc/draft-ietf-webtrans-http3.md#s3-1-settings) |
| draft-ietf-webtrans-http3 | §3.2, §3.3, §5.1, §5.2, §7.1 — sessions | 🔶 | 0.3.0 | The client opens WebTransport sessions after the server's SETTINGS and CONNECT answer. | [details](rfc/draft-ietf-webtrans-http3.md#s3-2-sessions) |
| draft-ietf-webtrans-http3 | §4.2, §4.3, §4.6 — streams | 🔶 | 0.3.0 | WebTransport uni and bidi streams are recognised by their type and signal and routed to their session. | [details](rfc/draft-ietf-webtrans-http3.md#s4-2-streams) |
| draft-ietf-webtrans-http3 | §4.4, §4.5, §4.7, §6 — session | 🔶 | 0.3.0 | `WebTransportSession` opens and accepts streams, maps application codes and closes the session. | [details](rfc/draft-ietf-webtrans-http3.md#s4-4-session) |
| draft-ietf-webtrans-http3 | Ktor server | 🔶 | 0.3.0 | The Ktor server routes WebTransport Extended CONNECT requests over HTTP/3. | [details](rfc/draft-ietf-webtrans-http3.md#ktor-server) |
| draft-ietf-webtrans-http3 | Ktor client | 🔶 | 0.3.0 | The Ktor client opens WebTransport sessions over https with the Kuicksilver engine. | [details](rfc/draft-ietf-webtrans-http3.md#ktor-client) |
| RFC 9113 | HTTP/2 | ❌ | — | HTTP/2 is not planned, by decision. | [details](rfc/9113.md#http-2) |
| RFC 9112 | HTTP/1.1 | ✅ | 0.2.1 | HTTP/1.1 is served and spoken by the Ktor engines. | [details](rfc/9112.md#http-1-1) |
| RFC 9110 | §9.2.2; RFC 9112 §9.2, §9.3.1 — client retry | ✅ | 0.2.1 | An idle pooled HTTP/1.1 connection the server closed is replaced once, for idempotent requests only. | [details](rfc/9110.md#s9-2-2-client-retry) |
| RFC 1928/1929 | §3–§6 (client) — SOCKS5 client | 🔶 | 0.3.0 | The client speaks SOCKS5 CONNECT only, with no authentication or username/password. | [details](rfc/1928-1929.md#s3-socks5-client) |
| RFC 1928/1929 | RFC 1929 — username/password | 🔶 | 0.3.0 | Username/password authentication is offered only with credentials and checked by the RFC's rules. | [details](rfc/1928-1929.md#username-password) |
| RFC 6455 | §4.1 (client: connecting, through a proxy) — connecting, through a proxy | 🔶 | 0.3.0 | At most one WebSocket per remote host is in the CONNECTING state; PAC is planned. | [details](rfc/6455.md#s4-1-connecting-through-a-proxy) |
| RFC 9110 | §9.3.6, §11.7.2; RFC 9931 §8 — client CONNECT tunnel | ✅ | 0.2.1 | HTTPS through an HTTP proxy uses a CONNECT tunnel. | [details](rfc/9110.md#s9-3-6-client-connect-tunnel) |
| RFC 9112 | §6.1, §6.3, §7.1, §8, §9.6 — client response framing | ✅ | 0.2.1 | The client frames a response as RFC 9112 §6.3 orders. | [details](rfc/9112.md#s6-1-client-response-framing) |
| RFC 9110 | §5.5, §6.2, §15; RFC 9112 §2.2, §4, §5.2 — client response head | ✅ | 0.2.1 | The response head is checked by the engine before Ktor's parser reads it. | [details](rfc/9110.md#s5-5-client-response-head) |
| RFC 9112 | §6.1, §6.2 — client request framing | 🔶 | 0.2.1 | A request body is framed by Content-Length or chunked; first contact per §6.1 is planned. | [details](rfc/9112.md#s6-1-client-request-framing) |
| RFC 9112 | §6.1, §6.3, §7.1 — server request framing | ✅ | 0.2.1 | The server frames a request as RFC 9112 §6.3 orders, with a strict chunk-size line. | [details](rfc/9112.md#s6-1-server-request-framing) |
| RFC 9112 | §2.3, §3, §3.1; RFC 9110 §6.2, §15.6.6 — server request line | ✅ | 0.2.1 | The request line is checked before Ktor's parser reads it. | [details](rfc/9112.md#s2-3-server-request-line) |
| RFC 9110 | §5.1, §5.5, §5.6.3; RFC 9112 §5.1, §5.2 — server request field lines | ✅ | 0.2.1 | Field lines that are not well formed get 400 and close the connection. | [details](rfc/9110.md#s5-1-server-request-field-lines) |
| RFC 6585 | §5 — server request-head size | ✅ | 0.2.1 | A request head above 64 KiB gets 431. | [details](rfc/6585.md#s5-server-request-head-size) |
| RFC 9110 | §8.6; RFC 9112 §6.1, §6.2 — server response framing fields | ✅ | 0.2.1 | No response carries framing fields the RFCs forbid for it. | [details](rfc/9110.md#s8-6-server-response-framing-fields) |
| RFC 9110 | §9.3.2, §6.4.1, §15.3.5, §15.4.5; RFC 9112 §6.3 item 1 — server responses without content | ✅ | 0.2.1 | Content written for HEAD, 1xx, 204 or 304 responses is dropped. | [details](rfc/9110.md#s9-3-2-server-responses-without-content) |
| RFC 9110 | §6.6.1 — server Date | ✅ | 0.2.1 | Every final response carries `Date` unless the application set one. | [details](rfc/9110.md#s6-6-1-server-date) |
| RFC 9112 | §9.3, §9.6 — server request `close` | ✅ | 0.2.1 | A request with `close`, or HTTP/1.0 without keep-alive, ends the connection after its response. | [details](rfc/9112.md#s9-3-server-request-close) |
| RFC 9112 | §9.3.2 — server pipelining | ✅ | 0.2.1 | Pipelined requests are answered in order. | [details](rfc/9112.md#s9-3-2-server-pipelining) |
| RFC 9112 | §4 — server status line | ✅ | 0.2.1 | The status line is always `HTTP/1.1` with a valid reason phrase. | [details](rfc/9112.md#s4-server-status-line) |
| RFC 9110 | §7.8, §15.2 — server Upgrade in HTTP/1.0 | ✅ | 0.2.1 | The Upgrade field of an HTTP/1.0 request is ignored. | [details](rfc/9110.md#s7-8-server-upgrade-in-http-1-0) |
| RFC 9931 | §8 (updates RFC 9112; server CONNECT) — server CONNECT | ✅ | 0.2.1 | Every CONNECT is refused and is the last request on its connection; tunnels are planned. | [details](rfc/9931.md#s8-server-connect) |
| RFC 9112 | §9.6 — server staged close | ✅ | 0.2.1 | A response that ends the connection while the client may still send closes in stages. | [details](rfc/9112.md#s9-6-server-staged-close) |
| RFC 9110 | §15.5.9; RFC 9112 §9.5 — server timeouts | ✅ | 0.2.1 | Incomplete request heads and stalled bodies time out. | [details](rfc/9110.md#s15-5-9-server-timeouts) |
| RFC 8941 | §4.2 — Dictionary parsing of the Priority field | ✅ | 0.2.0 | The `Priority` field and PRIORITY_UPDATE values are parsed as RFC 8941 Dictionaries, and a failed parse means the defaults. | [details](rfc/8941.md#s4-2-dictionary-parsing) |
| RFC 9111 | §1.2.2 — delta-seconds in Alt-Svc `ma` | ✅ | 0.2.1 | An Alt-Svc `ma` too large to represent counts as 2147483648 seconds. | [details](rfc/9111.md#s1-2-2-delta-seconds) |

## How to update

A row changes in the same PR as the implementation; the interop matrix (a release artifact) is the evidence for a ✅ status.

Both halves change together: the summary row (Status, Since, one sentence) and its section in `docs/spec/rfc/<rfc>.md` (requirement, files, tests, history, peer notes, open items); an RFC without a file gets one, linked from its row. A new interop run goes to [interop.md](interop.md). `tools/check/rfc-table.sh` (the CI lint job and `tools/ci/local-matrix.sh`) checks the table format and that every details link and anchor exists.
