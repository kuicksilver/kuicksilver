<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# HTTP/3 in the Ktor client

**What this page is for.** How the client engine finds a server's HTTP/3 and when it uses it: the discovery
modes, `Alt-Svc` and HTTPS records, the race against TCP and the fallback, stalled connections, the remote kill switch and
connection migration between networks.

**Before you start**

- In short: the first request to a host goes over TCP (HTTP/2 or HTTP/1.1); the server's `Alt-Svc` announces HTTP/3; the
  next request races HTTP/3 against the open TCP connection (TCP usually wins that one), and from then on the HTTP/3
  connection serves the requests; when HTTP/3 fails, the request goes over TCP.
- The imports of the code blocks: [Ktor engines: Imports](ktor.md#imports). When a request does not use HTTP/3 and you do not know why:
  [Observability: Why did this request not use HTTP/3?](observability.md#why-did-this-request-not-use-http3).

## HTTP/3 on the client

`http3 { discovery = ... }` (`Http3Discovery`) decides when HTTP/3 is used for `https://` (never through a proxy), and
`http3 { enabled = false }` turns it off: every request goes over TCP, HTTP/2 or HTTP/1.1 (0.2's `H1Only`; together with
`H3Only` the engine's creation fails):

| Mode | Behaviour |
|---|---|
| `Auto` (default) | TCP first (HTTP/2 or HTTP/1.1); once the origin announced HTTP/3 with `Alt-Svc`, the next request races HTTP/3 against TCP and HTTP/3 serves the requests from when its connection is up ([Discovery and Alt-Svc](#discovery-and-alt-svc)) |
| `Preferred` | HTTP/3 by prior knowledge, falling back to TCP (like `curl --http3`); `http3 { hints }` gives the same treatment to listed origins in `Auto` mode |
| `H3Only` | HTTP/3 only (like `curl --http3-only`): failures are reported, never retried over TCP; an `http://` or `ws://` request (HTTP/3 needs `https`, RFC 9114 section 3.1), and with a proxy configured every request, fails with `UnsupportedOperationException` |

HTTP/3 responses report `HttpProtocolVersion.HTTP_3_0`. One QUIC connection per origin carries all its requests; a
request the server did not process (GOAWAY above its stream, `H3_REQUEST_REJECTED`) is repeated on a new connection
without the application noticing. When HTTP/3 fails before the response headers, the request is repeated over TCP
— always if it cannot have reached the server, otherwise only for idempotent methods whose body can be sent again
(bytes, a `WriteChannelContent` writer, or no body). A streamed `ReadChannelContent` body that HTTP/3 already consumed
is never replayed, neither on the fallback nor after a 421 or a `RequestNotProcessed`: the call fails with
`H3BodyConsumed` and the application decides. The fallback uses the same `tls { }`: trust, pins and TLS 1.3 settings. When a call ends before its body was read, the rest of the stream is abandoned
with `STOP_SENDING`. A response body the connection cut short (a reset, a lost connection) never looks complete:
`bodyAsText`, `bodyAsBytes`, `readRemaining` and the other whole-body reads throw the cause, and the engine's own channel
(`rawContent`, the server's request body) throws it from `readAvailable` instead of answering -1. `bodyAsChannel()`
hands out Ktor's copy of the body, which keeps ktor-io's contract: its `readAvailable` answers -1 with the cause in
`closedCause`, so a loop over that channel checks `closedCause` after -1 (or reads the rest with `readRemaining`).

WebSockets use HTTP/1.1 `Upgrade` unless an HTTP/3 connection to the origin already allows Extended CONNECT and has
not received GOAWAY (or the mode is `H3Only`), or an HTTP/2 one does ([HTTP/2 on the client](client.md#http2-on-the-client)); over HTTP/3 the handshake is RFC
9220, over HTTP/2 RFC 8441, and the plugin sees the usual 101. Over HTTP/1.1 at most one
WebSocket is connecting to an address and port at a time (RFC 6455 section 4.1): another one to the same address, under
any name, opens its connection once the first handshake was answered or failed; through a proxy that resolves names,
the name counts as the host. The connect timeout applies twice to such a WebSocket, in two phases: resolving the name,
waiting for a pool slot and connecting (TCP and TLS) share one, as for any request; the answer to the handshake must then
arrive within the same timeout again, counted from the moment the connection is in hand. The wait for another WebSocket
to the address is in neither: only the call (its request timeout or cancellation) bounds it.

A session's own Close goes out even when its call ends with a failure or a cancellation once that Close was queued,
over every protocol: Ktor's `webSocketSession()` ends its call that way each time the session closes (it takes the
session's cancelled outgoing channel for a failure), and the Close, and the frames queued before it, would otherwise be
lost with the call (RFC 6455 section 7.1.2: the endpoint "MUST send a Close control frame"). The session runs on until
it ends, within 5 s counted from its own Close for writing it and for the server's Close; past that the HTTP/1.1
connection is closed at once, the HTTP/2 stream reset with CANCEL and the HTTP/3 stream reset with H3_REQUEST_CANCELLED.

The transport is then closed the server's side first (RFC 6455 section 7.1.1: the client "SHOULD wait for a TCP Close
from the server"): the engine reads and drops what the server still sends, waits for its FIN (close_notify, then the FIN,
over TLS), its END_STREAM (HTTP/2) or its FIN (HTTP/3), and closes its own side after it, cleanly: close_notify and a FIN,
END_STREAM, a FIN. A server that has not closed its side 5 s after both Closes (the close wait, counted again from
there) gets the client's clean close then; over HTTP/2 and HTTP/3 the stream is reset (RST_STREAM CANCEL,
STOP_SENDING H3_REQUEST_CANCELLED) only if the server's end has not come another 5 s later. Ktor's own WebSocket writer
closes its channel right after its Close, which used to half-close the connection (or end the stream) at once; the
engine no longer lets that through. The server engine closes first: its FIN right after its close_notify over TLS (the
client's close_notify is not waited for), END_STREAM or FIN right after the session.

How long `client.close()` can wait for a WebSocket whose server stays silent: it waits for the session's end, and that is
bounded by three close waits (15 s) after the session's own Close at most: 5 s for the server's Close (then the session
is cancelled and the connection or stream ended at once: an HTTP/1.1 connection is closed cleanly when everything the
session wrote was whole and taken by the socket, and reset when something was still queued, cut inside a frame or failed,
so nothing leaves after the wait (on macOS a server that stopped reading, its receive window at 0, ignores that reset
until it sends something itself); an HTTP/2 or HTTP/3 stream is reset), 5 s for the server's close of the transport (then the client
closes its side cleanly), and over HTTP/2 and HTTP/3 5 s more for the server's END_STREAM or FIN after the client's own
(then the stream is reset). The session's end handlers are cut off two close waits after the session ended, whatever
they still wait for. The pools close after that, as for any request (at most about 3 s more). The connection, its pool slot and the engine's
`close()` wait for the session, not for the call: `client.close()` right after `close(reason)` still sends the Close
before the pools close. A call that fails or is cancelled before the session queued its Close still closes it with the
closing handshake (RFC 6455 sections 7.1.7 and 7.3): one Close, 1001 Going Away (or the application's own code when it sends
one, as from a `finally`), bounded by the same close wait; only a call that ends during the handshake ends it at once. A coroutine of
the session that fails is reported to the event listener (`webSocketFailed`).

## Discovery and Alt-Svc

In `Auto` mode the engine learns alternatives from `Alt-Svc` headers (RFC 7838) of HTTPS responses, and from ALTSVC
frames on HTTP/2 connections (section 4: "semantically equivalent to receiving an Alt-Svc header field"; one on stream
0 counts only when its Origin is the connection's own origin), and sends the next requests to the origin over HTTP/3,
with an `Alt-Used` header; SNI and certificate verification still use the origin's host. The rules:

- only responses over verified TLS count (an `http://` response can never redirect a client to an alternative), and
  nothing is learned through a proxy;
- a new `Alt-Svc` replaces every entry of the origin, and `clear` removes them, alone or anywhere in the list (section
  3: "including those specified in the same response"); this applies to every response, over HTTP/1.1, HTTP/2 and
  HTTP/3, including the ones served while a cached alternative is broken or lost the race. A 421 from the origin
  changes nothing (it is not authoritative for the origin, RFC 9110 section 15.5.20, so its `Alt-Svc` is ignored too);
  a 421 over HTTP/3 from an alternative removes that alternative and keeps the others (RFC 7838 section 6);
- `ma` defaults to 86400 seconds and counts from the response's generation (section 3.1): the response's `Age` and the
  time from sending the request to the response are subtracted, so a copy a CDN kept for a day does not get a fresh
  day; expired entries are ignored;
- the alternatives are tried in the server's order of preference: the first fresh one that is not marked broken (section
  2.4), so a broken first alternative does not hide a working second one;
- an alternative port is digits only (`h3=":+443"` is malformed);
- an alternative on an unprivileged port (1024 and up) is refused for an origin on a privileged one, as Chromium does;
- an alternative on a loopback, link-local or private address, or a `localhost` name, is refused unless the origin is
  on such an address too, and one on an unspecified, multicast or broadcast address always; an IPv4 address counts in
  every form the resolvers accept without DNS (`127.1`, `2130706433`), and a numeric host in octal or hex (`0177.0.0.1`,
  `0x7f.1`, which platforms read differently) or that is no address (`256.1.1.1`) is always refused. A DNS name is not
  resolved for this check;
- only `h3` alternatives are used.

The same checks apply to every entry a store hands back, so a store file written by an older version or edited by hand,
or an application's own `AltSvcStore`, cannot bring in what the header path refuses; `FileAltSvcStore` also checks every
field of every record again on load (origin form, protocol, host, ports, expiry, persist flag), drops what fails, and
reads at most the first 8 MiB of a file (a full store takes less).

Entries live in `http3 { altSvcStore = ... }` — `InMemoryAltSvcStore` by default (an app without one learns HTTP/3 again
after every start: the mobile [first screen](client.md) keeps them in a `FileAltSvcStore`). `FileAltSvcStore(path)` keeps them
in one tab-separated text file (loaded once, rewritten atomically after every change, expired records dropped on load)
so the first request after a cold start can already use HTTP/3; implement `AltSvcStore` for any other backing store
(one engine per file: two engines sharing a file overwrite each other). A store is keyed by origin in one canonical form:
`scheme://host:port`, the host with its ASCII letters in lowercase and nothing else changed (`example.com.` is another
origin than `example.com`, RFC 6454 section 4; an internationalised name is keyed as the URL spells it, so use its
A-label), an IPv6 address in brackets in RFC 5952 text, the port always written (`https://example.com:443`,
`https://[2001:db8::1]:8443`), a `wss` URL keyed as its `https` origin. `AltSvcStore.originOf(url)` (experimental,
0.3.0) builds that key, for a store that looks an origin up or seeds one; `FileAltSvcStore` reads the origins of an
older file into it. There
is no change callback: wrap the store to see what it learns, as the engine calls `put`, `remove`, `clearNonPersistent` and
`clear` for every change. Both built-in stores keep at most 8 alternatives
per origin (the first ones of the header) and 1000 origins, dropping the least recently used; `FileAltSvcStore` skips
the rewrite when a repeated header only refreshes the expiry, and the engine writes it after releasing its lock. Entries
without `persist=1` are dropped when the network changes (RFC 7838 section 2.2): when `network { networkId }` reports a
new network, or, while `networkId` is not set (null, the default), when the networks `http3 { migration }` follows do
(the `followDefaultNetwork` factories). With `networkId`, a store also keeps the network its entries were learned on (`AltSvcStore.networkId`,
experimental; `FileAltSvcStore` writes it to its file), so the first request after a restart on another network drops
them too. A followed network is compared in memory: on Android the `Network` (a number the system gives each new
connection), on iOS and macOS the default path's interface, gateways and the interface's addresses, so a move between
two Wi-Fi networks on one interface is a change as well (a path that tells neither gateways nor addresses counts as a
change at each update; every update of the path, changed or not, flushes the HTTPS record cache). Neither survives a restart (the Android number is reused after a reboot; the Apple identity
holds local addresses and is never written), so it is never stored: at its first value after a start the engine takes
the network as changed, as it does for what it learned before that value came; requests wait for that value until
200 ms after the client was created, one deadline for all, then go on without it. Give `networkId` an identity of your
own for detection across restarts. `http3 { expert { clearAltSvcOnNetworkChange = false } }` keeps them. Without either source the engine sees no
network change.

RFC 7838 section 9.4: "In a user agent, any alternative service information MUST be removed when origin-specific data is
cleared (typically, when cookies [RFC6265] are cleared)". Call `client.clearAlternativeServices(url)` (experimental) where
the application clears an origin's cookies or other site data, or `client.clearAlternativeServices()` for all of them:
the cached alternatives (persistent ones too, and from the store file before it returns), broken marks and RTTs go;
open HTTP/3 connections stay (`closeHttp3Connections()` closes them). It returns whether everything asked for went. A
store of your own overrides `AltSvcStore.clear()`; for one that does not (written before 0.3.0) a full clear removes
the origins seen since the client started one by one, logs a warning that others it kept from earlier may remain, and
returns false, so the application can clear the store's own data.

`FileAltSvcStore(path)` takes a `kotlinx.io.files.Path`; on the JVM and Android `FileAltSvcStore(file)` (stable, 0.3.0)
takes a `java.io.File`. On Android keep the file in the app's private files directory. Do not write
`File(...).toPath()`: that is a `java.nio.file.Path`, which this API does not take, and `File.toPath()` and
`java.nio.file` only exist from API 26, while the library supports API 24. The `File` form uses no `java.nio.file`,
so it works on API 24 and 25 too (there a write replaces the file with `File.renameTo`, which is atomic on one file
system):

```kotlin
val filesDir = context.filesDir                  // android.content.Context
// guide:ktor:altsvc-store-android
HttpClient(Kuicksilver) {
    engine {
        http3 { altSvcStore = FileAltSvcStore(File(filesDir, "altsvc.tsv")) }
    }
}
```

## HTTPS records (experimental)

`network { httpsRecords = HttpsRecordSource.System }` (or `HttpsRecordSource.Exchange { query -> ... }` for your own
DNS-over-HTTPS client) makes the engine an HTTPS-record client (RFC 9460) in `Auto` mode: the origin's records say where
to connect, so the first request to an origin that publishes one with `alpn=h3` races HTTP/3 at once instead of waiting
for an `Alt-Svc` header, as browsers do. Off by default. The rules:

- for an `https://` request to a host name; never for `Preferred`, `H3Only`, `http3 { hints }`, IP addresses, requests
  through a proxy, or while `http3 { allowed }` says no;
- the name asked is the host for port 443, `_<port>._https.<host>` otherwise (section 9.1); AliasMode records are
  followed (one at random among several; at most 8 steps; a loop or a longer chain is treated as no record; an AliasMode
  "." is ignored); the ServiceMode records of the final name, by ascending priority and shuffled within a priority, are
  the endpoints (at most 32, the lowest priorities first), each at its target (the record's own name for ".") and
  `port` (the origin's when absent); after an
  AliasMode chain the last name with the origin's port is one more endpoint, last (section 3);
- an endpoint is tried over the transports its ALPN set allows (section 7.1.2; the default set is `http/1.1`, so
  `alpn=h3` means QUIC and TCP, `alpn=h2` TCP, and `no-default-alpn` with `alpn=h3` QUIC only); QUIC and TCP race as for
  an `Alt-Svc` alternative ([Racing and fallback](#racing-and-fallback)), TCP connecting to the endpoint's target and
  port, both offering the engine's usual ALPN lists. An endpoint that cannot be connected to is followed by the next one,
  and after the last by the origin as without records. TLS and the request still name the origin, and the certificate is
  checked against the origin's name whatever the record says; a QUIC endpoint that fails is marked broken like an
  alternative (`httpsRecordUsed` and `altSvcMarkedBroken` report both). The address hints are not used, `ech` is not (a
  record that requires it is skipped), and a malformed record makes the whole answer unusable (section 2.2);
- a cached `Alt-Svc` alternative is tried first, its TCP side going to the origin's first TCP endpoint; the
  alternative's own HTTPS records are looked up too (RFC 9460 section 9.3), and when it has some, HTTP/3 goes to their
  targets and ports that offer `h3`, and not to the alternative at all when none does (`Alt-Used` still names the
  alternative);
- the request waits for the records while the origin's addresses resolve and at most `network { httpsRecordWait }`
  (50 ms) longer; a lookup that answers later, fails or times out leaves the request on the origin as without records,
  and a late answer is cached for the next request (`httpsRecordWait` is 50 ms to 1 s: RFC 9460 section 5.1 asks for at
  least 50 ms before connecting without the records). While an AliasMode chain is followed, the addresses of each
  alias target are looked up in parallel (section 5). A malformed answer always counts as "no records". With
  `HttpsRecordSource.Exchange(secure = true) { ... }` (an exchange whose answers are protected: DNS over HTTPS or TLS, or
  validated DNSSEC) the request waits for the records instead, up to the connect timeout, and a failed lookup (an error
  answer such as SERVFAIL, a transport error, a timeout) abandons it with an `IOException`, so an attacker who drops the
  answers cannot downgrade the connection (RFC 9460 section 3.1). `HttpsRecordSource.ProtectedSystem { ... }` does the
  same for the system resolver when your check says its answers are protected; on Android
  `HttpsRecordSource.followingPrivateDns(connectivity)` says so while strict Private DNS is on (the engine has no
  `Context`: with plain `System` strict Private DNS is not taken into account, so opt in with this builder). Elsewhere no public API
  tells whether the system's DNS is encrypted, so `System` treats failures as "no records";
- answers are cached for their TTL (at most a day, expired once the monotonic or the wall clock has seen it pass, so
  neither a clock stepped back nor a device that slept keeps them longer; "no records" for the negative
  TTL of the answer's SOA record, RFC 2308 section 5, no longer than a CNAME that led there, and not at all without one; at most
  1000 names and about 1 MiB, and no answer of over 64 records), together with the other HTTPS records and the A/AAAA records the answer carried, which spare follow-up
  queries (RFC 9460 section 5; when only the A or only the AAAA records came, those are used at once and the other
  family is still looked up, joining the [Happy Eyeballs](client.md#happy-eyeballs) race whenever it answers), and forgotten
  when the network changes (`network { networkId }`, or the networks `http3 { migration }` follows); without either the engine
  cannot see a network change and keeps no answers
  of its own (RFC 9460 section 12: a forged record must not follow the device to the next network), so every request
  asks the source (the system resolver keeps its own cache); a failed lookup is not cached, and one lookup per name runs at a time, for at
  most the connect timeout (30 s at most); closing the client cancels the lookups still running.

`HttpsRecordSource.System` asks the operating system's resolver, so lookups follow the system's DNS settings:
`res_nquery` on Linux (JVM and Kotlin/Native), `DNSServiceQueryRecord` on macOS and iOS, `DnsQuery_W` on Windows, and
`DnsResolver.rawQuery` on the default network (Private DNS included) on Android from API 29. On Android API 24 to 28 there
is no public way to ask for a record type (and a resolver of the engine's own would bypass Private DNS), so every lookup
counts as failed there and requests behave as without records. At most four system lookups run at once per process.
`HttpsRecordSource.Exchange` works everywhere. Its queries carry ID 0 (RFC 8484 section 4.1: DoH clients "SHOULD use
a DNS ID of 0 in every DNS request") and the
engine checks the question of a response, not its ID, so the exchange must tie each response to its query: DNS over
HTTPS and DNS over TLS do; an exchange over plain UDP or TCP sets a random ID of its own in the query (its first two
bytes) and accepts only a response with that ID. An answer is read in time linear in its size, at most 65535 bytes
(RFC 8484 section 6: "This media type restricts the maximum size of the DNS message to 65535 bytes"), and
a lookup's timeout stops the read: a hostile resolver cannot hold a thread with one answer.

An `http://` request (not `ws://`, not through a proxy, not to an IP address) first looks up the records of the same URL
with `https` (port 80 becomes 443), waiting for the answer as an `https` request does (while the origin's addresses
resolve and `httpsRecordWait` longer; the whole lookup with a secure source); when the origin
has an AliasMode record or a ServiceMode record the engine could use, the engine answers `307 Temporary Redirect` to the
`https` URL itself, without connecting (RFC 9460 section 9.5). Ktor's `HttpRedirect` (on by default) follows it like any
307; with `followRedirects = false` the call sees the 307, and so does a POST, PUT or other unsafe request while
`HttpRedirect`'s `checkHttpMethod` is on (its default follows GET and HEAD only): set `checkHttpMethod = false` to have
those repeated over `https` too. An AliasMode record whose target is no host name counts as "." and does not upgrade. The upgrade is no more trusted than a 307 over cleartext:
nothing is remembered for the origin beyond the records' TTL. An origin that publishes HTTPS records but serves
different content on `http://` cannot be reached over `http://` by such a client.

## Racing and fallback

When HTTP/3 is an option (`Preferred`, an `http3 { hints }` entry, or a live Alt-Svc alternative) and no HTTP/3 connection to it is
open yet, the engine races connection setups (RFC 8305 section 5, after Chromium and curl): QUIC starts at once and
TCP + TLS starts when QUIC fails, or after a head start of 1.5 x the host's smoothed RTT (250 ms without history,
clamped to 100 ms..2 s: `RaceHeadStart.Adaptive`; `http3 { expert { raceHeadStart = RaceHeadStart.Fixed(d) } }`
overrides it) — and after 10 ms, the least RFC 8305 section 5 allows between two attempts, on a network where QUIC was
never seen working (`RaceHeadStart.NoRace` starts TCP only once QUIC failed, on any network). The TCP side is HTTP/2 when the server offers it (`raceEnded` reports `HTTP_2_0`), and an
HTTP/2 connection to the origin that is already open serves it at once. The request runs once, on the winner. A QUIC
setup that loses the race keeps going in the background and serves the next requests once it is up; a TCP connection
that loses goes back to the pool. When both setups fail, the TCP
failure is reported — the race was the one TCP attempt, there is no second one.

An alternative is marked broken only when HTTP/3 failed while TCP worked (a lost race, or a request that fell
back to TCP after the HTTP/3 connection failed as a whole: setup, QUIC transport, an HTTP/3 connection error; a
single stream reset or a malformed response falls back for that request only) — per origin and alternative, never "UDP is blocked" for everything: 5 minutes, doubling up to 2 days, and forgotten when the network changes
(`network { networkId }`, or the networks `http3 { migration }` follows). Broken alternatives are skipped (straight to TCP).
The first alternative marked broken on a network is one Warn line of the engine's logger: `HTTP/3 to <origin> failed
(<reason>); using TCP for <backoff>. See response.kuicksilverDiagnostics`; a network change arms it again. A server that refuses the QUIC setup with
`CONNECTION_REFUSED` (it is in `Drain`, stopping, or its accept queue is full: RFC 9000 section 5.2.2) has not shown the
alternative broken: that call falls back to TCP once (`fallback = Refused`), the alternative stays cached and
unmarked (RFC 7838 sections 2.2 and 3), and the next call tries HTTP/3 again. Any other close of the setup by the
server still marks it broken. Likewise a connection the server closes with H3_NO_ERROR after it sent GOAWAY (a graceful
stop whose grace period ended with requests still open: RFC 9114 section 5.2) ended in order: a request in flight on it
falls back to TCP when it may (idempotent, before its response), and the alternative is not marked broken; a close
with an error code after GOAWAY, or with H3_NO_ERROR but without a GOAWAY first, still marks it. So during a rolling restart the calls that meet a stopping instance fall back once each,
and the next calls use HTTP/3 again, instead of minutes to days of TCP for the whole origin.

## Stalled HTTP/3 connections

Some networks cut UDP flows: no answer to the first QUIC packet at all, or a handshake that completes and a flow that
stops carrying packets in both directions a moment later. On its own a QUIC connection notices only at its idle timeout
(RFC 9000 section 10.1; 30 s by default), so a request on it would wait that long before it fell back to TCP. The engine
watches the HTTP/3 connections it chose over TCP (`Auto`, `Preferred`, `http3 { hints }`; `http3 { stall { enabled } }`,
experimental, on by default) while a request runs on one: from before its wait for the handshake until its whole response arrived (the
server's FIN; from then on the exchange needs the network no more) or the call ended. The signal is the transport's,
never the response's:

- after the handshake, a connection is stalled when `stall { probeTimeouts }` probe timeouts in a row (3; RFC 9002
  section 6.2: a PTO fires only while ack-eliciting data goes unacknowledged, and doubles each time, so 3 of them take
  about 7 PTOs and grow with the RTT) went unanswered and no packet at all came back from the server for
  `stall { minSilence }` (2 s) since the first of them;
- before it (a request on a 0-RTT connection, `http3 { earlyData { } }`, on a network where QUIC worked before), when nothing at all
  came back from the server — not even an Initial — since the request started, for at least `minSilence` and two
  probe timeouts (they start from the 333 ms initial RTT and double, about 3 s: a slow path's handshake answers within
  them), instead of the connect timeout (10 s). Elsewhere the race already bounds that wait: on a network where QUIC was
  never seen working TCP starts 10 ms after QUIC ([Racing and fallback](#racing-and-fallback)), and a QUIC setup that
  loses keeps going in the background until its handshake timeout.

A slow server acknowledges the request while it thinks, and an idle long-lived response (a long poll, server-sent events
between two events) has nothing in flight: neither shows a probe timeout, so neither is a stall. Such a quiet watched
connection sends a PING now and then (RFC 9000 section 10.1.2: after half of `minSilence` without a packet, then at
twice the previous gap, up to 15 s or half the idle timeout in force, the smaller of both sides', whichever is shorter),
so that a path cut while nothing is in flight shows as well: a live server acknowledges it, a dead path turns it into
probe timeouts. Between two PINGs the watch sleeps. The PINGs also keep the connection open past the idle timeout while
a request waits for its response, as RFC 9114 section 5.1 expects of a client ("HTTP clients are expected to request
that the transport keep connections open while there are responses outstanding"). Each PING wakes the radio of a
mobile device: a client that holds long-lived responses open on a mobile network for minutes (a long poll, server-sent
events) may prefer `stall { enabled = false }` for them, or for the whole client.

On a stall the engine drains the connection: it takes no new request, the alternative is marked broken for its origin
(RFC 7838 section 2.4: 5 minutes, doubling; the backoff of a stall carries over the handshakes that work in between,
since such a network lets handshakes through, and walks one level back down for each later connection that carried a
whole exchange and that the client closed in order without it ever stalling; one that stalls after its first exchanges,
or dies by an idle timeout, never lowers it), and then, per request:

- a request that may be repeated — an idempotent method (RFC 9110 section 9.2.2: GET, HEAD, OPTIONS, PUT, DELETE,
  TRACE), a body that can be sent again (bytes, a writer, none), and no response yet — goes over TCP at once
  (`fallback = QuicStalled`, the `fallback` event with a `QuicStalledException`, one `altSvcMarkedBroken` per stalled connection);
  a request that waited for the handshake, or was handed the connection as it stalled, was never sent and goes over
  TCP whatever its method;
- any other (a POST, a streamed body) and a response body under way wait on: a short outage (a handover between radio
  networks, Wi-Fi roaming) that ends — any packet from the server — lets them finish over HTTP/3. When the path stays
  silent for `stall { abandonAfter }` (10 s) after the stall, or the QUIC idle timeout comes first, they fail with
  `QuicStalledException` (its `silence` and `probeTimeouts` say what was seen) and the connection is closed. A
  response that began is never repeated. A drained connection that came back closes once nothing runs on it any more,
  a WebSocket or WebTransport session that shared it included.

The engine does not honour an `Idempotency-Key` header (draft-ietf-httpapi-idempotency-key-header, not an RFC yet): a
POST that carries one is still not repeated; the application may send it again itself.

`stall { enabled = false }` waits for the QUIC idle timeout as before 0.3.0. `H3Only` (no TCP to go to), WebSockets and
WebTransport sessions are not watched.

## Turning HTTP/3 off remotely

`http3 { allowed = { ... } }` (stable) is a kill switch an application can flip from its remote
configuration (Firebase Remote Config, LaunchDarkly, its own config endpoint) when QUIC misbehaves on some network or
release, in the manner of Chrome's `QuicAllowed` policy or Cronet's `enableQuic(false)`, but per request and without a
restart. The engine calls it once per `https://` request, on the call's coroutine, before anything connects; it must
answer at once without blocking, so read a value your configuration keeps up to date:

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val remoteConfig = MutableStateFlow(true)
// guide:ktor:http3-switch
val quicAllowed: StateFlow<Boolean> = remoteConfig // updated by your remote configuration
val client =
    HttpClient(Kuicksilver) {
        engine { http3 { allowed = { quicAllowed.value } } }
    }
// to take HTTP/3 off at once, not only for the next requests:
client.closeHttp3Connections()
```

What it does while it returns false:

- requests go over TCP (HTTP/2 or HTTP/1.1), as with `http3 { enabled = false }`; `protocolSelected` and the response's diagnostics say
  `Http3Disabled` ([Why did this request not use HTTP/3?](observability.md#why-did-this-request-not-use-http3));
- with `discovery = H3Only` a request fails with `UnsupportedOperationException` before it opens any TCP or UDP
  connection: that mode promises never to use TCP;
- `HttpClient.webTransport` fails the same way: WebTransport has no TCP fallback;
- open HTTP/3 connections take no new requests; calls already running on them finish, and idle connections close after
  `pool { idleTimeout }`;
- `Alt-Svc` is still learned in `Auto` mode, so when the switch returns true again the next request goes to the known
  alternative without a warm-up.

`HttpClient.closeHttp3Connections()` takes HTTP/3 out of use at once, whatever the switch says: every established
pooled connection gets a GOAWAY and no further request (a request that had just been handed one, before its stream
opened, goes again on a new connection or, switched off, the next call goes over TCP), calls running on them
finish, and each closes when its last call is done; a connection still being set up serves the requests already
waiting for it and then closes; a race's own HTTP/3 setup still serves the request it was made for. A request refused
by that GOAWAY before anything of it went out is repeated on a new connection, a streamed body included (it was never
read). Every WebTransport connection gets a GOAWAY and every open session `WT_DRAIN_SESSION`: the server is asked to
wind the session down, the session's own `drainRequested` turns true so the application winds down too, and the
session stays open until either side closes it. A `webTransport` call whose CONNECT had not gone out yet fails with
`IllegalStateException` naming `closeHttp3Connections()`; one whose CONNECT completes after the call is drained as soon
as it opens. The call returns once
those frames are written, waiting at most 5 seconds for each.

The switch is not called for `http://` requests or with `http3 { enabled = false }`. A switch that throws an exception counts as true (HTTP/3
allowed), so a broken configuration cannot take down traffic; the engine logs that at `Warn`, at most once per 5
minutes. A `CancellationException` or an `Error` out of it fails the call instead.

## Connection migration

`http3 { migration = ... }` (experimental, off by default) lets the engine's pooled HTTP/3 connections follow
the device's network (RFC 9000 section 9): when the default network changes, say from Wi-Fi to the mobile network,
each connection opens a socket on the new network, validates the path to the server and moves there, so a download
and the requests in flight carry on. Without it, as in 0.2, the outcome depends on the system: the engine's socket is
bound to no network, so the system may send its datagrams over the new default network from a new address, which the
server then takes as a NAT rebinding (RFC 9000 section 9.3; that is what an Android emulator does when its default
network goes away), or keep them on an interface that is gone, and then the connection ends at its idle timeout (an
idempotent request still waiting for its response falls back to TCP). What the option adds over such a rebinding:

- the move is the client's decision, made when the system reports a new default network, not whenever the system
  happens to route a datagram elsewhere, and it does not depend on which network the system picks for an unbound socket
  (the new socket is bound to the new network: `Network.bindSocket`, `IP_BOUND_IF`);
- the new path is validated before the connection sends on it, and the connection stays where it was when it fails;
- the new path uses a fresh connection ID from the server, so the two networks' traffic cannot be linked by it (RFC
  9000 section 9.5); a rebinding keeps the old one;
- on iOS a socket the system reclaimed while the app was suspended is replaced.

On Android:

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val connectivity = context.getSystemService(ConnectivityManager::class.java)
// inside HttpClient(Kuicksilver) { engine { http3 { ... } } }:
// guide:ktor:android-migration
migration = Http3ConnectionMigration.followDefaultNetwork(connectivity)
```

On iOS and macOS, `Http3ConnectionMigration.followDefaultNetwork()` does the same with the Network framework
(`NWPathMonitor`, sockets bound to the new interface; it also replaces a socket iOS reclaimed while the app was
suspended). These are the `NetworkMigrator`s of [QUIC: Network changes](quic.md#network-changes), one per
connection over one shared system callback. The JVM, Linux and Windows have no network source of their own: pass
`Http3ConnectionMigration { connection, scope -> NetworkMigrator(connection, yourNetworks, yourOpenIo, scope) }`.

What the engine does:

- it starts the migrator once the connection's handshake has completed (a 0-RTT connection serves early requests
  first) and closes it when the connection closes (idle, lifetime, `closeHttp3Connections()`) or the client closes;
- the QUIC rules hold whatever the source says: no new path before the handshake is confirmed, none towards a server
  that sent `disable_active_migration` or uses zero-length connection IDs (RFC 9000 sections 9 and 9.5; no packet leaves
  the new socket), and every new path is validated before the connection sends on it. A refused or failed move leaves
  the connection where it was;
- every step reaches `KuicksilverEventListener.connectionMigrated(origin, event)`: `Migrated`, `Failed` (also logged at
  `Info`, or at `Debug` when the server does not allow migration), `NetworkLost` (the connection waits; its idle
  timeout decides if no network comes back) and `SourceFailed`;
- a migration itself neither marks the alternative broken nor forgets marks, but while `network { networkId }` is not set the
  network the factories follow (`Http3ConnectionMigration.networks`) is the engine's network: a new one gives
  alternatives marked broken on the old one a fresh chance, drops the alternatives without `persist=1` (RFC 7838 section
  2.2) and flushes the HTTPS record cache, as a `networkId` change does, within the limits of the platform's handle
  ([Discovery and Alt-Svc](#discovery-and-alt-svc)). A `networkId` that is set wins.

A WebSocket over HTTP/3 (RFC 9220) is one stream of a pooled connection, so it moves with it: the session carries on
across the switch, with no reconnect, and every message arrives once and in order, in both directions, a fragmented
message whose first half crossed the old network included, and so do pings and the closing handshake with its code
and reason (`ClientMigrationTest.webSocketSurvivesNetworkSwitch`, `.webSocketSurvivesNetworkSwitchServerCloses`: over
loopback, the old socket hears nothing once the connection moved). That needs the option and a server that allows
active migration: without the option, or towards a server that sent `disable_active_migration`, the session ends with
the old network, once the connection's idle timeout has passed: `incoming` fails and `closeReason` is 1006 (RFC 6455
section 7.1.5; `.negative_webSocketEndsWithItsNetworkWithoutMigration`,
`.negative_webSocketEndsWithItsNetworkWhenServerDisablesMigration`). A WebSocket goes over HTTP/3 only with `H3Only`
or on a connection to its origin that is open already and whose server allows Extended CONNECT ([HTTP/3 on the
client](#http3-on-the-client)); otherwise it opens over HTTP/1.1 or HTTP/2.

What does not survive a network change: HTTP/1.1 and HTTP/2 run over TCP, which cannot move, and so do WebSockets over
HTTP/1.1 and HTTP/2; a call on such a connection fails and the application repeats it. The extra connections a
server's WebTransport session limit makes (beyond the pooled one) do not follow the network either.

The Compose Multiplatform demo, [samples/compose-demo](../../samples/compose-demo/README.md) (Android and iOS, not
published), shows both sides: a download over HTTP/3 with `followDefaultNetwork` and the same download over OkHttp
(Android) or CIO and Darwin (iOS), while Wi-Fi is turned off, with the `connectionMigrated` events, an optional resume of
the TCP download with `Range`, and the limits of such a comparison on an emulator.
