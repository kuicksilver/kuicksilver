# ADR-0020. A pluggable name resolver for the Ktor client engine (`dns`)

Date: 2026-11-18. Status: accepted (0.3.0 feature parity, item 6 of the plan of 2026-11-16).

## Context

Until 0.3.0 the client engine resolved names only with the system's resolver (`getaddrinfo` once per address family,
RFC 8305 section 3; [RFC 8305](../spec/rfc/8305.md#s4-tcp-address-race)). Applications need their own: DNS over HTTPS
through a client they trust, fixed addresses for some names, a split-horizon policy, a test that points a name at a local
server. The reference stacks offer it:

- OkHttp's `Dns` (`okhttp3/Dns.kt`, 5.3.2, lines 30–37) is one blocking method, `lookup(hostname): List<InetAddress>`,
  called on the call's thread, with `Dns.SYSTEM` to delegate to. `RouteSelector.resetNextInetSocketAddress`
  (`okhttp3/internal/connection/RouteSelector.kt`, lines 138–190) never asks it for an IP literal (line 165), asks it for
  an HTTP proxy's host instead of the origin's (lines 145–155), gives a SOCKS proxy the origin's name unresolved (lines
  161–162), turns an empty answer into `UnknownHostException` (lines 171–172), and only interleaves the families of the
  answer for fast fallback (lines 180–184, `InetAddressOrder.kt`), keeping the resolver's order otherwise. It does not
  filter the answer.
- Netty's `AddressResolverGroup` (netty-resolver 4.2.17; no source in the local caches, read from the class files) is
  asynchronous: one `AddressResolver` per event loop whose `resolve` returns a `Future`, set with `Bootstrap.resolver`;
  `NoopAddressResolverGroup` leaves addresses unresolved for a proxy handler to send by name.
- Ktor's `HttpClientEngineConfig` (3.6.1) has no resolver; Ktor's CIO engine has its own,
  `CIOEngineConfig.dnsResolver: suspend (String) -> List<String>` (3.6.1, with a UDP `CioDnsResolver`).

## Decision

- **`KuicksilverEngineConfig.dns: Dns`, experimental.** `Dns` is a `fun interface` with one suspending method,
  `lookup(host): List<IpAddress>`; `Dns.System` is the default and is the engine's existing system path, unchanged
  (the same shared, bounded lookups, cache, NAT64 handling and order). Suspending, as Ktor's CIO and Netty's are, because
  the engine is coroutine-based and must not lose a thread per stalled lookup; `Dns.blocking { }` adapts a blocking
  resolver (OkHttp's shape) by running it on a pool of its own (8 threads by default) that a caller stops waiting for when
  it is cancelled or times out. `FamilyDns` answers each family on its own, for RFC 8305 section 3's separate queries.
  `IpAddress` is our own type (common code has none); `IpAddress.of(InetAddress)` converts on the JVM and Android.
- **The engine owns the order.** RFC 8305 section 4 says the client MUST sort the addresses by RFC 6724, so the engine
  sorts and interleaves an application's answer exactly as it does the system's; the resolver's order breaks ties only.
  OkHttp keeps the resolver's order; we do not, because the RFC leaves no choice.
- **What it is asked for.** Host names only, once per name per request (the h3/h1 race and a fallback share the answer).
  IP literals never reach it (as OkHttp), nor a host with the form of an IPv4 address that is not a dotted quad: one
  every platform reads alike (`127.1`) is its address, one platforms read differently (octal, hex) fails without a lookup
  (no host name has that form, RFC 1123 section 2.1). The origin's name, an `Alt-Svc` alternative's host and an HTTPS
  record's target, over TCP and QUIC, and a proxy's name; never the origin's behind an HTTP proxy or `socks5h` (as
  OkHttp and Netty's proxy handlers), but the origin's through `socks5`, where the engine resolves by definition. HTTPS
  records, the NAT64 prefix discovery and a PAC script's `dnsResolve` stay with the system: they have sources of their
  own (`http3.httpsRecords`) or are the platform's.
- **Its answers are untrusted for identity and checked as destinations.** SNI and certificate verification (and pins)
  use the URL's host, never the answer, over TCP and QUIC. Duplicates go, an IPv4-mapped address becomes IPv4, at most
  32 addresses per family are kept, and unspecified (0.0.0.0/8, `::`), multicast and limited broadcast addresses are
  dropped: RFC 1122 section 3.2.1.3 and RFC 4291 section 2.5.2 forbid them as destinations, RFC 9293 section 3.9.1
  (MUST-46) makes a TCP open to a multicast address an error, and a connect to 0.0.0.0 reaches the host's own listeners on
  Linux and macOS. The system path keeps its behaviour as it was (a requirement of this item: the default unchanged); the
  operating system's TCP refuses multicast there, and an answer of 0.0.0.0 from the system resolver is the open item below.
- **Failures and time.** An exception, an empty answer or one without a usable address fails the connection with the
  engine's existing `IOException` for a name that does not resolve, the resolver's exception as the cause. The lookup is
  part of connecting: the connect timeout bounds it and the call's cancellation cancels it. A `CancellationException` the
  resolver throws while its caller is active is a failed lookup.

## Consequences

- One code path for all lookups: the per-request `RequestDns` takes the application's resolver where it took the system's,
  so Happy Eyeballs, NAT64 synthesis, the RFC 6724 sort, the per-request sharing and every caller (TCP, QUIC, WebSocket
  keys, SOCKS5 targets, WebTransport, HTTPS-record endpoints) behave the same whichever resolver answers.
- The engine caches nothing across requests for an application resolver: TTLs are its business, as in OkHttp.
- New public API: `Dns`, `FamilyDns`, `IpAddress`, `KuicksilverEngineConfig.dns`, `IpAddress.Companion.of(InetAddress)`;
  all experimental.

## Alternatives rejected

- **OkHttp's blocking signature as the interface.** It would block an engine thread per lookup and could not be cancelled;
  the adapter gives blocking resolvers the same shape without that cost.
- **Keeping the resolver's order (OkHttp).** RFC 8305 section 4 makes the RFC 6724 sort a MUST.
- **Filtering 0.0.0.0 and multicast on the system path too.** Right on the merits, but it changes the default, which this
  item must not; recorded as an open item of [threat model 3.25](../spec/threat-model.md#325-an-application-name-resolver-dns).
- **Passing numeric hosts such as `127.1` to the resolver.** A resolver that hands them to `getaddrinfo` would read
  `010.0.0.1` as octal and another resolver as decimal; the engine decides once.
