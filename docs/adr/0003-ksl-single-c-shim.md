# ADR-0003. One narrow C shim `ksl` with a shared header for JNI and cinterop

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Context

We need JNI (JVM, Android) and cinterop (Native) bindings to OpenSSL. Direct cinterop to `openssl/ssl.h` pulls in a huge API, and JNI to the same API would have to be written separately. OpenSSL callbacks into Kotlin are upcalls from C, expensive and complicated on both bindings.

## Decision

One shim `ksl` (`ksl.h`, a stable C ABI, a few dozen functions). JNI and cinterop bind to the same header. Inside: TLS contexts, the QUIC TLS interface, AEAD/header protection by key handle, TLS over TCP through memory (memory BIO), certificate verification with a pause. OpenSSL callbacks are implemented in `ksl` and push events into an internal queue; Kotlin drains it by polling. There are no upcalls from C into Kotlin. Secrets never leave native memory: Kotlin only receives key handles.

## Consequences

- One set of functions for fuzzing (libFuzzer) and for both bindings.
- All sockets stay in Kotlin → TLS over any channel.
- The initial estimate was ~30 functions; the sketch gives ~40 (separate TCP, UDP and KslCrypto groups).

## Implementation (2026-10-02)

`ksl.h` closed at 50 functions (`KSL_ABI_VERSION 1`): options and getters go through selectors (`ksl_ctx_set_option`, `ksl_ssl_get`), one `ksl_drive` serves QUIC and TCP, the event queue has `peek` (an event that does not fit the JNI buffer stays in the queue). The CRYPTO buffer is not reallocated while a record is handed to OpenSSL (`rcd_level` + stash). Errors are copied into the object in the same call; alerts are recorded by the info callback in both modes. JNI (`RegisterNatives`, `JNI_OnLoad` 1_8/1_6) and cinterop (`ksl.def`, `staticLibraries`) bind to the same header; on K/N handles are `Long` via `interpretCPointer`.

## Endpoint keys (2026-10-08)

Retry token and stateless reset keys live in `ksl` and never reach Kotlin (secrets stay in native memory; see docs/architecture.md, `kuicksilver-native`): `ksl_key_random(KSL_EKEY_TOKEN)` creates
an AES-256-GCM key from 32 random bytes for `ksl_seal`/`ksl_open` (the token nonce is a 64-bit "packet number"), `ksl_key_random(KSL_EKEY_RESET)` creates
an HMAC-SHA256 key for `ksl_key_mac16` (the first 16 bytes of a MAC over the CID). Both objects are immutable after creation, `ksl_key_mac16` is safe for
concurrent calls (one MAC context per call). The reset key is deliberately separate from the CID generator (lesson of Netty CVE-2026-50009) and random per process:
after a restart the server cannot reset old connections — a persistent key would require passing the secret through Kotlin. `ksl` ABI 3,
51 functions (the ceiling of 50 was raised by owner decision 2026-10-08). The accelerated UDP work (2026-10-08) added `ksl_udp_open/send/recv/get/shutdown/close` — 57 functions in the same ABI 3 (56 were planned: a separate `ksl_udp_shutdown` is needed to wake a blocked receive from another thread without freeing the object, see ADR-0006, "History"). Also on 2026-10-08: one tuple of key exchange groups on both contexts (`X25519MLKEM768:X25519:…`), otherwise OpenSSL answered clients with a single X25519 share with a HelloRetryRequest.
In Kotlin these are `QuicCrypto.newTokenKey()`/`newResetKey()` (`TokenKey`, `ResetKey`); `NullCryptoProvider` gives deterministic variants for the simulator.

## ABI 4: sessions stay in `ksl` (native-tls review, 2026-10-08)

`KSL_GET_SESSION` handed Kotlin `i2d_SSL_SESSION` — with the TLS 1.2 master secret and the TLS 1.3 resumption PSK — and `SessionCache` kept these bytes on the heap for up to 7 days, contrary to the decision "secrets never leave native memory". ABI 4: an opaque `ksl_session` (an `SSL_SESSION` with reference counting): `ksl_ssl_get1_session` (a new reference or `NULL`; the same pointer while the session has not changed), `ksl_ssl_set_session(ksl_ssl *, ksl_session *)` instead of serialized bytes, `ksl_session_free` (the last reference wipes the secret in `SSL_SESSION_free`); selector 3 of `ksl_ssl_get` no longer returns anything. An incompatible change — `KSL_ABI_VERSION 4`, `KslLoader` rejects an ABI 3 library (`KslException.AbiMismatch`). Also in ABI 4: `ksl_ctx_set_session_context`: the `sid_ctx` of a server context, derived from its trust configuration; a ticket resumes only under the same context, otherwise OpenSSL performs a full handshake. 60 functions.

## ABI 5: identity keys stay in `ksl` (2026-10-12)

`TlsIdentity.InMemory` kept the PKCS#8 DER of the private key in a Kotlin `ByteArray` for the identity's lifetime and handed it to `ksl_ctx_set_identity` for every context, so a JVM heap dump of a running server contained its key. ABI 5: an opaque `ksl_pkey` (an `EVP_PKEY` with reference counting): `ksl_pkey_new` parses the DER once (exactly one key, no trailing bytes), `ksl_ctx_set_identity_pkey` installs it with the context's own reference, `ksl_pkey_free` drops a reference (the last one frees the key, whose private part OpenSSL clears). Kotlin keeps only the handle; `fromDer`/`fromPem` wipe the caller's array and the JNI copy. `ksl_ctx_set_identity` (DER) stays for C callers and tests. An incompatible change for the Kotlin bindings — `KSL_ABI_VERSION 5`. 63 functions.

## Live-object counters, additive in ABI 6 (soak, 2026-10-13)

The soak harness (`kuicksilver-soak`) needs to see native objects that the Kotlin heap cannot: `ksl_live_objects(int64_t *out, size_t n)` reports, process-wide, the `ksl_ctx`, `ksl_ssl` and `ksl_key` objects alive, the `ksl_pkey` and `ksl_session` handle references handed out and not yet dropped, the open `ksl_udp` objects and the wake descriptors they hold (`KSL_LIVE_*` indices, `KSL_LIVE_COUNT` = 7). Relaxed 32-bit atomics, one add per create and free; no allocation, no lock. The function is additive and changes nothing an ABI 6 caller relies on, so `KSL_ABI_VERSION` stays 6, as ABI 3 took `ksl_udp_*` without a bump: the Kotlin bindings and the library ship together (the loader checks the number, and a library from another release fails that check before any call). In Kotlin it is `Ksl.liveObjects()` (internal). 64 functions.

## Session ticket keys, additive in ABI 6 (security review, 2026-10-14)

The server's session ticket keys were generated in Kotlin and handed to every context as bytes, so they sat on the JVM heap for the life of the process, against the decision that secrets stay native. Three additive functions keep them in `ksl` (`ksl_tickets.c`): `ksl_ctx_use_default_ticket_keys(ctx, rotate_seconds)` gives a context the process-wide generated keys (current and previous, generated with `RAND_priv_bytes` and rotated under a lock when the current one is `rotate_seconds` old on the wall clock), `ksl_ticket_keys_register(keys, n)` copies explicit keys in once and returns an id (the same id for the same keys; at most 1024 distinct sets, 64 keys each, kept for the life of the process), `ksl_ctx_use_ticket_keys(ctx, id)` gives a context that set. Each context copies what it uses and cleanses it when freed. `ksl_ctx_set_ticket_keys` (bytes) stays for C callers and tests; the Kotlin binding of it is gone. Additive, so `KSL_ABI_VERSION` stays 6 (as for the live-object counters above). 67 functions.

The system CA store behind `ksl_ctx_set_roots(ctx, NULL, 0)` is parsed once per process and shared by reference between contexts (`ksl_trust_cache.c`, security review 2026-10-14); no function is added.

## Additions recorded late (ABI 6)

Three further functions are in ABI 6 and were not recorded above. `ksl_ctx_verify_chain` (security review, 2026-10-14)
re-verifies a cached chain when a session resumes (ADR-0011); it was added before ABI 6 was published, together with the
0-RTT controls (`KSL_OPT_EARLY_DATA`, `KSL_SET_EARLY_CONTEXT`, `KSL_SET_EARLY_DATA`, `KSL_GET_EARLY_DATA`, ADR-0015) that
made ABI 6 incompatible with ABI 5. `ksl_win_sockets_start` and `ksl_win_sockets_started_by` start Winsock once per
process and record who started it (ADR-0006, Windows); they are additive. 70 functions.

## ABI 7 (0.3.0): ICMP hints for PMTUD

`ksl_udp_take_ptb` (Packet Too Big from the Linux error queue) and `ksl_udp_emsgsize` (sends lost to EMSGSIZE), and a
`ksl_udp_recv` that no longer answers `KSL_ERROR` for a queued ICMP error (ADR-0006, "Linux and Android"). The functions
alone would be additive, but the receive behaviour changes and the 0.3.0 plan bumps once for every `ksl.h` change of the
release: `KSL_ABI_VERSION 7`, and later 0.3.0 additions go under 7. 72 functions. Under 7 as well: the error code `KSL_E_BIND`
(0xff000c: `ksl_udp_open` whose bind was refused; other steps keep their codes), and `ksl_tcp_read` answering `KSL_OK`
with nothing read when it must write first and the pair is full (it answered `KSL_WANT_READ`), and the local-address calls of a
wildcard UDP socket: `KSL_UDP_PKTINFO`, `ksl_udp_send_src` (a source per slot) and `ksl_udp_recv_dst` (each datagram's
destination), additive (ADR-0006, "Local addresses on a wildcard bind"); 74 functions. Also additive under 7:
`ksl_chain_level` and `KSL_OPT_LEVEL_AFTER_PAUSE` (OpenSSL's security level on the path the platform verifier built,
checked after its yes under `TrustConfig.Platform`, instead of on the presented chain before the pause; T.5b); 75 functions.

DNS query, additive under 7 (L1.2, HTTPS records for the Ktor client): `ksl_dns_query(name, type, server, timeout_ms, out,
cap, len)` asks the operating system's resolver for one record type, so the lookup follows the system's DNS settings:
`res_nquery` on Linux (`libresolv.so.2`, a new `DT_NEEDED` of the Linux libraries; glibc ships it, and the symbols are
older than the glibc floors), `DNSServiceQueryRecord` on Apple (libSystem), `DnsQuery_W` on Windows (`dnsapi.dll`).
Linux returns the whole DNS message, Apple and Windows a list of records (they hand out records, not messages); the first
byte of `out` says which. Android answers `KSL_DNS_NOT_SUPPORTED` (no public call below API 29: Kotlin asks
`DnsResolver.rawQuery` there). No state, no threads; the call blocks for about `timeout_ms` at most (on Linux about max(`timeout_ms`, one second per configured nameserver), every nameserver asked and the tries and waits sized to the budget, plus a possible TCP retry of a truncated answer), except on Windows,
whose call takes no timeout: Kotlin stops waiting and lets it end, at most four lookups at a time per process. 76 functions.

QUIC-LB block key, additive under 7 (routable server connection IDs, draft-ietf-quic-load-balancers-21 section 5.4):
`KSL_EKEY_LB`, `ksl_key_lb(key[16])` copies a configured AES-128 key into a `ksl_key` (the JNI copy and the Kotlin array are
wiped; the object is cleansed on `ksl_key_free`), `ksl_key_random(KSL_EKEY_LB)` makes a random one inside `ksl` (the key
that permutes plaintext nonces), `ksl_key_lb_dup(key)` an independent copy (an endpoint holds its own copy of each
configuration key, so the caller may close theirs), `ksl_key_lb_derive(key, label[16])` makes the key whose bytes are `key`'s encryption of
`label` (the nonce permutation key of an encrypted configuration, so its bytes never reach Kotlin either), and
`ksl_key_ecb16(key, decrypt, in, out)` runs one AES-128-ECB block. The key schedule is expanded once into two template
contexts at creation; each call runs on an `EVP_CIPHER_CTX_copy` of one, so the key object is immutable and the loops of a
group share it, and an attacker-triggered check (the Stateless Reset gate) costs no key expansion. An LB key has no AEAD or
header-protection context, so `ksl_seal`, `ksl_open`, `ksl_header_mask`, `ksl_key_mac16` and `ksl_key_next` refuse it.
Kotlin: `QuicCrypto.newLoadBalancerKey` (`LoadBalancerKey`, with `derive` and `duplicate`), `KslLbKey` (internal).
`test_key.c` `lb_key_concurrent_ecb16` runs one key on eight threads (clean under `KSL_TSAN=1`). 80 functions.

Send-only UDP clones, additive under 7 (several endpoint loops on one socket where the kernel does not balance
`SO_REUSEPORT`): `ksl_udp_sender(base, err, msg, msglen)` makes a clone of a `ksl_udp` that shares its descriptor, has its
own send scratch and refuses to receive (`KSL_E_NOT_SUPPORTED`); the descriptor closes with the last `ksl_udp_close` of
the group (ADR-0006, "One socket, several senders"). With it the error code `KSL_E_NO_MEMORY` (0xff000d): a failed
allocation in `ksl_udp_sender` or `ksl_udp_open`, which answered `KSL_E_BAD_ARG` for it before. JNI `KslNative.udpSender`, cinterop `ksl_udp_sender`, Kotlin
`Ksl.udpSender` and `KslUdpSocket.sender()`. 81 functions.

Renegotiation report, additive under 7 (HTTP/2 over TLS 1.2, RFC 9113 section 9.2.1: "An endpoint MUST treat a TLS
renegotiation as a connection error (Section 5.4.1) of type PROTOCOL_ERROR"): OpenSSL refuses every renegotiation itself
(`SSL_OP_NO_RENEGOTIATION`, a no_renegotiation warning) and the session went on without a word to the caller. The message
callback of a TCP session (`ksl_msg_cb`) now counts what asks for one on an established TLS 1.2 session, a HelloRequest to a
client or a ClientHello to a server, before OpenSSL refuses it; the getter `KSL_GET_RENEGOTIATION` (11, one byte) reports it, and
the `ksl_tcp_read` that refused one answers `KSL_OK` with nothing read, as for a read that must write first, so that the caller
drains the warning and looks before it reads what the peer sent after it. No function is added: 81 functions. Kotlin:
`KslConst.GET_RENEGOTIATION`; `TlsConnection` fails the input of an `h2` connection with it, and the HTTP/2 client turns that
into PROTOCOL_ERROR.

Per-family resolution and local address state, additive under 7 (Happy Eyeballs, RFC 8305 sections 3 and 4):
`ksl_resolve(name, family, out, cap, len)` is `getaddrinfo` with `AF_INET` or `AF_INET6` alone (`KSL_ADDR_V4`,
`KSL_ADDR_V6`; flags of its own, so Apple's `AI_V4MAPPED` default cannot make the IPv6 query wait for the A answer, and
IPv4-mapped answers are left out), each address a `KSL_RESOLVE_ENTRY_LEN` entry (family, 16 address bytes, scope id),
`KSL_DNS_NOT_FOUND` for none of that family, the first ones when more than `cap` holds: the JVM's and Android's `InetAddress` asks for both families in one call, and
RFC 8305 section 3 wants them apart. `ksl_addr_info(addr, len, scope, prefix_len, flags)` reports one of the host's own
addresses for RFC 6724 section 6: its on-link prefix length (`getifaddrs` netmask; Windows `OnLinkPrefixLength`) and
`KSL_ADDR_DEPRECATED` (Linux and Android: an `RTM_GETADDR` netlink dump, no file, as `/proc/net` is closed to Android apps; macOS `SIOCGIFAFLAG_IN6`, Windows `DadState`) and `KSL_ADDR_TUNNEL`
(Linux `sll_hatype` sit, ipip, ip6tnl, GRE; Apple `IFT_GIF`, `IFT_STF`; Windows `IF_TYPE_TUNNEL`). Windows loads
`iphlpapi.dll` for that call alone (`LoadLibraryExW` from System32), so no import library is added. No state, no threads;
`ksl_resolve` blocks for as long as the system resolver takes. `ksl_nat64_synthesize(v4, out, cap, len)` gives the IPv6
addresses the platform synthesizes for an IPv4 address with its own NAT64 prefixes: Apple's documented way, `getaddrinfo`
of the literal with `AI_DEFAULT` (`nw_nat64_copy_prefixes` is not public API); `KSL_DNS_NOT_SUPPORTED` elsewhere, where
Kotlin discovers the prefix by RFC 7050. JNI `KslNative.resolve`, `KslNative.addrInfo`, `KslNative.nat64Synthesize`,
cinterop the same, Kotlin `Ksl.resolve`, `Ksl.addrInfo`, `Ksl.nat64Synthesize` and `KslNet` (internal). `test_net.c`.
84 functions.
