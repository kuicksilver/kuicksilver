<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# TLS in the Ktor engines

**What this page is for.** The TLS tasks of the client and server engines: certificate pinning, client
certificates (mutual TLS), reloading a renewed certificate, a certificate per host name (SNI), TLS 1.2 for old clients and
Encrypted Client Hello.

**Before you start**

- A server certificate from PEM files, and a local test certificate: [Quickstart](quickstart.md#3-a-server). Trust and
  certificates below the engines (`TrustConfig`, `TlsIdentity`, TLS over a socket): [TLS](tls.md).
- The imports of the code blocks: [Ktor engines: Imports](ktor.md#imports).

## Certificate pinning

A client that talks to its own servers can pin their keys on top of the certificate checks: `TrustConfig.Pinned` in the
engine's `tls { trust }` accepts a server only when its chain verifies against `base` (the platform's store by default)
and the public key (SPKI, SHA-256) of its leaf is one of the pins:

```kotlin
// guide:ktor:pinning
val pinned = HttpClient(Kuicksilver) {
    engine {
        tls {
            trust = TrustConfig.Pinned(
                setOf(
                    SpkiSha256.parse(currentPin),   // your server's key: "sha256/<base64>", made as below
                    SpkiSha256.parse(backupPin),    // a backup key you hold offline
                ),
                base = TrustConfig.Platform,   // the chain is still verified; the pin comes on top
            )
        }
    }
}
```

A pin is `sha256/` and the base64 SHA-256 of the key's SubjectPublicKeyInfo, the text OkHttp's `CertificatePinner`
uses. From the server's certificate:

```sh
openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64
```

- The pins hold for every host the client talks to: give a pinned API a client of its own.
- The pins hold for every protocol: HTTP/3 over QUIC and the TCP fallback (HTTP/2, HTTP/1.1) use the one `tls { }`, so a
  blocked UDP path never leads to a connection with weaker checks. A pin never replaces the name check.
- Pin a backup key you hold offline as well, or a key change locks the app out until it is updated.
  `scope = PinScope.AnyInValidatedChain` matches any certificate of the validated chain (an intermediate CA's key, say)
  instead of the leaf.
- A `Pinned` trust names the origin's keys, so the TLS to a proxy (`proxies { tls { } }`, [Proxies](client-proxies.md#proxies)) starts
  from its `base` instead. The variants and their rules: [TLS: Trust](tls.md#trust).

## Mutual TLS (client certificates)

A server that admits only clients with a certificate from its own CA sets `clientAuth = ClientAuth.Required` and a
`clientTrust` in its `tls { }` (the engine's, for every TLS connector, or one connector's own `tls { }` for that port
only):

```kotlin
val clientCaPem = File("client-ca.pem").readText()
// guide:ktor:mtls-server
val clientCa = Certificate.parsePem(clientCaPem)   // the CA that issues the client certificates
val server = embeddedServer(Kuicksilver, configure = {
    tls {
        identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        clientAuth = ClientAuth.Required                 // no handshake without a client certificate that chains to clientCa
        clientTrust = TrustConfig.AnchoredCa(clientCa)   // or clientCaFile("/etc/kuicksilver/client-ca.pem")
    }
    tlsConnector { port = 443 }
}) {
    routing {
        get("/whoami") { call.respondText("client ${call.request.peerCertificates.first().dnsNames}") }
    }
}
server.start(wait = true)
```

The client presents its certificate with `tls { identity }`, for HTTP/3, HTTP/2 and HTTP/1.1 alike:

```kotlin
// guide:ktor:mtls-client
val identity = TlsIdentity.fromPem(clientChainPem, clientKeyPem.toCharArray())   // every target; the key array is zeroed
val client = HttpClient(Kuicksilver) {
    engine {
        tls {
            this.identity = identity                                            // presented over HTTP/3, HTTP/2 and HTTP/1.1 alike
            trust = TrustConfig.AnchoredCa(Certificate.parsePem(serverCaPem))   // or keep Platform for a public server certificate
        }
    }
}
```

- **The server.** `clientAuth` is `None` (the default), `Optional` (a certificate is asked for; a client without one
  still connects, and `peerCertificates` is empty) or `Required` (the handshake fails without one). Any value but `None`
  needs `clientTrust = TrustConfig.AnchoredCa(...)` (optionally inside `TrustConfig.Pinned`, the only trust for client
  certificates) or `clientCaFile(path)`, which reads a PEM bundle as that `AnchoredCa`; without either the start fails
  with `IllegalArgumentException` naming `tls { clientTrust }`. With `EngineMain`: `kuicksilver.tls.clientAuth` and
  `kuicksilver.tls.clientCa`. The setting applies to the TCP side and the HTTP/3
  side of the connector. `call.request.peerCertificates` is the client's chain as it was validated, leaf first, over
  TCP or QUIC. On the JVM, an `sslConnector` with a trust store requires client certificates the same way.
- **The client's key.** `TlsIdentity.fromPem(chain, key)` works on every target: the chain in PEM, leaf first, and the
  private key as one unencrypted PKCS#8 block (`-----BEGIN PRIVATE KEY-----`) in a `CharArray`. On the JVM (not
  Android) `TlsIdentity.fromPkcs12(bytes, password)` and `TlsIdentity.fromKeyStore(keyStore, alias, password)` read a
  `.p12` file or a `KeyStore` directly. Elsewhere convert a `.p12` once:
  `openssl pkcs12 -in client.p12 -nokeys -out client-chain.pem` and
  `openssl pkcs12 -in client.p12 -nocerts -nodes | openssl pkcs8 -topk8 -nocrypt -out client-key.pem`. The key has to
  be importable: a key that never leaves Android Keystore or the Apple Keychain cannot be used.
- **The client certificate.** One that carries an extended key usage must list `clientAuth` (TLS Web Client
  Authentication); otherwise the server refuses it with `InvalidPurpose` (alert 43). One without that extension is
  accepted.
- **A client without a certificate**, against `Required`: the server ends the handshake with the TLS alert
  `certificate_required` (116). Over TCP (`http3 { enabled = false }`) the client's side of the TLS handshake has
  completed by then, so the alert ends the connection the request is on: over HTTP/2, which the server offers by default
  since 0.3.0, the call fails with `Http2Exception.ConnectionClosed` ("the connection was lost: TLS alert received from
  the peer: certificate_required (116)") whose root cause is a `TlsException.AlertReceived`; over HTTP/1.1 (a server
  with `http2 { enabled = false }`) with an `IOException` (Ktor's `ClosedByteChannelException`) whose message is "TLS
  alert received from the peer: certificate_required (116)", with the same root cause. Over QUIC (`H3Only`) the call fails with
  `QuicException.ConnectionLost.TransportClosed`, `code` 0x174 (0x0100 + 116), with a `TlsException.AlertReceived` as
  its cause. In `Preferred` mode HTTP/3 fails that way first (the event listener's `raceEnded` or `fallback` gets that
  `TransportClosed`), the call goes on over TCP and fails there as over TCP, with no `suppressed` exceptions: the TCP
  setup did not fail. The server counts the failure by transport: over QUIC in
  `handshakesFailedTls` (`engine.http3Stats`), over TCP in its event listener's `tlsHandshakeFailed`.
- **0-RTT.** A server that asks for client certificates cannot accept 0-RTT: `http3 { earlyData { enabled = true } }`
  together with a `clientAuth` other than `None` fails the start with `IllegalArgumentException` "acceptEarlyData cannot
  be combined with client certificates" ([0-RTT](zero-rtt.md)). A client with a `tls { identity }` may keep
  `http3 { earlyData { enabled } }` on; such a
  server never offers it 0-RTT, so its connections use full handshakes.
- **Rotation.** The server's own identity can be a `TlsIdentity.Reloadable` ([Certificate rotation](#certificate-rotation)).
  The client CA in `clientTrust` is read when the server starts; a `TrustConfig.reloadable(...)` CA, or `clientCaFile`
  with `reloadInterval`, rotates without a restart ([Certificate rotation](#certificate-rotation), "The client CA").

## Certificate rotation

A renewed certificate can be put in place without a restart (experimental). Give the connector a
`TlsIdentity.Reloadable` and call `reload` when the new files are there (from a deploy hook, an admin route, a timer):

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:certificate-rotation
val identity = TlsIdentity.reloadable(TlsIdentity.fromPem(chainPem, keyChars)) // the key array is zeroed after import
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
}, module = Application::module)
// later, when the renewed files are in place: new TCP and QUIC handshakes present them, open connections keep theirs
identity.reload(TlsIdentity.fromPem(renewedChainPem, renewedKeyChars))
```

`keyChars` and `renewedKeyChars` are the key files read into `CharArray`s (not through a `String`, which would leave the
key on the heap). Every handshake whose ClientHello arrives after `reload` returns, HTTP/1.1 and HTTP/2 over TCP and
HTTP/3 over QUIC, presents the new chain and key (also on a TCP connection accepted before the reload); handshakes in
progress and open connections keep the old ones. A key that does not match its
certificate fails in `fromPem`, and `reload` refuses an expired leaf and one not valid yet (`TlsException.Config`): the
identity in use stays. Session tickets are bound to the certificate they were issued under, so after a reload clients
run one full handshake and see the new certificate (see [Rotating the server certificate](tls.md#rotating-the-server-certificate)
for ownership, resumption and key compromise). The same works for the engine's `tls { identity }` (Ktor's own
connectors served over TLS); on the JVM, an `sslConnector` keystore is read once, so build the identity with
`TlsIdentity.fromKeyStore` and wrap it yourself instead.

PEM files need no code of yours: `tls { pemFiles(chain, key); reloadInterval = 1.hours }` (the [first
screen](ktor.md#minimal-example)) has the engine watch them, with the rules of `EngineMain` below. For a source of your own the
application decides when to reload; a check of the files once an hour, from the application's own coroutine scope (it
ends when the server stops):

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val chainFile = File("/etc/letsencrypt/live/example.com/fullchain.pem")
val keyFile = File("/etc/letsencrypt/live/example.com/privkey.pem")
// guide:ktor:reload-from-files
/** A PEM key file as a CharArray without a String of it (PEM is ASCII); the bytes are wiped. */
fun readKeyChars(file: File): CharArray {
    val bytes = file.readBytes()
    try {
        return CharArray(bytes.size) { bytes[it].toInt().toChar() }
    } finally {
        bytes.fill(0)
    }
}

/** Reloads [identity] when the chain file changed since [served] (its modification time); returns the time now served. */
fun reloadIfChanged(identity: TlsIdentity.Reloadable, chainFile: File, keyFile: File, served: Long): Long {
    val modified = chainFile.lastModified()
    if (modified == served) return served
    return try {
        val next = TlsIdentity.fromPem(chainFile.readText(), readKeyChars(keyFile))   // fails while the key does not match yet
        try {
            identity.reload(next)                          // refuses an expired certificate, or one not valid yet
        } catch (e: TlsException) {
            next.close()                                   // a refused identity is still ours to close
            throw e
        }
        modified
    } catch (e: TlsException) {
        served                                             // the old identity keeps serving; tried again at the next check
    } catch (e: IOException) {
        served
    }
}

val identity = TlsIdentity.reloadable(TlsIdentity.fromPem(chainFile.readText(), readKeyChars(keyFile)))
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
}) {
    launch {
        var served = chainFile.lastModified()
        while (true) {
            delay(1.hours)
            served = reloadIfChanged(identity, chainFile, keyFile, served)
        }
    }
    module()
}
```

`reload` itself writes nothing to a log: log the outcome where `reloadIfChanged` returns (with `EngineMain` the engine
logs it, below). To see from outside which certificate a server presents, `openssl s_client -connect <host>:443
-servername <host> </dev/null | openssl x509 -noout -dates -serial` shows the dates and serial of the leaf served over TCP.

With `tls { pemFiles(…) }` and `reloadInterval` in code, or `kuicksilver.tls.reloadInterval` (`1h`, `30m`, ...; `off`
by default) with `EngineMain`, the engine checks the PEM files (`kuicksilver.tls.certificateChain` and
`kuicksilver.tls.privateKey`) that often. It reloads when the chain file holds other certificates than those served: a chain read
twice a second apart with the same content, and a key that matches it. Tools that write the chain before the key
(certbot) or swap a symlinked directory (Kubernetes secrets) are covered: a pair that does not match yet keeps the old
identity and is tried again after 1 s, then 2 s, 4 s and so on up to the interval. Failures are logged as warnings
(once per distinct failure, never with key material); a successful reload is logged at info level, and the files are
read once more a second later, so a chain whose writer paused longer than that is corrected then. Each file is read
whole on every check and refused above 1 MiB; a chain file that also holds a private key is refused, at startup too (keep
the key in its own file). The stop waits at most a second for a check in progress (a read on a hung network file system
cannot be interrupted). Polling once an hour means a renewed certificate may wait an hour to be served; certbot's `--deploy-hook`
(or a restart) is the alternative when it must take effect at once. With `reloadInterval` set, the files at startup get the same checks as a reload, so an expired or not yet valid
certificate fails the start; without it, the engine serves the files as they are, as before. The identity the engine
read from files is closed when the server stops.

**The client CA.** A connector that asks for client certificates ([Mutual TLS](#mutual-tls-client-certificates)) can
rotate the CA bundle it verifies them with in the same way: give it `tls { clientTrust = TrustConfig.reloadable(TrustConfig.AnchoredCa(roots)) }`
(alone or as the `base` of `Pinned`) and call `reload(TrustConfig.AnchoredCa(newRoots))`. Handshakes whose ClientHello
arrives after `reload` returns, HTTP/1.1 and HTTP/2 over TCP and HTTP/3 over QUIC, verify client certificates against the
new bundle. After `reload` returns, no handshake accepts a certificate that only a removed CA vouches for: one in progress
is checked again against the new bundle when it completes, a TCP connection accepted before the reload is no way around
it, and a session ticket from before the reload is not resumed. Open connections are not affected. `reload` refuses a bundle in which no certificate is
valid now ([Rotating the client CA](tls.md#rotating-the-client-ca)).

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:client-ca-rotation
val clientCa = TrustConfig.reloadable(TrustConfig.AnchoredCa(Certificate.parsePem(caBundlePem)))
val server = embeddedServer(Kuicksilver, configure = {
    tls {
        this.identity = identity
        clientAuth = ClientAuth.Required
        clientTrust = clientCa
    }
    tlsConnector { port = 443 }
}, module = Application::module)
// later: new TCP and QUIC handshakes verify client certificates against the new bundle
clientCa.reload(TrustConfig.AnchoredCa(Certificate.parsePem(renewedBundlePem)))
```

In code, `tls { clientCaFile(path) }` reads a PEM file of CA certificates as `clientTrust`; with `EngineMain`,
`kuicksilver.tls.clientAuth` (`optional` or `required`) and `kuicksilver.tls.clientCa` ask for client certificates on
the deployment port. With `reloadInterval` (`kuicksilver.tls.reloadInterval`) set, the CA file is watched at that interval with the rules above: a changed bundle is used once two reads a second apart agree. A
file holding a private key, a damaged file and a bundle with no certificate valid now keep the bundle in use, and so do
they at startup (where they fail the start). A reload is logged at info level, a failure as a warning, and so is a bundle
holding certificates that are not CA certificates (each is an anchor: a client presenting exactly it is accepted). The
keys apply to the port of `kuicksilver.tls.certificateChain`; on the JVM, a `-sslPort` connector (`ktor.security.ssl.*`)
takes client certificates from its `trustStore` instead, and the start is refused when both are configured.

## Certificate per name (SNI)

One connector can serve several names, each with its own certificate (RFC 6066 section 3): its `sniSelector` sees the
ClientHello's server name and answers with the identity, and optionally the client-certificate policy, trust and OCSP
response, for it:

```kotlin
// guide:ktor:sni-server
tlsConnector {
    port = 443
    tls {
        identity = defaultIdentity
        sniSelector = { hello ->
            when (hello.serverName) {
                "api.example.com" -> ServerTlsOverride(apiIdentity)
                "admin.example.com" -> ServerTlsOverride(adminIdentity, clientAuth = ClientAuth.Required, trust = adminCa)
                else -> null // a name not served here: the handshake ends with unrecognized_name
            }
        }
    }
}
```

The selector answers for TCP (HTTP/1.1, HTTP/2) and HTTP/3 alike, so a name gets the same certificate and policy on every
protocol, and the `Alt-Svc` its TCP responses carry leads to a QUIC endpoint that presents it. It is a suspending
function: it may look the identity up (a cache, a store); on QUIC it runs off the connection's loop while that handshake
waits, and a handshake that times out meanwhile cancels it. On QUIC it runs for each new connection's ClientHello, before
the client's address is validated (as RFC 9001 section 4.3 notes, a server that parses the ClientHello to decide can
require a Retry first): keep it cheap, or let `http3 { endpoint { admission } }` ask unvalidated clients for a Retry. A ClientHello without a server name (a client that connected
to an address) reaches it with `serverName == null`, and `null` from it then means the connector's own identity
(`defaultIdentity`). An answer's `alpn` restricts its name: without one the name gets every protocol of the connector;
with one TCP negotiates from that list without `h3` (which identifies HTTP/3 over QUIC only, RFC 9114 section 3.1; a list
of `h3` alone serves the name over HTTP/3 only, and its TCP handshake ends with `no_application_protocol`), and the name is
served over HTTP/3, and advertised with `Alt-Svc` on its TCP responses, only when the list names `h3`
(`listOf("h3", "h2", "http/1.1")`); a TCP client without ALPN speaks HTTP/1.1 (RFC 9113 section 3.3: "HTTP/2 connections
over TLS MUST use protocol negotiation in TLS"), so a list without `http/1.1` refuses it with `no_application_protocol`
(the connector's `alpnFallback`, [TLS guide](tls.md#configuration)); otherwise its QUIC handshake ends with
`no_application_protocol` (CRYPTO_ERROR 0x178, RFC 7301 section 3.2) and its TCP responses carry no `Alt-Svc` (RFC 7838
section 2.1: an alternative must serve the origin). Return the same `TrustConfig` and `OcspStapling` objects for a name,
so that its handshakes share one TLS context. A selector
that throws ends that handshake (on QUIC with `internal_error`; the exception's text is not sent to the client).

Session tickets resume only under the name and the certificate they were issued under: a client that comes back with a
ticket of another name, or after the selector started answering with another certificate, runs one full handshake (no
0-RTT) and gets a new ticket. A name whose answer asks for client certificates gets no 0-RTT and no tickets on HTTP/3
(`http3 { earlyData { enabled } }` applies to the other names). Requests on a connection must be for the name its identity was chosen for:
see [Misdirected requests](server-proxies.md#misdirected-requests).

## TLS 1.2 on the server

A TLS connector speaks TLS 1.3 only by default: a client without it is refused with a `protocol_version` alert.
`tls { versions = TlsVersions.Tls12And13 }` (on the engine, or in one `tlsConnector`'s `tls { }`), the `EngineMain`
key `kuicksilver.tls.versions = tls12And13` for the deployment port, or `enabledProtocols = listOf("TLSv1.2",
"TLSv1.3")` on Ktor's `sslConnector` (JVM) serves TLS 1.2 clients too (RFC 9325 section 3.1.1: "Implementations MUST
support TLS 1.2"). Turn it on only for clients that have no TLS 1.3 (older devices, embedded HTTP stacks, some
proxies and scanners): any client can then end up on TLS 1.2.

- A client that offers TLS 1.3 still gets it; a TLS 1.2 ServerHello carries the RFC 9846 downgrade sentinel, so a
  TLS 1.3 client notices an attacker who removed 1.3 from its offer.
- TLS 1.2 runs under the RFC 9325 profile: ECDHE with AES-GCM or ChaCha20-Poly1305 only (no static RSA, no CBC, no
  SHA-1 MAC, no finite-field DHE), Extended Master Secret required (a client without it is refused with
  `handshake_failure`), no renegotiation, no compression. Among the suites a client offers, the server picks AES-256-GCM
  first, then ChaCha20-Poly1305 (first when the client prefers it), then AES-128-GCM.
- An ECDSA certificate serves the TLS 1.2 clients that offer an ECDHE-ECDSA suite (most do); a client that offers only
  RSA suites needs a connector with an RSA certificate (2048 bits or more).
- With HTTP/2 on (the default), HTTP/2 is offered over TLS 1.2 too (RFC 9113 section 9.2), where the handshake can
  support `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` with P-256, the suite section 9.2.2 makes mandatory for such
  deployments: with an rsaEncryption certificate and `secp256r1` among the key-exchange groups. A TLS 1.2 handshake
  whose certificate has no rsaEncryption key (an EC or an RSA-PSS key, an `sniSelector`'s answer included) or whose
  groups leave P-256 out gets `http/1.1` instead (a client that offers `h2` alone gets `no_application_protocol`, so a
  TLS 1.2 client that speaks only HTTP/2 needs an RSA certificate, or TLS 1.3); a resumed TLS 1.2 session gets the same
  answer as its full handshake. A connector holds one certificate (no RSA and ECDSA pair side by side), so serve such
  clients from a connector, or an `sniSelector` answer, with an RSA one. The
  start says so at Info for the connector's own certificate, and fails for a connector whose `keyExchangeGroups` leave
  `secp256r1` out. TLS 1.3 clients get HTTP/2 either way. A client's attempt to renegotiate ends an HTTP/2 connection
  with GOAWAY PROTOCOL_ERROR, an HTTP/1.1 one goes on with the renegotiation refused.
- Client certificates, `sniSelector` and tickets work as over TLS 1.3. A TLS 1.2 session resumes for at most
  `SessionTicketConfig.ticketLifetime` after its full handshake (12 hours by default, at most half of `rotateEvery`),
  however often its ticket is renewed (TLS 1.2 has no fresh key exchange on resumption; RFC 9325 section 3.4). With
  explicit ticket keys the library does not rotate them: replace them at least every `rotateEvery`, as that option
  promises.
- HTTP/3 on the same port stays TLS 1.3 (QUIC allows nothing else).

## Encrypted Client Hello (experimental)

The engine offers Encrypted Client Hello (RFC 9849) on every `https://` connection, over TCP and HTTP/3: the ClientHello on
the network names only the configuration's `public_name`, and the origin's name travels encrypted. Where the
configuration comes from, for each connection:

1. the `ech` parameter of the HTTPS record whose endpoint the connection goes to (RFC 9848), when `network { httpsRecords }`
   looks records up (`Http3Discovery.Auto`) and `tls { ech { fromHttpsRecords } }` is on (the default; it does nothing
   while `httpsRecords` is `Off`, the default);
2. else `tls { ech { configLists } }` for the request's host, given out of band (keys compared as host names: case, a trailing dot
   and IPv6 brackets do not matter, and two keys for one host fail the engine's creation);
3. else none, and the connection sends GREASE ECH (`tls { ech { grease } }`, on by default, RFC 9849 section 6.2.1), so that it
   looks like one with ECH.

```kotlin
val publishedEch = "AEj+DQBE..." // optional: the base64 of the origin's `ech` parameter, had out of band
// guide:ktor:ech-client
val client =
    HttpClient(Kuicksilver) {
        engine {
            // the records' `ech`, through your DNS-over-HTTPS exchange (see "HTTPS records")
            network { httpsRecords = HttpsRecordSource.Exchange(secure = true) { query -> dohPost(query) } }
            tls { ech { configLists = mapOf("example.com" to EchConfigList.parseBase64(publishedEch)) } }
        }
    }
```

- **Rejection.** A server that cannot decrypt the configuration (it rotated its keys) answers with its retry
  configurations after the client authenticated it for the `public_name`: the engine retries once, on a new connection
  to the addresses the request already resolved (over HTTP/3 the same address; over TCP the race of those addresses
  again), with them (RFC 9849 section 6.1.6), or without ECH when the server sent none, or none of a version this client
  supports ("securely disabled"). Retry configurations of the supported version of which none is usable fail the
  request instead: never a retry with the name in the clear. A retry that is rejected again fails the request with
  `TlsException.EchRejected` in its causes. No request is processed on a rejected connection: a 0-RTT request the server
  ignored there is sent again on the retry. Retry configurations are used for that retry only, never stored.
- **SVCB-reliant.** When every endpoint of the origin's HTTPS records has an `ech` parameter, the request never falls back
  to a connection without it: not to the origin's own address, not to the endpoint an AliasMode chain appends, not to an
  `Alt-Svc` alternative whose own records have none (RFC 9848 sections 5.1 and 6); when no endpoint can be reached the
  request fails. With ECH from the records the engine also sends no ClientHello before the records resolved (section 5.3),
  within the connect timeout: `httpsRecordWait` does not apply then.
- **0-RTT.** With `http3 { earlyData { enabled } }` the early data goes under the inner ClientHello's session. A server that rejects ECH
  ignores it (RFC 9849 section 6.1; RFC 8446 section 4.2.10), and the engine sends the request again on the retry; it is
  processed once.
- **Certificates.** On an accepted ECH the certificate is checked for the origin, as always, with its pins. On a rejection
  it is checked for the `public_name` by the base trust (`Platform`, `AnchoredCa`, a custom verifier); the origin's pins
  (`TrustConfig.Pinned`) do not apply to it, and `TrustConfig.Tofu` accepts a `public_name` only with a key stored for it
  earlier (a rejection is no first contact). Such a connection only triggers the retry, which is held to the pins. No client
  certificate is sent on a rejected connection.
- **Proxies.** Through an HTTP CONNECT or SOCKS5 proxy the TLS session inside the tunnel is the origin's, with
  `tls { ech { configLists } }` or GREASE (HTTPS records are not looked up through a proxy, RFC 9460 section 3.2); the same holds
  for the HTTP/3 connection inside a CONNECT-UDP tunnel, whose retry after a rejection goes through the same tunnel. The
  proxy learns the origin's name from the CONNECT line or the CONNECT-UDP target. The hop to an `http://` proxy is plain
  TCP; the TLS (or QUIC) hop to an `https://` or CONNECT-UDP proxy has a ClientHello of its own, which never offers the
  origin's configuration: it sends GREASE as `tls { ech { grease } }` says, and `proxies { tls { ech { configLists } } }`
  may set the proxy's own (its entry for the proxy's host is what that hop offers). A rejection on that hop fails the request as a proxy failure, never as a retry of the origin's ECH.
- **TLS 1.3 only.** ECH needs TLS 1.3 (RFC 9849 section 6.1): with a `tls` block that allows TLS 1.2, `configLists` fails
  the engine's creation and the records' `ech` is not used.
- **Unusable configurations.** A `configLists` entry with no ECHConfig this build can use, or any entry in a build without
  ECH (a system OpenSSL), fails the engine's creation with `IllegalArgumentException` (two different messages): a list
  given for a host never turns into GREASE with the host's name in the clear. The engine builds each entry's client
  configuration when it is created, for that check: a `TlsException.Config` from that build becomes the entry's
  `IllegalArgumentException`, whose message names the host. An HTTPS record's `ech` with nothing usable
  is different: that connection sends GREASE, as RFC 9849 section 6.1 allows ("If no compatible configuration is found,
  then the client SHOULD proceed as described in Section 6.2"); a record whose `mandatory` names `ech` is skipped then,
  since it must not be reached without ECH (RFC 9848 section 5).
- **What it does not hide.** The DNS queries for the origin's records and addresses (protect them with DNS over HTTPS),
  the server's address, and the traffic's sizes and timing.

## Encrypted Client Hello on the server

*Experimental.* With `tls { echKeys }` the TLS connectors decrypt Encrypted Client Hello (RFC 9849, shared mode) on TCP and HTTP/3
alike, so the name a client asks for never crosses the network in the clear. Make a key with OpenSSL 4 and publish its
ECHConfigList in the `ech` parameter of the HTTPS record of every name the connector serves (RFC 9848):

```shell
openssl ech -public_name cover.example.com -out ech-1.pem   # the PEM: the private key and an ECHCONFIG block
```

```kotlin
val ech1 = File("/etc/kuicksilver/ech-1.pem")
val ech2 = File("/etc/kuicksilver/ech-2.pem")
// guide:ktor:ech-server
val keys = EchServerKeys(listOf(EchKey(ech1.readBytes())))
val server =
    embeddedServer(Kuicksilver, configure = {
        tls {
            this.identity = identity
            echKeys = keys
        }
        tlsConnector { port = 443 }
    }) { routing { get("/") { call.respondText("hidden") } } }
// later: a new key; the old one still decrypts for clients that hold it, but is not sent in retry configurations
keys.rotate(listOf(EchKey(ech2.readBytes()), EchKey(ech1.readBytes(), inRetryConfigs = false)))
```

- **The public name.** A client whose configuration the server cannot decrypt (an old key, or GREASE) gets the keys' retry
  configurations, but only after it authenticated the server for the configuration's `public_name` (RFC 9849 section
  6.1.7): the connector's certificate must cover that name. With an `sniSelector` the selector is asked for the
  `public_name` then (the outer ClientHello's name), and its answer is the certificate the client checks; after an
  accepted ECH it is asked for the inner name, as without ECH.
- **Key material.** `EchKey` takes the PEM as a `ByteArray` or `CharArray` and zeroes it; its own copy is zeroed once
  `EchServerKeys` (or `rotate`) has read it into native memory, so such a key is used once. A `String` cannot be wiped and
  stays in memory as long as the key. `kuicksilver.tls.echKeys` reads its files without making a `String`.
- **Rotation.** `rotate` replaces the whole set for handshakes that start afterwards, on TCP and QUIC; handshakes in
  progress keep the set they started with. Keep a replaced key (`inRetryConfigs = false`) until the DNS TTL of the old
  record has run out. The keys of a set need distinct config_ids: one sharing a config_id with another (1 case in 256
  for keys made apart) is refused with "two ECH keys share a config_id"; make the new key again with `openssl ech`
  before publishing it.
- **Shared mode only.** The connector is both the client-facing and the backend server; split mode (a front end that
  forwards to a backend) is not supported.
- `EngineMain`: `kuicksilver.tls.echKeys` (above).
