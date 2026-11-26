<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Proxies in the Ktor client

**What this page is for.** How the client engine goes through HTTP, HTTPS and SOCKS proxies (the system's settings,
PAC files, an explicit proxy, credentials) and how HTTP/3 goes through a CONNECT-UDP proxy.

**Before you start**

- Words such as origin, alternative, route or race: the [glossary](glossary.md).
- HTTP/3 never goes through an HTTP or SOCKS proxy: a request a proxy applies to goes over TCP.
- The imports of the code blocks: [Ktor engines: Imports](ktor.md#imports).

## Proxies

The usual setups first: one proxy with credentials, a resolver of your own, an `https://` proxy. With none of
them the system's proxy settings apply. HTTP/3 never goes through an HTTP or SOCKS proxy (below).

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:proxy
val password = System.getenv("PROXY_PASSWORD") ?: ""
// one proxy for everything, with credentials for it
val viaProxy = HttpClient(Kuicksilver) {
    engine {
        proxy = ProxyBuilder.http("http://proxy.corp.test:3128")
        proxies { credentials = ProxyCredentials("user", password) } // for `proxy` only
    }
}
// a resolver of your own: its proxy carries its own credentials (ProxyResolvers.Environment takes them from https_proxy)
val perHost = HttpClient(Kuicksilver) {
    engine {
        proxies {
            resolver = ProxyResolver { url ->
                if (url.host.endsWith(".internal.test")) null // direct
                else ResolvedProxy.http("proxy.corp.test", 3128, ProxyCredentials("user", password))
            }
        }
    }
}
// an https:// proxy: TLS to the proxy itself, the CONNECT and the credentials inside it
val overTls = HttpClient(Kuicksilver) {
    engine {
        proxies {
            resolver = ProxyResolver { ResolvedProxy.https("proxy.corp.test", 443, ProxyCredentials("user", password)) }
            tls { trust = TrustConfig.Platform } // the proxy's own trust (default: the origin's, without pins)
        }
    }
}
```

Where a request's proxy comes from:

1. `engine { proxy = ... }` (Ktor's `ProxyConfig`) when set: it applies to every request, `localhost` and loopback
   addresses included (as `curl -x` does; `java.net.Proxy.NO_PROXY` means none).
2. Otherwise `engine { proxies { resolver = ... } }` (*experimental*), asked per request and remembered for 30 seconds per
   scheme, host and port. The default is **`ProxyResolvers.System`**, the platform's settings:

| Target | `ProxyResolvers.System` | PAC / WPAD |
|---|---|---|
| JVM | `java.net.ProxySelector.getDefault()`: `https.proxyHost`/`http.proxyHost`, `socksProxyHost`, `http.nonProxyHosts`, and with `-Djava.net.useSystemProxies=true` the OS settings; its HTTP proxies (`https.proxyHost`/`https.proxyPort` included: the `https` names the URLs it serves) are always plain HTTP proxies, as on Android, since a `java.net.Proxy` has no scheme; TLS to a proxy needs `proxies { resolver = ProxyResolver { ResolvedProxy.https(..) } }` | as the JDK does |
| Android | the same: the active network's proxy, PAC through the system | yes (by the system) |
| macOS, iOS | the system proxy settings via `CFNetworkCopyProxiesForURL` (HTTP, HTTPS, SOCKS; the exceptions list; the settings' "HTTPS" proxy is the plain proxy for `https` URLs) | run by the engine on JavaScriptCore: the PAC URL or script of the settings, or WPAD when they say "auto discover" (DHCP option 252 on macOS, `http`/`https` only; `wpad.<domain>` for each DNS search domain exactly, never a parent domain, though a search domain is used as given; then `http://wpad/wpad.dat` for the resolver to complete, the only candidate on iOS); scripts fetched directly (`http`, `https`, `file`, at most 1 MiB read, kept 30 min), each run limited to 2 s; a script that fails within 5 s: the next setting, else direct, and one warning; an answer entry `HTTPS host:port` (Chrome's extension) is an `https://` proxy, port 443 by default; an answer with only proxies the engine cannot use (`SOCKS4`): the next setting, else the request fails; no WPAD script found: logged once at Info |
| Windows | the user's Internet settings via `WinHttpGetIEProxyConfigForCurrentUser` (`host:port` or `http=…;https=…;socks=…`, the bypass list with `<local>`; an entry whose value starts with `https://` is an `https://` proxy, as Chrome reads it, while `https=host:port` is the plain proxy for `https` URLs) | run by WinHTTP (`WinHttpGetProxyForUrl`, WPAD by DHCP and DNS, then the PAC URL), waited for at most 5 s; a script that fails or takes longer: the fixed proxy next to it, else direct, and one warning; no WPAD script found: the same, logged once at Info, and detection again after 5 minutes |
| Linux | `ProxyResolvers.Environment` (there is no system API; desktop settings are not read) | — |

What a PAC script sees. A PAC script is code from the network: whoever answers WPAD on the local network, or serves a
plain-`http` PAC URL, writes it, and it can send any string it is given out through
`dnsResolve("<data>.attacker.example")`. So the URL the engine passes `FindProxyForURL` is built as Chrome builds it (no
user info or fragment, the host in lower case, the default port left out; the `host` argument in lower case too), and
for secure URLs it is the origin only, as in Chrome (since 52, CVE-2016-5134), Android (CVE-2016-3763) and Firefox
(which strips the path of every URL by default). A plain `http` URL also gives its origin only, but for another reason:
the engine keeps answers per scheme, host and port, so a path could not change them (Chrome and Android pass an `http`
URL's path; Firefox strips it):

| Request | On Apple platforms and Windows the script gets | On the JVM and Android `ProxySelector.select` gets |
|---|---|---|
| `https://h/p?q` | `https://h/` | `https://h:443/` |
| `wss://h:8443/p?q` | `wss://h:8443/` (with `pacFullWebSocketUrl` and the settings' own script, inline or from an `https`/local `file` URL: `wss://h:8443/p?q`; WinHTTP: as `https://` when it refuses `wss`) | `https://h:8443/p?q` (Android's selector cuts it to `https://h:8443/` before its PAC runs; the JDK's passes the OS only scheme and host) |
| `ws://h/p?q` | `ws://h/p?q` (WinHTTP: as `http://` when it refuses `ws`) | `http://h:80/p?q` |
| `http://h/p?q` | `http://h/` | `http://h:80/` |

RFC 6455 section 4.1 asks for a WebSocket's whole URI, resource name included; for `wss` the engine departs from that
by default for this reason. `engine { proxies { pacFullWebSocketUrl = true } }` (*experimental, delicate*) gives the whole `wss` URI to the
script the system settings name, given inline (Apple) or by an `https://` or local `file:///` URL (Windows: the "Use setup
script" address; Apple: the PAC URL), and never to one WPAD found or one fetched over plain `http://`: whoever answers
on the local network writes those. On Apple platforms the PAC URL CFNetwork reports must equal the settings' string
exactly; a URL written differently (case, a trailing slash) gets the origin only. A `file:` URL with a host
(`file://srv/share/p.pac`, `file:////srv/share/p.pac`) is fetched over SMB from that host and counts as remote: origin
only. Turn it on only when that script is
yours.
On Apple platforms the engine's own runner also bounds the script: 2 s per run (creating the script's context, evaluating
the PAC utility functions and the script, and its `FindProxyForURL` call; preparing a new script's text comes before),
20 distinct lookups per run in total (as
Chrome; a name looked up by both `dnsResolve` and `dnsResolveEx` counts twice; a name with a NUL resolves to nothing),
an answer of at most 64 KiB of ASCII without a NUL, a script of at most 1 MiB; an answer entry it cannot read is skipped,
and an answer with none left counts as a failed script. JavaScriptCore's public API has no memory limit: a script that
allocates without end is stopped only by the time limit (its thread is given up, threat model 3.20.3).

`ProxyResolvers.Environment` reads the variables as curl does: `https_proxy`/`HTTPS_PROXY` for `https` and `wss`,
`http_proxy` (lower case only) for `http` and `ws`, then `all_proxy`/`ALL_PROXY`; `no_proxy`/`NO_PROXY` exempts `*`,
names with their subdomains (`example.com` covers `a.example.com`, not `badexample.com`), IP addresses and CIDR ranges;
an entry with a port (`example.com:8080`, `[2001:db8::1]:443`) exempts that port only, as Go does. On Windows
environment names are case-insensitive, so there an `HTTP_PROXY` variable is read as `http_proxy` (curl has the same
caveat).
A value is `http://host:port`, `https://host[:port]` (TLS to the proxy; port 443 by default, as curl (despite its manual's 1080), Chrome and Go), `socks5://`
(names resolved by the client), `socks5h://` (by the proxy) or a bare `host:port`; user info in it becomes the
credentials. `ProxyResolvers.None` connects directly, as 0.2 did without
`proxy`; any `ProxyResolver { url -> ... }` of your own works too. Both built-in resolvers send `localhost`,
`*.localhost` and loopback addresses directly whatever the settings say.

A proxy the engine cannot use (`socks4://`, an unknown type) fails the request with `UnsupportedOperationException`: it
is never bypassed.

How a proxy is used. An HTTP proxy gets `CONNECT` tunnels for `https` and for WebSockets, `ws://` included (RFC 6455
section 4.1, as browsers), and absolute-form requests for plain `http`; a SOCKS proxy is SOCKS5 (RFC 1928, CONNECT only;
no SOCKS4), every request tunneled, the proxy resolving the origin's name unless `socks5://` asked otherwise.
Credentials authenticate to either: SOCKS5 username/password (RFC 1929), offered and sent only when the proxy picks
that method, or `Proxy-Authorization: Basic` with the first CONNECT or absolute-form request unless the request sets
its own. A request's own `Proxy-Authorization` goes only on a hop to a proxy, never to an origin (directly or in a
tunnel, over HTTP/1.1, HTTP/2 and HTTP/3 alike). `proxies { credentials }` are for the explicit `proxy` only (off the JVM a proxy URL's user info,
`http://user:password@proxy:3128`, wins); a resolver's proxy carries its own: the user info of `https_proxy` and the
like with `ProxyResolvers.Environment`, or the `credentials` of the `ResolvedProxy` your resolver returns. Both go in
clear to an `http://` or SOCKS5 proxy (RFC 7617 section 4, RFC 1929 section 5; anyone on the path to the proxy reads
them, as with curl, Go and OkHttp) and only inside TLS to an `https://` proxy, never to the origin. `Basic` cannot carry a
user name with a colon, nor control characters (0x00-0x1F, 0x7F) in either part (RFC 7617 section 2): credentials like that
for an HTTP, `https://` or CONNECT-UDP proxy fail with `IllegalArgumentException` where the proxy is configured (the
engine's creation for its `proxy`), before anything is sent; a SOCKS5 user name may contain a colon. Through `socks5://` (names resolved here) the engine tries the origin's
addresses in turn while the proxy answers "network unreachable" or "host unreachable", within the connect timeout. A
resolver that does not answer within the engine's `connectTimeout` (not a per-request `HttpTimeout`) fails the request with
`ProxyException`. A proxy that refuses fails the request with `ProxyException` (*experimental*):
`replyCode` is the SOCKS5 reply or the CONNECT status (407: credentials wanted; not retried, so a proxy that keeps
answering 407 costs one CONNECT per request, never a loop; a plain `http` request gets the proxy's 407 as its response).

**`https://` proxies** (*experimental*, 0.3.0). `ResolvedProxy.https(host, port, credentials)`, an `https://` value in
the environment, an `https://` entry of Windows' settings, a PAC answer's `HTTPS host:port`, or, off the JVM,
`ProxyBuilder.http(Url("https://proxy:443"))` (a `java.net.Proxy` has no scheme, so on the JVM name it with a resolver;
there an HTTP `proxy` on port 443, which is what that URL becomes, fails every request with `UnsupportedOperationException`
rather than speak plain HTTP to what may be an `https://` proxy: use `ResolvedProxy.https` for TLS to it, or
`ResolvedProxy.http(host, 443)` from a resolver for a plain proxy on that port)
makes the engine speak TLS to the proxy itself, as curl's HTTPS proxy and Chrome do, before anything else: the CONNECT
or the absolute-form request, its `Proxy-Authorization` and the CONNECT's target travel inside that TLS session
([ADR-0023](../adr/0023-https-proxy.md)).

- The proxy's certificate is verified against the proxy's host as configured (a DNS name, or an IP address as an IP-ID;
  RFC 9525), which is also its SNI unless it is an IP address (RFC 6066 section 3); the name goes through the engine's
  `network { dns }`. A failed handshake (a certificate that does not verify, an alert, a proxy that closes) fails the request with
  `ProxyTlsException`, a `ProxyException` whose `cause` is the TLS layer's error; a failure of the origin's TLS inside
  the tunnel stays the origin's `TlsException`.
- Trust: `proxies { tls { } }` (the `ClientTlsConfig` of `engine { tls { } }`) configures that connection on its own. By
  default it takes the engine's `tls { trust }` without what names the origin (an `ExpectedName` gives way to its base, a `Pinned` to its base:
  the proxy has another name and another key, as curl's `--pinnedpubkey` is not applied to its proxy) and without the
  client certificate; a `proxies { tls { } }` block starts from that same trust and no identity and may set anything.
  Whatever it sets, the server name is the proxy's host and ALPN `http/1.1` alone.
- Inside the tunnel the origin's TLS runs as without a proxy (TLS in TLS): its own SNI, certificate check, pins, ALPN
  (`h2` included). Plain `http` goes in the absolute form inside TLS to the proxy, and that connection is pooled per proxy
  (an `https://` and an `http://` proxy at the same address are different routes).
- HTTP/2 to the proxy itself (CONNECT over HTTP/2, RFC 9113 section 8.5, several tunnels on one connection) is not
  offered: one TLS connection to the proxy carries one tunnel, as with curl's default and OkHttp. A new connection to the
  proxy resumes an earlier TLS session from a cache that holds proxy tickets only.

**Through an HTTP, HTTPS or SOCKS5 proxy there is no HTTP/3.** QUIC is UDP, which neither CONNECT (to an `http://` or an
`https://` proxy) nor SOCKS5 CONNECT carries (SOCKS5 UDP ASSOCIATE is not supported), as with Chrome and curl. HTTP/3 goes
through a CONNECT-UDP proxy instead: [HTTP/3 through a CONNECT-UDP proxy](#http3-through-a-connect-udp-proxy-experimental).
A proxied request uses TCP (`ProtocolReason.Proxy`: HTTP/1.1, or HTTP/2 inside a tunnel),
`Alt-Svc` is neither used nor learned and `http3 { hints }` are ignored; `H3Only` fails it with
`UnsupportedOperationException` without contacting the proxy, and `HttpClient.webTransport` refuses the URL unless
`http3 { webTransport { proxyPolicy } }` lets it bypass the proxy. To use HTTP/3 to a host, exempt it from the proxy
(`no_proxy`, the OS bypass list), or connect directly everywhere with `proxies { resolver = ProxyResolvers.None }`.

## HTTP/3 through a CONNECT-UDP proxy (experimental)

`proxies { connectUdp }` sends the engine's HTTP/3 through a CONNECT-UDP proxy (RFC 9298, MASQUE): each HTTP/3 connection to an
origin it applies to runs inside a UDP tunnel through the proxy, with TLS end to end to the origin, so the proxy sees the
origin's name, port and UDP, never the requests ([HTTP/3, CONNECT-UDP](http3.md#connect-udp-experimental)). The proxy is
reached directly over HTTP/3 (its template's authority, port 443 when it names none) with the proxy's TLS settings, as
an `https://` proxy over TCP ([Proxies](#proxies)): `proxies { tls { } }`, or by default the engine's trust without an
`ExpectedName` or pins and without the client certificate (`tls { identity }` goes to the origin only); the certificate is
verified against the proxy's host, and a failed handshake with the proxy is a `ProxyTlsException`. Each tunnelled
connection has its own connection to the proxy, closed with it, a full handshake each time (no session resumption, and no
ticket of the proxy's ever shared with origins). Through several addresses of the proxy, an address whose TLS failed
makes the request's failure a `ProxyTlsException` even when a later address only timed out (the timeout is then among
its suppressed exceptions), as long as no address of the proxy completed its handshake: once one did, the CONNECT may
have gone out, and a timeout of the tunnel or of the origin's handshake is a `ConnectTimeoutException`. QUIC is TLS 1.3 only (RFC 9001 section 4.2), so a `proxies { tls { } }` limited to TLS 1.2 cannot
reach a CONNECT-UDP proxy; an ECH configuration that `proxies { tls { ech { } } }` gives the proxy is offered as given and not retried after a
rejection (RFC 9849 section 6.1.6 applies to the origin's connection). Inside the tunnel the origin's connection has the engine's `tls { }`, as a direct one. The origin's name goes to the proxy, which
resolves it: the engine does not look it up.

What it changes, for the `https` URLs its `applies` admits (all of them by default):

- They go over HTTP/3 through the tunnel only, whatever the discovery mode (H3Only, Auto, Preferred): never over HTTP/1.1
  or HTTP/2 and never directly, since both would leave the proxy out. An origin without HTTP/3, a refused tunnel
  (`Http3Exception.ConnectRejected`, its `proxy-status` in `headers`) or a failed handshake fails the request instead of
  falling back. `http3 { enabled = false }` and an `http3 { allowed }` that says no fail it with
  UnsupportedOperationException.
- `Alt-Svc` and HTTPS records are neither used nor learned for them: the tunnel goes to the URL's host and port.
- `proxy` and `proxies { resolver }` (HTTP and SOCKS5 proxies, which carry TCP) keep deciding for every other request: `http://`
  URLs and the URLs `applies` turns away. A deployment that must send everything through proxies sets both.
- WebTransport refuses such URLs (its sessions do not go through the tunnel) unless
  `http3 { webTransport { proxyPolicy = WebTransportProxyPolicy.BypassConnectUdpProxy } }` (or `BypassAll`) connects
  them directly; `BypassHttpProxy` is about HTTP and SOCKS proxies only.
- Tunnelled connections keep their session tickets apart from direct connections', one cache per proxy route, so the
  origin cannot link a proxied connection to the client's own address by the ticket it resumes.

The `ConnectUdpProxy`'s credentials go to the proxy as `proxy-authorization: Basic ...` on each tunnel's CONNECT. The connection to the proxy
must carry the inner connection's 1200-byte datagrams in its own: the engine's sockets set Don't Fragment, so DPLPMTUD
finds a path MTU above about 1250 bytes within a few round trips; over a path that does not carry that, the handshake
through the tunnel times out.

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:connect-udp-client
val client = HttpClient(Kuicksilver) {
    engine {
        proxies { connectUdp = ConnectUdpProxy(
            UdpProxyTemplate.parse("https://masque.example/.well-known/masque/udp/{target_host}/{target_port}/"),
            ProxyCredentials("user", password),
        ) { url -> !url.host.endsWith(".internal.test") } }   // these go the usual way
    }
}
```
