<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Windows: what WinHTTP's PAC engine hands the script (RFC 6455 §4.1)

A manual check, run on a Windows host. Goal: learn whether `WinHttpGetProxyForUrl` passes the path and query (and the `ws`/`wss`
scheme) of the URL to `FindProxyForURL` when the engine hands it a whole WebSocket URI. By default the engine passes a
`wss` URI as its origin only; the check runs the opt-in path (`pacFullWebSocketUrl`, the settings' PAC URL), which is
what the result decides for the RFC 6455 §4.1 row (docs/spec/rfc/6455.md, Open items).

1. On a Windows host, in a checkout of the repository, serve the echo script over plain HTTP:
   `cd tools\check && python -m http.server 8999`
   (`win-pac-echo.pac` answers `PROXY <url with non-alphanumerics as '-'>.<host>:1`).
2. Build and run the mingwX64 test binary with the variable set (any shell):
   `set KSL_WIN_PAC_URL=http://127.0.0.1:8999/win-pac-echo.pac`
   `gradlew --offline -Pkuicksilver.openssl.prebuilt=true :kuicksilver-ktor-client:mingwX64Test --tests "*WinPacUrlCheckTest*"`
   (or build `linkDebugTestMingwX64` on macOS and run `test.exe --ktest_filter=*WinPacUrlCheckTest*` on the VM).
3. Read the `WINPAC` lines (stdout, or the mingwX64Test test-results XML under the module's build directory):
   - `wss://h.test:8443/chat?room=1 -> wss---h-test-8443-chat-room-1.h.test:1`: WinHTTP passes the WebSocket URI whole:
     with the opt-in the MUST is met on Windows.
   - `… -> https---h-test-8443-chat-room-1…`: it refused `wss` and the retry as `https` passed the path and query
     (met with the scheme mapping, as on the JVM).
   - `… -> https---h-test-8443-.h.test:1` (no `chat`): WinHTTP strips the path; the rule is not met on Windows.
   - `Failed`: the script was not fetched or run (check the server log and `KSL_WIN_PAC_URL`).
4. The three lines decide the Windows part of the RFC 6455 §4.1 row (docs/spec/rfc/6455.md, Open items).
5. Redirect: serve the script behind an `https` URL that answers `302` to an `http://` copy of it, set `KSL_WIN_PAC_URL`
   to the `https` URL and run step 2 again. A `Failed` line means WinHTTP refuses the https→http redirect; a `WINPAC`
   answer means it follows it, so a whole `wss` URI (`pacFullWebSocketUrl`) could reach a script served over plain
   `http`: record that in docs/spec/rfc/6455.md, Open items.
