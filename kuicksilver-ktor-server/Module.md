# Module kuicksilver-ktor-server

The Ktor server engine `embeddedServer(Kuicksilver)`: HTTP/1.1 (and HTTP/2 on request) over TLS on TCP and HTTP/3 on
UDP on the same port, with Alt-Svc advertising. Guides: `docs/guide/ktor.md`, `docs/guide/deployment.md`.

# Package io.kuicksilver.ktor.server

`Kuicksilver` (the engine factory), `KuicksilverApplicationEngine` and its configuration, the TLS connector, the event
listener, and what a call can read about its connection (peer certificates, early data, priority).
