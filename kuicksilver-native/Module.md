# Module kuicksilver-native

The `ksl` C shim with OpenSSL 4.1 statically linked inside, its JNI and cinterop bindings, the native library loader and
the opt-in annotations shared by every Kuicksilver module. Applications rarely use it directly: the other modules call
it. `KslLoader.availability` tells whether the native library could be loaded on this platform.

# Package io.kuicksilver.annotations

Opt-in markers: `ExperimentalKuicksilverApi` (may change without a deprecation cycle), `DelicateKuicksilverApi` (needs
care to use safely), `InternalKuicksilverApi` (for Kuicksilver's own modules, never stable) and the `KuicksilverDsl`
marker of the configuration builders.

# Package io.kuicksilver.io

`ConnectionEndedException`, the end of a TCP connection under an HTTP/1.1 or HTTP/2 exchange by its initiator: the peer
or the network (`PeerClosed`, `PeerUnresponsive`) or this side (`LocalClose`). It lives in the bottom layer so that the
HTTP/2 runtime, the TLS socket and the client engine throw the same types.

# Package io.kuicksilver.native

The native library loader (`KslLoader`, `NativeAvailability`), `PacketBuffer` (native memory for datagrams) and
`KslException`.
