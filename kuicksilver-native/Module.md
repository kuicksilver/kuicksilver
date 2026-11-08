# Module kuicksilver-native

The `ksl` C shim with OpenSSL 3.5 statically linked inside, its JNI and cinterop bindings, the native library loader and
the opt-in annotations shared by every Kuicksilver module. Applications rarely use it directly: the other modules call
it. `KslLoader.availability` tells whether the native library could be loaded on this platform.

# Package io.kuicksilver.annotations

Opt-in markers: `ExperimentalKuicksilverApi` (may change without a deprecation cycle), `DelicateKuicksilverApi` (needs
care to use safely), `InternalKuicksilverApi` (for Kuicksilver's own modules, never stable) and the `KuicksilverDsl`
marker of the configuration builders.

# Package io.kuicksilver.native

The native library loader (`KslLoader`, `NativeAvailability`), `PacketBuffer` (native memory for datagrams) and
`KslException`.
