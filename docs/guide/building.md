<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Building from source

**What this page is for.** It is for the person who builds Kuicksilver from a checkout instead of taking it from Maven
Central: a snapshot of `main`, a patched copy, or a build with their own compiler and flags for the native code (for
example to add hardening flags a distribution requires).

**Before you start.** The tools the build needs are listed in [CONTRIBUTING.md, Building](../../CONTRIBUTING.md#building):
a JDK, a C compiler, Docker for the Linux and Windows native code, the Android NDK for the AAR and, on macOS, Xcode for
the Apple targets.

## What the build makes

Gradle builds the Kotlin code; the native code is built by scripts that the Gradle tasks call:

| Native output | Script | Gradle task |
|---|---|---|
| Static OpenSSL per target, in `build/openssl/<target>` | `tools/openssl/build.sh` (Linux and Windows targets inside Docker: `tools/openssl/build-docker.sh`) | `:kuicksilver-native:opensslBuild<Target>` |
| The JVM's JNI library for this machine | `tools/build-jni.sh` | `:kuicksilver-native:buildJniHost` |
| The Android `libksl.so` per ABI | `tools/build-android-so.sh` | `:kuicksilver-native:buildAndroidJni` |
| `libksl.a` for each Kotlin/Native target | `tools/build-ksl-a.sh` | `:kuicksilver-native:buildKslA<Target>` |

To publish a build into the local Maven repository, run `./gradlew --max-workers=2 publishToMavenLocal` (every target),
or the JVM-only variant in the [README](../../README.md#install).

## Your compiler and flags

The native build scripts take the standard variables from the environment and **add** them to their own flags; they
never replace the project's flags with yours:

| Variable | Where it goes |
|---|---|
| `CPPFLAGS`, `CFLAGS` | after the project's compile flags, on every compile line of `libksl` and of OpenSSL |
| `LDFLAGS` | after the project's link flags, on the link line of the JNI library and of the Android `libksl.so`; OpenSSL and `libksl.a` are static archives and are not linked, so there it has no effect |
| `CC` | the compiler of the JNI library on macOS (default `clang`) and Linux (default `gcc`), of `libksl.a` for macOS, and of OpenSSL, which passes it to `Configure` (the Docker and Kotlin/Native builds of OpenSSL set
their own); targets that need a toolchain of their own ignore it: Android (the NDK's clang), iOS (Xcode's SDK compilers), the Kotlin/Native Linux and Windows targets (Kotlin/Native's LLVM and sysroots), and the Windows JNI library (`x86_64-w64-mingw32-gcc`) |

Because your flags come last, where one of them conflicts with a project flag, yours wins (the compiler takes the later
one). The project compiles `libksl` with `-Werror`, so a flag of yours that makes the compiler warn fails the build;
add `-Wno-error=<warning>` for it. A flag that a target's toolchain does not know fails that target's build.

For example, to build the JNI library on a Linux host with stack protection, `_FORTIFY_SOURCE` and full RELRO:

```sh
export CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2" LDFLAGS="-Wl,-z,relro,-z,now"
./gradlew --max-workers=2 :kuicksilver-native:buildJniHost
```

What else to know:

- **OpenSSL.** Its `Configure` would read `CPPFLAGS`, `CFLAGS` and `LDFLAGS` from the environment and use them *instead
  of* the target's own flags, so `tools/openssl/build.sh` takes them out of its environment and passes them as
  `Configure` options after the project's. Each must therefore be one word that starts with `-` (or `/`, the argument
  of the flag before it) and is not one of `Configure`'s own options (`-d`, `-v`, `-w`, `-t`, `-rpath`, `-R`,
  `-framework`, `--prefix=` and the other `--` options of `Configure`); a `%` is refused too (`Configure` decodes
  `%xx`). The script refuses anything else before it starts. `CXXFLAGS` and `LDLIBS` are not used. Your flags are
  recorded in `build/openssl/<target>/configure-target.txt` and `provenance.txt`, and they are part of the build cache's
  key, so a build with other flags is never taken from the cache. The Docker builds get the same three variables.
- **Gradle.** `CC`, `CPPFLAGS`, `CFLAGS` and `LDFLAGS` are inputs of the native tasks: changing one rebuilds what it
  affects. With `-Pkuicksilver.openssl.prebuilt=true` an existing OpenSSL build is reused only when it was configured
  with the flags you have now; otherwise the build stops and says the directory is stale.
- **Reproducibility.** The published artifacts are built with the project's own compiler and flags only: the release
  script (`tools/release/local-release.sh`), the double build of the release gate (`tools/check/double-build.sh`) and
  the rebuild of `tools/verify/verify-release.sh` unset these variables before they build anything. A build with your
  own flags is therefore not byte-identical to a release, and comparing it with one ([verifying.md](../verifying.md))
  is expected to differ.
- **Tests.** `tools/check/native-flags-test.sh` checks all of the above (it runs in the gate's reproducibility step).
  The C tests (`tools/c-test.sh`) are a test build with sanitizers: they honour `CC`, and take extra flags as their
  second argument instead of `CFLAGS`.
