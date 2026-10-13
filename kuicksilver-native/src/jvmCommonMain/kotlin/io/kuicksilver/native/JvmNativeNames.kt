// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

/** Platform classifier and library file name shared by the JVM loader and the build, which must agree on where the library sits in the jar. */
internal object JvmNativeNames {
    /** The operating system part of the classifier, from `os.name`: `osx`, `windows`, or `linux` for anything else. */
    val os: String =
        System.getProperty("os.name").lowercase().let {
            when {
                it.contains("mac") || it.contains("darwin") -> "osx"
                it.contains("win") -> "windows"
                else -> "linux"
            }
        }

    /** The CPU part of the classifier, from `os.arch`: `aarch_64`, `x86_64`, or the lower-cased property value for anything else. */
    val arch: String =
        System.getProperty("os.arch").lowercase().let {
            when (it) {
                "aarch64", "arm64" -> "aarch_64"
                "amd64", "x86_64" -> "x86_64"
                else -> it
            }
        }

    /** Maven classifier, same values as os-maven-plugin's `os.detected.classifier`. */
    val classifier: String get() = "$os-$arch"

    /**
     * The file name of the library for ABI [abi] on this platform, e.g. `libksl_5_linux_x86_64.so`; with the ABI in the name,
     * libraries of different releases never replace each other in the shared extraction directory.
     */
    fun libraryFileName(abi: Int = KSL_ABI_VERSION): String =
        "libksl_${abi}_${os}_$arch." +
            when (os) {
                "osx" -> "dylib"
                "windows" -> "dll"
                else -> "so"
            }

    /** The jar directory that holds the libraries and their `manifest.sha256`. */
    const val RESOURCE_DIR: String = "META-INF/native/"
}
