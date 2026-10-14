// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinMultiplatform

// Publication to Maven Central through the Central Portal (docs/release.md). Credentials and the signing key come from
// Gradle properties only (~/.gradle/gradle.properties or ORG_GRADLE_PROJECT_* in CI), never from the repository:
//   mavenCentralUsername / mavenCentralPassword               the portal's user token
//   signingInMemoryKey / signingInMemoryKeyId / signingInMemoryKeyPassword   (CI) or signing.keyId / signing.password / signing.secretKeyRingFile (a local key ring)
// Without a key the build still publishes to mavenLocal unsigned; with one, every publication is signed.
plugins { id("com.vanniktech.maven.publish") }

private val descriptions = mapOf(
    "kuicksilver-native" to "The ksl C shim with OpenSSL 3.5 inside, its JNI and cinterop bindings and the native library loader",
    "kuicksilver-tls" to "TLS 1.3 configuration and trust (platform verifier, private CA, SPKI pins, TOFU) over any byte channel",
    "kuicksilver-ktor-network" to "Socket.tls() and Socket.tlsServer() for ktor-network sockets",
    "kuicksilver-quic" to "QUIC transport (v1 and v2) for Kotlin Multiplatform: streams, datagrams, migration, a coroutine API over a sans-IO core",
    "kuicksilver-http3" to "HTTP/3 and QPACK over kuicksilver-quic",
    "kuicksilver-ktor-client" to "Ktor client engine: HTTP/1.1 over TLS and HTTP/3 with Alt-Svc discovery, racing and fallback",
    "kuicksilver-ktor-server" to "Ktor server engine: HTTP/1.1 over TLS on TCP and HTTP/3 on UDP on the same port",
)

mavenPublishing {
    publishToMavenCentral(automaticRelease = false)   // the first releases are released by hand in the portal after the deployment validated
    // -Pkuicksilver.sign=false skips signing on purpose (counting a local publication, a machine without the key); without it a configured key always signs
    val signed = providers.gradleProperty("kuicksilver.sign").orNull != "false" && (providers.gradleProperty("signingInMemoryKey").isPresent || providers.gradleProperty("signing.keyId").isPresent)
    if (signed) signAllPublications()
    // one empty javadoc jar per publication: Central requires the file, and a Dokka site per platform publication would multiply the upload (publishing limits)
    configure(KotlinMultiplatform(javadocJar = JavadocJar.Empty(), sourcesJar = true))
    coordinates("io.kuicksilver", project.name, project.version.toString())
    pom {
        name.set(project.name)
        description.set(descriptions[project.name] ?: "Kotlin Multiplatform QUIC, HTTP/3 and TLS 1.3 over OpenSSL 3.5")
        inceptionYear.set("2026")
        url.set("https://github.com/kuicksilver/kuicksilver")
        licenses { license { name.set("Apache-2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0.txt"); distribution.set("repo") } }
        developers { developer { id.set("kuicksilver"); name.set("The Kuicksilver Authors"); email.set("hello@kuicksilver.io"); url.set("https://kuicksilver.io") } }
        scm {
            url.set("https://github.com/kuicksilver/kuicksilver")
            connection.set("scm:git:git://github.com/kuicksilver/kuicksilver.git")
            developerConnection.set("scm:git:ssh://git@github.com/kuicksilver/kuicksilver.git")
        }
        issueManagement { system.set("GitHub"); url.set("https://github.com/kuicksilver/kuicksilver/issues") }
    }
}
