// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The bill of materials: `implementation(platform("io.kuicksilver:kuicksilver-bom:<version>"))` pins every Kuicksilver module to one version.
plugins {
    `java-platform`
    id("com.vanniktech.maven.publish")
}
group = "io.kuicksilver"
version = providers.gradleProperty("kuicksilver.version").getOrElse("0.1.0-SNAPSHOT")

dependencies {
    constraints {
        for (m in listOf("native", "tls", "ktor-network", "quic", "http3", "ktor-client", "ktor-server")) api(project(":kuicksilver-$m"))
    }
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = false)
    if (providers.gradleProperty("kuicksilver.sign").orNull != "false" && (providers.gradleProperty("signingInMemoryKey").isPresent || providers.gradleProperty("signing.keyId").isPresent)) signAllPublications()
    configure(com.vanniktech.maven.publish.JavaPlatform())
    coordinates("io.kuicksilver", project.name, project.version.toString())
    pom {
        name.set(project.name)
        description.set("Bill of materials for the Kuicksilver modules (QUIC, HTTP/3 and TLS 1.3 over OpenSSL 3.5 for Kotlin Multiplatform)")
        inceptionYear.set("2026")
        url.set("https://github.com/kuicksilver/kuicksilver")
        licenses { license { name.set("Apache-2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0.txt"); distribution.set("repo") } }
        developers { developer { id.set("kuicksilver"); name.set("The Kuicksilver Authors"); email.set("hello@kuicksilver.io"); url.set("https://kuicksilver.io") } }
        scm { url.set("https://github.com/kuicksilver/kuicksilver"); connection.set("scm:git:git://github.com/kuicksilver/kuicksilver.git"); developerConnection.set("scm:git:ssh://git@github.com/kuicksilver/kuicksilver.git") }
        issueManagement { system.set("GitHub"); url.set("https://github.com/kuicksilver/kuicksilver/issues") }
    }
}
