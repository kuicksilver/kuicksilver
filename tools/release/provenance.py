#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Writes the build provenance of a release made by tools/release/local-release.sh (docs/release.md, "Build provenance").

An in-toto Statement v1 with a SLSA provenance v1 predicate: the source commit, the toolchain pins of gradle/toolchains.toml
and what the host actually had, the OpenSSL tarball (version, SHA-256, signing key, configure flags), the Gradle distribution,
and as subjects the SHA-256 of every file of the local publication that goes to Maven Central (no .asc, .md5 or .sha1) plus
the SBOM archive. Byproducts: the JNI libraries and the OpenSSL archives of every target. local-release.sh signs the file
with the release key (a detached .asc, as the Maven artifacts). Stdlib only, Python 3.9 or newer (no tomllib);
--options is the argument list local-release.sh was given. Deterministic for the same inputs and times.

Usage: provenance.py --version V --m2 DIR --out FILE --started EPOCH [--sbom-zip FILE] [--dry-run] [--signed]
                     [--options "..."] [--gate FILE]
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import subprocess
import sys

REPO = "https://github.com/kuicksilver/kuicksilver"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def iso(epoch):
    return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def toml_tables(path):
    """The [table] / key = "value" subset of TOML the pin files use (no tomllib: macOS's /usr/bin/python3 is 3.9)."""
    tables, cur = {}, None
    for line in open(path).read().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[([A-Za-z0-9_.-]+)\]", line)
        if m:
            cur = tables.setdefault(m.group(1), {})
            continue
        m = re.fullmatch(r'([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"\s*(#.*)?', line)
        if not m or cur is None:
            sys.exit(f"{path}: unsupported TOML line: {line}")
        cur[m.group(1)] = m.group(2)
    return tables


def toml_value(path, key):
    m = re.search(r'^%s\s*=\s*"(.*)"' % re.escape(key), open(path).read(), re.M)
    return m.group(1) if m else None


def subjects(m2, version):
    skip = (".asc", ".md5", ".sha1", ".sha256", ".sha512")
    base = os.path.join(m2, "io", "kuicksilver")
    out = []
    for module in sorted(os.listdir(base)):
        d = os.path.join(base, module, version)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if name.endswith(skip) or name.startswith("maven-metadata"):
                continue
            path = os.path.join(d, name)
            out.append({"name": os.path.relpath(path, m2), "digest": {"sha256": sha256(path)}})
    return out


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--version", required=True)
    a.add_argument("--m2", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--started", required=True, type=int)
    a.add_argument("--sbom-zip")
    a.add_argument("--dry-run", action="store_true")
    a.add_argument("--signed", action="store_true")
    a.add_argument("--options", default="")
    a.add_argument("--gate")
    o = a.parse_args()
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    os.chdir(root)

    subj = subjects(o.m2, o.version)
    if not subj:
        sys.exit(f"no io.kuicksilver publication of {o.version} in {o.m2}")
    if o.sbom_zip:
        subj.append({"name": os.path.basename(o.sbom_zip), "digest": {"sha256": sha256(o.sbom_zip)}})

    commit = run("git", "rev-parse", "HEAD")
    tree_clean = run("git", "status", "--porcelain") == ""
    toolchains = toml_tables("gradle/toolchains.toml")
    ossl = toml_tables("gradle/openssl.toml")["openssl"]
    wrapper = dict(l.split("=", 1) for l in open("gradle/wrapper/gradle-wrapper.properties").read().splitlines() if "=" in l)
    gradle_url = wrapper["distributionUrl"].replace("\\:", ":")
    tarball = f"https://github.com/openssl/openssl/releases/download/openssl-{ossl['version']}/openssl-{ossl['version']}.tar.gz"

    deps = [
        {"uri": f"git+{REPO}@{commit}", "digest": {"gitCommit": commit}},
        {"uri": tarball, "digest": {"sha256": ossl["sha256"]},
         "annotations": {"pgpFingerprint": ossl["pgp_fingerprint"], "configureFlags": ossl["configure_flags"],
                         "configureFlagsSha256": sha256(ossl["configure_flags"])}},
        {"uri": gradle_url, "digest": {"sha256": wrapper.get("distributionSha256Sum", "")}},
        {"uri": "file:gradle/verification-metadata.xml", "digest": {"sha256": sha256("gradle/verification-metadata.xml")}},
        {"uri": "file:gradle/libs.versions.toml", "digest": {"sha256": sha256("gradle/libs.versions.toml")}},
    ]
    if "windows" in toolchains:
        deps.append({"uri": toolchains["windows"]["jdk-url"], "digest": {"sha256": toolchains["windows"]["jdk-sha256"]}})
    # the images the Linux and mingw OpenSSL and JNI builds ran in (built locally from tools/openssl/docker)
    for img in ("kuicksilver-openssl-linux-x64", "kuicksilver-openssl-linux-arm64", "kuicksilver-openssl-mingw"):
        iid = run("docker", "image", "inspect", "--format", "{{.Id}}", img)
        if iid and iid.startswith("sha256:"):
            deps.append({"uri": f"docker-image:{img}", "digest": {"sha256": iid.removeprefix("sha256:")},
                         "annotations": {"dockerfile": f"tools/openssl/docker/{img.removeprefix('kuicksilver-openssl-')}.Dockerfile"}})

    ndk_dir = os.environ.get("ANDROID_NDK_ROOT") or os.path.expanduser(f"~/Library/Android/sdk/ndk/{toolchains['android']['ndk']}")
    ndk = None
    if os.path.isfile(os.path.join(ndk_dir, "source.properties")):
        m = re.search(r"Pkg\.Revision\s*=\s*(\S+)", open(os.path.join(ndk_dir, "source.properties")).read())
        ndk = m and m.group(1)
    xcode = run("xcodebuild", "-version")
    host = {
        "os": f"{platform.system()} {platform.release()} {platform.machine()}",
        "macos": run("sw_vers", "-productVersion"),
        "xcode": xcode.splitlines()[0].removeprefix("Xcode ") if xcode else None,
        "ndk": ndk,
        "docker": run("docker", "version", "--format", "{{.Server.Version}}"),
    }

    byproducts = []
    art = "build/release/jni-artifacts"
    if os.path.isdir(art):
        for cls_dir in sorted(os.listdir(art)):
            d = os.path.join(art, cls_dir, cls_dir.removeprefix("jni-"))
            if os.path.isdir(d):
                for name in sorted(os.listdir(d)):
                    if name.startswith("libksl_"):
                        byproducts.append({"name": f"jni/{name}", "digest": {"sha256": sha256(os.path.join(d, name))}})
    if os.path.isdir("build/openssl"):
        for t in sorted(os.listdir("build/openssl")):
            for lib in ("libcrypto.a", "libssl.a"):
                p = os.path.join("build/openssl", t, "lib", lib)
                if os.path.isfile(p):
                    byproducts.append({"name": f"openssl/{t}/{lib}", "digest": {"sha256": sha256(p)}})

    gate = None
    if o.gate and os.path.isfile(o.gate):
        g = dict(l.split("=", 1) for l in open(o.gate).read().splitlines() if "=" in l)
        gate = {k: g.get(k) for k in ("result", "steps", "failed", "finished", "with_interop", "with_windows", "skip_android", "skip_docker") if k in g}

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subj,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": f"{REPO}/blob/{commit}/docs/release.md#build-provenance",
                "externalParameters": {
                    "source": {"uri": f"git+{REPO}", "digest": {"gitCommit": commit}},
                    "version": o.version,
                    "command": f"tools/release/local-release.sh {o.options}".strip(),
                },
                "internalParameters": {
                    "dryRun": o.dry_run,
                    "signed": o.signed,
                    "treeClean": tree_clean,
                    "toolchainPins": toolchains,
                    "opensslPin": ossl,
                    "kotlin": toml_value("gradle/libs.versions.toml", "kotlin"),
                    "host": host,
                    "localGate": gate,
                },
                "resolvedDependencies": deps,
            },
            "runDetails": {
                # not a hosted build platform: the owner's Mac, with the owner's key (SLSA Build L1, docs/release.md)
                "builder": {"id": f"{REPO}/blob/main/docs/release.md#build-provenance:owner-workstation"},
                "metadata": {"invocationId": f"{commit}/{o.started}", "startedOn": iso(o.started),
                             "finishedOn": iso(int(datetime.datetime.now(datetime.timezone.utc).timestamp()))},
                "byproducts": byproducts,
            },
        },
    }
    with open(o.out, "w") as f:
        json.dump(statement, f, indent=2)
        f.write("\n")
    print(f"{o.out}: {len(subj)} subjects, {len(deps)} resolved dependencies, {len(byproducts)} byproducts, commit {commit[:7]}")


if __name__ == "__main__":
    main()
