# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# manylinux2014 (glibc 2.17) + devtoolset gcc: JVM Linux x86_64 native builds.
# Pinned by digest (review I8; tag and digest resolved from the registry 2026-10-08). Renovate updates the digest; to pin the image
# a local build already used instead: docker inspect --format "{{index .RepoDigests 0}}" <image>.
FROM quay.io/pypa/manylinux2014_x86_64:latest@sha256:ffd6d1f11237599748657996b750db6b3a5b724fea5a81cd9ea65add4f45b6c9
# java-11-openjdk-devel: the JNI headers for tools/build-jni.sh (the containers run as the invoking user on Linux hosts and cannot yum later)
RUN yum -y install perl-core gnupg2 java-11-openjdk-devel && yum clean all
ENV CC=gcc
