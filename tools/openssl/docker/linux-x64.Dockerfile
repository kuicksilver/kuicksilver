# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# manylinux2014 (glibc 2.17) + devtoolset gcc: JVM Linux x86_64 native builds.
FROM quay.io/pypa/manylinux2014_x86_64
RUN yum -y install perl-core gnupg2 && yum clean all
ENV CC=gcc
