// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Manual check of what a PAC engine hands FindProxyForURL (docs/spec/rfc/6455.md): the answer's proxy host is the URL
// and host the script got, with every character that is not a letter or digit replaced by '-'.
function FindProxyForURL(url, host) {
  return "PROXY " + url.replace(/[^a-zA-Z0-9]/g, "-") + "." + host.replace(/[^a-zA-Z0-9.]/g, "-") + ":1";
}
