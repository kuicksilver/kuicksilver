// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import dnssd
import Foundation

/// Advertises the server as `_kuicksilver._udp` (listed in Info.plist NSBonjourServices) with the DNS-SD C API: the
/// socket belongs to Kuicksilver, so Network.framework's NWListener, which advertises its own socket, does not fit.
final class BonjourAdvertiser {
    private var ref: DNSServiceRef?

    /// Registers [name] on [port]; returns the DNSServiceErrorType (0 is success).
    func start(name: String, port: UInt16) -> Int32 {
        stop()
        var r: DNSServiceRef?
        let err = DNSServiceRegister(&r, 0, 0, name, "_kuicksilver._udp", nil, nil, port.bigEndian, 0, nil, nil, nil)
        if err == kDNSServiceErr_NoError, let r {
            DNSServiceSetDispatchQueue(r, .main)
            ref = r
        }
        return err
    }

    func stop() {
        if let ref { DNSServiceRefDeallocate(ref) }
        ref = nil
    }
}

/// The phone's own addresses, to type into another device.
enum LocalAddresses {
    static func current() -> [String] {
        var out: [String] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return out }
        defer { freeifaddrs(head) }
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = p.pointee
            guard let sa = ifa.ifa_addr, (ifa.ifa_flags & UInt32(IFF_UP)) != 0, (ifa.ifa_flags & UInt32(IFF_LOOPBACK)) == 0 else { continue }
            let family = Int32(sa.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = socklen_t(family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(sa, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let s = String(cString: host)
            if s.hasPrefix("fe80") { continue }   // link-local needs a scope id, skip it
            out.append(s)
        }
        return out
    }
}
