//
//  main.swift
//  Client
//
//  Created by kisu Park on 2020/09/19.
//  Copyright © 2020 kisu Park. All rights reserved.
//

import Foundation
import TLSProtocol

let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)

assert(fd != -1, "Error creating socket: " + POSIXErrorCode(rawValue: errno).debugDescription)

let hostname = "google.com".data(using: .ascii)!
let hostent = hostname.withUnsafeBytes { (buffer) -> hostent in
    let pointer = buffer.bindMemory(to: Int8.self).baseAddress!
    return gethostbyname(pointer)!.pointee
}

var temp: in_addr?
var i: Int = 0
var addrs: [in_addr] = []
while let addrPointer = hostent.h_addr_list[i] {
    let addr = addrPointer.withMemoryRebound(to: in_addr.self, capacity: 1) { (pointer) -> in_addr in
        return pointer.pointee
    }
    addrs.append(addr)
    i += 1
}

assert(!addrs.isEmpty, "Error getting in_addr from hostname")
print(String(format: "host ip: %s", inet_ntoa(addrs[0])))

var serverAddr = sockaddr_in(sin_len: UInt8(MemoryLayout<sockaddr_in>.size),
                             sin_family: UInt8(hostent.h_addrtype),
                             sin_port: in_port_t(bigEndian: 443),
                             sin_addr: addrs[0],
                             sin_zero: ( 0, 0, 0, 0, 0, 0, 0, 0 ))
let result = withUnsafePointer(to: &serverAddr) { (pointer) -> Int32 in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { (pointer) -> Int32 in
        return connect(fd, pointer, UInt32(MemoryLayout<sockaddr_in>.size))
    }
}

assert(-1 != result, "Error connecting to host: " + POSIXErrorCode(rawValue: errno).debugDescription)

var hello = ClientHello(ProtocolVersion.TLS_1_2,
                        Random(),
                        nil,
                        [.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                         .TLS_DH_anon_WITH_AES_128_CBC_SHA,
                         .TLS_DH_anon_WITH_AES_128_CBC_SHA256,
                         .TLS_DH_anon_WITH_AES_256_CBC_SHA,
                         .TLS_DH_anon_WITH_AES_256_CBC_SHA256,
                         .TLS_DH_anon_WITH_RC4_128_MD5,
                         .TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                         .TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                         .TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                         .TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                         .TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                         .TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                         .TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                         .TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                         .TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                         .TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                         .TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                         .TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA],
                        [CompressionMethod.NULL],
                        [SignatureAlgorithms([SignatureAndHashAlgorithm(.sha256, .ecdsa),
                        SignatureAndHashAlgorithm(.sha256, .rsa)])])

var handshake = Handshake(type: .client_hello).bytes(with: hello)
var text = TLSPlaintext(type: .handshake, version: .TLS_1_0, fragment: handshake).bytes
let countOfSentBytes = send(fd, &text, text.count, 0)
print("\(countOfSentBytes)")

var buffer: [UInt8] = .init(repeating: 0, count: 4096)
let countOfReadBytes = read(fd, &buffer, buffer.count)
print("\(countOfReadBytes)")
