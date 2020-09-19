//
//  CipherSuites.swift
//  TLSProtocol
//
//  Created by kisu Park on 2020/09/19.
//  Copyright © 2020 sadarm. All rights reserved.
//

import Foundation

struct CipherSuite {
    var a: uint8
    var b: uint8
    
    init(_ a: uint8, _ b: uint8) {
        self.a = a
        self.b = b
    }
}

// TLS_{키 합의 프로토콜}_{인증 방법}_WITH_{암호화 기법}_{데이터 무결성 체크 방법}
// TLS_{Key exchange}_{Authentication}_WITH_{Block ciphers}_{Message authentication}
let TLS_NULL_WITH_NULL_NULL             = CipherSuite(0x00, 0x00)
let TLS_RSA_WITH_NULL_MD5               = CipherSuite(0x00, 0x01)
let TLS_RSA_WITH_NULL_SHA               = CipherSuite(0x00, 0x02)
let TLS_RSA_WITH_NULL_SHA256            = CipherSuite(0x00, 0x3B)
let TLS_RSA_WITH_RC4_128_MD5            = CipherSuite(0x00, 0x04)
let TLS_RSA_WITH_RC4_128_SHA            = CipherSuite(0x00, 0x05)
let TLS_RSA_WITH_3DES_EDE_CBC_SHA       = CipherSuite(0x00, 0x0A)
let TLS_RSA_WITH_AES_128_CBC_SHA        = CipherSuite(0x00, 0x2F)
let TLS_RSA_WITH_AES_256_CBC_SHA        = CipherSuite(0x00, 0x35)
let TLS_RSA_WITH_AES_128_CBC_SHA256     = CipherSuite(0x00, 0x3C)
let TLS_RSA_WITH_AES_256_CBC_SHA256     = CipherSuite(0x00, 0x3D)
let TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA    = CipherSuite(0x00, 0x0D)
let TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA    = CipherSuite(0x00, 0x10)
let TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA   = CipherSuite(0x00, 0x13)
let TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   = CipherSuite(0x00, 0x16)
let TLS_DH_DSS_WITH_AES_128_CBC_SHA     = CipherSuite(0x00, 0x30)
let TLS_DH_RSA_WITH_AES_128_CBC_SHA     = CipherSuite(0x00, 0x31)
let TLS_DHE_DSS_WITH_AES_128_CBC_SHA    = CipherSuite(0x00, 0x32)
let TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = CipherSuite(0x00, 0x33)
let TLS_DH_DSS_WITH_AES_256_CBC_SHA     = CipherSuite(0x00, 0x36)
let TLS_DH_RSA_WITH_AES_256_CBC_SHA     = CipherSuite(0x00, 0x37)
let TLS_DHE_DSS_WITH_AES_256_CBC_SHA    = CipherSuite(0x00, 0x38)
let TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = CipherSuite(0x00, 0x39)
let TLS_DH_DSS_WITH_AES_128_CBC_SHA256  = CipherSuite(0x00, 0x3E)
let TLS_DH_RSA_WITH_AES_128_CBC_SHA256  = CipherSuite(0x00, 0x3F)
let TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00, 0x40)
let TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00, 0x67)
let TLS_DH_DSS_WITH_AES_256_CBC_SHA256  = CipherSuite(0x00, 0x68)
let TLS_DH_RSA_WITH_AES_256_CBC_SHA256  = CipherSuite(0x00, 0x69)
let TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = CipherSuite(0x00, 0x6A)
let TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite(0x00, 0x6B)
let TLS_DH_anon_WITH_RC4_128_MD5        = CipherSuite(0x00, 0x18)
let TLS_DH_anon_WITH_3DES_EDE_CBC_SHA   = CipherSuite(0x00, 0x1B)
let TLS_DH_anon_WITH_AES_128_CBC_SHA    = CipherSuite(0x00, 0x34)
let TLS_DH_anon_WITH_AES_256_CBC_SHA    = CipherSuite(0x00, 0x3A)
let TLS_DH_anon_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00, 0x6C)
let TLS_DH_anon_WITH_AES_256_CBC_SHA256 = CipherSuite(0x00, 0x6D)
