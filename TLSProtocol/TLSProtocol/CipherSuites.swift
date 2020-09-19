//
//  CipherSuites.swift
//  TLSProtocol
//
//  Created by kisu Park on 2020/09/19.
//  Copyright © 2020 sadarm. All rights reserved.
//

import Foundation

public struct CipherSuite {
    let a: uint8
    let b: uint8
    
    init(_ a: uint8, _ b: uint8) {
        self.a = a
        self.b = b
    }
    
    // TLS_{키 합의 프로토콜}_{인증 방법}_WITH_{암호화 기법}_{데이터 무결성 체크 방법}
    // TLS_{Key exchange}_{Authentication}_WITH_{Block ciphers}_{Message authentication}
    public static let TLS_NULL_WITH_NULL_NULL             = CipherSuite(0x00, 0x00)
    public static let TLS_RSA_WITH_NULL_MD5               = CipherSuite(0x00, 0x01)
    public static let TLS_RSA_WITH_NULL_SHA               = CipherSuite(0x00, 0x02)
    public static let TLS_RSA_WITH_NULL_SHA256            = CipherSuite(0x00, 0x3B)
    public static let TLS_RSA_WITH_RC4_128_MD5            = CipherSuite(0x00, 0x04)
    public static let TLS_RSA_WITH_RC4_128_SHA            = CipherSuite(0x00, 0x05)
    public static let TLS_RSA_WITH_3DES_EDE_CBC_SHA       = CipherSuite(0x00, 0x0A)
    public static let TLS_RSA_WITH_AES_128_CBC_SHA        = CipherSuite(0x00, 0x2F)
    public static let TLS_RSA_WITH_AES_256_CBC_SHA        = CipherSuite(0x00, 0x35)
    public static let TLS_RSA_WITH_AES_128_CBC_SHA256     = CipherSuite(0x00, 0x3C)
    public static let TLS_RSA_WITH_AES_256_CBC_SHA256     = CipherSuite(0x00, 0x3D)
    public static let TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA    = CipherSuite(0x00, 0x0D)
    public static let TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA    = CipherSuite(0x00, 0x10)
    public static let TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA   = CipherSuite(0x00, 0x13)
    public static let TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   = CipherSuite(0x00, 0x16)
    public static let TLS_DH_DSS_WITH_AES_128_CBC_SHA     = CipherSuite(0x00, 0x30)
    public static let TLS_DH_RSA_WITH_AES_128_CBC_SHA     = CipherSuite(0x00, 0x31)
    public static let TLS_DHE_DSS_WITH_AES_128_CBC_SHA    = CipherSuite(0x00, 0x32)
    public static let TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = CipherSuite(0x00, 0x33)
    public static let TLS_DH_DSS_WITH_AES_256_CBC_SHA     = CipherSuite(0x00, 0x36)
    public static let TLS_DH_RSA_WITH_AES_256_CBC_SHA     = CipherSuite(0x00, 0x37)
    public static let TLS_DHE_DSS_WITH_AES_256_CBC_SHA    = CipherSuite(0x00, 0x38)
    public static let TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = CipherSuite(0x00, 0x39)
    public static let TLS_DH_DSS_WITH_AES_128_CBC_SHA256  = CipherSuite(0x00, 0x3E)
    public static let TLS_DH_RSA_WITH_AES_128_CBC_SHA256  = CipherSuite(0x00, 0x3F)
    public static let TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00, 0x40)
    public static let TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00, 0x67)
    public static let TLS_DH_DSS_WITH_AES_256_CBC_SHA256  = CipherSuite(0x00, 0x68)
    public static let TLS_DH_RSA_WITH_AES_256_CBC_SHA256  = CipherSuite(0x00, 0x69)
    public static let TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = CipherSuite(0x00, 0x6A)
    public static let TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite(0x00, 0x6B)
    public static let TLS_DH_anon_WITH_RC4_128_MD5        = CipherSuite(0x00, 0x18)
    public static let TLS_DH_anon_WITH_3DES_EDE_CBC_SHA   = CipherSuite(0x00, 0x1B)
    public static let TLS_DH_anon_WITH_AES_128_CBC_SHA    = CipherSuite(0x00, 0x34)
    public static let TLS_DH_anon_WITH_AES_256_CBC_SHA    = CipherSuite(0x00, 0x3A)
    public static let TLS_DH_anon_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00, 0x6C)
    public static let TLS_DH_anon_WITH_AES_256_CBC_SHA256 = CipherSuite(0x00, 0x6D)

}

