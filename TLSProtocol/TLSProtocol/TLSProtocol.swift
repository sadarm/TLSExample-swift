//
//  TLSProtocol.swift
//  TLSProtocol
//
//  Created by kisu Park on 2020/09/19.
//  Copyright © 2020 sadarm. All rights reserved.
//

import Foundation

//ProtocolVersion version = { 3, 3 };     /* TLS v1.2*/
struct ProtocolVersion {
    var major: UInt8
    var minor: UInt8
}

struct Random {
    var gmt_unix_time: uint32
    var random_bytes: [UInt8] = [UInt8](repeating: 0, count: 28)
}


//
//enum {
//    change_cipher_spec(20), alert(21), handshake(22),
//    application_data(23), (255)
//} ContentType;
//
//struct {
//    ContentType type;
//    ProtocolVersion version;
//    uint16 length;
//    opaque fragment[TLSPlaintext.length];
//} TLSPlaintext;
//
//struct {
//    ContentType type;
//    ProtocolVersion version;
//    uint16 length;
//    opaque fragment[TLSCompressed.length];
//} TLSCompressed;
//
//struct {
//    ContentType type;
//    ProtocolVersion version;
//    uint16 length;
//    select (SecurityParameters.cipher_type) {
//        case stream: GenericStreamCipher;
//        case block:  GenericBlockCipher;
//        case aead:   GenericAEADCipher;
//    } fragment;
//} TLSCiphertext;
//
//stream-ciphered struct {
//    opaque content[TLSCompressed.length];
//    opaque MAC[SecurityParameters.mac_length];
//} GenericStreamCipher;


typealias SessionID = String
//typealias CompressionMethod = uint8
//let CompressionMethod_NULL: CompressionMethod = 0

struct CompressionMethod {
    let rawValue: UInt8
    
    static let NULL = CompressionMethod(rawValue: 0)
}

/*
 struct {
     ProtocolVersion client_version;
     Random random;
     SessionID session_id;
     CipherSuite cipher_suites<2..2^16-2>;
     CompressionMethod compression_methods<1..2^8-1>;
     select (extensions_present) {
         case false:
             struct {};
         case true:
             Extension extensions<0..2^16-1>;
     };
 } ClientHello;
 */
struct ClientHello {
    var clientVersion: ProtocolVersion
    var random: Random
    var sessionID: SessionID
    var cipherSuites: [CipherSuite]
    var compressionMethods: CompressionMethod
    var extensions: [Extension]
};

/*
 struct {
     ProtocolVersion server_version;
     Random random;
     SessionID session_id;
     CipherSuite cipher_suite;
     CompressionMethod compression_method;
     select (extensions_present) {
         case false:
             struct {};
         case true:
             Extension extensions<0..2^16-1>;
     };
 } ServerHello;
 */

struct ServerHello {
    var serverVersion: ProtocolVersion
    var random: Random
    var session_id: SessionID
    var cipherSuites: [CipherSuite]
    var compressionMethods: CompressionMethod
    var extensions: [Extension]
};



struct Extension {

    enum ExtensionType: Int {
        case serverName = 0
        case maxFragmentLength = 1
        case clientCertificateURL = 2
        case trustedCaKeys = 3
        case truncatedHMAC = 4
        case statusRequest = 5
        case supportedGroups = 10
        case ecPointFormats = 11
        case signatureAlgorithms = 13
        case applicationLayerProtocolNegotiation = 16
        case signedCertificateTimestamp = 18
        case padding = 21
        case extendedMasterSecret = 23
        case supportedVersions = 43
        case pskKeyExchangeModes = 45
        case keyShare = 51
        case renegotiationInfo = 65281
    }
    
    let type: ExtensionType
    let data: Data // max length: 2^16-1 = 65535
}

enum HashAlgorithm: Int {
    case none = 0
    case md5 = 1
    case sha1 = 2
    case sha224 = 3
    case sha256 = 4
    case sha384 = 5
    case sha512 = 6
}

enum SignatureAlgorithm: Int {
    case anonymous = 0
    case rsa = 1
    case dsa = 2
    case ecdsa = 3
}

struct SignatureAndHashAlgorithm {
    let hash: HashAlgorithm
    let signature: SignatureAlgorithm
}
