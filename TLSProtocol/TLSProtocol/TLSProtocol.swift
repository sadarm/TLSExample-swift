//
//  TLSProtocol.swift
//  TLSProtocol
//
//  Created by kisu Park on 2020/09/19.
//  Copyright © 2020 sadarm. All rights reserved.
//

import Foundation

//ProtocolVersion version = { 3, 3 };     /* TLS v1.2*/
public struct ProtocolVersion {
    public var major: UInt8
    public var minor: UInt8
}

public struct Random {
    public var gmt_unix_time: uint32
    public var random_bytes: [UInt8] = [UInt8](repeating: 0, count: 28)
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


public typealias SessionID = String
//typealias CompressionMethod = uint8
//let CompressionMethod_NULL: CompressionMethod = 0

public struct CompressionMethod {
    let rawValue: UInt8
    
    public static let NULL = CompressionMethod(rawValue: 0)
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
public struct ClientHello {
    public var clientVersion: ProtocolVersion
    public var random: Random
    public var sessionID: SessionID?
    public var cipherSuites: [CipherSuite] = []
    public var compressionMethod: CompressionMethod
    public var extensions: [Extension] = []
    
    public init(_ clientVersion: ProtocolVersion, _ random: Random, _ sessionID: SessionID? = nil, _ cipherSuites: [CipherSuite], _ compressionMethod: CompressionMethod, _ extensions: [Extension]) {
        self.clientVersion = clientVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuites = cipherSuites
        self.compressionMethod = compressionMethod
        self.extensions = extensions
    }
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

public struct ServerHello {
    public var serverVersion: ProtocolVersion
    public var random: Random
    public var sessionID: SessionID?
    public var cipherSuites: [CipherSuite] = []
    public var compressionMethod: CompressionMethod
    public var extensions: [Extension] = []
    
    public init(_ serverVersion: ProtocolVersion, _ random: Random, _ sessionID: SessionID? = nil, _ cipherSuites: [CipherSuite], _ compressionMethod: CompressionMethod, _ extensions: [Extension]) {
        self.serverVersion = serverVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuites = cipherSuites
        self.compressionMethod = compressionMethod
        self.extensions = extensions
    }
};



public struct Extension {

    public enum ExtensionType: Int {
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
    
    public let type: ExtensionType
    public let data: Data // max length: 2^16-1 = 65535
}

public enum HashAlgorithm: Int {
    case none = 0
    case md5 = 1
    case sha1 = 2
    case sha224 = 3
    case sha256 = 4
    case sha384 = 5
    case sha512 = 6
}

public enum SignatureAlgorithm: Int {
    case anonymous = 0
    case rsa = 1
    case dsa = 2
    case ecdsa = 3
}

public struct SignatureAndHashAlgorithm {
    let hash: HashAlgorithm
    let signature: SignatureAlgorithm
}
