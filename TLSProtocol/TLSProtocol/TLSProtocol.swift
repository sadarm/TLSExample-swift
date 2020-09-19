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
    var major: uint8
    var minor: uint8
}

struct Random {
    var gmt_unix_time: uint32
    var random_bytes: [uint8] = [uint8](repeating: 0, count: 28)
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

struct CipherSuites {
    var _1: CipherSuite
    var _2: CipherSuite?
    var _3: CipherSuite?
    var _4: CipherSuite?
    var _5: CipherSuite?
    var _6: CipherSuite?
    var _7: CipherSuite?
    var _8: CipherSuite?
    var _9: CipherSuite?
    var _10: CipherSuite?
    var _11: CipherSuite?
    var _12: CipherSuite?
    var _13: CipherSuite?
    var _14: CipherSuite?
    var _15: CipherSuite?
}

struct ClientHello {
    var clientVersion: ProtocolVersion
    var random: Random
    var session_id: [uint8] = [uint8](repeating: 0, count: 32)
    CompressionMethod compression_methods<1..2^8-1>;
    select (extensions_present) {
        case false:
            struct {};
        case true:
            Extension extensions<0..2^16-1>;
    };
};
