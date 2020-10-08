//
//  Extensions.swift
//  TLSProtocol
//
//  Created by kisupark on 2020/09/20.
//  Copyright © 2020 sadarm. All rights reserved.
//

import Foundation
import Security
import CryptoKit

public protocol Extension {
    var type: ExtensionType { get }
    var bytes: [UInt8] { get }
    var contents: [UInt8] { get }
}

extension Extension {
    public var bytes: [UInt8] {
        var buffer: [UInt8] = []
        var type = UInt16(self.type.rawValue).bigEndian
        withUnsafeBytes(of: &type) { (type) -> Void in
            buffer.append(contentsOf: type.bindMemory(to: UInt8.self))
        }

        var length: UInt16 = UInt16(self.contents.count).bigEndian
        withUnsafeBytes(of: &length) { (length) -> Void in
            buffer.append(contentsOf: length.bindMemory(to: UInt8.self))
        }
        buffer.append(contentsOf: self.contents)
        return buffer
    }
}

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
    case sessionTicket = 35
    case supportedVersions = 43
    case pskKeyExchangeModes = 45
    case keyShare = 51
    case renegotiationInfo = 65281
}

public enum HashAlgorithm: Int {
    case none = 0
    case md5 = 1
    case sha1 = 2
    case sha224 = 3
    case sha256 = 4
    case sha384 = 5
    case sha512 = 6
    case rsae_sha256 = 8
}

public enum SignatureAlgorithm: Int {
    case anonymous = 0
    case rsa = 1
    case dsa = 2
    case ecdsa = 3
    case rsa_pss = 4
}

public struct SignatureAndHashAlgorithm {
    let hash: HashAlgorithm
    let signature: SignatureAlgorithm
    
    public init(_ hash: HashAlgorithm, _ signature: SignatureAlgorithm) {
        self.hash = hash
        self.signature = signature
    }
}

public struct SignatureAlgorithms: Extension {
    public let type: ExtensionType = .signatureAlgorithms
    public let signatureAndHashAlgorithms: [SignatureAndHashAlgorithm]
    public var contents: [UInt8] {
        var algorithms: [UInt8] = []
        self.signatureAndHashAlgorithms.forEach {
            algorithms.append(UInt8($0.hash.rawValue))
            algorithms.append(UInt8($0.signature.rawValue))
        }
        
        var contents: [UInt8] = []
        var lengthOfAlgorithms: UInt16 = UInt16(algorithms.count).bigEndian
        withUnsafeBytes(of: &lengthOfAlgorithms) { (lengthOfAlgorithms) -> Void in
            contents.append(contentsOf: lengthOfAlgorithms.bindMemory(to: UInt8.self))
        }
        contents.append(contentsOf: algorithms)
        return contents
    }
    
    public init(_ signatureAndHashAlgorithms: [SignatureAndHashAlgorithm]) {
        self.signatureAndHashAlgorithms = signatureAndHashAlgorithms
    }
}

public struct RenegotiationInfo: Extension {
    public let type: ExtensionType = .renegotiationInfo
    public var contents: [UInt8] {
        return [0]
    }
    
    public init() {
        
    }
}


public struct ServerName {
    let nameType: NameType
    let hostName: HostName
    
    public init(_ nameType: NameType, _ hostName: HostName) {
        self.nameType = nameType
        self.hostName = hostName
    }
}

public enum NameType: Int {
    case hostName = 0
}

public typealias HostName = String

// SNI: Server Name Indication
public struct ServerNameList: Extension {
    public let type: ExtensionType = .serverName
    public let serverNames: [ServerName]
    public var contents: [UInt8] {
        var serverNames: [UInt8] = []
        self.serverNames.forEach {
            serverNames.append(UInt8($0.nameType.rawValue))
            let hostName = $0.hostName.data(using: .ascii) ?? Data()
            var lengthOfHostName = UInt16(hostName.count).bigEndian
            withUnsafeBytes(of: &lengthOfHostName) { (lengthOfHostName) -> Void in
                serverNames.append(contentsOf: lengthOfHostName.bindMemory(to: UInt8.self))
            }
            serverNames.append(contentsOf: hostName)
        }
        
        var body: [UInt8] = []
        var lengthOfServerNames = UInt16(serverNames.count).bigEndian
        withUnsafeBytes(of: &lengthOfServerNames) { (lengthOfServerNames) -> Void in
            body.append(contentsOf: lengthOfServerNames.bindMemory(to: UInt8.self))
        }
        body.append(contentsOf: serverNames)
        return body
    }
    
    public init(_ serverNames: [ServerName]) {
        self.serverNames = serverNames
    }
}


public struct Padding: Extension {
    public let type: ExtensionType = .padding
    let length: UInt16
    public var contents: [UInt8] {
        return [UInt8](repeating: 0, count: Int(self.length))
    }
    
    public init(length: UInt16) {
        self.length = length
    }
}

public struct ApplicationLayerProtocolNegotiation: Extension {
    public let type: ExtensionType = .applicationLayerProtocolNegotiation
    public let alpnStrings: [String]
    
    public var contents: [UInt8] {
        let alpns = self.alpnStrings
            .compactMap { $0.data(using: .utf8) }
            .reduce([]) { (result, data) -> [UInt8] in
                var result = result
                result.append(UInt8(data.count).bigEndian)
                result.append(contentsOf: data)
                return result
        }
        var contents: [UInt8] = []
        var countOfALPNs = UInt16(alpns.count).bigEndian
        withUnsafeBytes(of: &countOfALPNs) { (countOfALPNs) -> Void in
            contents.append(contentsOf: countOfALPNs.bindMemory(to: UInt8.self))
        }
        contents.append(contentsOf: alpns)
        return contents
    }
    
    public init(alpnStrings: [String]) {
        self.alpnStrings = alpnStrings
    }
}

public struct SessionTicket: Extension {
    public let type: ExtensionType = .sessionTicket
    public var contents: [UInt8] {
        return []
    }
    
    public init() {
        
    }
}

public struct SupportedVersions: Extension {
    public let type: ExtensionType = .supportedVersions
    let supportedVersions: [ProtocolVersion]
    public var contents: [UInt8] {
        let versions: [UInt8] = self.supportedVersions.reduce([]) { (result, version) -> [UInt8] in
            var result = result
            result.append(version.major)
            result.append(version.minor)
            return result
        }
        let lengthOfVersions: UInt8 = UInt8(versions.count).bigEndian
        var contents: [UInt8] = []
        contents.append(lengthOfVersions)
        contents.append(contentsOf: versions)
        return contents
    }
    
    public init(supportedVersions: [ProtocolVersion]) {
        self.supportedVersions = supportedVersions
    }
}

public struct PskKeyExchangeModes: Extension {
    public var type: ExtensionType = .pskKeyExchangeModes
    public var contents: [UInt8] {
        return [1, 1]
    }
    
    public init() {
        
    }
}


public enum NamedGroup: UInt {
    /* Elliptic Curve Groups (ECDHE) */
    case secp256r1 = 0x0017
    case secp384r1 = 0x0018
    case secp521r1 = 0x0019
    case x25519 = 0x001D
    case x448 = 0x001E

    /* Finite Field Groups (DHE) */
    case ffdhe2048 = 0x0100
    case ffdhe3072 = 0x0101
    case ffdhe4096 = 0x0102
    case ffdhe6144 = 0x0103
    case ffdhe8192 = 0x0104
}

public struct NamedGroupList: Extension {
    public let type: ExtensionType = .supportedGroups
    public let groups: [NamedGroup]
    public var contents: [UInt8] {
        let groups = self.groups.reduce([]) { (result, group) -> [UInt8] in
            var result = result
            var group = UInt16(group.rawValue).bigEndian
            withUnsafeBytes(of: &group) { (group) -> Void in
                result.append(contentsOf: group.bindMemory(to: UInt8.self))
            }
            return result
        }
        var contents: [UInt8] = []
        var lengthOfGroups = UInt16(groups.count).bigEndian
        withUnsafeBytes(of: &lengthOfGroups) { (lengthOfGroups) -> Void in
            contents.append(contentsOf: lengthOfGroups.bindMemory(to: UInt8.self))
        }
        contents.append(contentsOf: groups)
        return contents
    }
    
    public init(groups: [NamedGroup]) {
        self.groups = groups
    }
    
}

public struct KeyShare: Extension {
    public let type: ExtensionType = .keyShare
    public var contents: [UInt8] {
        return []
    }
    
    public init() {
        
    }
}
