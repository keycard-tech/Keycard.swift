enum ECDSASignatureTag: UInt8 {
    case signatureTemplate = 0xA0
    case rawSignature = 0x80
    case ecdsaTemplate = 0x30
}

public struct RecoverableSignature {
    public let publicKey: [UInt8]
    public let recId: UInt8
    public let r: [UInt8]
    public let s: [UInt8]
    public let compressed: Bool
    
    public init(r: [UInt8], s: [UInt8], recId: UInt8, publicKey: [UInt8], compressed: Bool) {
        self.r = r
        self.s = s
        self.recId = recId
        self.publicKey = publicKey
        self.compressed = compressed
    }
    
    public init(hash: [UInt8], data: [UInt8]) throws {
        let tlv = TinyBERTLV(data)
        let tag = try tlv.readTag()
        tlv.unreadLastTag()
        
        if (tag == ECDSASignatureTag.rawSignature.rawValue) {
            try self.init(hash: hash, signature: tlv.readPrimitive(tag: tag))
        } else if (tag == ECDSASignatureTag.signatureTemplate.rawValue) {
            try self.init(hash: hash, tlv: tlv)
        } else {
            throw TLVError.unexpectedTag(expected: ECDSASignatureTag.signatureTemplate.rawValue, actual: tag)
        }
    }

    private init(hash: [UInt8], tlv: TinyBERTLV) throws {
        _ = try tlv.enterConstructed(tag: ECDSASignatureTag.signatureTemplate.rawValue)
        self.publicKey = try tlv.readPrimitive(tag: AppInfoTag.pubKey.rawValue)
        _ = try tlv.enterConstructed(tag: ECDSASignatureTag.ecdsaTemplate.rawValue)
        self.r = try Util.shared.dropZeroPrefix(uint8: tlv.readPrimitive(tag: TLVTag.int.rawValue))
        self.s = try Util.shared.dropZeroPrefix(uint8: tlv.readPrimitive(tag: TLVTag.int.rawValue))
        self.compressed = false
        self.recId = try RecoverableSignature.calculateRecId(hash: hash, pubkey: self.publicKey, r: self.r, s: self.s, compressed: self.compressed)
    }
    
    private init(hash: [UInt8], signature: [UInt8]) throws {
        self.r = Array(signature[0..<32])
        self.s = Array(signature[32..<64])
        self.recId = signature[64]
        self.compressed = false
        self.publicKey = Crypto.shared.secp256k1RecoverPublic(r: self.r, s: self.s, recId: self.recId, hash: hash, compressed: self.compressed)
    }
    
    public static func calculateRecId(hash: [UInt8], pubkey: [UInt8], r: [UInt8], s: [UInt8], compressed: Bool) throws -> UInt8 {
        var foundID: UInt8 = UInt8.max
        
        for i: UInt8 in 0...3 {
            let pub = Crypto.shared.secp256k1RecoverPublic(r: r, s: s, recId: i, hash: hash, compressed: compressed)
            if (pub == pubkey) {
                foundID = i
                break
            }
        }
        
        if (foundID == UInt8.max) {
            throw CardError.unrecoverableSignature
        }
        
        return foundID
    }
}
