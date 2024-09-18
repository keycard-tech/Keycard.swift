enum CertificateTag: UInt8 {
    case certificate = 0x8A
}

public struct Certificate {
    let identPub: [UInt8]
    let caSignature: RecoverableSignature
    
    public static func fromTLV(certData: [UInt8]) -> Certificate {
        let pub = Array(certData[0..<33])
        let r = Array(certData[33..<65])
        let s = Array(certData[65..<97])
        let recId = certData[97]
        
        let hash = Crypto.shared.sha256(pub)
        let caPub = Crypto.shared.secp256k1RecoverPublic(r: r, s: s, recId: recId, hash: hash, compressed: true)
        let caSig = RecoverableSignature(r: r, s: s, recId: recId, publicKey: caPub, compressed: true)

        return Certificate(identPub: pub, caSignature: caSig);
    }
    
    public static func verifyIdentity(hash: [UInt8], tlvData: [UInt8]) throws -> [UInt8]? {
        let tlv = TinyBERTLV(tlvData)
        _ = try tlv.enterConstructed(tag: ECDSASignatureTag.signatureTemplate.rawValue)
        let certData = try tlv.readPrimitive(tag: CertificateTag.certificate.rawValue)
        let cert = Certificate.fromTLV(certData: certData)
        let signature = tlv.peekUnread()
        
        if (!Crypto.shared.secp256k1Verify(signature: signature, hash: hash, pubKey: cert.identPub)) {
            return nil
        }
        
        return cert.caSignature.publicKey
    }
}
