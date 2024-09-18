import secp256k1
import CryptoSwift
import CommonCrypto
import Foundation

enum PBKDF2HMac {
    case sha256
    case sha512
}

class Crypto {
    static let shared = Crypto()

    let secp256k1Ctx: OpaquePointer

    private init() {
        secp256k1Ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
    }

    deinit {
        secp256k1_context_destroy(secp256k1Ctx)
    }

    func aes256Enc(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        let result = try! AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding).encrypt(data)
        return result
    }

    func aes256Dec(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        let result = try! AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding).decrypt(data)
        return result
    }

    func aes256CMac(data: [UInt8], key: [UInt8]) -> [UInt8] {
        let result = aes256Enc(data: data, iv: [UInt8](repeating: 0, count: SecureChannel.blockLength), key: key).suffix(16)
        return Array(result)
    }
    
    func desEnc(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [UInt8](repeating: 0, count: data.count)
        var encrypted: Int = 0
        var tmpKey = key
        var tmpData = data
        var tmpIV = iv
        
        CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(0), &tmpKey, key.count, &tmpIV, &tmpData, data.count, &out, out.count, &encrypted)
        return out
    }
    
    func desDec(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [UInt8](repeating: 0, count: data.count)
        var decrypted: Int = 0
        var tmpKey = key
        var tmpData = data
        var tmpIV = iv
        
        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(0), &tmpKey, key.count, &tmpIV, &tmpData, data.count, &out, out.count, &decrypted)
        return out
    }
       
    func des3Enc(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [UInt8](repeating: 0, count: data.count)
        var encrypted: Int = 0
        var tmpKey = key
        var tmpData = data
        var tmpIV = iv
        
        CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithm3DES), CCOptions(0), &tmpKey, key.count, &tmpIV, &tmpData, data.count, &out, out.count, &encrypted)
        return out
    }
    
    func des3Dec(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [UInt8](repeating: 0, count: data.count)
        var decrypted: Int = 0
        var tmpKey = key
        var tmpData = data
        var tmpIV = iv
        
        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithm3DES), CCOptions(0), &tmpKey, key.count, &tmpIV, &tmpData, data.count, &out, out.count, &decrypted)
        return out
    }
    
    func des3Mac(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        let enc: [UInt8] = des3Enc(data: data, iv: iv, key: key)
        return Array(enc.suffix(8))
    }
    
    func des3FullMac(data: [UInt8], iv: [UInt8], key: [UInt8]) -> [UInt8] {
        let des3IV : [UInt8]
        
        if (data.count > 8) {
            des3IV = Array(desEnc(data: Array(data[0..<(data.count - 8)]), iv: iv, key: resizeDESKey8(key)).suffix(8))
        } else {
            des3IV = iv
        }
        
        return des3Mac(data: Array(data.suffix(8)), iv: des3IV, key: key)
    }
    
    func resizeDESKey8(_ key: [UInt8]) -> [UInt8] {
        return Array(key[0..<8])
    }
    
    func iso7816_4Pad(data: [UInt8], blockSize: Int) -> [UInt8] {
        var padded = Array(data)
        padded.append(0x80)

        // can be obviously optimized, but I really doubt it makes sense, and this is easier to read
        while (padded.count % blockSize) != 0 {
            padded.append(0x00)
        }

        return padded
    }

    func iso7816_4Unpad(data: [UInt8]) -> [UInt8] {
        if let idx = data.lastIndex(of: 0x80) {
            return Array(data[..<idx])
        } else {
            return data
        }
    }

    func pbkdf2(password: String, salt: [UInt8], iterations: Int, hmac: PBKDF2HMac) -> [UInt8] {
        // implemented using CommonCrypto because it is much faster (ms vs s) on the device than CryptoSwfit implementation.
        let keyLength: Int
        let prf: CCPseudoRandomAlgorithm

        switch hmac {
        case .sha256:
            keyLength = 32
            prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .sha512:
            keyLength = 64
            prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }

        precondition(salt.count < 133, "Salt must be less than 133 bytes length")
        var saltBytes = salt
        var outKey: [UInt8] = [UInt8](repeating: 0, count: keyLength)
        let result = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                          password,
                                          password.lengthOfBytes(using: String.Encoding.utf8),
                                          &saltBytes,
                                          saltBytes.count,
                                          prf,
                                          UInt32(iterations),
                                          &outKey,
                                          keyLength)
        if result == kCCParamError {
            preconditionFailure("PBKDF error")
        }
        return outKey
    }

    func hmacSHA512(data: [UInt8], key: [UInt8]) -> [UInt8] {
        return try! HMAC(key: key, variant: .sha512).authenticate(data)
    }

    func sha256(_ data: [UInt8]) -> [UInt8] {
        Digest.sha256(data)
    }

    func sha512(_ data: [UInt8]) -> [UInt8] {
        Digest.sha512(data)
    }

    func keccak256(_ data: [UInt8]) -> [UInt8] {
        Digest.sha3(data, variant: .keccak256)
    }

    func secp256k1GeneratePair() -> ([UInt8], [UInt8]) {
        var secretKey: [UInt8]

        repeat {
            secretKey = random(count: 32)
        } while secp256k1_ec_seckey_verify(secp256k1Ctx, &secretKey) != Int32(1)

        return (secretKey, secp256k1PublicFromPrivate(secretKey))
    }

    func secp256k1ECDH(privKey: [UInt8], pubKey pubKeyBytes: [UInt8]) -> [UInt8] {
        var pubKey = secp256k1_pubkey()
        var ecdhOut = [UInt8](repeating: 0, count: 32)
        _ = secp256k1_ec_pubkey_parse(secp256k1Ctx, &pubKey, pubKeyBytes, pubKeyBytes.count)
        _ = secp256k1_ecdh(secp256k1Ctx, &ecdhOut, &pubKey, privKey, { (output, x, _, _) -> Int32 in memcpy(output, x, 32); return 1 }, nil)

        return ecdhOut
    }

    func secp256k1PublicToEthereumAddress(_ pubKey: [UInt8]) -> [UInt8] {
        Array(keccak256(Array(pubKey[1...]))[12...])
    }

    func secp256k1PublicFromPrivate(_ privKey: [UInt8]) -> [UInt8] {
        var pubKey = secp256k1_pubkey()
        _ = secp256k1_ec_pubkey_create(secp256k1Ctx, &pubKey, privKey)
        return _secp256k1PubToBytes(&pubKey, false)
    }

    func secp256k1RecoverPublic(r: [UInt8], s: [UInt8], recId: UInt8, hash: [UInt8], compressed: Bool) -> [UInt8] {
        var sig = secp256k1_ecdsa_recoverable_signature()
        _ = secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1Ctx, &sig, r + s, Int32(recId))

        var pubKey = secp256k1_pubkey()
        _ = secp256k1_ecdsa_recover(secp256k1Ctx, &pubKey, &sig, hash)
        return _secp256k1PubToBytes(&pubKey, compressed)
    }

    func secp256k1Sign(hash: [UInt8], privKey: [UInt8]) -> [UInt8] {
        var sig = secp256k1_ecdsa_signature()

        _ = secp256k1_ecdsa_sign(secp256k1Ctx, &sig, hash, privKey, nil, nil)
        var derSig = [UInt8](repeating: 0, count: 72)
        var derOutLen = 72

        secp256k1_ecdsa_signature_serialize_der(secp256k1Ctx, &derSig, &derOutLen, &sig)
        return Array(derSig[0..<derOutLen])
    }
    
    func secp256k1Verify(signature: [UInt8], hash: [UInt8], pubKey: [UInt8]) -> Bool {
        var sig = secp256k1_ecdsa_signature()
        _ = secp256k1_ecdsa_signature_parse_der(secp256k1Ctx, &sig, signature, signature.count)
        
        var pkey = secp256k1_pubkey();
        _ = secp256k1_ec_pubkey_parse(secp256k1Ctx, &pkey, pubKey, pubKey.count)
        
        return secp256k1_ecdsa_verify(secp256k1Ctx, &sig, hash, &pkey) != 0
    }

    private func _secp256k1PubToBytes(_ pubKey: inout secp256k1_pubkey, _ compressed: Bool) -> [UInt8] {
        var outputLen: Int
        var compressedFlag: UInt32
        
        if (compressed) {
            outputLen = 33
            compressedFlag = UInt32(SECP256K1_EC_COMPRESSED)
        } else {
            outputLen = 65
            compressedFlag = UInt32(SECP256K1_EC_UNCOMPRESSED)
        }
        
        var pubKeyBytes = [UInt8](repeating: 0, count: outputLen)
        _ = secp256k1_ec_pubkey_serialize(secp256k1Ctx, &pubKeyBytes, &outputLen, &pubKey, compressedFlag)

        return pubKeyBytes
    }

    func random(count: Int) -> [UInt8] {
        AES.randomIV(count)
    }
}
