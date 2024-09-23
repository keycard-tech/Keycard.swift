import Foundation
import CryptoSwift

public class KeycardCommandSet {
    public enum ExportOption {
        case privateAndPublic
        case publicOnly
        case extendedPublic
    }
    
    let cardChannel: CardChannel
    let secureChannel: SecureChannel
    public var info: ApplicationInfo?
    public var pairing: Pairing? { get { secureChannel.pairing } set { secureChannel.pairing = newValue }}
    public var isSecureChannelOpen: Bool { return secureChannel.open }

    public init(cardChannel: CardChannel) {
        self.cardChannel = cardChannel
        self.secureChannel = SecureChannel()
    }

    func pairingPasswordToSecret(password: String) -> [UInt8] {
        Crypto.shared.pbkdf2(password: password,
                             salt: Array("Keycard Pairing Password Salt".utf8),
                             iterations: cardChannel.pairingPasswordPBKDF2IterationCount,
                             hmac: PBKDF2HMac.sha256)
    }

    public func select(instanceIdx: UInt8 = 1) throws -> APDUResponse {
        let selectApplet: APDUCommand = APDUCommand(cla: CLA.iso7816.rawValue, ins: ISO7816INS.select.rawValue, p1: 0x04, p2: 0x00, data: Identifier.getKeycardInstanceAID(instanceId: instanceIdx))
        let resp: APDUResponse = try cardChannel.send(selectApplet)

        if resp.sw == StatusWord.ok.rawValue {
            info = try ApplicationInfo(resp.data)

            if (info!.hasSecureChannelCapability) {
                secureChannel.generateSecret(pubKey: info!.secureChannelPubKey)
                secureChannel.reset()
            }
        }

        return resp
    }

    public func autoOpenSecureChannel() throws {
        try secureChannel.autoOpenSecureChannel(channel: cardChannel)
    }

    public func autoPair(password: String) throws {
        try autoPair(secret: pairingPasswordToSecret(password: password))
    }

    public func autoPair(secret: [UInt8]) throws {
        try secureChannel.autoPair(channel: cardChannel, sharedSecret: secret)
    }

    public func autoUnpair() throws {
        try secureChannel.autoUnpair(channel: cardChannel)
    }

    public func unpairOthers() throws {
        try secureChannel.unpairOthers(channel: cardChannel)
    }
    
    public func identifyCard(challenge: [UInt8]) throws -> APDUResponse {
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.identifyCard.rawValue, p1: 0x00, p2: 0x00, data: challenge)
        return try cardChannel.send(cmd)
    }

    public func openSecureChannel(index: UInt8, data: [UInt8]) throws -> APDUResponse {
        try secureChannel.openSecureChannel(channel: cardChannel, index: index, data: data)
    }

    public func mutuallyAuthenticate() throws -> APDUResponse {
        try secureChannel.mutuallyAuthenticate(channel: cardChannel)
    }

    public func mutuallyAuthenticate(data: [UInt8]) throws -> APDUResponse {
        try secureChannel.mutuallyAuthenticate(channel: cardChannel, data: data)
    }

    public func pair(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        try secureChannel.pair(channel: cardChannel, p1: p1, data: data)
    }

    public func unpair(p1: UInt8) throws -> APDUResponse {
        try secureChannel.unpair(channel: cardChannel, p1: p1)
    }

    public func getStatus(info: UInt8) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.getStatus.rawValue, p1: info, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func setNDEF(ndef: [UInt8]) throws -> APDUResponse {
        if (info!.appVersion >> 8) > 2 {
            let len = (Int(ndef[0]) << 8) | Int(ndef[1])

            var finalNDEF: [UInt8]

            if len != (ndef.count - 2) {
                finalNDEF = [UInt8(ndef.count >> 8), UInt8(ndef.count & 0xff)] + ndef
            } else {
                finalNDEF = ndef
            }

            return try storeData(data: finalNDEF, type: StoreDataP1.ndef.rawValue)
        } else {
            let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.setNDEF.rawValue, p1: 0, p2: 0, data: ndef)
            return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
        }
    }

    public func storeData(data: [UInt8], type: UInt8) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.storeData.rawValue, p1: type, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func getData(type: UInt8) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.getData.rawValue, p1: type, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func verifyPIN(pin: String) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.verifyPIN.rawValue, p1: 0, p2: 0, data: Array(pin.utf8))
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func changePIN(pin: String) throws -> APDUResponse {
        try changePIN(p1: ChangePINP1.userPIN.rawValue, data: Array(pin.utf8))
    }

    public func changePUK(puk: String) throws -> APDUResponse {
        try changePIN(p1: ChangePINP1.puk.rawValue, data: Array(puk.utf8))
    }

    public func changePairingPassword(pairingPassword: String) throws -> APDUResponse {
        try changePIN(p1: ChangePINP1.pairingSecret.rawValue, data: pairingPasswordToSecret(password: pairingPassword))
    }

    public func changePIN(type: UInt8, pin: String) throws -> APDUResponse {
        try changePIN(p1: type, data: Array(pin.utf8))
    }

    public func changePIN(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.changePIN.rawValue, p1: p1, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func unblockPIN(puk: String, newPIN: String) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.unblockPIN.rawValue, p1: 0, p2: 0, data: Array((puk + newPIN).utf8))
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func loadKey(seed: [UInt8]) throws -> APDUResponse {
        try loadKey(p1: LoadKeyP1.seed.rawValue, data: seed)
    }

    public func loadKey(privateKey: [UInt8], chainCode: [UInt8]?, publicKey: [UInt8]?) throws -> APDUResponse {
        try loadKey(keyPair: BIP32KeyPair(privateKey: privateKey, chainCode: chainCode, publicKey: publicKey), omitPublic: publicKey == nil)
    }

    public func loadKey(keyPair: BIP32KeyPair, omitPublic: Bool = false) throws -> APDUResponse {
        let p1 = keyPair.isExtended ? LoadKeyP1.extEC.rawValue : LoadKeyP1.ec.rawValue
        return try loadKey(p1: p1, data: keyPair.toTLV(includePublic: !omitPublic))
    }

    public func loadKey(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.loadKey.rawValue, p1: p1, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func generateMnemonic(length: GenerateMnemonicP1) throws -> APDUResponse {
        try generateMnemonic(p1: length.rawValue)
    }

    public func generateMnemonic(p1: UInt8) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.generateMnemonic.rawValue, p1: p1, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func removeKey() throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.removeKey.rawValue, p1: 0, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func generateKey() throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.generateKey.rawValue, p1: 0, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func sign(hash: [UInt8]) throws -> APDUResponse {
        return try sign(p1: SignP1.currentKey.rawValue, data: hash)
    }

    public func sign(hash: [UInt8], path: String, makeCurrent: Bool) throws -> APDUResponse {
        let path = try KeyPath(path)
        let p1 = (makeCurrent ? SignP1.deriveAndMakeCurrent.rawValue : SignP1.deriveKey.rawValue) | path.source.rawValue
        return try sign(p1: p1, data: (hash + path.data))
    }

    public func signPinless(hash: [UInt8]) throws -> APDUResponse {
        try sign(p1: SignP1.pinless.rawValue, data: hash)
    }

    public func sign(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.sign.rawValue, p1: p1, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func deriveKey(path: String) throws -> APDUResponse {
        let path = try KeyPath(path)
        return try deriveKey(p1: path.source.rawValue, data: path.data)
    }

    public func deriveKey(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.deriveKey.rawValue, p1: p1, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func setPinlessPath(path: String) throws -> APDUResponse {
        let path = try KeyPath(path)
        precondition(path.source == DeriveKeyP1.fromMaster)

        return try setPinlessPath(data: path.data)
    }

    public func resetPinlessPath() throws -> APDUResponse {
        try setPinlessPath(data: [])
    }

    public func setPinlessPath(data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.setPinlessPath.rawValue, p1: 0, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    @available(*, deprecated, renamed: "exportCurrentKey(exportOption:)")
    public func exportCurrentKey(publicOnly: Bool) throws -> APDUResponse {
        let p2 = publicOnly ? ExportKeyP2.publicOnly.rawValue : ExportKeyP2.privateAndPublic.rawValue
        return try exportKey(p1: ExportKeyP1.currentKey.rawValue, p2: p2, data: [])
    }
    
    public func exportCurrentKey(exportOption: ExportOption) throws -> APDUResponse {
        let p2: UInt8
        switch exportOption {
        case .privateAndPublic:
            p2 = ExportKeyP2.privateAndPublic.rawValue
        case .publicOnly:
            p2 = ExportKeyP2.publicOnly.rawValue
        case .extendedPublic:
            p2 = ExportKeyP2.extendedPublic.rawValue
        }
        return try exportKey(p1: ExportKeyP1.currentKey.rawValue, p2: p2, data: [])
    }

    @available(*, deprecated, renamed: "exportKey(path:makeCurrent:exportOption:)")
    public func exportKey(path: String, makeCurrent: Bool, publicOnly: Bool) throws -> APDUResponse {
        let path = try KeyPath(path)
        let p1 = (makeCurrent ? ExportKeyP1.deriveAndMakeCurrent.rawValue : ExportKeyP1.deriveKey.rawValue) | path.source.rawValue
        let p2 = publicOnly ? ExportKeyP2.publicOnly.rawValue : ExportKeyP2.privateAndPublic.rawValue
        return try exportKey(p1: p1, p2: p2, data: path.data)
    }
    
    public func exportKey(path: String, makeCurrent: Bool, exportOption: ExportOption) throws -> APDUResponse {
        let path = try KeyPath(path)
        let p1 = (makeCurrent ? ExportKeyP1.deriveAndMakeCurrent.rawValue : ExportKeyP1.deriveKey.rawValue) | path.source.rawValue
        let p2: UInt8
        switch exportOption {
        case .privateAndPublic:
            p2 = ExportKeyP2.privateAndPublic.rawValue
        case .publicOnly:
            p2 = ExportKeyP2.publicOnly.rawValue
        case .extendedPublic:
            p2 = ExportKeyP2.extendedPublic.rawValue
        }
        return try exportKey(p1: p1, p2: p2, data: path.data)
    }

    public func exportKey(p1: UInt8, p2: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.exportKey.rawValue, p1: p1, p2: p2, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func initialize(pin: String, puk: String, pairingPassword: String) throws -> APDUResponse {
        try initialize(pin: pin, puk: puk, sharedSecret: pairingPasswordToSecret(password: pairingPassword))
    }

    public func initialize(pin: String, puk: String, sharedSecret: [UInt8]) throws -> APDUResponse {
        let data = (Array((pin + puk).utf8) + sharedSecret)
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.initialize.rawValue, p1: 0, p2: 0, data: secureChannel.oneShotEncrypt(data: data))
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    public func initialize(pin: String, pinAttempts: UInt8?, duressPin: String?, puk: String, pukAttempts: UInt8?, pairingPassword: String) throws -> APDUResponse {
        try initialize(pin: pin, pinAttempts: pinAttempts, duressPin: duressPin, puk: puk, pukAttempts: pukAttempts, sharedSecret: pairingPasswordToSecret(password: pairingPassword))
    }
    
    public func initialize(pin: String, pinAttempts: UInt8?, duressPin: String?, puk: String, pukAttempts: UInt8?, sharedSecret: [UInt8]) throws -> APDUResponse {
        let pinAttempts: UInt8 = pinAttempts ?? 3
        let pukAttempts: UInt8 = pukAttempts ?? 5
        let duressPin = duressPin ?? String(puk[puk.startIndex ..< puk.index(puk.startIndex, offsetBy: 6)])
        let data = (Array((pin + puk).utf8) + sharedSecret + [pinAttempts, pukAttempts] + Array(duressPin.utf8))
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.initialize.rawValue, p1: 0, p2: 0, data: secureChannel.oneShotEncrypt(data: data))
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    public func factoryReset() throws -> APDUResponse {
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.factoryReset.rawValue, p1: FactoryResetP1.magic.rawValue, p2: FactoryResetP2.magic.rawValue, data: [])
        return try cardChannel.send(cmd)
    }
}
