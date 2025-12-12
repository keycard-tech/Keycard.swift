import Foundation
import CoreNFC
import os.log

@available(iOS 13.0, *)
public class CoreNFCCardChannel: CardChannel {

    public enum Error: Swift.Error {
        case invalidAPDU
    }

    private let tag: NFCISO7816Tag

    public init(tag: NFCISO7816Tag) {
        self.tag = tag
    }

    public var connected: Bool {
        return tag.isAvailable
    }

    /// This call is blocking. Do not call it on main thread or within the `connect()` method of the NFCTagReaderSession.
    /// Instead, call it asynchronously on a background thread.
    public func send(_ cmd: APDUCommand) throws -> APDUResponse {
        dispatchPrecondition(condition: DispatchPredicate.notOnQueue(DispatchQueue.main))

        os_log("CardChannel: ==> (cla=0x%02X ins=0x%02X p1=0x%02X p2=0x%02X lc=0x%02X)", log: .default, type: .debug, cmd.cla, cmd.ins, cmd.p1, cmd.p2, cmd.data.count)

        typealias APDUResult = (responseData: Data, sw1: UInt8, sw2: UInt8, error: Swift.Error?)

        var result: APDUResult! = nil

        guard let apdu = NFCISO7816APDU(data: Data(cmd.serialize())) else {
            throw Error.invalidAPDU
        }

        let semaphore = DispatchSemaphore(value: 0)
        tag.sendCommand(apdu: apdu) {
            result = ($0, $1, $2, $3)
            os_log("CardChannel: <== (data len=0x%02X sw=0x%02X%02X)", log: .default, type: .debug, result.responseData.count, result.sw1, result.sw2)
            semaphore.signal()
        }
        semaphore.wait()

        if let error = result.error {
            os_log("CardChannel: error: %@", error.localizedDescription)
            throw error
        }

        var array = [UInt8](repeating: 0, count: result.responseData.count)
        
        for i in 0..<array.count {
            array[i] = result.responseData[i]
        }

        return APDUResponse(sw1: result.sw1, sw2: result.sw2, data: array)
    }

}
