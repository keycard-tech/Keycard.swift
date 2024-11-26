import Foundation

extension StringProtocol {
  var asciiValues: [UInt8] { compactMap(\.asciiValue) }
}

enum MetadataError: Error {
  case invalidVersion
}

public struct Metadata {
  public var cardName: String
  public var wallets: Set<UInt32>
  
  public static func fromData(_ data: [UInt8]) throws -> Metadata {
    let version = (data[0] & 0xe0) >> 5

    if (version != 1) {
        throw MetadataError.invalidVersion
    }

    let namelen = Int(data[0] & 0x1f)
    var off = 1

    let cardName = String(bytes: data[off..<(off + namelen)], encoding: .ascii)!
    
    off += namelen

    var wallets = Set<UInt32>()

    while(off < data.count) {
      let (start, startoff) = try TinyBERTLV.readNum(data, off);
      let (count, countoff) = try TinyBERTLV.readNum(data, startoff)
      off = countoff

      for i in start...(start + count) {
        wallets.insert(i)
      }
    }

    return Metadata(cardName, wallets)
  }

  init(_ cardName: String, _ wallets: Set<UInt32>) {
    self.cardName = cardName;
    self.wallets = wallets;
  }

  public init(_ cardName: String) {
    self.init(cardName, Set<UInt32>());
  }

  public func serialize() -> [UInt8] {
    let name = self.cardName.asciiValues
    var result = [UInt8(0x20 | name.count)] + name

    if (self.wallets.isEmpty) {
      return result
    }

    let sortedWallets = self.wallets.sorted()
    var start = sortedWallets[0]
    var len = 0

    for i in 1..<sortedWallets.count {
      if (sortedWallets[i] == (start + UInt32(len) + 1)) {
        len = len + 1;
      } else {
        result = result + TinyBERTLV.writeNum(start) + TinyBERTLV.writeNum(UInt32(len))
        len = 0;
        start = sortedWallets[i];
      }
    }

    result = result + TinyBERTLV.writeNum(start) + TinyBERTLV.writeNum(UInt32(len))

    return result;
  }
}
