enum TLVTag: UInt8 {
  case bool = 0x01
  case int = 0x02
}

enum TLVError: Error {
  case unexpectedTag(expected: UInt8, actual: UInt8)
  case unexpectedLength(length: Int)
  case endOfTLV
}

class TinyBERTLV {
  let buf: [UInt8]
  var pos: Int

  public static func readNum(_ buf: [UInt8], _ ioff: Int) throws -> (UInt32, Int) {
    var off = ioff
    var len = UInt32(buf[off])
    off += 1
    var lenlen = 0

    if ((len & 0x80) == 0x80) {
      lenlen = Int(len & 0x7f)
      len = try readVal(buf, off, lenlen)
    }

    return (len, off + lenlen)
  }

  public static func readVal(_ val: [UInt8], _ off: Int, _ len: Int) throws -> UInt32 {
    switch (len) {
    case 1:
      return UInt32(val[off])
    case 2:
      return UInt32(val[off] << 8) | UInt32(val[off+1])
    case 3:
      return UInt32(val[off] << 16) | UInt32(val[off+1] << 8) | UInt32(val[off+2])
    case 4:
      return UInt32(val[off] << 24) | UInt32(val[off+1] << 16) | UInt32(val[off+2] << 8) | UInt32(val[off+3])
    default:
      throw TLVError.unexpectedLength(length: len)
    }    
  }

  public static func writeNum(_ len: UInt32) -> [UInt8] {
    if ((len & 0xff000000) != 0) {
      return [
        UInt8(0x84), 
        UInt8((len & 0xff000000) >> 24), 
        UInt8((len & 0x00ff0000) >> 16), 
        UInt8((len & 0x0000ff00) >> 8), 
        UInt8(len & 0x000000ff)
      ]
    } else if ((len & 0x00ff0000) != 0) {
      return [
        UInt8(0x83), 
        UInt8((len & 0x00ff0000) >> 16), 
        UInt8((len & 0x0000ff00) >> 8), 
        UInt8(len & 0x000000ff)
      ]
    } else if ((len & 0x0000ff00) != 0) {
      return [
        UInt8(0x82), 
        UInt8((len & 0x0000ff00) >> 8), 
        UInt8(len & 0x000000ff)
      ]
    } else if ((len & 0x00000080) != 0) {
      return [
        UInt8(0x81),
        UInt8(len & 0x000000ff)
      ]
    } else {
      return [
        UInt8(len & 0x000000ff)
      ]
    }
  }  

  init(_ buf: [UInt8]) {
    self.buf = buf
    self.pos = 0
  }

  func enterConstructed(tag: UInt8) throws -> Int {
    try checkTag(expected: tag, actual: readTag())
    return readLength()
  }

  func readPrimitive(tag: UInt8) throws -> [UInt8] {
    try checkTag(expected: tag, actual: readTag())
    let len = readLength()
    pos += len
    return Array(buf[Int((pos - len))..<pos])
  }

  func readBoolean() throws -> Bool {
    let val = try readPrimitive(tag: TLVTag.bool.rawValue)
    return val[0] == 0xff
  }

  func readInt() throws -> Int {
    let val = try readPrimitive(tag: TLVTag.int.rawValue)
    switch val.count {
    case 1:
      return Int(val[0])
    case 2:
      return (Int(val[0]) << 8) | Int(val[1])
    case 3:
      return (Int(val[0]) << 16) | (Int(val[1] << 8)) | Int(val[2])
    case 4:
      return (Int(val[0]) << 24) | (Int(val[1] << 16)) | (Int(val[2] << 8)) | Int(val[3])
    default:
      throw TLVError.unexpectedLength(length: val.count)
    }
  }
    
  func peekUnread() -> [UInt8] {
    return Array(self.buf[self.pos..<self.buf.count])
  }

  func readLength() -> Int {
    var len = Int(buf[pos])
    pos += 1

    if (len == 0x81) {
      len = Int(buf[pos])
      pos += 1
    }

    return len
  }

  func readTag() throws -> UInt8 {
    if (pos < buf.count) {
      let ret = buf[pos]
      pos += 1
      return ret
    } else {
      throw TLVError.endOfTLV
    }
  }

  func unreadLastTag() {
    if (pos < buf.count) {
      pos -= 1;
    }
  }

  func checkTag(expected: UInt8, actual: UInt8) throws {
    if (expected != actual) {
      unreadLastTag()
      throw TLVError.unexpectedTag(expected: expected, actual: actual)
    }
  }
}
