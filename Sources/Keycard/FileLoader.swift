import Foundation

#if USE_SPM
import ZipArchive
#else
import SSZipArchive
#endif

struct FileLoader {
    private static let blockSize = 247 // 255 - 8 bytes for MAC
    private static let fileNames = ["Header.cap", "Directory.cap", "Import.cap", "Applet.cap", "Class.cap", "Method.cap", "StaticField.cap", "Export.cap", "ConstantPool.cap", "RefLocation.cap"]
    private static let fileTag: UInt8 = 0xc4

    public enum Error: Swift.Error {
        case fileIsTooLarge
        case fileIsEmpty
    }

    private var currentBlock: UInt8 = 0
    private var dataOffset: Int = 0
    private var data: [UInt8]

    public init(fileURL: URL) throws {
        let files = try Self.unzipFileAndGetSubfilesURLs(fileURL: fileURL)

        // Flatten the data contained in each file
        let flattenedFileData = try files.flatMap { Array(try Data(contentsOf: $0)) }
        let encodedLength = try Self.encodeFullLength(flattenedFileData.count)
        self.data = [Self.fileTag] + encodedLength + flattenedFileData
    }

    private static func unzipFileAndGetSubfilesURLs(fileURL: URL) throws -> [URL] {
        let unzipDirectory = Self.quickUnzipFile(fileURL)
        var files = [URL](repeating: unzipDirectory, count: fileNames.count)
        if let enumerator = FileManager.default.enumerator(at: unzipDirectory, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles, .skipsPackageDescendants]) {
            for case let fileURL as URL in enumerator {
                if let fileIndex = fileNames.firstIndex(of: fileURL.pathComponents.last ?? "") {
                    // Add the files to their appropriate location (order)
                    files[fileIndex] = fileURL
                }
            }
            // Remove files that were not presen in the CAP file
            files = files.filter { $0 != unzipDirectory }
        }

        guard !files.isEmpty else { throw Error.fileIsEmpty }
        return files
    }

    private static func quickUnzipFile(_ path: URL) -> URL {
        let fileExtension = path.pathExtension
        let fileName = path.lastPathComponent
        let directoryName = fileName.replacingOccurrences(of: ".\(fileExtension)", with: "")
        let documentsUrl = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]

        let destinationUrl = documentsUrl.appendingPathComponent(directoryName, isDirectory: true)
        SSZipArchive.unzipFile(atPath: path.path, toDestination: destinationUrl.path)

        return destinationUrl
    }    

    private static func encodeFullLength(_ length: Int) throws -> [UInt8] {
        if length < 0x80 {
            return [UInt8(length)]
        } else if length < 0xff {
            return [0x81, UInt8(length)]
        } else if length < 0xffff {
            return [0x82, UInt8((length & 0xff00) >> 8), UInt8(length & 0xff)]
        } else if length <= 0xffffff {
            return [0x83, UInt8((length & 0xff0000) >> 16), UInt8((length & 0xff00) >> 8), UInt8(length & 0xff)]
        } else {
            throw Error.fileIsTooLarge
        }
    }
}

extension FileLoader: Sequence, IteratorProtocol {

    struct Element {
        var data: [UInt8]
        var blockCount: UInt8
        var hasMoreBlocks: Bool
    }

    var underestimatedCount: Int { (data.count / Self.blockSize) + ((data.count % Self.blockSize) > 0 ? 1 : 0) }

    mutating func next() -> Element? {
        guard currentBlock < underestimatedCount else { return nil }
        defer {
            currentBlock += 1
            dataOffset = dataOffset + Self.blockSize
        }
        return Element(
            data: Array(data[dataOffset ..< Swift.min(dataOffset + Self.blockSize, data.count)]),
            blockCount: currentBlock,
            hasMoreBlocks: currentBlock < underestimatedCount - 1
        )
    }
}
