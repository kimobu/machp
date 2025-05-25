import Foundation

private let logger = LoggerFactory.make("com.machp.SegmentSectionParser")

public class SegmentSectionParser {
    static let segmentCommandSize = 72  // Size of LC_SEGMENT_64 command before sections
    static let sectionSize = 80         // Size of each section_64 struct
    
    // Helper function to read a UInt32 with the appropriate endianness
    private static func readUInt32(from data: Data, at offset: Int, isBigEndian: Bool) -> UInt32 {
        let value: UInt32 = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
        return isBigEndian ? UInt32(bigEndian: value) : UInt32(littleEndian: value)
    }
    
    // Helper function to read a UInt64 with the appropriate endianness
    private static func readUInt64(from data: Data, at offset: Int, isBigEndian: Bool) -> UInt64 {
        let value: UInt64 = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt64.self) }
        return isBigEndian ? UInt64(bigEndian: value) : UInt64(littleEndian: value)
    }
    
    // Helper function to read an Int32 with the appropriate endianness
    private static func readInt32(from data: Data, at offset: Int, isBigEndian: Bool) -> Int32 {
        let value: Int32 = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: Int32.self) }
        return isBigEndian ? Int32(bigEndian: value) : Int32(littleEndian: value)
    }
    
    // Helper function to read a fixed-length string from data
    private static func readString(from data: Data, at offset: Int, length: Int) -> String {
        let subdata = data.subdata(in: offset..<offset+length)
        return String(data: subdata, encoding: .ascii)?.trimmingCharacters(in: .controlCharacters).trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }
    
    /// Parses a LC_SEGMENT_64 command and its associated sections from the provided data
    /// - Parameters:
    ///   - fileData: The complete Mach-O file data
    ///   - offset: The offset where the LC_SEGMENT_64 command starts
    ///   - isBigEndian: Whether the data is in big-endian format
    /// - Returns: A dictionary representing the segment and an array of its parsed sections
    public static func parseSegmentAndSections(from fileData: Data, at offset: Int, isBigEndian: Bool) throws -> [String: Any] {
        // Ensure sufficient data for LC_SEGMENT_64 command
        guard fileData.count >= offset + segmentCommandSize else {
            throw MachOParsingError.parsingFailed("Incomplete LC_SEGMENT_64 command at offset \(offset)")
        }
        
        // Parse segment fields from LC_SEGMENT_64 (fields as per structure layout)
        let segname = readString(from: fileData, at: offset + 8, length: 16)
        let vmaddr = readUInt64(from: fileData, at: offset + 24, isBigEndian: isBigEndian)
        let vmsize = readUInt64(from: fileData, at: offset + 32, isBigEndian: isBigEndian)
        let fileoff = readUInt64(from: fileData, at: offset + 40, isBigEndian: isBigEndian)
        let filesize = readUInt64(from: fileData, at: offset + 48, isBigEndian: isBigEndian)
        let maxprot = readInt32(from: fileData, at: offset + 56, isBigEndian: isBigEndian)
        let initprot = readInt32(from: fileData, at: offset + 60, isBigEndian: isBigEndian)
        let nsects = readUInt32(from: fileData, at: offset + 64, isBigEndian: isBigEndian)
        let flags = readUInt32(from: fileData, at: offset + 68, isBigEndian: isBigEndian)

        logger.debug("Parsing segment '\(segname)' at offset \(offset): vmaddr=0x\(String(format: "%016x", vmaddr)), vmsize=\(vmsize), fileoff=\(fileoff), filesize=\(filesize), nsects=\(nsects), flags=0x\(String(format: "%08x", flags))")
        
        var segmentDict: [String: Any] = [
            "segname": segname,
            "vmaddr": vmaddr,
            "vmsize": vmsize,
            "fileoff": fileoff,
            "filesize": filesize,
            "maxprot": maxprot,
            "initprot": initprot,
            "nsects": nsects,
            "flags": flags
        ]

        if filesize > 0 && Int(fileoff) + Int(filesize) <= fileData.count {
            let start = Int(fileoff)
            let end = start + Int(filesize)
            let segData = fileData.subdata(in: start..<end)
            segmentDict["entropy"] = segData.entropy()
        }
        
        var sections: [[String: Any]] = []
        // Sections start immediately after the LC_SEGMENT_64 command (72 bytes into the command)
        var sectionOffset = offset + segmentCommandSize
        
        for i in 0..<nsects {
            guard fileData.count >= sectionOffset + sectionSize else {
                throw MachOParsingError.parsingFailed("Incomplete section_64 at index \(i) in segment \(segname)")
            }
            
            let sectname = readString(from: fileData, at: sectionOffset, length: 16)
            let segnameSection = readString(from: fileData, at: sectionOffset + 16, length: 16)
            let addr = readUInt64(from: fileData, at: sectionOffset + 32, isBigEndian: isBigEndian)
            let size = readUInt64(from: fileData, at: sectionOffset + 40, isBigEndian: isBigEndian)
            let offsetField = readUInt32(from: fileData, at: sectionOffset + 48, isBigEndian: isBigEndian)
            let align = readUInt32(from: fileData, at: sectionOffset + 52, isBigEndian: isBigEndian)
            let reloff = readUInt32(from: fileData, at: sectionOffset + 56, isBigEndian: isBigEndian)
            let nreloc = readUInt32(from: fileData, at: sectionOffset + 60, isBigEndian: isBigEndian)
            let sectFlags = readUInt32(from: fileData, at: sectionOffset + 64, isBigEndian: isBigEndian)
            let reserved1 = readUInt32(from: fileData, at: sectionOffset + 68, isBigEndian: isBigEndian)
            let reserved2 = readUInt32(from: fileData, at: sectionOffset + 72, isBigEndian: isBigEndian)
            let reserved3 = readUInt32(from: fileData, at: sectionOffset + 76, isBigEndian: isBigEndian)
            
            let sectionDict: [String: Any] = [
                "sectname": sectname,
                "segname": segnameSection,
                "addr": addr,
                "size": size,
                "offset": offsetField,
                "align": align,
                "reloff": reloff,
                "nreloc": nreloc,
                "flags": sectFlags,
                "reserved1": reserved1,
                "reserved2": reserved2,
                "reserved3": reserved3
            ]
            sections.append(sectionDict)
            
            // Debug log
            logger.debug(" Section \(i): sectname='\(sectname)', segname='\(segnameSection)', addr=0x\(String(format: "%016x", addr)), size=\(size), offset=\(offsetField), align=\(align), flags=0x\(String(format: "%08x", sectFlags))")
            
            sectionOffset += sectionSize
        }
        
        segmentDict["sections"] = sections
        return segmentDict
    }
}
