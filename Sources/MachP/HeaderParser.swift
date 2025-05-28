//
//  HeaderParser.swift
//  MachP
//
//  Created by Kimo Bumanglag on 4/13/25.
//
import Foundation
private let logger = LoggerFactory.make("com.machp.HeaderParser")

public struct HeaderParser {
    static let headerSize: Int = 32 // Size of mach_header_64 is 32 bytes

    /// Mapping of `mach_header.flags` bit values to their symbolic names.
    /// The order matches the definitions from <mach-o/loader.h> for
    /// readability when returning decoded flag strings.
    static let flagMapping: [(UInt32, String)] = [
        (0x1,        "MH_NOUNDEFS"),
        (0x2,        "MH_INCRLINK"),
        (0x4,        "MH_DYLDLINK"),
        (0x8,        "MH_BINDATLOAD"),
        (0x10,       "MH_PREBOUND"),
        (0x20,       "MH_SPLIT_SEGS"),
        (0x40,       "MH_LAZY_INIT"),
        (0x80,       "MH_TWOLEVEL"),
        (0x100,      "MH_FORCE_FLAT"),
        (0x200,      "MH_NOMULTIDEFS"),
        (0x400,      "MH_NOFIXPREBINDING"),
        (0x800,      "MH_PREBINDABLE"),
        (0x1000,     "MH_ALLMODSBOUND"),
        (0x2000,     "MH_SUBSECTIONS_VIA_SYMBOLS"),
        (0x4000,     "MH_CANONICAL"),
        (0x8000,     "MH_WEAK_DEFINES"),
        (0x10000,    "MH_BINDS_TO_WEAK"),
        (0x20000,    "MH_ALLOW_STACK_EXECUTION"),
        (0x40000,    "MH_ROOT_SAFE"),
        (0x80000,    "MH_SETUID_SAFE"),
        (0x100000,   "MH_NO_REEXPORTED_DYLIBS"),
        (0x200000,   "MH_PIE"),
        (0x400000,   "MH_DEAD_STRIPPABLE_DYLIB"),
        (0x800000,   "MH_HAS_TLV_DESCRIPTORS"),
        (0x1000000,  "MH_NO_HEAP_EXECUTION"),
        (0x02000000, "MH_APP_EXTENSION_SAFE"),
        (0x04000000, "MH_NLIST_OUTOFSYNC_WITH_DYLDINFO"),
        (0x08000000, "MH_SIM_SUPPORT"),
        (0x80000000, "MH_DYLIB_IN_CACHE")
    ]

    /// Converts a bitmask of header flags into their string representations.
    static func decodeFlags(_ flags: UInt32) -> [String] {
        var result: [String] = []
        for (mask, name) in flagMapping {
            if (flags & mask) != 0 {
                result.append(name)
            }
        }
        return result
    }

    public static func parseMachOHeader(from fileData: Data, at offset: Int) throws -> [String: Any] {
        // Debug helper

        logger.debug("Starting parseMachOHeader at offset \(offset), fileSize=\(fileData.count)")

        guard fileData.count >= offset + headerSize else {
            throw MachOParsingError.parsingFailed("Data too short to contain a valid Mach-O header at offset \(offset)")
        }
        logger.debug("Header data available from \(offset) to \(offset + headerSize)")

        // Read the magic number from the header
        let headerMagic: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
        var isBigEndian: Bool = false
        if headerMagic == 0xfeedfacf { // MH_MAGIC_64
            isBigEndian = false
        } else if headerMagic == 0xcffaedfe { // MH_CIGAM_64
            isBigEndian = true
        } else {
            throw MachOParsingError.invalidFormat("Invalid Mach-O header magic number at offset \(offset): \(headerMagic)")
        }
        logger.debug("Header magic: \(String(format: "0x%08x", headerMagic)), bigEndian: \(isBigEndian)")
        // Utility to read a UInt32 value with the correct endianness
        func readUInt32(at offset: Int) -> UInt32 {
            let value: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
            return isBigEndian ? UInt32(bigEndian: value) : UInt32(littleEndian: value)
        }
        logger.debug("Reading header fields with \(isBigEndian ? "big-endian" : "little-endian") ordering")

        let magic = readUInt32(at: offset)
        let cputype = readUInt32(at: offset + 4)
        let cpusubtype = readUInt32(at: offset + 8)
        let filetype = readUInt32(at: offset + 12)
        let ncmds = readUInt32(at: offset + 16)
        let sizeofcmds = readUInt32(at: offset + 20)
        let flags = readUInt32(at: offset + 24)
        let reserved = readUInt32(at: offset + 28)
        let decodedFlags = decodeFlags(flags)

        logger.debug("Parsed header: magic=0x\(String(format: "%08x", magic)), cputype=\(cputype), cpusubtype=\(cpusubtype), filetype=\(filetype), ncmds=\(ncmds), sizeofcmds=\(sizeofcmds), flags=0x\(String(format: "%08x", flags)), reserved=\(reserved)")

        let headerDict: [String: Any] = [
            "magic": String(format: "0x%08x", magic),
            "cputype": cputype,
            "cpusubtype": cpusubtype,
            "filetype": filetype,
            "ncmds": ncmds,
            "sizeofcmds": sizeofcmds,
            "flags": flags,
            "flagStrings": decodedFlags,
            "reserved": reserved
        ]
        return headerDict
    }
}
