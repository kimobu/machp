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

        logger.debug("Parsed header: magic=0x\(String(format: "%08x", magic)), cputype=\(cputype), cpusubtype=\(cpusubtype), filetype=\(filetype), ncmds=\(ncmds), sizeofcmds=\(sizeofcmds), flags=0x\(String(format: "%08x", flags)), reserved=\(reserved)")

        let headerDict: [String: Any] = [
            "magic": String(format: "0x%08x", magic),
            "cputype": cputype,
            "cpusubtype": cpusubtype,
            "filetype": filetype,
            "ncmds": ncmds,
            "sizeofcmds": sizeofcmds,
            "flags": flags,
            "reserved": reserved
        ]
        return headerDict
    }
}
