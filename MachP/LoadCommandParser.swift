import Foundation

// Extend or reuse MachOParsingError if needed
// Assuming MachOParsingError is available in the project
public class LoadCommandParser {

    /// Parses all load commands from the given file data starting at the specified offset.
    /// - Parameters:
    ///   - fileData: The complete file data.
    ///   - offset: The offset at which the load commands begin (immediately after the Mach-O header).
    ///   - ncmds: The number of load commands to parse.
    ///   - isBigEndian: A flag indicating whether the file uses big-endian byte order.
    /// - Returns: An array of dictionaries where each dictionary represents a parsed load command.
    public static func parseLoadCommands(from fileData: Data, offset: Int, ncmds: UInt32, isBigEndian: Bool) throws -> [[String: Any]] {
        var loadCommands: [[String: Any]] = []
        var currentOffset = offset

        for _ in 0..<ncmds {
            // Each load command starts with two UInt32 fields: cmd and cmdsize
            guard fileData.count >= currentOffset + 8 else {
                throw MachOParsingError.parsingFailed("Not enough data for load command at offset \(currentOffset)")
            }

            let cmdRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset, as: UInt32.self) }
            let cmdsizeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 4, as: UInt32.self) }
            let cmd = isBigEndian ? UInt32(bigEndian: cmdRaw) : UInt32(littleEndian: cmdRaw)
            let cmdsize = isBigEndian ? UInt32(bigEndian: cmdsizeRaw) : UInt32(littleEndian: cmdsizeRaw)

            var loadCommand: [String: Any] = [
                "cmd": String(format: "0x%08x", cmd),
                "cmdsize": cmdsize
            ]

            // Depending on the command type, parse additional fields
            // LC_SEGMENT_64: 0x19
            if cmd == 0x19 {
                // Ensure sufficient data for LC_SEGMENT_64 (72 bytes total)
                guard fileData.count >= currentOffset + 72 else {
                    throw MachOParsingError.parsingFailed("Not enough data for LC_SEGMENT_64 at offset \(currentOffset)")
                }
                // Read segname (16 bytes) and other fields
                let segnameData = fileData.subdata(in: currentOffset + 8..<currentOffset + 24)
                let segname = String(data: segnameData, encoding: .ascii)?.trimmingCharacters(in: .controlCharacters) ?? ""
                let vmaddr: UInt64 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 24, as: UInt64.self) }
                let vmsize: UInt64 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 32, as: UInt64.self) }
                let fileoff: UInt64 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 40, as: UInt64.self) }
                let filesize: UInt64 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 48, as: UInt64.self) }
                let maxprot: Int32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 56, as: Int32.self) }
                let initprot: Int32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 60, as: Int32.self) }
                let nsects: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 64, as: UInt32.self) }
                let flags: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 68, as: UInt32.self) }

                loadCommand["type"] = "LC_SEGMENT_64"
                loadCommand["segname"] = segname
                loadCommand["vmaddr"] = vmaddr
                loadCommand["vmsize"] = vmsize
                loadCommand["fileoff"] = fileoff
                loadCommand["filesize"] = filesize
                loadCommand["maxprot"] = maxprot
                loadCommand["initprot"] = initprot
                loadCommand["nsects"] = nsects
                loadCommand["flags"] = flags
            } else if cmd == 0x2 {
                // LC_SYMTAB: 0x2
                // Ensure sufficient data for LC_SYMTAB (24 bytes total)
                guard fileData.count >= currentOffset + 24 else {
                    throw MachOParsingError.parsingFailed("Not enough data for LC_SYMTAB at offset \(currentOffset)")
                }
                let symoff: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 8, as: UInt32.self) }
                let nsyms: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 12, as: UInt32.self) }
                let stroff: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 16, as: UInt32.self) }
                let strsize: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 20, as: UInt32.self) }

                loadCommand["type"] = "LC_SYMTAB"
                loadCommand["symoff"] = symoff
                loadCommand["nsyms"] = nsyms
                loadCommand["stroff"] = stroff
                loadCommand["strsize"] = strsize
            } else if cmd == 0xc || cmd == 0xd {
                // LC_LOAD_DYLIB (0xc) or LC_ID_DYLIB (0xd)
                // Minimum size for dylib_command is 24 bytes
                guard fileData.count >= currentOffset + 24 else {
                    throw MachOParsingError.parsingFailed("Not enough data for LC_LOAD_DYLIB/LC_ID_DYLIB at offset \(currentOffset)")
                }
                let nameOffset: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 8, as: UInt32.self) }
                let timestamp: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 12, as: UInt32.self) }
                let currentVersion: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 16, as: UInt32.self) }
                let compatibilityVersion: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: currentOffset + 20, as: UInt32.self) }

                loadCommand["type"] = (cmd == 0xc) ? "LC_LOAD_DYLIB" : "LC_ID_DYLIB"
                loadCommand["nameOffset"] = nameOffset
                loadCommand["timestamp"] = timestamp
                loadCommand["currentVersion"] = currentVersion
                loadCommand["compatibilityVersion"] = compatibilityVersion
                
                // Attempt to read the library name string
                let nameStart = currentOffset + Int(nameOffset)
                let nameLength = Int(cmdsize) - Int(nameOffset)
                if fileData.count >= nameStart + nameLength {
                    let nameData = fileData.subdata(in: nameStart..<nameStart + nameLength)
                    if let libName = String(data: nameData, encoding: .utf8)?.trimmingCharacters(in: .controlCharacters) {
                        loadCommand["libraryName"] = libName
                    }
                }
            } else {
                // For other load commands, simply record the type as unknown
                loadCommand["type"] = "Unknown (0x\(String(format: "%08x", cmd)))"
            }

            loadCommands.append(loadCommand)
            currentOffset += Int(cmdsize)
        }

        return loadCommands
    }
}
