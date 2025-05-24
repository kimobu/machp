import Foundation

public class SymbolParser {
    private static func readUInt32(from data: Data, at offset: Int, isBigEndian: Bool) -> UInt32 {
        let value: UInt32 = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
        return isBigEndian ? UInt32(bigEndian: value) : UInt32(littleEndian: value)
    }

    private static func readUInt64(from data: Data, at offset: Int, isBigEndian: Bool) -> UInt64 {
        let value: UInt64 = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt64.self) }
        return isBigEndian ? UInt64(bigEndian: value) : UInt64(littleEndian: value)
    }

    private static func readUInt8(from data: Data, at offset: Int) -> UInt8 {
        return data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt8.self) }
    }

    /// Parses the complete symbol table (LC_SYMTAB) and dynamic symbol table
    /// (LC_DYSYMTAB) returning symbol names along with table
    /// metadata.
    public static func parseSymbolTables(from fileData: Data,
                                         loadCommands: [[String: Any]],
                                         isBigEndian: Bool) -> [String: Any] {
        var result: [String: Any] = [:]

        if let symtab = loadCommands.first(where: { ($0["type"] as? String) == "LC_SYMTAB" }),
           let symoff = symtab["symoff"] as? UInt32,
           let nsyms  = symtab["nsyms"]  as? UInt32,
           let stroff = symtab["stroff"] as? UInt32,
           let strsize = symtab["strsize"] as? UInt32 {

            var entries: [String] = []
            for i in 0..<nsyms {
                let entryOffset = Int(symoff) + Int(i) * 16
                guard entryOffset + 16 <= fileData.count else { break }

                let strx = readUInt32(from: fileData, at: entryOffset, isBigEndian: isBigEndian)
                let nameOffset = Int(stroff) + Int(strx)
                if nameOffset < fileData.count && Int(stroff) + Int(strsize) > nameOffset {
                    var nameData: [UInt8] = []
                    var idx = nameOffset
                    while idx < fileData.count {
                        let c: UInt8 = fileData[idx]
                        if c == 0 { break }
                        nameData.append(c)
                        idx += 1
                    }
                    if let name = String(bytes: nameData, encoding: .utf8) {
                        entries.append(name)
                    } else {
                        entries.append("")
                    }
                } else {
                    entries.append("")
                }
            }

            result["symtab"] = [
                "symoff": symoff,
                "nsyms": nsyms,
                "stroff": stroff,
                "strsize": strsize,
                "entries": entries
            ]
        }

        if let dysym = loadCommands.first(where: { ($0["type"] as? String) == "LC_DYSYMTAB" }) {
            var dys: [String: Any] = [:]
            for key in ["ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym", "tocoff", "ntoc", "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms", "indirectsymoff", "nindirectsyms", "extreloff", "nextrel", "locreloff", "nlocrel"] {
                if let val = dysym[key] {
                    dys[key] = val
                }
            }
            if !dys.isEmpty {
                result["dysymtab"] = dys
            }
        }

        return result
    }

    private static func readUInt16(from data: Data, at offset: Int, isBigEndian: Bool) -> UInt16 {
        let value: UInt16 = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt16.self) }
        return isBigEndian ? UInt16(bigEndian: value) : UInt16(littleEndian: value)
    }

    /// Parses imported (undefined external) symbol names from the Mach-O slice.
    /// - Parameters:
    ///   - fileData: Slice data starting at offset 0 of the Mach-O image.
    ///   - loadCommands: Load commands dictionary array parsed for this slice.
    ///   - isBigEndian: Indicates if the slice uses big-endian byte order.
    /// - Returns: Dictionary with keys "importedSymbols" (array of symbol names) and "numImportedSymbols" (count).
    public static func parseImportedSymbols(from fileData: Data,
                                            loadCommands: [[String: Any]],
                                            isBigEndian: Bool) -> [String: Any] {
        guard let symtab = loadCommands.first(where: { ($0["type"] as? String) == "LC_SYMTAB" }),
              let symoff = symtab["symoff"] as? UInt32,
              let nsyms  = symtab["nsyms"]  as? UInt32,
              let stroff = symtab["stroff"] as? UInt32,
              let strsize = symtab["strsize"] as? UInt32 else {
            return ["importedSymbols": [], "numImportedSymbols": 0]
        }

        var imported: [String] = []

        for i in 0..<nsyms {
            let entryOffset = Int(symoff) + Int(i) * 16
            guard entryOffset + 16 <= fileData.count else { break }

            let strx = readUInt32(from: fileData, at: entryOffset, isBigEndian: isBigEndian)
            let n_type = readUInt8(from: fileData, at: entryOffset + 4)
            // let n_sect = readUInt8(from: fileData, at: entryOffset + 5)
            // let n_desc = readUInt16 ... not needed
            let n_value = readUInt64(from: fileData, at: entryOffset + 8, isBigEndian: isBigEndian)

            // N_TYPE mask = 0x0e, N_EXT = 0x01, N_UNDF = 0x0
            if (n_type & 0x0e) == 0x0 && (n_type & 0x01) != 0 && n_value == 0 {
                let nameOffset = Int(stroff) + Int(strx)
                if nameOffset < fileData.count && Int(stroff) + Int(strsize) > nameOffset {
                    var nameData: [UInt8] = []
                    var idx = nameOffset
                    while idx < fileData.count {
                        let c: UInt8 = fileData[idx]
                        if c == 0 { break }
                        nameData.append(c)
                        idx += 1
                    }
                    if let name = String(bytes: nameData, encoding: .utf8) {
                        imported.append(name)
                    }
                }
            }
        }

        return ["importedSymbols": imported, "numImportedSymbols": imported.count]
    }

    /// Parses exported symbol names from the Mach-O slice.
    /// - Parameters:
    ///   - fileData: Slice data starting at offset 0 of the Mach-O image.
    ///   - loadCommands: Load commands dictionary array parsed for this slice.
    ///   - isBigEndian: Indicates if the slice uses big-endian byte order.
    /// - Returns: Dictionary with keys "exports" (array of symbol names) and "numExports" (count).
    public static func parseExportedSymbols(from fileData: Data,
                                            loadCommands: [[String: Any]],
                                            isBigEndian: Bool) -> [String: Any] {
        guard let symtab = loadCommands.first(where: { ($0["type"] as? String) == "LC_SYMTAB" }),
              let symoff = symtab["symoff"] as? UInt32,
              let nsyms  = symtab["nsyms"]  as? UInt32,
              let stroff = symtab["stroff"] as? UInt32,
              let strsize = symtab["strsize"] as? UInt32 else {
            return ["exports": [], "numExports": 0]
        }

        var exports: [String] = []

        for i in 0..<nsyms {
            let entryOffset = Int(symoff) + Int(i) * 16
            guard entryOffset + 16 <= fileData.count else { break }

            let strx = readUInt32(from: fileData, at: entryOffset, isBigEndian: isBigEndian)
            let n_type = readUInt8(from: fileData, at: entryOffset + 4)
            // Skip STABS debug symbols
            if (n_type & 0xe0) != 0 { continue }
            // External and defined symbols
            if (n_type & 0x01) != 0 && (n_type & 0x0e) != 0x0 {
                let nameOffset = Int(stroff) + Int(strx)
                if nameOffset < fileData.count && Int(stroff) + Int(strsize) > nameOffset {
                    var nameData: [UInt8] = []
                    var idx = nameOffset
                    while idx < fileData.count {
                        let c: UInt8 = fileData[idx]
                        if c == 0 { break }
                        nameData.append(c)
                        idx += 1
                    }
                    if let name = String(bytes: nameData, encoding: .utf8) {
                        exports.append(name)
                    }
                }
            }
        }

        return ["exports": exports, "numExports": exports.count]
    }
}
