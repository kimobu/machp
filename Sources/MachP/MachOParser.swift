import Foundation
import Crypto

enum MachOParsingError: Error {
    case fileNotFound
    case invalidFormat(String)
    case unsupported(String)
    case parsingFailed(String)
}

private let logger = LoggerFactory.make("com.machp.MachOParser")

class MachOParser {

    /// Recursively convert any Data values into base64 strings so JSONSerialization can handle them.
    private static func sanitizeJSON(_ object: Any) -> Any {
        if let dict = object as? [String: Any] {
            var newDict = [String: Any]()
            for (key, value) in dict {
                newDict[key] = sanitizeJSON(value)
            }
            return newDict
        } else if let array = object as? [Any] {
            return array.map { sanitizeJSON($0) }
        } else if let data = object as? Data {
            return data.base64EncodedString()
        } else {
            return object
        }
    }
    
    static func parseFile(at filePath: String,
                          recursive: Bool,
                          outputPath: String? = nil,
    ) throws -> String {
        let fileURL = URL(fileURLWithPath: filePath)
        guard FileManager.default.fileExists(atPath: filePath) else {
            throw MachOParsingError.fileNotFound
        }
        let fileData = try Data(contentsOf: fileURL)
        
        // Magic numbers & constants
        let FAT_MAGIC: UInt32    = 0xcafebabe
        let FAT_MAGIC_64: UInt32 = 0xcafebabf
        let MH_MAGIC_64: UInt32  = 0xfeedfacf
        let MH_CIGAM_64: UInt32  = 0xcffaedfe
        let CPU_ARCH_ABI64: UInt32 = 0x01000000
        let LC_CODE_SIGNATURE: UInt32 = 0x1d
        
        // Base output dictionary
        var result: [String: Any] = [
            "filePath": filePath,
            "recursive": recursive,
            "fileSize": fileData.count,
            "entropy": fileData.entropy()
        ]
        
        // Accumulate imported symbols from all slices
        var allImportedSymbols: Set<String> = []
        
        // Accumulate dylibs referenced by all slices (unique by name)
        var allDylibs: [[String: Any]] = []
        var seenDylibNames: Set<String> = []
        
        // Accumulate exported symbols from all slices
        var allExportedSymbols: Set<String> = []
        
        
        // Make sure we can at least read the magic
        guard fileData.count >= 4 else {
            throw MachOParsingError.invalidFormat("File is too small to be a valid Mach‑O binary")
        }
        
        // All fat headers are big‑endian, so interpret magic that way
        let rawMagic: UInt32 = fileData.withUnsafeBytes { $0.load(as: UInt32.self) }
        let magic: UInt32    = UInt32(bigEndian: rawMagic)
        ("Top‑level magic: 0x\(String(format: "%08x", magic))")
        
        // Unified slice parser
        func parseMachOSlice(sliceOffset: Int, sliceSize: Int) throws -> [String: Any] {
            logger.debug("Parsing Mach‑O slice @\(sliceOffset) (\(sliceSize) bytes)")
            let rawSliceMagic: UInt32 = fileData.withUnsafeBytes {
                $0.load(fromByteOffset: sliceOffset, as: UInt32.self)
            }
            let sliceMagic: UInt32 = UInt32(bigEndian: rawSliceMagic)
            logger.debug("Slice header magic: 0x\(String(format: "%08x", sliceMagic))")
            var sliceInfo: [String: Any] = [
                "offset": sliceOffset,
                "size": sliceSize
            ]
            
            // Extract just this slice's data
            let sliceEnd = sliceOffset + sliceSize
            guard sliceEnd <= fileData.count else {
                throw MachOParsingError.parsingFailed("Slice extends beyond file size")
            }
            let sliceData = fileData.subdata(in: sliceOffset..<sliceEnd)
            // Compute slice-relative header offset
            let headerOffsetAbsolute = sliceOffset
            let headerOffsetInSlice = headerOffsetAbsolute - sliceOffset
            
            // Compute SHA-256 of raw slice bytes for output naming
            let sha256 = SHA256.hash(data: sliceData)
                .compactMap { String(format: "%02x", $0) }
                .joined()
            sliceInfo["sha256"] = sha256
            sliceInfo["entropy"] = sliceData.entropy()
            
            // ---------- Header ----------
            var headerInfo = try HeaderParser.parseMachOHeader(from: sliceData, at: headerOffsetInSlice)
            let magicStr = (headerInfo["magic"] as? String ?? "").lowercased()
            let isBigEndianSlice = magicStr == "0xcffaedfe"
            
            // ---------- Load Commands ----------
            if let ncmds = headerInfo["ncmds"] as? UInt32 {
                let lcOffset = headerOffsetInSlice + 32 // after mach_header_64
                let loadCommands = try LoadCommandParser.parseLoadCommands(
                    from: sliceData,
                    offset: lcOffset,
                    ncmds: ncmds,
                    isBigEndian: isBigEndianSlice,
                )
                headerInfo["loadCommands"] = loadCommands
                
                // Extract referenced dylibs from load commands
                let dylibs = DylibParser.extractDylibs(from: loadCommands)
                if !dylibs.isEmpty {
                    sliceInfo["dylibs"] = dylibs
                    for dylib in dylibs {
                        if let name = dylib["name"] as? String, !seenDylibNames.contains(name) {
                            allDylibs.append(dylib)
                            seenDylibNames.insert(name)
                        }
                    }
                }
                
                // Parse imported symbols from the symbol table if present
                let imported = SymbolParser.parseImportedSymbols(
                    from: sliceData,
                    loadCommands: loadCommands,
                    isBigEndian: isBigEndianSlice
                )
                if let importedSymbols = imported["importedSymbols"] as? [String], !importedSymbols.isEmpty {
                    sliceInfo["importedSymbols"] = importedSymbols
                    sliceInfo["numImportedSymbols"] = imported["numImportedSymbols"]
                }
                
                
                // Parse symbol and dynamic symbol tables
                let symData = SymbolParser.parseSymbolTables(
                    from: sliceData,
                    loadCommands: loadCommands,
                    isBigEndian: isBigEndianSlice
                )
                
                // Parse exported symbols from the symbol table if present
                let exported = SymbolParser.parseExportedSymbols(
                    
                    from: sliceData,
                    loadCommands: loadCommands,
                    isBigEndian: isBigEndianSlice
                )
                
                if let symtab = symData["symtab"] {
                    sliceInfo["symtab"] = symtab
                }
                if let dysymtab = symData["dysymtab"] {
                    sliceInfo["dysymtab"] = dysymtab
                    
                    if let exportSyms = exported["exports"] as? [String], !exportSyms.isEmpty {
                        sliceInfo["exports"] = exportSyms
                        sliceInfo["numExports"] = exported["numExports"]
                        
                    }
                    
                    // ---------- Segments / Code‑sig ----------
                    var segments: [[String: Any]] = []
                    var cmdOffset = lcOffset
                    for _ in 0..<ncmds {
                        let cmdRaw: UInt32 = sliceData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset, as: UInt32.self) }
                        let cmd = isBigEndianSlice ? UInt32(bigEndian: cmdRaw) : UInt32(littleEndian: cmdRaw)
                        
                        let cmdsizeRaw: UInt32 = sliceData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 4, as: UInt32.self) }
                        let cmdsize = isBigEndianSlice ? UInt32(bigEndian: cmdsizeRaw) : UInt32(littleEndian: cmdsizeRaw)
                        
                        if cmd == 0x19 { // LC_SEGMENT_64
                            let seg = try SegmentSectionParser.parseSegmentAndSections(
                                from: sliceData,
                                at: cmdOffset,
                                isBigEndian: isBigEndianSlice
                            )
                            segments.append(seg)
                        } else if cmd == LC_CODE_SIGNATURE {
                            let csOffsetRaw: UInt32 = sliceData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 8, as: UInt32.self) }
                            let csSizeRaw: UInt32   = sliceData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 12, as: UInt32.self) }
                            let csOffset = isBigEndianSlice ? UInt32(bigEndian: csOffsetRaw) : UInt32(littleEndian: csOffsetRaw)
                            let csSize   = isBigEndianSlice ? UInt32(bigEndian: csSizeRaw)   : UInt32(littleEndian: csSizeRaw)
                            logger.debug("Starting csOffset \(csOffset), size \(csSize)")
                            do {
                                let csInfo = try CodeSigAndEntitlement.extractCodeSignatureInfo(
                                    from: sliceData,
                                    csOffset: Int(csOffset),
                                    csSize:   Int(csSize)
                                )
                                headerInfo["codeSignature"] = csInfo
                            } catch {
                                print("❌ CodeSignatureParser failed for file \(filePath) at offset \(csOffset), size \(csSize): \(error)")
                                throw error
                            }
                        }
                        cmdOffset += Int(cmdsize)
                    }
                    headerInfo["segments"] = segments
                }
                
                sliceInfo["header"] = headerInfo
                
                return sliceInfo
            }
            // Fallback return to satisfy all paths
            return sliceInfo
        }

        // ---------- FAT or THIN ----------
        if magic == FAT_MAGIC || magic == FAT_MAGIC_64 {
            logger.debug("Detected fat Mach‑O")
            let is64Fat      = (magic == FAT_MAGIC_64)
            let fatArchSize  = is64Fat ? 32 : 20
            
            guard fileData.count >= 8 else {
                throw MachOParsingError.parsingFailed("Incomplete fat header")
            }
            
            let nfatArchRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
            let nfatArch            = UInt32(bigEndian: nfatArchRaw)
            logger.debug("Number of architecture slices: \(nfatArch)")
            
            var slices: [[String: Any]] = []
            for i in 0..<nfatArch {
                let entryOffset = 8 + Int(i) * fatArchSize
                guard entryOffset + fatArchSize <= fileData.count else {
                    throw MachOParsingError.parsingFailed("Unexpected EOF reading fat‑arch \(i)")
                }
                
                // Parse fat_arch(64) entry (always big‑endian)
                let cputype:    UInt32
                let cpusubtype: UInt32
                let sliceOffset: UInt64
                let sliceSize:  UInt64
                let align:      UInt32
                
                if is64Fat {
                    cputype     = UInt32(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset,     as: UInt32.self) })
                    cpusubtype  = UInt32(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset + 4, as: UInt32.self) })
                    sliceOffset = UInt64(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset + 8, as: UInt64.self) })
                    sliceSize   = UInt64(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset + 16, as: UInt64.self) })
                    align       = UInt32(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset + 24, as: UInt32.self) })
                } else {
                    cputype     = UInt32(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset,     as: UInt32.self) })
                    cpusubtype  = UInt32(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset + 4, as: UInt32.self) })
                    sliceOffset = UInt64(UInt32(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset + 8,  as: UInt32.self) }))
                    sliceSize   = UInt64(UInt32(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset + 12, as: UInt32.self) }))
                    align       = UInt32(bigEndian: fileData.withUnsafeBytes { $0.load(fromByteOffset: entryOffset + 16, as: UInt32.self) })
                }
                
                logger.debug("Slice \(i): cputype=\(cputype) cpusubtype=\(cpusubtype) offset=\(sliceOffset) size=\(sliceSize)")
                
                // Only handle 64‑bit slices for now
                if (cputype & CPU_ARCH_ABI64) != 0 {
                    var sliceDict = try parseMachOSlice(sliceOffset: Int(sliceOffset), sliceSize: Int(sliceSize))
                    sliceDict["cputype"]    = cputype
                    sliceDict["cpusubtype"] = cpusubtype
                    sliceDict["align"]      = align
                    if let syms = sliceDict["importedSymbols"] as? [String] {
                        allImportedSymbols.formUnion(syms)
                    }
                    if let exps = sliceDict["exports"] as? [String] {
                        allExportedSymbols.formUnion(exps)
                    }
                    slices.append(sliceDict)
                } else {
                    logger.debug("Skipping non‑64‑bit slice \(i)")
                }
            }
            
            result["fat"]        = true
            result["is64BitFat"] = is64Fat
            result["nfatArch"]   = nfatArch
            result["slices"]     = slices
            result["parsed"]     = true
        } else if magic == MH_MAGIC_64 || magic == MH_CIGAM_64 {
            logger.debug("Detected thin 64‑bit Mach‑O")
            result["fat"]         = false
            let sliceInfo = try parseMachOSlice(sliceOffset: 0, sliceSize: fileData.count)
            if let syms = sliceInfo["importedSymbols"] as? [String] {
                allImportedSymbols.formUnion(syms)
            }
            if let exps = sliceInfo["exports"] as? [String] {
                allExportedSymbols.formUnion(exps)
            }
            result["headerSlice"] = sliceInfo
            result["parsed"]      = true
        } else {
            throw MachOParsingError.invalidFormat("Unrecognized Mach‑O / fat header")
        }
        
        // Attach aggregated imported symbols
        if !allImportedSymbols.isEmpty {
            result["importedSymbols"] = Array(allImportedSymbols).sorted()
        }
        // Attach aggregated exported symbols
        if !allExportedSymbols.isEmpty {
            result["exports"] = Array(allExportedSymbols).sorted()
        }
        
        // Attach aggregated dylibs
        if !allDylibs.isEmpty {
            result["dylibs"] = allDylibs
        }
        
        // Placeholder for recursive handling
        if recursive { result["filesParsed"] = [] }
        
        // Write per-slice JSON files for FAT binaries only if output path is set
        if let outPath = outputPath,
           let isFat = result["fat"] as? Bool, isFat,
           let slices = result["slices"] as? [[String: Any]] {
            let outputDirectory = URL(fileURLWithPath: outPath)
            try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true, attributes: nil)
            for slice in slices {
                guard let offset = slice["offset"] as? Int,
                      let size = slice["size"] as? Int else { continue }
                // Extract raw Mach-O bytes for this slice
                // Use precomputed hash from slice info
                guard let hash = slice["sha256"] as? String else { continue }
                
                let outURL = outputDirectory.appendingPathComponent("\(hash).json")
                // Format and write the JSON for this slice
                let sliceJSON = try JSONOutputFormatter.format(output: slice)
                try sliceJSON.write(to: outURL, atomically: true, encoding: String.Encoding.utf8)
            }
        }
        let sanitizedResult = MachOParser.sanitizeJSON(result)
        do {
            return try JSONOutputFormatter.format(output: sanitizedResult as! [String: Any])
        } catch {
            print("⚠️ JSON formatting failed for file: \(filePath)")
            throw error
        }
    }
}
