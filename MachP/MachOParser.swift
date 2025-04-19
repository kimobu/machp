import Foundation

enum MachOParsingError: Error {
    case fileNotFound
    case invalidFormat(String)
    case unsupported(String)
    case parsingFailed(String)
}

class MachOParser {

    static func parseFile(at filePath: String, includeRaw: Bool, recursive: Bool) throws -> String {
        let fileURL = URL(fileURLWithPath: filePath)
        guard FileManager.default.fileExists(atPath: filePath) else {
            throw MachOParsingError.fileNotFound
        }

        // Load the file data
        let fileData = try Data(contentsOf: fileURL)
        
        // Constants for Mach-O and Fat binary magic numbers
        let FAT_MAGIC: UInt32    = 0xcafebabe
        let FAT_CIGAM: UInt32    = 0xbebafeca
        let MH_MAGIC_64: UInt32  = 0xfeedfacf
        let MH_CIGAM_64: UInt32  = 0xcffaedfe
        let CPU_ARCH_ABI64: UInt32 = 0x01000000
        
        // Prepare the result dictionary with basic file metadata
        var result: [String: Any] = [
            "filePath": filePath,
            "includeRaw": includeRaw,
            "recursive": recursive,
            "fileSize": fileData.count
        ]
        
        // Read the magic number from the file
        guard fileData.count >= 4 else {
            throw MachOParsingError.invalidFormat("File is too small to be a valid Mach-O binary")
        }
        let magic: UInt32 = fileData.withUnsafeBytes { $0.load(as: UInt32.self) }

        // Constant for LC_CODE_SIGNATURE command
        let LC_CODE_SIGNATURE: UInt32 = 0x1d

        if magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64 {
            let isBigEndian = (magic == FAT_MAGIC || magic == FAT_MAGIC_64)
            let is64Bit = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64)
            
            // Ensure we have enough data for the fat header (8 bytes)
            guard fileData.count >= 8 else {
                throw MachOParsingError.parsingFailed("Incomplete fat header")
            }
            
            // Read the number of architecture slices
            let nfatArchRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
            let nfatArch = isBigEndian ? UInt32(bigEndian: nfatArchRaw) : UInt32(littleEndian: nfatArchRaw)
            
            var slices: [[String: Any]] = []
            
            if is64Bit {
                // Each fat_arch_64 entry is 32 bytes long
                let fatArchSize = 32
                for i in 0..<nfatArch {
                    let archEntryOffset = 8 + Int(i) * fatArchSize
                    guard archEntryOffset + fatArchSize <= fileData.count else {
                        throw MachOParsingError.parsingFailed("Unexpected end of file when reading fat_arch_64 entry \(i)")
                    }

                    let cputypeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset, as: UInt32.self) }
                    let cpusubtypeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset + 4, as: UInt32.self) }
                    let offsetRaw: UInt64 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset + 8, as: UInt64.self) }
                    let sizeRaw: UInt64 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset + 16, as: UInt64.self) }
                    let alignRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset + 24, as: UInt32.self) }
                    
                    let cputype = isBigEndian ? UInt32(bigEndian: cputypeRaw) : UInt32(littleEndian: cputypeRaw)
                    let cpusubtype = isBigEndian ? UInt32(bigEndian: cpusubtypeRaw) : UInt32(littleEndian: cpusubtypeRaw)
                    let sliceOffset = isBigEndian ? UInt64(bigEndian: offsetRaw) : UInt64(littleEndian: offsetRaw)
                    let sliceSize = isBigEndian ? UInt64(bigEndian: sizeRaw) : UInt64(littleEndian: sizeRaw)
                    let align = isBigEndian ? UInt32(bigEndian: alignRaw) : UInt32(littleEndian: alignRaw)
                    
                    // Process only 64-bit slices (using the CPU_ARCH_ABI64 flag)
                    if (cputype & CPU_ARCH_ABI64) != 0 {
                        var sliceInfo: [String: Any] = [
                            "cputype": cputype,
                            "cpusubtype": cpusubtype,
                            "offset": sliceOffset,
                            "size": sliceSize,
                            "align": align
                        ]

                        let headerOffset = Int(sliceOffset)
                        var headerInfo = try HeaderParser.parseMachOHeader(from: fileData, at: headerOffset)
                        let magicStr = headerInfo["magic"] as? String ?? ""
                        let isBigEndianSlice = magicStr.lowercased() == "0xcffaedfe"
                        
                        if let ncmds = headerInfo["ncmds"] as? UInt32 {
                            let loadCommands = try LoadCommandParser.parseLoadCommands(from: fileData, offset: headerOffset + 32, ncmds: ncmds, isBigEndian: isBigEndianSlice)
                            headerInfo["loadCommands"] = loadCommands
                            var segments: [[String: Any]] = []
                            var cmdOffset = headerOffset + 32
                            for _ in 0..<ncmds {
                                let cmdRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset, as: UInt32.self) }
                                let cmd = isBigEndianSlice ? UInt32(bigEndian: cmdRaw) : UInt32(littleEndian: cmdRaw)
                                let cmdsizeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 4, as: UInt32.self) }
                                let cmdsize = isBigEndianSlice ? UInt32(bigEndian: cmdsizeRaw) : UInt32(littleEndian: cmdsizeRaw)
                                if cmd == 0x19 {
                                    let segmentInfo = try SegmentSectionParser.parseSegmentAndSections(from: fileData, at: cmdOffset, isBigEndian: isBigEndianSlice)
                                    segments.append(segmentInfo)
                                } else if cmd == LC_CODE_SIGNATURE {
                                    let csOffsetRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 8, as: UInt32.self) }
                                    let csSizeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 12, as: UInt32.self) }
                                    let csOffset = isBigEndianSlice ? UInt32(bigEndian: csOffsetRaw) : UInt32(littleEndian: csOffsetRaw)
                                    let csSize = isBigEndianSlice ? UInt32(bigEndian: csSizeRaw) : UInt32(littleEndian: csSizeRaw)
                                    let csInfo = try CodeSigAndEntitlement.extractCodeSignatureInfo(from: fileData, csOffset: Int(csOffset), csSize: Int(csSize), isBigEndian: isBigEndianSlice)
                                    headerInfo["codeSignature"] = csInfo
                                }
                                cmdOffset += Int(cmdsize)
                            }
                            headerInfo["segments"] = segments
                        }
                        
                        sliceInfo["header"] = headerInfo
                        
                        if includeRaw {
                            let sliceStart = Int(sliceOffset)
                            let sliceEnd = sliceStart + Int(sliceSize)
                            if sliceEnd <= fileData.count {
                                let sliceData = fileData.subdata(in: sliceStart..<sliceEnd)
                                sliceInfo["rawDataBase64"] = sliceData.base64EncodedString()
                            } else {
                                sliceInfo["rawDataError"] = "Slice data extends beyond file size."
                            }
                        }

                        slices.append(sliceInfo)
                    }
                }
            } else {
                // 32-bit fat header: each fat_arch entry is 20 bytes long
                let fatArchSize = 20
                for i in 0..<nfatArch {
                    let archEntryOffset = 8 + Int(i) * fatArchSize
                    guard archEntryOffset + fatArchSize <= fileData.count else {
                        throw MachOParsingError.parsingFailed("Unexpected end of file when reading fat_arch entry \(i)")
                    }

                    let cputypeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset, as: UInt32.self) }
                    let cpusubtypeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset + 4, as: UInt32.self) }
                    let sliceOffsetRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset + 8, as: UInt32.self) }
                    let sliceSizeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset + 12, as: UInt32.self) }
                    let alignRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: archEntryOffset + 16, as: UInt32.self) }
                    
                    let cputype = isBigEndian ? UInt32(bigEndian: cputypeRaw) : UInt32(littleEndian: cputypeRaw)
                    let cpusubtype = isBigEndian ? UInt32(bigEndian: cpusubtypeRaw) : UInt32(littleEndian: cpusubtypeRaw)
                    let sliceOffset = isBigEndian ? UInt32(bigEndian: sliceOffsetRaw) : UInt32(littleEndian: sliceOffsetRaw)
                    let sliceSize = isBigEndian ? UInt32(bigEndian: sliceSizeRaw) : UInt32(littleEndian: sliceSizeRaw)
                    let align = isBigEndian ? UInt32(bigEndian: alignRaw) : UInt32(littleEndian: alignRaw)
                    
                    if (cputype & CPU_ARCH_ABI64) != 0 {
                        var sliceInfo: [String: Any] = [
                            "cputype": cputype,
                            "cpusubtype": cpusubtype,
                            "offset": sliceOffset,
                            "size": sliceSize,
                            "align": align
                        ]

                        let headerOffset = Int(sliceOffset)
                        var headerInfo = try HeaderParser.parseMachOHeader(from: fileData, at: headerOffset)
                        let magicStr = headerInfo["magic"] as? String ?? ""
                        let isBigEndianSlice = magicStr.lowercased() == "0xcffaedfe"
                        
                        if let ncmds = headerInfo["ncmds"] as? UInt32 {
                            let loadCommands = try LoadCommandParser.parseLoadCommands(from: fileData, offset: headerOffset + 32, ncmds: ncmds, isBigEndian: isBigEndianSlice)
                            headerInfo["loadCommands"] = loadCommands
                            var segments: [[String: Any]] = []
                            var cmdOffset = headerOffset + 32
                            for _ in 0..<ncmds {
                                let cmdRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset, as: UInt32.self) }
                                let cmd = isBigEndianSlice ? UInt32(bigEndian: cmdRaw) : UInt32(littleEndian: cmdRaw)
                                let cmdsizeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 4, as: UInt32.self) }
                                let cmdsize = isBigEndianSlice ? UInt32(bigEndian: cmdsizeRaw) : UInt32(littleEndian: cmdsizeRaw)
                                if cmd == 0x19 {
                                    let segmentInfo = try SegmentSectionParser.parseSegmentAndSections(from: fileData, at: cmdOffset, isBigEndian: isBigEndianSlice)
                                    segments.append(segmentInfo)
                                } else if cmd == LC_CODE_SIGNATURE {
                                    let csOffsetRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 8, as: UInt32.self) }
                                    let csSizeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 12, as: UInt32.self) }
                                    let csOffset = isBigEndianSlice ? UInt32(bigEndian: csOffsetRaw) : UInt32(littleEndian: csOffsetRaw)
                                    let csSize = isBigEndianSlice ? UInt32(bigEndian: csSizeRaw) : UInt32(littleEndian: csSizeRaw)
                                    let csInfo = try CodeSigAndEntitlement.extractCodeSignatureInfo(from: fileData, csOffset: Int(csOffset), csSize: Int(csSize), isBigEndian: isBigEndianSlice)
                                    headerInfo["codeSignature"] = csInfo
                                }
                                cmdOffset += Int(cmdsize)
                            }
                            headerInfo["segments"] = segments
                        }
                        
                        sliceInfo["header"] = headerInfo
                        
                        if includeRaw {
                            let sliceStart = Int(sliceOffset)
                            let sliceEnd = sliceStart + Int(sliceSize)
                            if sliceEnd <= fileData.count {
                                let sliceData = fileData.subdata(in: sliceStart..<sliceEnd)
                                sliceInfo["rawDataBase64"] = sliceData.base64EncodedString()
                            } else {
                                sliceInfo["rawDataError"] = "Slice data extends beyond file size."
                            }
                        }

                        slices.append(sliceInfo)
                    }
                }
            }
            
            result["fat"] = true
            result["is64BitFat"] = is64Bit
            result["nfatArch"] = nfatArch
            result["slices"] = slices
            result["parsed"] = true
        } else if magic == MH_MAGIC_64 || magic == MH_CIGAM_64 {
            // Single 64-bit Mach-O file
            result["fat"] = false
            var headerInfo = try HeaderParser.parseMachOHeader(from: fileData, at: 0)
            let magicStr = headerInfo["magic"] as? String ?? ""
            let isBigEndianSingle = magicStr.lowercased() == "0xcffaedfe"
            if let ncmds = headerInfo["ncmds"] as? UInt32 {
                let loadCommands = try LoadCommandParser.parseLoadCommands(from: fileData, offset: 32, ncmds: ncmds, isBigEndian: isBigEndianSingle)
                headerInfo["loadCommands"] = loadCommands
                var segments: [[String: Any]] = []
                var cmdOffset = 32
                for _ in 0..<ncmds {
                    let cmdRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset, as: UInt32.self) }
                    let cmd = isBigEndianSingle ? UInt32(bigEndian: cmdRaw) : UInt32(littleEndian: cmdRaw)
                    let cmdsizeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 4, as: UInt32.self) }
                    let cmdsize = isBigEndianSingle ? UInt32(bigEndian: cmdsizeRaw) : UInt32(littleEndian: cmdsizeRaw)
                    if cmd == 0x19 {
                        let segmentInfo = try SegmentSectionParser.parseSegmentAndSections(from: fileData, at: cmdOffset, isBigEndian: isBigEndianSingle)
                        segments.append(segmentInfo)
                    } else if cmd == LC_CODE_SIGNATURE {
                        let csOffsetRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 8, as: UInt32.self) }
                        let csSizeRaw: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: cmdOffset + 12, as: UInt32.self) }
                        let csOffset = isBigEndianSingle ? UInt32(bigEndian: csOffsetRaw) : UInt32(littleEndian: csOffsetRaw)
                        let csSize = isBigEndianSingle ? UInt32(bigEndian: csSizeRaw) : UInt32(littleEndian: csSizeRaw)
                        let csInfo = try CodeSigAndEntitlement.extractCodeSignatureInfo(from: fileData, csOffset: Int(csOffset), csSize: Int(csSize), isBigEndian: isBigEndianSingle)
                        headerInfo["codeSignature"] = csInfo
                    }
                    cmdOffset += Int(cmdsize)
                }
                headerInfo["segments"] = segments
            }
            result["header"] = headerInfo
            if includeRaw {
                result["rawDataBase64"] = fileData.base64EncodedString()
            }
            result["parsed"] = true
        } else {
            throw MachOParsingError.invalidFormat("Not a valid Mach-O binary")
        }
        
        // If recursive parsing is enabled, add a placeholder for nested files (not implemented in this snippet)
        if recursive {
            result["filesParsed"] = []
        }
        
        // Convert the result dictionary to a JSON string using JSONOutputFormatter
        return try JSONOutputFormatter.format(output: result)
    }
}
