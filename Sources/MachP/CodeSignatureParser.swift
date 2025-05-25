import Crypto
import Foundation
import Security

@_silgen_name("SecCMSCertificatesOnlyMessageCopyCertificates")
func SecCMSCertificatesOnlyMessageCopyCertificates(_ cms: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFArray?

private let logger = LoggerFactory.make("com.machp.CodeSignatureParser")

// MARK: - CodeSignatureParser

public class CodeSignatureParser {
    
    // Constants for code signature blob types
    static let CSMAGIC_REQUIREMENT: UInt32         = 0xfade0c00
    static let CSMAGIC_REQUIREMENTS: UInt32        = 0xfade0c01
    static let CSMAGIC_CODEDIRECTORY: UInt32       = 0xfade0c02
    static let CSMAGIC_EMBEDDED_ENTITLEMENTS: UInt32 = 0xfade7171
    static let CSMAGIC_DER_EMBEDDED_ENTITLEMENTS: UInt32 = 0xfade7172
    static let CSMAGIC_BLOBWRAPPER: UInt32         = 0xfade0b01
    static let CSMAGIC_EMBEDDED_SIGNATURE: UInt32  = 0xfade0cc0
    static let CSMAGIC_DETACHED_SIGNATURE: UInt32  = 0xfade0cc1
    
    

    private static func readUInt32(from data: Data, at offset: Int, bigEndian: Bool = true) throws -> UInt32 {
        guard data.count >= offset + 4 else {
            throw MachOParsingError.parsingFailed("Insufficient data to read UInt32 at offset \(offset)")
        }
        var raw: UInt32 = 0
        withUnsafeMutableBytes(of: &raw) { pointer in
            data.copyBytes(to: pointer, from: offset..<(offset + 4))
        }
        return bigEndian ? UInt32(bigEndian: raw) : UInt32(littleEndian: raw)
    }
    
    /// Extracts certificate common names from a CMS blob containing PKCS7 encoded certificates.
    /// - Parameter cmsData: The CMS blob data.
    /// - Returns: An array of certificate common names if extraction is successful, otherwise nil.
    public static func extractCMSCertificates(from cmsData: Data) -> [String]? {
        logger.debug("[CodeSignatureParser] extractCMSCertificates called with data length \(cmsData.count)")
        // Strip the 8-byte BlobHeader (magic + length)
        guard cmsData.count > 8 else {
                logger.debug("[CodeSignatureParser] CMS data too short to strip header")
            return nil
        }
        let derData = cmsData.subdata(in: 8..<cmsData.count)
        logger.debug("[CodeSignatureParser] Stripped header, DER data length: \(derData.count)")
        
        // Use CMSDecoder API to parse the PKCS#7 and extract certificates
        var decoder: CMSDecoder?
        var status = CMSDecoderCreate(&decoder)
        guard status == errSecSuccess, let decoder = decoder else {
            logger.debug("[CodeSignatureParser] CMSDecoderCreate failed: \(status)")
            return []
        }
        // Feed DER data to CMSDecoder
        status = derData.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> OSStatus in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }
            return CMSDecoderUpdateMessage(decoder, baseAddress, derData.count)
        }
        guard status == errSecSuccess else {
            logger.debug("[CodeSignatureParser] CMSDecoderUpdateMessage failed: \(status)")
            return []
        }
        status = CMSDecoderFinalizeMessage(decoder)
        guard status == errSecSuccess else {
            logger.debug("[CodeSignatureParser] CMSDecoderFinalizeMessage failed: \(status)")
            return []
        }
        var certsCF: CFArray?
        status = CMSDecoderCopyAllCerts(decoder, &certsCF)
        guard status == errSecSuccess, let certsArray = certsCF as? [SecCertificate] else {
            logger.debug("[CodeSignatureParser] CMSDecoderCopyAllCerts failed: \(status)")
            return []
        }
        
        logger.debug("[CodeSignatureParser] Extracted \(certsArray.count) certificates via CMSDecoder")
        var certificateNames: [String] = []
        for cert in certsArray {
            if let name = SecCertificateCopySubjectSummary(cert) as String? {
                certificateNames.append(name)
            }
        }
        return certificateNames
    }
    
    /// Extracts binary entitlements from a plist-encoded entitlement blob.
    /// - Parameter entitlementData: The entitlement blob data.
    /// - Returns: A dictionary where each entitlement key is mapped to true if present, otherwise nil if parsing fails.
    public static func extractEntitlements(from entitlementData: Data) -> [String]? {
        logger.debug("[CodeSignatureParser] extractEntitlements called with data length \(entitlementData.count)")
        // Skip the 8-byte BlobHeader (magic + length) to get the actual plist payload
        guard entitlementData.count > 8 else {
            logger.debug("[CodeSignatureParser] Entitlement data too short to strip header")
            return nil
        }
        let plistData = entitlementData.subdata(in: 8..<entitlementData.count)
        logger.debug("[CodeSignatureParser] Stripped header, plistData length: \(plistData.count)")
        var format = PropertyListSerialization.PropertyListFormat.xml
        do {
            let plist = try PropertyListSerialization.propertyList(from: plistData, options: [], format: &format)
            if let dict = plist as? [String: Any] {
                return Array(dict.keys)
            }
        } catch {
            logger.error("[CodeSignatureParser] Failed to parse entitlement plist: \(error)")
        }
        return nil
    }

    /// Parses DER-encoded entitlements (ASN.1-wrapped plist) and returns entitlement keys.
    /// Parses DER-encoded entitlements (ASN.1-wrapped plist) and returns entitlement keys.
    public static func extractEntitlementsDER(from derData: Data) -> [String]? {
        logger.error("[CodeSignatureParser] extractEntitlementsDER called with data length \(derData.count)")
        // Strip the 8-byte BlobHeader
        guard derData.count > 8 else {
            logger.warning("[CodeSignatureParser] DER entitlement data too short to strip header")
            return nil
        }
        let data = derData.subdata(in: 8..<derData.count)
        var idx = 0

        // Read outer sequence tag (Application 16, 0x70)
        guard idx < data.count else { return nil }
        idx += 1
        // Read outer length
        guard idx < data.count else { return nil }
        let lengthByte = data[idx]; idx += 1
        var length = 0
        if (lengthByte & 0x80) != 0 {
            let byteCount = Int(lengthByte & 0x7F)
            for _ in 0..<byteCount {
                guard idx < data.count else { return nil }
                length = (length << 8) | Int(data[idx])
                idx += 1
            }
        } else {
            length = Int(lengthByte)
        }

        // Skip the INTEGER wrapper (tag=0x02)
        guard idx + 2 <= data.count else { return nil }
        idx += 1               // skip tag
        let intLen = Int(data[idx]); idx += 1
        idx += intLen          // skip integer contents

        // Context-specific dict tag (0xB0)
        guard idx < data.count else { return nil }
        idx += 1
        // Read dict length
        guard idx < data.count else { return nil }
        let dictLenByte = data[idx]; idx += 1
        var dictLen = 0
        if (dictLenByte & 0x80) != 0 {
            let byteCount = Int(dictLenByte & 0x7F)
            for _ in 0..<byteCount {
                guard idx < data.count else { return nil }
                dictLen = (dictLen << 8) | Int(data[idx])
                idx += 1
            }
        } else {
            dictLen = Int(dictLenByte)
        }

        // Walk entries and pull out each UTF8 key
        var keys: [String] = []
        let end = idx + dictLen
        while idx < end {
            // Expect sequence wrapper (0x30)
            guard data[idx] == 0x30 else { break }
            idx += 1
            // Entry length
            guard idx < data.count else { break }
            let entryLen = Int(data[idx]); idx += 1
            let entryEnd = idx + entryLen

            // Expect UTF8 string tag (0x0C)
            guard data[idx] == 0x0C else { break }
            idx += 1
            guard idx < data.count else { break }
            let keyLen = Int(data[idx]); idx += 1
            guard idx + keyLen <= data.count else { break }
            let keyData = data.subdata(in: idx..<(idx + keyLen))
            if let key = String(data: keyData, encoding: .utf8) {
                keys.append(key)
            }
            idx = entryEnd
        }

        return keys
    }

    /// Parses a code signing requirement blob into its string representation.
    public static func extractRequirements(from reqData: Data) -> String? {
        logger.debug("[CodeSignatureParser] extractRequirements called with data length \(reqData.count)")
        // Strip the 8-byte BlobHeader
        guard reqData.count > 8 else {
            logger.warning("[CodeSignatureParser] Requirement data too short to strip header")
            return nil
        }
        let data = reqData.subdata(in: 8..<reqData.count)
        logger.debug("[CodeSignatureParser] Stripped header, requirement data length: \(data.count)")
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithData(data as CFData, SecCSFlags(), &requirement)
        if status != errSecSuccess || requirement == nil {
            logger.warning("[CodeSignatureParser] SecRequirementCreateWithData failed: \(status); falling back to ASCII extraction")
            // Fallback: extract contiguous printable ASCII substrings of length >= 4
            var substrings: [String] = []
            var current = ""
            for byte in data {
                if byte >= 32 && byte <= 126 {
                    current.append(Character(UnicodeScalar(byte)))
                } else {
                    if current.count >= 4 {
                        substrings.append(current)
                    }
                    current = ""
                }
            }
            if current.count >= 4 {
                substrings.append(current)
            }
            return substrings.joined(separator: ", ")
        }
        let req = requirement!
        // Obtain the requirement’s string via SecRequirementCopyString
        var cfString: CFString? = nil
        let status2 = SecRequirementCopyString(req, SecCSFlags(), &cfString)
        guard status2 == errSecSuccess, let cfString = cfString else {
            logger.warning("[CodeSignatureParser] SecRequirementCopyString failed: \(status2)")
            return nil
        }
        let str = cfString as String
        logger.debug("[CodeSignatureParser] Requirement string: \(str)")
        return str
    }
    /// Parses a CodeDirectory blob and extracts key information.
    /// - Parameter blobData: The CodeDirectory blob data.
    /// - Returns: A dictionary containing parsed CodeDirectory fields if successful, otherwise nil.
    public static func parseCodeDirectory(from blobData: Data) -> [String: Any]? {
        // Ensure we have at least 40 bytes for the header.
        guard blobData.count >= 40 else { return nil }
        print("Entering parseCodeDirectory with blobData count:", blobData.count)
        var offset = 0
        // Read fixed header fields:
        guard let magic = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        guard let length = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        guard let version = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        guard let flags = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        guard let hashOffset = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        guard let identOffset = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        guard let nSpecialSlots = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        guard let nCodeSlots = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        guard let codeLimit = try? readUInt32(from: blobData, at: offset) else { return nil }
        offset += 4
        
        // Next 4 bytes: hashSize, hashType, platform, pageSize.
        guard blobData.count >= offset + 4 else { return nil }
        let hashSize = blobData[offset]
        let hashType = blobData[offset+1]
        let platform = blobData[offset+2]
        let pageSize = blobData[offset+3]
        offset += 4
        
        // Parse special slots.
        // Special slots are assumed to begin at offset 40, with total length = nSpecialSlots * hashSize bytes.
        let specialSlotsStart = 40
        let specialSlotsLength = Int(nSpecialSlots) * Int(hashSize)
        var specialSlots: [String: String] = [:]
        // Map special slot indices to labels (based on the provided sample).
        // Here we assume nSpecialSlots == 5 and the ordering is as follows:
        // Index 0: Entitlements Blob
        // Index 1: Application Specific
        // Index 2: Resource Directory
        // Index 3: Requirements Blob
        // Index 4: Bound Info.plist
        let specialSlotLabels: [Int: String] = [
            0: "Entitlements Blob",
            1: "Application Specific",
            2: "Resource Directory",
            3: "Requirements Blob",
            4: "Bound Info.plist"
        ]
        if blobData.count >= specialSlotsStart + specialSlotsLength {
            for i in 0..<Int(nSpecialSlots) {
                let slotOffset = specialSlotsStart + i * Int(hashSize)
                let hashData = blobData.subdata(in: slotOffset..<slotOffset+Int(hashSize))
                let allZeros = hashData.allSatisfy { $0 == 0 }
                // Determine label using the mapping; if missing, use a generic label.
                let label = specialSlotLabels[i] ?? "Special Slot \(i)"
                if allZeros {
                    specialSlots[label] = "Not Bound"
                } else {
                    let hashHex = hashData.map { String(format: "%02x", $0) }.joined()
                    specialSlots[label] = hashHex
                }
            }
        }
        
        // Extract identifier string from identOffset.
        var identifier = ""
        if Int(identOffset) < blobData.count {
            let identData = blobData.subdata(in: Int(identOffset)..<blobData.count)
            if let nullIndex = identData.firstIndex(of: 0) {
                identifier = String(data: identData.prefix(upTo: nullIndex), encoding: .utf8) ?? ""
            } else {
                identifier = String(data: identData, encoding: .utf8) ?? ""
            }
        }
        
        // Compute cdhash as SHA1 hash of the entire CodeDirectory blob.
        let cdHash = Insecure.SHA1.hash(data: blobData).map { String(format: "%02x", $0) }.joined()
        
        let result: [String: Any] = [
            "ident": identifier,
            "version": version,
            "flags": flags,
            "hashOffset": hashOffset,
            "nSpecialSlots": nSpecialSlots,
            "nCodeSlots": nCodeSlots,
            "codeLimit": codeLimit,
            "hashSize": hashSize,
            "hashType": hashType,
            "platform": platform,
            "pageSize": pageSize,
            "cdHash": cdHash,
            "specialSlots": specialSlots
        ]
        return result
    }
    

    
    /// Parses the code signature blob (superblob) from the given data at the specified offset and size.
    /// - Parameters:
    ///   - fileData: The complete Mach-O file data
    ///   - offset: The offset where the code signature blob starts
    ///   - size: The size of the code signature blob
    ///   - isBigEndian: Boolean indicating whether the data is in big-endian format
    /// - Returns: A dictionary containing extracted code signing blobs (codedirectory, entitlements, cms, etc.)
    public static func parseCodeSignature(from fileData: Data, at offset: Int, size: Int, isBigEndian: Bool) throws -> [String: Any] {
        // Debug helper

        logger.debug("Starting parseCodeSignature at offset \(offset), size \(size)")

        // Ensure there's enough data for the superblob header (12 bytes)
        guard fileData.count >= offset + 12 else {
            throw MachOParsingError.parsingFailed("Incomplete code signature superblob header")
        }
        
        // Read superblob header: magic, length, count
        let magic = try readUInt32(from: fileData, at: offset, bigEndian: true)
        
        // Expected magic values for code signature superblob
        let CS_MAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xfade0cc0
        let CS_MAGIC_DETACHED_SIGNATURE: UInt32 = 0xfade0cc1
        guard magic == CS_MAGIC_EMBEDDED_SIGNATURE || magic == CS_MAGIC_DETACHED_SIGNATURE else {
            throw MachOParsingError.invalidFormat("Invalid code signature superblob magic: 0x\(String(format: "%08x", magic))")
        }
        
        let totalLength = try readUInt32(from: fileData, at: offset + 4, bigEndian: true)
        
        let count = try readUInt32(from: fileData, at: offset + 8, bigEndian: true)
        
        var result: [String: Any] = [:]
        
        // Each index entry is 8 bytes: type and offset
        let indexSize = 8
        for i in 0..<count {
            let indexOffset = offset + 12 + Int(i) * indexSize
            guard fileData.count >= indexOffset + indexSize else {
                throw MachOParsingError.parsingFailed("Incomplete code signature blob index at \(i)")
            }
            _ = try readUInt32(from: fileData, at: indexOffset, bigEndian: true)
            let blobOffset = try readUInt32(from: fileData, at: indexOffset + 4, bigEndian: true)
            
            // The blob offset is relative to the beginning of the code signature blob
            let blobAbsoluteOffset = offset + Int(blobOffset)
            
            // Ensure there's enough data for the blob header (8 bytes)
            guard fileData.count >= blobAbsoluteOffset + 8 else {
                throw MachOParsingError.parsingFailed("Incomplete blob header at offset \(blobAbsoluteOffset)")
            }
            
            // Read blob header: magic and length
            let blobMagic = try readUInt32(from: fileData, at: blobAbsoluteOffset, bigEndian: true)
            let blobLength = try readUInt32(from: fileData, at: blobAbsoluteOffset + 4, bigEndian: true)
            logger.debug("Blob header at \(blobAbsoluteOffset): magic=0x\(String(format: "%08x", blobMagic)), length=\(blobLength)")
            
            // Ensure the blob fits within the fileData
            guard fileData.count >= blobAbsoluteOffset + Int(blobLength) else {
                throw MachOParsingError.parsingFailed("Blob at offset \(blobAbsoluteOffset) exceeds data bounds")
            }
            
            // Extract the blob data and encode it as base64
            let blobData = fileData.subdata(in: blobAbsoluteOffset..<blobAbsoluteOffset + Int(blobLength))
            let blobBase64 = blobData.base64EncodedString()
            switch blobMagic {
            case CSMAGIC_CODEDIRECTORY:
                if let cd = parseCodeDirectory(from: blobData) {
                    result["codedirectory"] = cd
                } else {
                    result["codedirectory"] = blobBase64
                }
            case CSMAGIC_EMBEDDED_ENTITLEMENTS:
                if let entitlementKeys = extractEntitlements(from: blobData) {
                    result["entitlements"] = entitlementKeys
                } else {
                    result["entitlements"] = blobBase64
                }
            case CSMAGIC_DER_EMBEDDED_ENTITLEMENTS:
                if let derKeys = extractEntitlementsDER(from: blobData) {
                    result["der_entitlements"] = derKeys
                } else {
                    result["der_entitlements"] = blobBase64
                }
            case CSMAGIC_REQUIREMENT, CSMAGIC_REQUIREMENTS:
                if let reqStr = extractRequirements(from: blobData) {
                    result["requirement"] = reqStr
                } else {
                    result["requirement"] = blobBase64
                }
            case CSMAGIC_BLOBWRAPPER:
                // Parse the CMS superblob to extract certificate common names
                logger.debug("[CodeSignatureParser] Parsing CMS blob for certificates")
                if let certCNs = extractCMSCertificates(from: blobData) {
                    result["certCommonNames"] = certCNs
                } else {
                    logger.warning("[CodeSignatureParser] Failed to extract certificates; returning empty list")
                    result["certCommonNames"] = []
                }
            default:
                var other = result["other_blobs"] as? [String: String] ?? [:]
                other[String(format: "0x%08x", blobMagic)] = blobBase64
                result["other_blobs"] = other
            }
        }
        
        return result
    }
}

// MARK: - CodeSigAndEntitlement Convenience

// This class provides a high-level function that combines code signature and entitlement extraction
public class CodeSigAndEntitlement {
    
    /// Attempts to locate and parse the code signature blob from the provided Mach-O file data.
    /// - Parameters:
    ///   - fileData: The complete Mach-O file data
    ///   - csOffset: The offset where the LC_CODE_SIGNATURE blob is located
    ///   - csSize: The size of the LC_CODE_SIGNATURE blob
    ///   - isBigEndian: Whether the Mach-O file uses big-endian formatting
    /// - Returns: A dictionary with code signing information, including codedirectory, entitlements, and CMS blob if available.
    public static func extractCodeSignatureInfo(from fileData: Data, csOffset: Int, csSize: Int) throws -> [String: Any] {
        // fileData is already a single-arch slice; always use big-endian for code signature parsing
        return try CodeSignatureParser.parseCodeSignature(from: fileData, at: csOffset, size: csSize, isBigEndian: true)
    }
}
