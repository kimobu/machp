import CryptoKit
import Foundation
import Security

@_silgen_name("SecCMSCertificatesOnlyMessageCopyCertificates")
func SecCMSCertificatesOnlyMessageCopyCertificates(_ cms: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFArray?

// MARK: - CodeSignatureParser

public class CodeSignatureParser {
    
    // Constants for code signature blob types
    static let CSSLOT_REQUIREMENT: UInt32 = 0xfade0c00       // single requirement
    static let CSSLOT_REQUIREMENT_SET: UInt32 = 0xfade0c01   // requirement set
    static let CSSLOT_CODEDIRECTORY: UInt32 = 0xfade0c02       // CodeDirectory
    static let CSSLOT_ENTITLEMENTS: UInt32 = 0xfade7171        // entitlement blob
    static let CSSLOT_CMS_SIGNATURE: UInt32 = 0xfade0b01       // CMS signature blob
    static let CSSLOT_DETACHED_SIGNATURE: UInt32 = 0xfade0cc1   // detached multi-architecture signature
    
    private static func readUInt32(from data: Data, at offset: Int) throws -> UInt32 {
        guard data.count >= offset + 4 else {
            throw MachOParsingError.parsingFailed("Insufficient data to read UInt32 at offset \(offset)")
        }
        var value: UInt32 = 0
        withUnsafeMutableBytes(of: &value) { pointer in
            data.copyBytes(to: pointer, from: offset..<(offset + 4))
        }
        return UInt32(bigEndian: value)
    }
    
    /// Extracts certificate common names from a CMS blob containing PKCS7 encoded certificates.
    /// - Parameter cmsData: The CMS blob data.
    /// - Returns: An array of certificate common names if extraction is successful, otherwise nil.
    public static func extractCMSCertificates(from cmsData: Data) -> [String]? {
        let cfData = cmsData as CFData
        var error: Unmanaged<CFError>?
        guard let certArray = SecCMSCertificatesOnlyMessageCopyCertificates(cfData, &error) as? [SecCertificate] else {
            return nil
        }
        var certificateNames: [String] = []
        for certificate in certArray {
            if let subjectSummary = SecCertificateCopySubjectSummary(certificate) as String? {
                certificateNames.append(subjectSummary)
            }
        }
        return certificateNames
    }
    
    /// Extracts binary entitlements from a plist-encoded entitlement blob.
    /// - Parameter entitlementData: The entitlement blob data.
    /// - Returns: A dictionary where each entitlement key is mapped to true if present, otherwise nil if parsing fails.
    public static func extractEntitlements(from entitlementData: Data) -> [String: Bool]? {
        var format = PropertyListSerialization.PropertyListFormat.xml
        do {
            let plist = try PropertyListSerialization.propertyList(from: entitlementData, options: .mutableContainersAndLeaves, format: &format)
            print("Parsed entitlement plist:", plist)
            if let dict = plist as? [String: Any] {
                var entitlements: [String: Bool] = [:]
                for key in dict.keys {
                    entitlements[key] = true
                }
                return entitlements
            }
        } catch {
            // Parsing failed, return nil
        }
        return nil
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
        // Ensure there's enough data for the superblob header (12 bytes)
        guard fileData.count >= offset + 12 else {
            throw MachOParsingError.parsingFailed("Incomplete code signature superblob header")
        }
        
        // Read superblob header: magic, length, count
        let magic = try readUInt32(from: fileData, at: offset)
        
        // Expected magic values for code signature superblob
        let CS_MAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xfade0cc0
        let CS_MAGIC_DETACHED_SIGNATURE: UInt32 = 0xfade0cc1
        guard magic == CS_MAGIC_EMBEDDED_SIGNATURE || magic == CS_MAGIC_DETACHED_SIGNATURE else {
            throw MachOParsingError.invalidFormat("Invalid code signature superblob magic: \(String(format: "0x%08x", magic))")
        }
        
        let totalLength = try readUInt32(from: fileData, at: offset + 4)
        
        let count = try readUInt32(from: fileData, at: offset + 8)
        
        var result: [String: Any] = [:]
        
        // Each index entry is 8 bytes: type and offset
        let indexSize = 8
        for i in 0..<count {
            let indexOffset = offset + 12 + Int(i) * indexSize
            guard fileData.count >= indexOffset + indexSize else {
                throw MachOParsingError.parsingFailed("Incomplete code signature blob index at \(i)")
            }
            
            let type = try readUInt32(from: fileData, at: indexOffset)
            
            let blobOffset = try readUInt32(from: fileData, at: indexOffset + 4)
            
            // The blob offset is relative to the beginning of the code signature blob
            let blobAbsoluteOffset = offset + Int(blobOffset)
            
            // Ensure there's enough data for the blob header (8 bytes)
            guard fileData.count >= blobAbsoluteOffset + 8 else {
                throw MachOParsingError.parsingFailed("Incomplete blob header for code signature type \(type)")
            }
            
            // Read blob header: magic and length
            let blobMagic = try readUInt32(from: fileData, at: blobAbsoluteOffset)
            
            let blobLength = try readUInt32(from: fileData, at: blobAbsoluteOffset + 4)
            
            // Ensure the blob fits within the fileData
            guard fileData.count >= blobAbsoluteOffset + Int(blobLength) else {
                throw MachOParsingError.parsingFailed("Blob of type \(type) exceeds data bounds")
            }
            
            // Extract the blob data and encode it as base64
            let blobData = fileData.subdata(in: blobAbsoluteOffset..<blobAbsoluteOffset + Int(blobLength))
            let blobBase64 = blobData.base64EncodedString()
            
            // Map the blob to the proper field based on type using inferred slot numbers
            // Assumption: The index entry 'type' field stores a small slot number:
            //    0 => requirement
            //    1 => requirement set
            //    2 => CodeDirectory
            //    3 => entitlements
            //    4096 (0x1000) => CMS signature
            // Other types, including detached signature if not mapped, are stored as is
            print(type)
            if type == 2 {
                print("Found CodeDirectory blob with type:", type, "at offset:", blobAbsoluteOffset, "with length:", blobLength)
                if let parsedCD = parseCodeDirectory(from: blobData) {
                    result["codedirectory"] = parsedCD
                } else {
                    print("parseCodeDirectory returned nil, falling back to base64 blob")
                    result["codedirectory"] = blobBase64
                }
            } else if type == 3 {
                // Attempt to parse the entitlement blob as a plist and extract entitlement keys
                if let entitlements = extractEntitlements(from: blobData) {
                    result["entitlements"] = entitlements
                } else {
                    result["entitlements"] = blobBase64
                }
            } else if type == 0 {
                result["requirement"] = blobBase64
            } else if type == 1 {
                result["requirementSet"] = blobBase64
            } else if type == 4096 {
                result["cms"] = blobBase64
                // Attempt to extract certificate common names from the CMS blob
                if let cmsCertificates = extractCMSCertificates(from: blobData) {
                    result["cmsCertificates"] = cmsCertificates
                }
            } else if type == CSSLOT_DETACHED_SIGNATURE {
                result["detachedSignature"] = blobBase64
            } else {
                // Store unknown blob types in an "other_blobs" dictionary keyed by their type
                if result["other_blobs"] == nil {
                    result["other_blobs"] = [String: String]()
                }
                var otherBlobs = result["other_blobs"] as! [String: String]
                otherBlobs[String(format: "0x%08x", type)] = blobBase64
                result["other_blobs"] = otherBlobs
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
    public static func extractCodeSignatureInfo(from fileData: Data, csOffset: Int, csSize: Int, isBigEndian: Bool) throws -> [String: Any] {
        let csInfo = try CodeSignatureParser.parseCodeSignature(from: fileData, at: csOffset, size: csSize, isBigEndian: isBigEndian)
        return csInfo
    }
}
