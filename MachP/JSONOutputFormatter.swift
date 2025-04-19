import Foundation

/// JSONOutputFormatter is responsible for formatting the parsed Mach-O data into a consistent and well-defined JSON structure.
/// The structure uses clear, human-readable keys such as "architecture", "header", "load_commands", "segments", "code_signature", etc.
/// This formatter ensures that downstream tools or machine learning models can consume the JSON output without requiring custom parsing.
public class JSONOutputFormatter {
    
    /// Formats the given dictionary into a pretty-printed JSON string.
    ///
    /// - Parameter output: A dictionary containing parsed Mach-O data.
    /// - Returns: A JSON string with standardized key naming.
    /// - Throws: An error if the JSON serialization fails.
    public static func format(output: [String: Any]) throws -> String {
        // Standardize keys to snake_case for consistency (e.g. "loadCommands" becomes "load_commands").
        let standardizedOutput = standardizeKeys(in: output)
        
        let jsonData = try JSONSerialization.data(withJSONObject: standardizedOutput, options: .prettyPrinted)
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw NSError(domain: "JSONOutputFormatter", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unable to encode JSON as string"])
        }
        return jsonString
    }
    
    /// Recursively standardizes keys in the dictionary to use snake_case.
    ///
    /// - Parameter dictionary: The dictionary whose keys will be standardized.
    /// - Returns: A new dictionary with keys in snake_case.
    private static func standardizeKeys(in dictionary: [String: Any]) -> [String: Any] {
        var newDict: [String: Any] = [:]
        for (key, value) in dictionary {
            let standardizedKey = toSnakeCase(key)
            if let subDict = value as? [String: Any] {
                newDict[standardizedKey] = standardizeKeys(in: subDict)
            } else if let subArray = value as? [[String: Any]] {
                newDict[standardizedKey] = subArray.map { standardizeKeys(in: $0) }
            } else {
                newDict[standardizedKey] = value
            }
        }
        return newDict
    }
    
    /// Converts a camelCase or mixed-case string to snake_case.
    ///
    /// - Parameter input: The input string.
    /// - Returns: The snake_case version of the input.
    private static func toSnakeCase(_ input: String) -> String {
        var result = ""
        for (index, character) in input.enumerated() {
            if character.isUppercase {
                if index != 0 {
                    result.append("_")
                }
                result.append(character.lowercased())
            } else {
                result.append(character)
            }
        }
        return result
    }
}
