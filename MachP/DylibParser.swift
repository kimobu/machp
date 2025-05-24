import Foundation

public class DylibParser {
    /// Extracts referenced dylibs from the given load commands.
    /// - Parameter loadCommands: Array of load command dictionaries.
    /// - Returns: Array of dictionaries describing each referenced dylib.
    public static func extractDylibs(from loadCommands: [[String: Any]]) -> [[String: Any]] {
        var dylibs: [[String: Any]] = []
        let dylibTypes: Set<String> = [
            "LC_LOAD_DYLIB",
            "LC_LOAD_WEAK_DYLIB",
            "LC_REEXPORT_DYLIB",
            "LC_LAZY_LOAD_DYLIB",
            "LC_LOAD_UPWARD_DYLIB"
        ]

        for cmd in loadCommands {
            guard let type = cmd["type"] as? String, dylibTypes.contains(type) else {
                continue
            }
            guard let name = cmd["libraryName"] as? String else { continue }
            var entry: [String: Any] = ["name": name]
            if let timestamp = cmd["timestamp"] as? UInt32 {
                entry["timestamp"] = timestamp
            }
            if let compat = cmd["compatibilityVersion"] as? UInt32 {
                entry["compatibilityVersion"] = formatVersion(compat)
            }
            if let current = cmd["currentVersion"] as? UInt32 {
                entry["currentVersion"] = formatVersion(current)
            }
            dylibs.append(entry)
        }
        return dylibs
    }

    private static func formatVersion(_ raw: UInt32) -> String {
        let major = (raw >> 16) & 0xffff
        let minor = (raw >> 8) & 0xff
        let patch = raw & 0xff
        return "\(major).\(minor).\(patch)"
    }
}
