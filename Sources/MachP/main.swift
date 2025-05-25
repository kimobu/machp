import Foundation
import Logging

// A structure to hold command-line options
struct CLIOptions {
    var includeRaw: Bool = false
    var recursive: Bool = false
    var filePath: String = ""
    var debug: Bool = false
    var outputPath: String? = nil
}

// Function to parse the command-line arguments and return CLIOptions
func parseArguments() -> CLIOptions? {
    let usage = "Usage: MachP <file_path> [--include-raw] [--recursive|-r] [--output <path>]"
    let args = CommandLine.arguments
    guard args.count >= 2 else {
        print(usage)
        return nil
    }
    
    var options = CLIOptions()
    // The first argument is the executable name, so the file path is at index 1
    options.filePath = args[1]
    
    var iterator = args.dropFirst(2).makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--include-raw":
            options.includeRaw = true
        case "--recursive", "-r":
            options.recursive = true
        case "--debug":
            options.debug = true
        case "--output":
            if let path = iterator.next() {
                options.outputPath = path
            } else {
                print("Missing output path for --output")
                print(usage)
                return nil
            }
        default:
            print("Unknown argument: \(arg)")
            print(usage)
            return nil
        }
    }
    
    return options
}

// Helper to recursively collect files from a path
func collectFiles(at path: String) -> [String] {
    var isDir: ObjCBool = false
    let fm = FileManager.default
    if fm.fileExists(atPath: path, isDirectory: &isDir) {
        if !isDir.boolValue { return [path] }

        var files: [String] = []
        if let enumerator = fm.enumerator(atPath: path) {
            for case let file as String in enumerator {
                let full = (path as NSString).appendingPathComponent(file)
                var subDir: ObjCBool = false
                if fm.fileExists(atPath: full, isDirectory: &subDir), !subDir.boolValue {
                    files.append(full)
                }
            }
        }
        return files
    }
    return []
}

// Parse multiple files concurrently
func parseFiles(_ files: [String], with options: CLIOptions) {
    let group = DispatchGroup()
    let queue = DispatchQueue(label: "machp.parse", attributes: .concurrent)
    for file in files {
        group.enter()
        queue.async {
            defer { group.leave() }
            do {
                let jsonOutput = try MachOParser.parseFile(
                    at: file,
                    includeRaw: options.includeRaw,
                    recursive: false,
                    outputPath: options.outputPath,
                    debugEnabled: options.debug
                )
                if options.outputPath == nil {
                    print(jsonOutput)
                }
            } catch {
                fputs("Error parsing file \(file): \(error)\n", stderr)
            }
        }
    }
    group.wait()
}

// Main entry point
guard let options = parseArguments() else {
    exit(1)
}

print("Starting Mach-O parsing for file: \(options.filePath)")
if options.includeRaw {
    print("Raw data will be included in output.")
}
if options.recursive {
    print("Recursive parsing is enabled.")
}
if options.debug {
    print("Debug logging enabled.")
}

if options.recursive {
    let files = collectFiles(at: options.filePath)
    if files.isEmpty {
        print("No files found to parse")
        exit(1)
    }
    parseFiles(files, with: options)
} else {
    do {
        let jsonOutput = try MachOParser.parseFile(
                at: options.filePath,
                includeRaw: options.includeRaw,
                recursive: false,
                outputPath: options.outputPath,
                debugEnabled: options.debug
            )
            if options.outputPath == nil {
                print(jsonOutput)
            }
    } catch {
        print("Error parsing file: \(error)")
        exit(1)
    }
}
