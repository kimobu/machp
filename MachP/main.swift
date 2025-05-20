/// Global debug flag for the application and parsers
enum DebugConfig {
    static var isEnabled: Bool = false
}

import Foundation

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
    let usage = "Usage: MachP <file_path> [--include-raw] [--recursive] [--output <path>]"
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
        case "--recursive":
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
    // Enable global debug
    DebugConfig.isEnabled = options.debug
}

// Call the Mach-O parser. Assume MachOParser is implemented elsewhere in the project.
// The parseFile method is expected to return a JSON string representation of the parsed file.
do {
    let jsonOutput = try MachOParser.parseFile(
            at: options.filePath,
            includeRaw: options.includeRaw,
            recursive: options.recursive,
            outputPath: options.outputPath
        )
        // If the user didn’t supply --output, print to stdout
        if options.outputPath == nil {
            print(jsonOutput)
        }
} catch {
    print("Error parsing file: \(error)")
    exit(1)
}
