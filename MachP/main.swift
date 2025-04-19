import Foundation

// A structure to hold command-line options
struct Options {
    var includeRaw: Bool = false
    var recursive: Bool = false
    var filePath: String = ""
}

// Function to parse the command-line arguments and return Options
func parseArguments() -> Options? {
    let usage = "Usage: MachP <file_path> [--include-raw] [--recursive]"
    let args = CommandLine.arguments
    guard args.count >= 2 else {
        print(usage)
        return nil
    }
    
    var options = Options()
    // The first argument is the executable name, so the file path is at index 1
    options.filePath = args[1]
    
    // Process additional flags
    for arg in args.dropFirst(2) {
        if arg == "--include-raw" {
            options.includeRaw = true
        } else if arg == "--recursive" {
            options.recursive = true
        } else {
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

// Call the Mach-O parser. Assume MachOParser is implemented elsewhere in the project.
// The parseFile method is expected to return a JSON string representation of the parsed file.
do {
    let jsonOutput = try MachOParser.parseFile(at: options.filePath, includeRaw: options.includeRaw, recursive: options.recursive)
    print(jsonOutput)
} catch {
    print("Error parsing file: \(error)")
    exit(1)
}
