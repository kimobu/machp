import XCTest
@testable import MachP

final class ArgumentParserTests: XCTestCase {
    func testMinimalArguments() {
        CommandLine.arguments = ["machp", "file"]
        let opts = parseArguments()
        XCTAssertNotNil(opts)
        XCTAssertEqual(opts?.filePath, "file")
        XCTAssertFalse(opts!.includeRaw)
        XCTAssertFalse(opts!.recursive)
        XCTAssertFalse(opts!.debug)
        XCTAssertNil(opts!.outputPath)
    }

    func testIncludeRaw() {
        CommandLine.arguments = ["machp", "file", "--include-raw"]
        let opts = parseArguments()
        XCTAssertNotNil(opts)
        XCTAssertTrue(opts!.includeRaw)
    }

    func testRecursiveShortOption() {
        CommandLine.arguments = ["machp", "file", "-r"]
        let opts = parseArguments()
        XCTAssertNotNil(opts)
        XCTAssertTrue(opts!.recursive)
    }

    func testRecursiveLongOption() {
        CommandLine.arguments = ["machp", "file", "--recursive"]
        let opts = parseArguments()
        XCTAssertNotNil(opts)
        XCTAssertTrue(opts!.recursive)
    }

    func testDebugOption() {
        CommandLine.arguments = ["machp", "file", "--debug"]
        let opts = parseArguments()
        XCTAssertNotNil(opts)
        XCTAssertTrue(opts!.debug)
    }

    func testOutputOption() {
        CommandLine.arguments = ["machp", "file", "--output", "out.json"]
        let opts = parseArguments()
        XCTAssertNotNil(opts)
        XCTAssertEqual(opts!.outputPath, "out.json")
    }

    func testMissingOutputPath() {
        CommandLine.arguments = ["machp", "file", "--output"]
        let opts = parseArguments()
        XCTAssertNil(opts)
    }

    func testUnknownArgument() {
        CommandLine.arguments = ["machp", "file", "--unknown"]
        let opts = parseArguments()
        XCTAssertNil(opts)
    }

    func testMissingFilePath() {
        CommandLine.arguments = ["machp"]
        let opts = parseArguments()
        XCTAssertNil(opts)
    }
}
