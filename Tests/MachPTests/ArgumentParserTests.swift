import XCTest
@testable import MachP

final class ArgumentParserTests: XCTestCase {
    func testMinimalArguments() {
        let opts = parseArguments(from: ["machp", "file"])
        XCTAssertNotNil(opts)
        XCTAssertEqual(opts?.filePath, "file")
        XCTAssertFalse(opts!.recursive)
        XCTAssertFalse(opts!.debug)
        XCTAssertNil(opts!.outputPath)
    }

    func testRecursiveShortOption() {
        let opts = parseArguments(from: ["machp", "file", "-r"])
        XCTAssertNotNil(opts)
        XCTAssertTrue(opts!.recursive)
    }

    func testRecursiveLongOption() {
        let opts = parseArguments(from: ["machp", "file", "--recursive"])
        XCTAssertNotNil(opts)
        XCTAssertTrue(opts!.recursive)
    }

    func testDebugOption() {
        let opts = parseArguments(from: ["machp", "file", "--debug"])
        XCTAssertNotNil(opts)
        XCTAssertTrue(opts!.debug)
    }

    func testOutputOption() {
        let opts = parseArguments(from: ["machp", "file", "--output", "out.json"])
        XCTAssertNotNil(opts)
        XCTAssertEqual(opts!.outputPath, "out.json")
    }

    func testMissingOutputPath() {
        let opts = parseArguments(from: ["machp", "file", "--output"])
        XCTAssertNil(opts)
    }

    func testUnknownArgument() {
        let opts = parseArguments(from: ["machp", "file", "--unknown"])
        XCTAssertNil(opts)
    }

    func testMissingFilePath() {
        let opts = parseArguments(from: ["machp"])
        XCTAssertNil(opts)
    }
}
