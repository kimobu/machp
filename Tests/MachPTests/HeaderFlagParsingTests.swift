import XCTest
@testable import MachP

final class HeaderFlagParsingTests: XCTestCase {
    func testDecodeFlags() {
        let value: UInt32 = 0x1 | 0x4 | 0x200000
        let flags = HeaderParser.decodeFlags(value)
        XCTAssertEqual(flags.sorted(), ["MH_DYLDLINK", "MH_NOUNDEFS", "MH_PIE"].sorted())
    }
}
