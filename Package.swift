// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MachP",
    platforms: [
        .macOS(.v15)
    ],
    dependencies: [
            .package(url: "https://github.com/apple/swift-log.git", from: "1.4.0"),
            .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "4.0.0")
        ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .executableTarget(
            name: "MachP",
            dependencies: [
                        .product(name: "Logging", package: "swift-log"),
                        .product(name: "Crypto", package: "swift-crypto")
                    ],
            path: "Sources/MachP"),
        .testTarget(
            name: "MachPTests",
            dependencies: ["MachP"],
            path: "Tests/MachPTests")
    ]
)
