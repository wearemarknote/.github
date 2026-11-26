// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FixtureKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FixtureCore", targets: ["FixtureCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.1.1"),
        .package(name: "Helper", url: "https://github.com/example/unreleased-helper", branch: "main"),
    ],
    targets: [
        .target(name: "FixtureCore", dependencies: [
            .product(name: "Crypto", package: "swift-crypto"),
        ]),
    ]
)
