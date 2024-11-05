// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Cipher", // Defines the package name as Cipher
    platforms: [
        .macOS(.v14), // macOS 14 and later
        .iOS(.v17) // iOS 17 and later
    ], // Specifies the platforms supported by the package
    products: [
        .library(
            name: "Cipher",
            targets: ["Cipher"]) // Defines the library product with the target Cipher
    ], // Lists the products of the package
    dependencies: [
        .package(url: "https://github.com/sentryco/Logger", branch: "main"), // Adds Logger as a dependency
        .package(url: "https://github.com/sentryco/Dice", branch: "main") // Adds Dice as a dependency
    ], // Lists the dependencies of the package
    targets: [
        .target(
            name: "Cipher",
            dependencies: ["Logger", "Dice"]), // Defines the Cipher target with Logger and Dice as dependencies
        .testTarget(
            name: "CipherTests",
            dependencies: ["Cipher", "Logger", "Dice"]) // Defines the CipherTests target with dependencies on Cipher, Logger, and Dice
    ] // Lists the targets of the package
)
