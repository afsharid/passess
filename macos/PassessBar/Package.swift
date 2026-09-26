// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PassessBar",
    platforms: [.macOS(.v13)],
    targets: [
        // Models, the CLI runner and what the menu shows: no AppKit, so it can be checked headless.
        .target(name: "PassessKit"),
        // The menu bar app itself.
        .executableTarget(name: "PassessBar", dependencies: ["PassessKit"]),
        // Decodes the JSON fixtures the Go tests write and checks what the menu would show.
        .executableTarget(name: "PassessKitCheck", dependencies: ["PassessKit"]),
        // Draws AppIcon.iconset; `make macos-icon` turns it into AppIcon.icns.
        .executableTarget(name: "IconMaker"),
    ]
)
