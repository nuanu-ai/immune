// swift-tools-version:6.0
// The menu-bar app: Swift on the frameworks macOS ships, no third-party packages.
import PackageDescription

let package = Package(
  name: "PersonalSOC",
  platforms: [.macOS(.v14)],
  products: [.executable(name: "PersonalSOC", targets: ["PersonalSOC"])],
  targets: [
    // Everything that can be tested without a screen: decoding, the icon's state,
    // inert text, the lines shown, running `soc`, the run guard.
    .target(name: "SOCCore"),
    // AppKit status item, popover and window around SwiftUI views.
    .executableTarget(name: "PersonalSOC", dependencies: ["SOCCore"]),
    .testTarget(name: "SOCCoreTests", dependencies: ["SOCCore"]),
  ]
)
