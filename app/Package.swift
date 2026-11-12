// swift-tools-version:6.0
// The menu-bar app: Swift on the frameworks macOS ships, no third-party packages.
import PackageDescription

let package = Package(
  name: "Immune",
  platforms: [.macOS(.v14)],
  // The product, and so the app's binary, is ImmuneApp: the bundle also holds `immune`, and
  // on a case-insensitive volume `Immune` and `immune` would be one file.
  products: [.executable(name: "ImmuneApp", targets: ["Immune"])],
  targets: [
    // Everything that can be tested without a screen: decoding, the icon's state,
    // inert text, the lines shown, running `immune`, the run guard.
    .target(name: "ImmuneCore"),
    // AppKit status item, popover and window around SwiftUI views.
    .executableTarget(name: "Immune", dependencies: ["ImmuneCore"]),
    .testTarget(name: "ImmuneCoreTests", dependencies: ["ImmuneCore"]),
  ]
)
