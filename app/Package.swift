// swift-tools-version:6.0
// The menu-bar app: Swift on the frameworks macOS ships, no third-party packages.
import PackageDescription

let package = Package(
  name: "Immune",
  platforms: [.macOS(.v15)],
  // The product, and so the app's binary, is ImmuneApp: the bundle also holds `immune`, and
  // on a case-insensitive volume `Immune` and `immune` would be one file.
  products: [.executable(name: "ImmuneApp", targets: ["Immune"])],
  targets: [
    // Everything that can be tested without a screen: decoding, the icon's state,
    // inert text, the lines shown, running `immune`, the run guard.
    .target(name: "ImmuneCore"),
    // The SwiftUI views of the panel and the opened finding, and the menu-bar icon.
    .target(name: "ImmuneUI", dependencies: ["ImmuneCore"]),
    // AppKit status item and popover around the views.
    .executableTarget(name: "Immune", dependencies: ["ImmuneCore", "ImmuneUI"]),
    // Draws the icon and the panel off screen into PNG files from fixture JSON, for review:
    // no status item, no popover, no `immune`. Not part of the app.
    .executableTarget(name: "ImmuneRender", dependencies: ["ImmuneCore", "ImmuneUI"]),
    .testTarget(name: "ImmuneCoreTests", dependencies: ["ImmuneCore", "ImmuneUI"]),
  ]
)
