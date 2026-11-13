// Draws the menu-bar icon and the panel off screen into PNG files, for review, from the
// invented fixtures in `app/fixtures`. Nothing is captured from the screen, no status item or
// popover is made, `immune` is not run and nothing is read but the fixtures: a stand-in answers
// `immune status` and `immune finding <id>` with them.
//
// Usage: swift run --package-path app ImmuneRender <fixtures folder> <output folder>
// Writes <output>/icons/*.png and <output>/panel/*.png at 2x, each in light and dark.

import AppKit
import ImmuneCore
import ImmuneUI
import SwiftUI

/// Answers as `immune` would, from fixture files: `status` from one file, `finding <id>` from
/// `finding-<id>.json`, with exit code 2 and its `Failure` for an id that has no file.
struct FixtureImmune: ImmuneRunning {
  let folder: URL
  let status: String
  /// The finding every `immune finding <id>` answers with, whatever the id: a mismatched answer.
  var finding: String?

  func run(_ arguments: [String], timeout: TimeInterval) async -> ImmuneOutput {
    func file(_ name: String) -> Data? {
      try? Data(contentsOf: folder.appendingPathComponent(name))
    }
    switch arguments.first {
    case "status": return ImmuneOutput(exitCode: 0, stdout: file(status) ?? Data())
    case "finding" where arguments.count > 1:
      if let data = file(finding ?? "finding-\(arguments[1]).json") {
        return ImmuneOutput(exitCode: 0, stdout: data)
      }
      return ImmuneOutput(exitCode: 2, stdout: file("finding-failure.json") ?? Data())
    default: return ImmuneOutput(exitCode: 0)
    }
  }
}

let args = CommandLine.arguments
guard args.count == 3 else {
  FileHandle.standardError.write(Data("usage: ImmuneRender <fixtures> <output>\n".utf8))
  exit(2)
}
let fixtures = URL(fileURLWithPath: args[1])
let output = URL(fileURLWithPath: args[2])
/// One fixed moment, so the times in the pictures do not depend on when they are drawn: shortly
/// after the fixtures' last check.
let now = ISO8601DateFormatter().date(from: "2026-11-13T11:41:00Z") ?? Date()

@MainActor
func write(_ data: Data?, _ folder: String, _ name: String) {
  let dir = output.appendingPathComponent(folder)
  try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
  guard let data else {
    print("not drawn: \(folder)/\(name)")
    return
  }
  try? data.write(to: dir.appendingPathComponent(name))
  print("\(folder)/\(name)")
}

// MARK: - The panel

@MainActor
func panel(_ name: String, status: String, open: String? = nil, answer: String? = nil) async {
  let model = AppModel(immune: FixtureImmune(folder: fixtures, status: status, finding: answer))
  model.immuneCommand = ImmuneCommand(path: "/Applications/Immune.app/Contents/MacOS/immune")
  await model.refresh()
  if let open { await model.openFinding(open) }
  for (look, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
    let view = PanelView(model: model, watcher: WatcherBox(nil), now: now)
    write(await Snapshot.png(view, appearance: appearance), "panel", "\(name)-\(look).png")
  }
  let text = Panel.of(model.reading, now: now, immune: model.immuneCommand).lines
  try? (text.joined(separator: "\n") + "\n").write(
    to: output.appendingPathComponent("panel/\(name).txt"), atomically: true, encoding: .utf8)
}

// MARK: - The icon

/// A stretch of menu bar 22 pt high: a reference item of the system's, then the icon with its
/// count as the status item draws it.
@MainActor
func bar(
  _ image: NSImage?, title: NSAttributedString, label: String, dark: Bool
) -> NSView {
  let background = dark ? NSColor(white: 0.13, alpha: 1) : NSColor(white: 0.93, alpha: 1)
  let root = NSStackView()
  root.orientation = .horizontal
  root.spacing = 14
  root.edgeInsets = NSEdgeInsets(top: 0, left: 10, bottom: 0, right: 10)
  root.wantsLayer = true
  root.layer?.backgroundColor = background.cgColor
  // The system's own extras at the size macOS draws them.
  let wifi = NSImage(systemSymbolName: "wifi", accessibilityDescription: nil)
  wifi?.isTemplate = true
  let battery = NSImage(systemSymbolName: "battery.75percent", accessibilityDescription: nil)
  battery?.isTemplate = true
  for reference in [wifi, battery] {
    let v = NSImageView(image: reference ?? NSImage())
    v.imageScaling = .scaleNone
    v.contentTintColor = .labelColor
    root.addArrangedSubview(v)
  }
  let clock = NSTextField(labelWithString: "Fri 13 Nov  11:41")
  clock.font = NSFont.menuBarFont(ofSize: 0)
  root.addArrangedSubview(clock)
  let button = NSButton(title: "", image: image ?? NSImage(), target: nil, action: nil)
  button.isBordered = false
  button.imagePosition = .imageLeading
  // The menu bar draws a template image and its title in the label colour of the bar.
  button.contentTintColor = .labelColor
  let titled = NSMutableAttributedString(attributedString: title)
  titled.addAttribute(
    .foregroundColor, value: NSColor.labelColor, range: NSRange(location: 0, length: titled.length))
  button.attributedTitle = titled
  root.addArrangedSubview(button)
  let caption = NSTextField(labelWithString: label)
  caption.font = NSFont.systemFont(ofSize: 10)
  caption.textColor = .secondaryLabelColor
  root.addArrangedSubview(caption)
  root.frame = NSRect(x: 0, y: 0, width: root.fittingSize.width, height: 22)
  root.layoutSubtreeIfNeeded()
  return root
}

@MainActor
func icons() {
  let states: [(String, Light, String?, Bool)] = [
    ("calm", .nothingToReport, nil, false),
    ("watched-in-part", .watchedInPart, nil, false),
    ("one-finding", .attention(1), "medium", false),
    ("urgent-with-count", .attention(3), "high", true),
    ("cant-tell", .cannotRead("not read"), nil, false),
  ]
  let candidates: [(String, NSImage.SymbolConfiguration?)] = [
    ("before", nil),
    ("15pt-medium", MenuIcon.configuration),
    ("16pt-regular", NSImage.SymbolConfiguration(pointSize: 16, weight: .regular, scale: .medium)),
  ]
  for (look, dark) in [("light", false), ("dark", true)] {
    guard let appearance = NSAppearance(named: dark ? .darkAqua : .aqua) else { continue }
    let sheet = NSStackView()
    sheet.orientation = .vertical
    sheet.alignment = .leading
    sheet.spacing = 6
    sheet.edgeInsets = NSEdgeInsets(top: 8, left: 8, bottom: 8, right: 8)
    for (cname, config) in candidates {
      let head = NSTextField(labelWithString: cname)
      head.font = NSFont.boldSystemFont(ofSize: 11)
      sheet.addArrangedSubview(head)
      for (sname, light, worst, urgent) in states {
        var image: NSImage?
        if let config {
          image = MenuIcon.image(
            light, worst: worst, urgent: urgent, words: sname, configuration: config)
        } else {
          image = NSImage(
            systemSymbolName: Light.menuSymbol(light, worst: worst, urgent: urgent),
            accessibilityDescription: sname)
          image?.isTemplate = true
        }
        let title =
          config == nil
          ? NSAttributedString(string: MenuIcon.count(light).map { " " + $0 } ?? "")
          : MenuIcon.title(light)
        let b = bar(image, title: title, label: sname, dark: dark)
        b.appearance = appearance
        sheet.addArrangedSubview(b)
        if cname == "15pt-medium" {
          write(Snapshot.png(b, appearance: appearance), "icons", "\(sname)-\(look).png")
        }
      }
    }
    // The other shape considered for a Mac watched in part: a ring with a check, as in the panel.
    let ring = NSImage(systemSymbolName: "checkmark.circle", accessibilityDescription: nil)?
      .withSymbolConfiguration(MenuIcon.configuration)
    ring?.isTemplate = true
    let alt = bar(ring, title: NSAttributedString(), label: "in part, other shape", dark: dark)
    alt.appearance = appearance
    sheet.addArrangedSubview(alt)
    sheet.appearance = appearance
    sheet.wantsLayer = true
    appearance.performAsCurrentDrawingAppearance {
      sheet.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
    }
    sheet.frame = NSRect(origin: .zero, size: sheet.fittingSize)
    sheet.layoutSubtreeIfNeeded()
    write(Snapshot.png(sheet, appearance: appearance), "icons", "compare-\(look).png")
  }
}

@MainActor
func main() async {
  _ = NSApplication.shared
  icons()
  await panel("1-calm", status: "panel-calm.json")
  await panel("2-two-findings", status: "panel-two.json")
  await panel("3-not-covered", status: "panel-in-part.json")
  await panel("4-program-start-and-verdict", status: "panel-start.json")
  await panel("5-first-day", status: "panel-first-day.json")
  await panel("6-open-program-start", status: "panel-start.json", open: "f95f8472164")
  await panel("7-open-shell-file-harmless", status: "panel-two.json", open: "fbb00986139")
  await panel("8-open-agent-answer", status: "panel-two.json", open: "f3c1d2e4a51")
  await panel("9-open-failure", status: "panel-two.json", open: "f0000000000")
  await panel(
    "10-open-mismatched-answer", status: "panel-two.json", open: "f3c1d2e4a51",
    answer: "finding-fbb00986139.json")
  await panel("11-cant-tell-with-findings", status: "panel-cant-tell.json")
  await panel("12-hostile-rows", status: "panel-hostile.json")
  await panel("13-open-hostile-program-start", status: "panel-hostile.json", open: "fa5b0f00c1d")
  exit(0)
}

Task { @MainActor in await main() }
RunLoop.main.run()
