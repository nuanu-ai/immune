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
func panel(
  _ name: String, status: String, open: String? = nil, answer: String? = nil,
  screen: CGFloat? = nil, at moment: Date? = nil
) async {
  let model = AppModel(immune: FixtureImmune(folder: fixtures, status: status, finding: answer))
  model.immuneCommand = ImmuneCommand(path: "/Applications/Immune.app/Contents/MacOS/immune")
  await model.refresh()
  if let open { await model.openFinding(open) }
  // A status the real binary made carries its own time: drawn a few minutes after it.
  let when = moment ?? now
  for (look, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
    let view = PanelView(
      model: model, watcher: WatcherBox(nil), now: when,
      maxHeight: screen.map { PanelView.maxHeight(visible: $0) })
    write(await Snapshot.png(view, appearance: appearance), "panel", "\(name)-\(look).png")
  }
  let text = Panel.of(model.reading, now: when, immune: model.immuneCommand).lines
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
  // The sheet's six: calm, watched in part, to look at, needs you now (the only filled one), old,
  // can't tell. A high level no longer fills the triangle: only `urgent` does.
  let states: [(String, Light, Bool)] = [
    ("calm", .nothingToReport, false),
    ("watched-in-part", .watchedInPart, false),
    ("to-look-at-high", .attention(2), false),
    ("needs-you-now", .attention(3), true),
    ("stale", .stale(since: nil), false),
    ("cant-tell", .cannotRead("not read"), false),
  ]
  for (look, dark) in [("light", false), ("dark", true)] {
    guard let appearance = NSAppearance(named: dark ? .darkAqua : .aqua) else { continue }
    let sheet = NSStackView()
    sheet.orientation = .vertical
    sheet.alignment = .leading
    sheet.spacing = 6
    sheet.edgeInsets = NSEdgeInsets(top: 8, left: 8, bottom: 8, right: 8)
    for (sname, light, urgent) in states {
      let image = MenuIcon.image(light, urgent: urgent, words: sname)
      var things = 0
      if case .attention(let n) = light { things = n }
      let b = bar(image, title: MenuIcon.title(light, things: things), label: sname, dark: dark)
      b.appearance = appearance
      sheet.addArrangedSubview(b)
      write(Snapshot.png(b, appearance: appearance), "icons", "\(sname)-\(look).png")
    }
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

/// The notifications of the sheet's cases, as text: the system draws them, the app gives only
/// their words.
@MainActor
func notes() {
  func status(_ name: String) -> Status? {
    (try? Data(contentsOf: fixtures.appendingPathComponent(name)))
      .flatMap { Interpret.reading(from: ImmuneOutput(exitCode: 0, stdout: $0)).status }
  }
  var out: [String] = []
  for name in ["sheet-real.json", "sheet-two.json", "sheet-overflow.json"] {
    let all = status(name)?.needsALook ?? []
    let items = all.filter(\.urgent)
    out.append("== " + name)
    // Each new urgent thing, then every finding new at once, counted as the rows show them.
    for n in Announcer.notes(items, among: all) + Announcer.notes(all, among: all) {
      out += [n.title, "  " + (n.subtitle ?? "-"), "  " + (n.body ?? "-")]
    }
  }
  let dir = output.appendingPathComponent("notifications")
  try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
  try? (out.joined(separator: "\n") + "\n").write(
    to: dir.appendingPathComponent("notes.txt"), atomically: true, encoding: .utf8)
  print("notifications/notes.txt")
}

@MainActor
func main() async {
  _ = NSApplication.shared
  icons()
  notes()
  // The design sheet's screens, from fixtures with its invented data.
  await panel("s1-calm", status: "sheet-calm.json")
  await panel("s2-two", status: "sheet-two.json")
  await panel("s3-real", status: "sheet-real.json")
  await panel("s4-overflow-700", status: "sheet-overflow.json", screen: 700)
  await panel("s4b-overflow-whole", status: "sheet-overflow.json")
  await panel("s5-silent", status: "panel-silent.json")
  await panel("s6-first-day", status: "panel-first-day.json")
  await panel("s7-open-dd", status: "sheet-two.json", open: "f95f8472164")
  await panel("s8-open-zsh", status: "sheet-real.json", open: "fbb00986139")
  await panel("s9-open-agent", status: "sheet-overflow.json", open: "f3c1d2e4a51")
  await panel("1-calm", status: "panel-calm.json")
  await panel("1b-calm-all-judged", status: "panel-calm-all-judged.json")
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
  await panel("14-stale", status: "panel-stale.json")
  await panel("15-stale-while-checking", status: "panel-stale-checking.json")
  await panel("16-collector-silent", status: "panel-silent.json")
  // The status of real size the real binary made (`tests/app_samples.rs`): whole, and on a
  // screen whose visible part is 400 pt high, where the list scrolls between the headline and
  // the footer.
  let real = (try? Data(contentsOf: fixtures.appendingPathComponent("real/status-real-size.json")))
    .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
  let made = (real?["answered_at"] as? NSNumber).map {
    Date(timeIntervalSince1970: $0.doubleValue + 240)
  }
  await panel("17-real-size", status: "real/status-real-size.json", at: made)
  await panel(
    "18-real-size-small-screen", status: "real/status-real-size.json", screen: 400, at: made)
  exit(0)
}

Task { @MainActor in await main() }
RunLoop.main.run()
