// The panel as the owner sees it: it fits the screen, its words for the schema's values are
// complete, and its measures come from one place. Each test names the promise it pins.

import AppKit
import Foundation
import SwiftUI
import Testing

@testable import ImmuneCore
@testable import ImmuneUI

/// The values of each enum in the contract's `.proto` files, as the JSON prints them: lower case,
/// without the enum's prefix (`common.proto`), and without `UNSPECIFIED`.
func schemaEnums() throws -> [String: [String]] {
  let dir = fixtures.deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("contract/immune/v1")
  var out: [String: [String]] = [:]
  for file in try FileManager.default.contentsOfDirectory(atPath: dir.path)
  where file.hasSuffix(".proto") {
    let text = try String(contentsOf: dir.appendingPathComponent(file), encoding: .utf8)
    var current: String?
    var prefix = ""
    for raw in text.components(separatedBy: "\n") {
      let line = raw.trimmingCharacters(in: .whitespaces)
      if line.hasPrefix("enum "), line.hasSuffix("{") {
        current = String(line.dropFirst(5).dropLast()).trimmingCharacters(in: .whitespaces)
        out[current!] = []
        prefix = ""
      } else if current != nil, line == "}" {
        current = nil
      } else if let name = current, let eq = line.firstIndex(of: "="), !line.hasPrefix("//") {
        let value = line[..<eq].trimmingCharacters(in: .whitespaces)
        if value.hasSuffix("_UNSPECIFIED") {
          prefix = String(value.dropLast("UNSPECIFIED".count))
        } else if !prefix.isEmpty, value.hasPrefix(prefix) {
          out[name]?.append(value.dropFirst(prefix.count).lowercased())
        }
      }
    }
  }
  return out
}

@Suite("The app's words for the schema's values")
struct SchemaWords {
  @Test(
    "Every value of every enum the app shows or decides on has the app's words or decision, so no raw word of the schema reaches the person"
  )
  func everyValueHasWords() throws {
    let enums = try schemaEnums()
    let tables: [(String, Set<String>)] = [
      ("Change", Set(Words.changes.keys)),
      ("AnswerKind", Set(Words.answers.keys)),
      ("Via", Set(Words.vias.keys)),
      ("VerdictKind", Set(Words.verdicts.keys)),
      ("Level", Set(Words.levels.keys)),
      ("FindingState", Set(Words.findingStates.keys)),
      ("FileAction", Set(Words.fileActions.keys)),
      ("CollectorState", Set(Words.collectorOn.keys)),
      ("ThisMacState", Set(Light.macStates.keys)),
    ]
    for (name, known) in tables {
      let values = try #require(enums[name], "no enum \(name) in the schema")
      #expect(!values.isEmpty, "\(name)")
      for value in values {
        #expect(known.contains(value), "\(name): \(value) has no words in the app")
      }
      // No word for a value the schema does not have, such as the store's own spelling.
      for word in known {
        #expect(values.contains(word), "\(name): \(word) is not a value of the schema")
      }
    }
    // A value the core adds later is still shown, as it is and inert, never as one it knows.
    #expect(Words.change("brand_new\u{202E}") == "brand new\\u{202E}")
    #expect(Words.via(nil) == "by someone not recorded")
    // The opened finding's levels go through the same words.
    #expect(Levels.words(severity: "not_stated", confidence: nil) == "how bad: not stated")
  }
}

@Suite("The panel on a real Mac")
struct PanelOnScreen {
  /// The panel for a status, laid out as the popover lays it out, at most `maxHeight` high;
  /// where its headline and footer are drawn, and its size.
  @MainActor
  func laidOut(_ status: String, maxHeight: CGFloat?) async -> (
    CGSize, [PanelPart: CGRect], Panel
  ) {
    _ = NSApplication.shared
    let data = fixture(status)
    let model = AppModel(immune: TableImmune { _ in ImmuneOutput(exitCode: 0, stdout: data) })
    await model.refresh()
    var frames: [PanelPart: CGRect] = [:]
    let now = model.reading.status?.generatedAt ?? Date()
    let view = PanelView(
      model: model, watcher: WatcherBox(nil), now: now, maxHeight: maxHeight,
      probe: { part, rect in frames[part] = rect })
    let host = NSHostingView(rootView: view.fixedSize(horizontal: false, vertical: true))
    for _ in 0..<6 {
      host.frame = NSRect(origin: .zero, size: host.fittingSize)
      host.layoutSubtreeIfNeeded()
      try? await Task.sleep(for: .milliseconds(50))
    }
    return (host.frame.size, frames, Panel.of(model.reading, now: now))
  }

  @MainActor
  @Test(
    "On a small screen a status of real size never makes the panel taller than the screen: the headline and the footer are inside it, and the list between them scrolls"
  )
  func fitsTheScreen() async throws {
    let status = "real/status-real-size.json"
    // Drawn whole, the panel of real size is taller than a small screen.
    let (whole, _, p) = await laidOut(status, maxHeight: nil)
    #expect(p.headline.hasPrefix("I can't tell") == false, "\(p.headline)")
    let screen: CGFloat = 400
    let cap = PanelView.maxHeight(visible: screen)
    #expect(cap < screen)
    #expect(whole.height > cap, "the sample is not of real size: \(whole.height)")
    // Capped, it is no taller than the screen allows, and both ends are drawn inside it.
    let (size, frames, _) = await laidOut(status, maxHeight: cap)
    #expect(size.height <= cap, "\(size.height)")
    let bounds = CGRect(origin: .zero, size: size).insetBy(dx: -0.5, dy: -0.5)
    let headline = try #require(frames[.headline])
    let footer = try #require(frames[.footer])
    #expect(bounds.contains(headline), "\(headline) in \(bounds)")
    #expect(bounds.contains(footer), "\(footer) in \(bounds)")
    #expect(abs(headline.minY) < 0.5)
    #expect(abs(footer.maxY - size.height) < 0.5)
    #expect(headline.height > 0 && footer.height > 0)
  }

  @Test(
    "What is watched in the panel of real size is two short lines with no count of program starts, and every kind is in its tooltip"
  )
  func coverageOfRealSize() throws {
    let p = panel(output("real/status-real-size.json"))
    #expect(p.watched.map(\.title) == ["All the time", "Every hour"])
    #expect(p.watched.map(\.kinds) == [10, 5])
    #expect(p.watched.map(\.detail.count) == [10, 5])
    #expect(p.watched.first?.starts?.on == true)
    let text = p.lines.joined(separator: "\n")
    #expect(!text.contains("4812337") && !text.contains("4,812,337"))
  }

  @Test(
    "A thing not seen that is a name and then what a source said is cut at its end, never inside what the source said; a path alone keeps its last part; the count of the rest stays"
  )
  func notSeenIsCutAtItsEnd() throws {
    let p = panel(output("real/status-real-size.json"))
    let servers = try #require(p.notSeen.first { $0.id == "servers-not-opened" })
    let example = try #require(servers.example)
    // The core gives the name alone; what the source said is beside it, not in the row.
    #expect(example == "staging-db")
    #expect(!servers.examplePath)
    #expect(servers.more == 3)
    // Cut at its end: the start stays, and the cut ends the line.
    let fits = { (s: String) in s.count <= 24 }
    let cut = Inert.end("staging-db: ssh exited with 255 (kex_exchange_identification)", fits: fits)
    #expect(cut == "staging-db: ssh exited …")
    #expect(Inert.end("short", fits: fits) == "short")
    #expect(Inert.end(example, fits: { _ in false }) == "…")
    // A path alone keeps its last part whole.
    let path = NotSeenRow(
      id: "p", title: "t", example: "~/Library/LaunchAgents/com.example.agent.plist", more: 0,
      request: nil)
    #expect(path.examplePath)
    let withReason = NotSeenRow(
      id: "p", title: "t", example: "~/.ssh/config: Permission denied (os error 13)", more: 0,
      request: nil)
    #expect(!withReason.examplePath)
  }
}

@Suite("The panel's design")
struct PanelDesign {
  @Test(
    "No view of the panel or of the opened finding writes its own size, inset, spacing, colour, font or symbol: every one comes from Style.swift"
  )
  func measuresFromOnePlace() throws {
    let forbidden = [
      #"size: [0-9]"#, #"\.padding\([0-9]"#, #"\.padding\(\.[a-z]+, [0-9]"#, #"spacing: [1-9]"#,
      #"width: [0-9]"#, #"height: [0-9]"#, #"cornerRadius: [0-9]"#, #"lineWidth: [0-9]"#,
      #"Color\.(red|green|orange|gray|blue|white|accentColor)"#, #"Color\(nsColor"#,
      #"\.font\(\.system"#, #"opacity\([0-9]"#, #"Image\(systemName: ""#,
      #"\.foregroundStyle\(\.(red|green|orange|blue)"#,
    ]
    for name in ["PanelView.swift", "FindingView.swift"] {
      let file = fixtures.deletingLastPathComponent()
        .appendingPathComponent("Sources/ImmuneUI/" + name)
      let code = try String(contentsOf: file, encoding: .utf8)
      for (n, line) in code.components(separatedBy: "\n").enumerated() {
        for pattern in forbidden where line.range(of: pattern, options: .regularExpression) != nil {
          Issue.record("\(name):\(n + 1) writes its own measure: \(line)")
        }
      }
    }
  }

  @Test(
    "The panel's short words: how long ago in minutes, hours or days; a thing not seen says Immune's own kind, under its example or above since when; a long title breaks only after a slash or a hash; an answer's day has its year only when it is another year's; a hash is one line"
  )
  func shortWords() throws {
    let now = Date(timeIntervalSince1970: 1_794_570_060)
    func ago(_ seconds: Double) -> String {
      Clock.since(now.addingTimeInterval(-seconds), now: now)
    }
    #expect(ago(30) == "just now")
    #expect(ago(60) == "1 min ago")
    #expect(ago(59 * 60) == "59 min ago")
    #expect(ago(3600) == "1 hour ago")
    #expect(ago(2 * 3600 + 59 * 60) == "2 hours ago")
    #expect(ago(24 * 3600) == "1 day ago")
    #expect(ago(49 * 3600) == "2 days ago")
    #expect(ago(-60).hasPrefix("on "))
    let silent = panel(output("panel-silent.json"))
    let row = try #require(silent.notSeen.first)
    #expect(row.example == nil && row.moreText == nil)
    #expect(row.kind == "Event level silent")
    #expect(row.second.hasPrefix("Since ") && row.second.hasSuffix("M"))
    #expect(Inert.wrapping("~/a/b#c d") == "~/\u{200B}a/\u{200B}b#\u{200B}c d")
    let real = panel(output("real/status-real-size.json"))
    #expect(real.notSeen.contains { $0.moreText == "+3 more" })
    // Under an example, Immune's own kind, never its sentence; the sentence is the tooltip's.
    let servers = try #require(real.notSeen.first { $0.id == "servers-not-opened" })
    #expect(servers.second == "Servers that could not be opened")
    #expect(servers.title != servers.second)
    // No time given: nothing under the kind.
    var timeless = row
    timeless.since = nil
    #expect(timeless.second == "")
    // No kind given: Immune's sentence stands in its place, never an empty line.
    for kind in [nil, ""] as [String?] {
      var root = try #require(
        try JSONSerialization.jsonObject(with: fixture("panel-silent.json")) as? [String: Any])
      var list = try #require(root["not_covered"] as? [[String: Any]])
      list[0]["kind"] = kind
      root["not_covered"] = list
      let kindless = panel(
        ImmuneOutput(exitCode: 0, stdout: try JSONSerialization.data(withJSONObject: root)))
      let unnamed = try #require(kindless.notSeen.first)
      #expect(unnamed.kind == unnamed.title && !unnamed.kind.isEmpty)
    }
    // An answer's end day carries its year only when it is not this year's.
    #expect(Clock.day(now.addingTimeInterval(30 * 86_400), now: now) == "Dec 13")
    #expect(Clock.day(now.addingTimeInterval(317 * 86_400), now: now).hasSuffix(", 2027"))
    #expect(Clock.day(now.addingTimeInterval(30 * 86_400)).hasSuffix(", 2026"))
    let agent = panel(output("sheet-overflow.json"))
    #expect(agent.answered?.lines.first?.answer == "Expected until Dec 13")
    // A hash is one line cut in its middle; a path and words with spaces wrap.
    #expect(Fact(label: "After", value: "sha256:5e6f7a8b5e6f").oneLine)
    #expect(!Fact(label: "Path", value: "~/a/b").oneLine)
    #expect(!Fact(label: "Line", value: "two words").oneLine)
    #expect(!Fact(label: "Words", value: "plain", isData: false).oneLine)
    #expect(!Fact(label: "Empty", value: "").oneLine)
  }

  @Test(
    "Three state colours only, and one signal of importance: the header's glyph is red only when something needs the person now, green only when calm, grey in every other state"
  )
  func oneSignalOfImportance() throws {
    let calm = panel(output("panel-calm.json"))
    #expect(calm.state == .calm)
    let urgent = panel(output("panel-two.json"))
    #expect(urgent.urgent && urgent.state == .now)
    let part = panel(output("panel-in-part.json"))
    #expect(part.state == .part)
    #expect(panel(output("panel-stale.json")).state == .stale)
    #expect(panel(output("panel-cant-tell.json")).state == .cant)
    // A finding of a high level, not urgent: to look at, grey.
    let look = panel(looking([lookItem(severity: "critical", urgent: false)]))
    #expect(look.state == .look)
    #expect(Light.menuSymbol(look.light, urgent: look.urgent) == "exclamationmark.triangle")
    let now = panel(looking([lookItem(severity: "low", urgent: true)]))
    #expect(now.state == .now)
    #expect(Light.menuSymbol(now.light, urgent: now.urgent) == "exclamationmark.triangle.fill")
    var busy = calm
    busy.busy = true
    #expect(busy.state == .busy)
  }
}
