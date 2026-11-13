// What the opened finding shows, from `immune finding <id> --json` alone: the thing large, a
// table of facts for its kind, the response layer's verdicts, the answer, and a short history.
// Built here so it can be tested without a screen. Labels are the app's words; every value
// that is text from the Mac or a source is inert, and long values keep both ends.

import Foundation

/// One line of the table of facts: the app's label, and one value. A value is either data from
/// the Mac or a source, inert, or the app's own words; never the two joined in one string, so
/// a source cannot continue the app's sentence.
public struct Fact: Sendable, Equatable {
  public let label: String
  public let value: String
  /// The value is data, drawn in monospace; false for the app's own words.
  public let isData: Bool

  public init(label: String, value: String, isData: Bool = true) {
    self.label = label
    self.value = value
    self.isData = isData
  }
}

/// A finding's or a verdict's levels in the report's words: "how bad: high, how sure: medium".
/// A level is never shown as a bare word; one that is absent is left out, and none is invented.
public enum Levels {
  public static func words(severity: String?, confidence: String?) -> String? {
    let parts = [("how bad", severity), ("how sure", confidence)].compactMap { label, value in
      value.flatMap { $0.isEmpty ? nil : label + ": " + Inert.text($0, limit: 20) }
    }
    return parts.isEmpty ? nil : parts.joined(separator: ", ")
  }
}

/// A button of the opened finding.
public enum FindingAction: Sendable, Equatable {
  case askAgent, seen, expected
}

/// How the response layer's box is drawn: red when a verdict said suspicious, green only when
/// both counts are given and none of the verdicts is suspicious, and neither when a count it
/// would rest on is missing.
public enum VerdictTone: Sendable, Equatable {
  case suspicious, harmless, unknown

  public static func of(total: Int?, suspicious: Int?) -> VerdictTone {
    if let s = suspicious, s > 0 { return .suspicious }
    if let t = total, t > 0, suspicious == 0 { return .harmless }
    return .unknown
  }
}

public enum FindingFacts {
  /// The thing itself, as data: the program that ran, a file event's file, a package by its
  /// name; otherwise where it is, and Immune's title when nothing names a thing.
  public static func object(_ f: Contract.Finding) -> String {
    switch f.evidence {
    case .publishedRule(_, _, let events, _), .verdictGiven(_, let events):
      switch events.first {
      case .programStart(let s)?:
        if let exe = s.executableText { return Inert.whole(exe) }
      case .fileEvent(let e)?:
        if let path = e.pathText { return Inert.whole(path) }
      default: break
      }
    case .vulnerablePackage(let p):
      if let name = p.packageText { return Inert.whole(name) }
    default: break
    }
    if let place = f.whereText ?? f.finding?.aboutText, !place.isEmpty {
      return Inert.whole(place)
    }
    return Inert.text(f.title ?? "", limit: 400)
  }

  /// What happened to a watched place, in the app's words, when the evidence says.
  public static func change(_ f: Contract.Finding) -> String? {
    if case .placeChanged(let change?, _) = f.evidence { return Words.change(change) }
    return nil
  }

  /// The table of facts for the finding's kind of evidence, in the order it is read. Each value
  /// is one piece of data, or the app's own words, under its own label.
  public static func facts(_ f: Contract.Finding) -> [Fact] {
    var out: [Fact] = []
    func data(_ label: String, _ value: String?, limit: Int = 1000) {
      guard let value, !value.isEmpty else { return }
      out.append(Fact(label: label, value: Inert.whole(value, limit: limit)))
    }
    func words(_ label: String, _ value: String?) {
      guard let value, !value.isEmpty else { return }
      out.append(Fact(label: label, value: value, isData: false))
    }
    switch f.evidence {
    case .placeChanged(let change, let presenceOnly):
      if change == nil { words("Change", "not given") }
      if presenceOnly == true { words("Read", "only that it is there") }
      if let content = f.restsOn.last(where: { $0.predicate == "has_content" }) {
        data("Before", content.oldValueText, limit: 200)
        data("After", content.newValueText, limit: 200)
      }
      if let unread = f.restsOn.last(where: { $0.entry == "not_read" }) {
        data("Can't be read", unread.newValueText)
      }
    case .changedInPlace(let became):
      data("Became", became)
    case .indicatorMatched(let indicators):
      data("Indicators", indicators)
    case .detachedProcess(let pid, _):
      words("Process", pid.map { "pid \($0)" })
    case .vulnerablePackage(let p):
      data("Project", p.projectText)
      data("Ecosystem", p.ecosystem, limit: 40)
      for r in p.releases {
        data("Version", r.versionText, limit: 200)
        data("Declared at", r.atText)
      }
      for r in p.records {
        data("Record", r.idText, limit: 200)
        data("Database", r.source, limit: 40)
        words("Level", Levels.words(severity: r.label, confidence: nil))
        if r.exploited == true { words("Exploited", "known to be exploited") }
        data("Summary", r.summaryText)
        for fixed in r.fixedText { data("Fixed in", fixed, limit: 200) }
      }
    case .publishedRule(let rule, let matches, let events, _):
      out += eventFacts(events.first)
      if let rule {
        data("Rule", rule.titleText, limit: 300)
        data("Rule set", rule.set, limit: 80)
        for t in rule.techniquesText.prefix(2) { data("Technique", t, limit: 80) }
      }
      if let n = matches, n > 1 { words("Matches", "\(n) since it was raised") }
    case .verdictGiven(let rule, let events):
      out += eventFacts(events.first)
      data("About rule", rule)
    case .other(let key):
      words("Evidence", "of a kind this version does not show")
      data("Its name", key, limit: 80)
    case nil:
      break
    }
    return out
  }

  static func eventFacts(_ e: Contract.Event?) -> [Fact] {
    var out: [Fact] = []
    func data(_ label: String, _ value: String?, limit: Int = 1000) {
      guard let value, !value.isEmpty else { return }
      out.append(Fact(label: label, value: Inert.whole(value, limit: limit)))
    }
    func words(_ label: String, _ value: String) {
      out.append(Fact(label: label, value: value, isData: false))
    }
    switch e {
    case .programStart(let s)?:
      // Led by the program that ran (the object above); its first argument only when it is
      // not that program, under its own label.
      let started = Evidence.started(executable: s.executableText, args: s.argsText)
      let rest = s.executableText == nil ? s.argsText : Array(s.argsText.dropFirst())
      if !rest.isEmpty {
        out.append(Fact(label: "Arguments", value: Evidence.commandLine(rest)))
      }
      if let startedAs = started.startedAs {
        out.append(Fact(label: "Started as", value: startedAs))
      }
      data("Started by", s.instigatorText)
      data("In folder", s.workingDirectoryText)
      data("Script", s.scriptText)
      data("Signed", s.signingIdText, limit: 200)
      data("Team", s.teamIdText, limit: 200)
    case .fileEvent(let ev)?:
      switch ev.action {
      case "rename":
        words("Done", "renamed")
        if let source = ev.sourceText {
          data("From", source)
        } else {
          words("From", "a path not given")
        }
      case "create": words("Done", "created")
      case let action?: data("Done", action, limit: 40)
      case nil: words("Done", "not given")
      }
      data("By", ev.instigatorText)
      data("Signed", ev.signingIdText, limit: 200)
    case .other?:
      words("Event", "of a kind this version does not show")
    case nil:
      break
    }
    return out
  }

  /// A verdict's case, the response layer's own text, under the app's label "Case": the value
  /// alone, as data, never continued from the app's word.
  public static func caseFact(_ v: Contract.RecordedVerdict) -> Fact? {
    guard let c = v.caseText, !c.isEmpty else { return nil }
    return Fact(label: "Case", value: Inert.text(c, limit: 200))
  }

  /// "Expected until Dec 13, through your agent": the answer in the app's words.
  public static func answer(_ a: Contract.Answer) -> String {
    Words.answer(a.given, until: a.untilAt) + ", " + via(a.via)
  }

  static func via(_ via: String?) -> String {
    switch via {
    case "agent": "through your agent"
    case "command": "from the command line"
    case "app": "in the app"
    default: "by someone not recorded"
    }
  }

  /// What can be done with the opened finding, the primary first. It follows Immune's `urgent`:
  /// for an urgent finding, asking the agent comes first; otherwise Seen. Seen and Expected are
  /// offered only for a finding the status lists with an id the app can pass.
  public static func actions(urgent: Bool, canAnswer: Bool) -> [FindingAction] {
    let answers: [FindingAction] = canAnswer ? [.seen, .expected] : []
    return urgent ? [.askAgent] + answers : answers + [.askAgent]
  }

  /// The answer is one the person did not give in the app and may hide the finding now: a box at
  /// the top, with Take back. Whether it is in force not being said is not "not in force".
  public static func answeredOutside(_ f: Contract.Finding) -> Bool {
    guard let a = f.answer else { return false }
    return a.inForce != false && a.via != "app"
  }

  /// A short history from what the message holds: when it was found, the journal entries it
  /// rests on, the verdicts and the answer, oldest first, the latest six.
  public static func history(_ f: Contract.Finding, now: Date) -> String {
    var events: [(Date, String)] = []
    if let first = f.firstSeenAt { events.append((first, "found")) }
    for e in f.restsOn {
      guard let at = e.recordedAt, let entry = e.entry else { continue }
      events.append((at, entryWords(entry)))
    }
    for v in f.verdicts?.listed ?? [] {
      guard let at = v.recordedAt else { continue }
      events.append((at, "verdict " + Inert.text(v.kind ?? "not given", limit: 20)))
    }
    if let a = f.answer, let at = a.givenAt {
      events.append((at, (a.given == "expected" ? "marked expected " : "answered ") + via(a.via)))
    }
    if let last = f.lastSeenAt, last != f.firstSeenAt { events.append((last, "last seen")) }
    var lines: [String] = []
    for (at, words) in events.enumerated().sorted(by: {
      ($0.element.0, $0.offset) < ($1.element.0, $1.offset)
    }).map(\.element) {
      let line = words + " " + Clock.at(at, now: now)
      if lines.last != line { lines.append(line) }
    }
    return lines.suffix(6).joined(separator: " · ")
  }

  static func entryWords(_ entry: String) -> String {
    switch entry {
    case "matched": "rule matched"
    case "not_read": "could not be read"
    case "place_first_read": "read for the first time"
    case "sampled": "seen running"
    default: Inert.text(entry, limit: 40).replacingOccurrences(of: "_", with: " ")
    }
  }
}
