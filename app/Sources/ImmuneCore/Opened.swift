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

  /// Data that is one word and not a path, such as a hash: one line cut in its middle, the whole
  /// value in the tooltip. A path or words with spaces wrap.
  public var oneLine: Bool {
    isData && !value.isEmpty && !value.contains("/") && !value.contains(where: \.isWhitespace)
  }

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
      value.flatMap { $0.isEmpty ? nil : label + ": " + Words.word($0, Words.levels) }
    }
    return parts.isEmpty ? nil : parts.joined(separator: ", ")
  }
}

/// A button of the opened finding.
public enum FindingAction: Sendable, Equatable {
  case askAgent, seen, expected
}

/// One voice of "Who said what": who it is, what they said, and what it rests on. What a source
/// wrote is data in its own field (`saidIsData`, `quote`, `data`), never joined into the app's
/// words.
public struct Voice: Sendable, Equatable {
  /// Who: "Published rule", "Response layer", "Your agent", "Immune".
  public let who: String
  /// Beside who, as data: the rule set's name.
  public var whoData: String? = nil
  public let said: String
  public var saidIsData = false
  /// Under what was said, as data: the techniques a rule names.
  public var data: String? = nil
  /// Under what was said, in the app's words: how a rule's authors rate it, earlier verdicts.
  public var detail: String? = nil
  /// The reason as the source gave it, set apart.
  public var quote: String? = nil
  /// A value under its label, as data: a verdict's case.
  public var facts: [Fact] = []
  /// What to do, in Immune's words, behind a link.
  public var advice: String? = nil
}

/// How the response layer's verdicts read in a word: suspicious when a verdict said so,
/// harmless only when both counts are given and none of the verdicts is suspicious, and neither
/// when a count it would rest on is missing.
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
  /// name; otherwise what Immune says it is about when no name from the Mac says it (`thing`),
  /// where it is, and Immune's title when nothing names a thing.
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
    if let thing = f.thing, !thing.isEmpty { return Inert.text(thing, limit: 400) }
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
    case .publishedRule(_, let matches, let events, _):
      // The rule itself is a voice of "Who said what" (`voices`).
      out += eventFacts(events.first)
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
      case let action? where Words.fileActions[action] != nil:
        out.append(Fact(label: "Done", value: Words.word(action, Words.fileActions), isData: false))
        if action == "rename" {
          if let source = ev.sourceText {
            data("From", source)
          } else {
            words("From", "a path not given")
          }
        }
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
  public static func answer(_ a: Contract.Answer, now: Date? = nil) -> String {
    Words.answer(a.given, until: a.untilAt, now: now) + ", " + via(a.via)
  }

  static func via(_ via: String?) -> String { Words.via(via) }

  /// Who gave an answer, as a voice is named: "Your agent".
  public static let voiceOf: [String: String] = [
    "app": "You, in the app", "agent": "Your agent", "command": "From the command line",
    "unknown": "Someone not recorded",
  ]
  static func who(_ via: String?) -> String {
    via.flatMap { voiceOf[$0] } ?? voiceOf["unknown"] ?? ""
  }

  /// The footer of a finding answered outside the app, one line beside Take back: the answer
  /// alone, "Expected until Dec 13". Who gave it is its voice above and the tooltip's
  /// (`answeredHelp`): with it, the longest cases do not fit one line at the panel's width.
  public static func answeredLine(_ a: Contract.Answer, now: Date? = nil) -> String {
    Words.answer(a.given, until: a.untilAt, now: now)
  }

  /// The footer's tooltip: "Your agent: expected until Dec 13".
  public static func answeredHelp(_ a: Contract.Answer, now: Date? = nil) -> String {
    let said = answeredLine(a, now: now)
    return who(a.via) + ": " + said.prefix(1).lowercased() + said.dropFirst()
  }

  /// The line under the thing: its kind in Immune's words, what happened and when in the app's:
  /// "Shell startup file · changed · 11:37". "Needs you now" goes before it, when it does. From
  /// an Immune that gives no title for the kind, the kind's own name as Immune gave it.
  public static func caption(_ f: Contract.Finding, now: Date) -> String {
    let kind = Words.kind(title: f.kindTitle, kind: f.kind)
    let change = change(f)
    let when = (f.lastSeenAt ?? f.firstSeenAt).map { Clock.at($0, now: now) }
    let parts = change?.lowercased() == kind?.lowercased() ? [kind, when] : [kind, change, when]
    return parts.compactMap { $0 }.joined(separator: " · ")
  }

  /// Who said what about it: the published rule and how its authors rate it; the response
  /// layer's latest verdict, how sure it is and its reason; the person's answer, when one is in
  /// force, and its reason; Immune's own sentence and what to do. A voice with nothing to say is
  /// left out; nothing is invented.
  public static func voices(_ f: Contract.Finding, now: Date? = nil) -> [Voice] {
    var out: [Voice] = []
    if case .publishedRule(let rule?, _, _, _) = f.evidence {
      let techniques = rule.techniquesText.prefix(2).map { Inert.text($0, limit: 80) }
      out.append(
        Voice(
          who: "Published rule", whoData: rule.set.map { Inert.text($0, limit: 80) },
          said: Inert.text(rule.titleText ?? rule.name ?? "a rule not named", limit: 300),
          saidIsData: rule.titleText != nil || rule.name != nil,
          data: techniques.isEmpty ? nil : techniques.joined(separator: " · "),
          detail: rule.level.map { "its authors rate it " + Words.word($0, Words.levels) }))
    }
    if let v = f.verdicts, let voice = responseLayer(v) { out.append(voice) }
    if let a = f.answer, a.inForce != false {
      out.append(
        Voice(
          who: who(a.via), said: Words.answer(a.given, until: a.untilAt, now: now),
          quote: a.reasonText.map { Inert.text($0, limit: 1000) }))
    }
    if f.meaning != nil || f.advice != nil {
      out.append(
        Voice(
          who: "Immune", said: f.meaning.map { Inert.text($0, limit: 600) } ?? "",
          advice: f.advice.map { Inert.text($0, limit: 1000) }))
    }
    return out
  }

  /// The response layer's voice: its latest verdict in a word and how sure it is, its reason
  /// quoted and its case; or, with none listed, the counts in a word. No level of how bad.
  ///
  /// While the response layer's own finding about this one stands (`verdict_finding`), a verdict
  /// called it suspicious, perhaps one about a match: the voice says suspicious, whatever the
  /// latest verdict about this finding says, and names that latest word apart.
  static func responseLayer(_ v: Contract.Verdicts) -> Voice? {
    if v.verdictFinding != nil, v.listed.last?.kind != "suspicious" {
      let latest = v.listed.last?.kind.map {
        "latest verdict here: " + Words.word($0, Words.verdicts).lowercased()
      }
      return Voice(
        who: "Response layer", said: "Suspicious",
        detail: (["its own finding stands"] + (latest.map { [$0] } ?? [])).joined(separator: " · "))
    }
    let earlier = max(0, v.listed.count - 1)
    let more =
      earlier == 0
      ? nil : earlier == 1 ? "1 earlier verdict in report" : "\(earlier) earlier verdicts in report"
    if let last = v.listed.last {
      let word = last.kind.map { Words.word($0, Words.verdicts) } ?? "No kind given"
      let sure = last.confidence.map { ", how sure: " + Words.word($0, Words.levels) } ?? ""
      return Voice(
        who: "Response layer", said: word + sure, detail: more,
        quote: last.reasonText.map { Inert.text($0, limit: 1000) },
        facts: caseFact(last).map { [$0] } ?? [])
    }
    switch VerdictTone.of(total: v.total, suspicious: v.suspicious) {
    case .suspicious: return Voice(who: "Response layer", said: "Suspicious")
    case .harmless: return Voice(who: "Response layer", said: "Harmless")
    case .unknown: return nil
    }
  }

  /// The thing needs the person now: Immune marked the finding urgent, or the response layer's own
  /// finding about it, which the app shows with it as one thing.
  public static func urgent(_ f: Contract.Finding) -> Bool {
    f.finding?.urgent == true || f.verdicts?.verdictFinding?.urgent == true
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
  /// rests on, the verdicts and the answer, oldest first, the latest six. Each item is kept whole
  /// on a line, its spaces no-break ones, and a line breaks only after a "·".
  public static func history(_ f: Contract.Finding, now: Date) -> String {
    let items = historyItems(f, now: now).map { $0.replacingOccurrences(of: " ", with: "\u{A0}") }
    return items.joined(separator: historyBreak)
  }

  /// Between two items of the history: the "·" stays at the end of a line.
  public static let historyBreak = "\u{A0}· "

  /// The history's items, as words: "Found 9:12 AM", "verdict 9:40 AM".
  static func historyItems(_ f: Contract.Finding, now: Date) -> [String] {
    var events: [(Date, String)] = []
    if let first = f.firstSeenAt { events.append((first, "found")) }
    for e in f.restsOn {
      guard let at = e.recordedAt, let entry = e.entry else { continue }
      events.append((at, entryWords(entry)))
    }
    for v in f.verdicts?.listed ?? [] {
      guard let at = v.recordedAt else { continue }
      events.append((at, "verdict"))
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
    var items = Array(lines.suffix(6))
    if let first = items.first { items[0] = first.prefix(1).uppercased() + first.dropFirst() }
    return items
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
