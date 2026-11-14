// What the app knows after asking Immune, and the icon's state derived from it.
// The false-calm rule applies here: "nothing to report" is shown only when every
// piece the icon judges by was reported. Anything unknown is "cannot be read".

import Foundation

public enum Reading: Sendable, Equatable {
  case notYetRead
  /// Immune could not be read. `reason` is the app's own words; `detailText` is
  /// what Immune said, which is data and is shown inert; `plain` is the reason in
  /// words for the owner, which ends the headline "I can't tell: …".
  case failed(reason: String, detailText: String?, plain: String)
  case read(Status, errors: [ImmuneError])

  public var status: Status? {
    if case .read(let s, _) = self { return s }
    return nil
  }
}

/// The levels of how bad, as Immune names them (OCSF's), from least to worst.
public enum Severity {
  public static let levels = ["informational", "low", "medium", "high", "critical"]

  /// The worst level among the items, or nil when there are none or none is known.
  public static func worst(_ items: [Item]) -> String? {
    items.compactMap { $0.severity }.filter(levels.contains)
      .max { levels.firstIndex(of: $0)! < levels.firstIndex(of: $1)! }
  }

  /// High and critical get the stronger of the two weights the panel has.
  public static func isStrong(_ severity: String?) -> Bool {
    severity == "high" || severity == "critical"
  }
}

public enum Light: Sendable, Equatable {
  case nothingToReport
  /// Nothing needs a look, and Immune says a reading of this Mac's own places failed: quiet,
  /// never an alarm, never counted, and never drawn as the calm of a Mac watched whole.
  case watchedInPart
  case attention(Int)
  /// Nothing needs a look as far as Immune knows, and Immune says what it knows is old: its
  /// last full check finished at `since`, or none has. Never calm, and never an incomplete
  /// answer: it says that it is old and since when.
  case stale(since: Date?)
  case cannotRead(String)

  /// The light of a reading at `now`: a status Immune called fresh is old once `now` is past
  /// its last full check by more than Immune's `fresh_for_seconds`.
  public static func of(_ reading: Reading, now: Date) -> Light {
    switch reading {
    case .notYetRead: return .cannotRead("The program has not been read yet.")
    case .failed(let reason, _, _): return .cannotRead(reason)
    case .read(let s, let errors):
      // Errors beside an answer that says it succeeded: not calm, whatever else it says.
      if let e = errors.first {
        return .cannotRead(
          "immune reported a problem beside its answer: "
            + Inert.text(Interpret.words(e), limit: 300)
            + ".")
      }
      return of(s, now: now)
    }
  }

  static func of(_ s: Status, now: Date) -> Light {
    // An answer with a value of another type than the one read is not a smaller valid answer.
    if let path = s.misfits.first {
      return .cannotRead(
        "immune's answer does not have the shape this app reads at " + Inert.text(path, limit: 200)
          + ".")
    }
    switch s.store?.exists {
    case true?: break
    case false?: return .cannotRead("There is no store yet. Run a full run to create it.")
    case nil: return .cannotRead("Whether the store exists is not reported.")
    }
    // What needs a look is Immune's to say, whether or not a full check has finished.
    // Not computed, or not said, is not calm.
    if let nc = s.notComputed?.first(where: { $0.section == "needs_a_look" }) {
      return .cannotRead(
        "What needs a look is not computed yet: " + Inert.text(nc.reason ?? "no reason given") + "."
      )
    }
    guard let total = s.needsALookTotal, let items = s.needsALook else {
      return .cannotRead("What needs a look is not reported.")
    }
    // The urgent ones are counted over all of them: never more than all, never fewer than listed.
    let listedUrgent = items.filter(\.urgent).count
    guard total >= items.count, (s.needsALookUrgent ?? listedUrgent) <= total,
      (s.needsALookUrgent ?? listedUrgent) >= listedUrgent
    else {
      return .cannotRead("What needs a look does not add up.")
    }
    // A finding outranks everything else.
    if total > 0 { return .attention(total) }
    // Calm only on a status Immune says is fresh: an old last check is not calm, however quiet;
    // freshness not said is an answer that is not whole.
    guard let mac = s.thisMac, let fresh = mac.fresh else {
      return .cannotRead("Whether what Immune knows is fresh is not reported.")
    }
    guard fresh else { return .stale(since: mac.checkedAt) }
    // Fresh when Immune answered; held past how long that holds, the same answer is old, by the
    // same rule as Immune's own: more than `fresh_for_seconds` after the check. A status that
    // does not say how long is taken at its word.
    if let freshFor = mac.freshFor, let checked = mac.checkedAt,
      now.timeIntervalSince(checked) > Double(freshFor)
    {
      return .stale(since: checked)
    }
    // Calm only when Immune says this Mac is watched, wholly or in part; not checked,
    // or anything else, is not calm. What it does not cover never raises the icon.
    return mac.state.flatMap { macStates[$0] }
      ?? .cannotRead("Whether this Mac is watched is not reported.")
  }

  /// The light for each value of `ThisMacState` (status.proto). A test walks the schema against
  /// it, so a state the core adds is decided on here; until then it is not calm.
  static let macStates: [String: Light] = [
    "watched": .nothingToReport, "watched_in_part": .watchedInPart,
    "not_checked": .cannotRead("Nothing of this Mac has been read yet."),
  ]

  /// The menu-bar symbol: filled only when Immune marked something urgent, whatever the levels.
  public static func menuSymbol(_ light: Light, urgent: Bool = false) -> String {
    if case .attention = light, urgent { return light.symbol + ".fill" }
    return light.symbol
  }

  /// One SF Symbol per state, each a different shape, so the states are told apart without
  /// colour: a whole shield with a check, half a shield, a triangle, a circle with a question
  /// mark.
  public var symbol: String {
    switch self {
    case .nothingToReport: "checkmark.shield"
    case .watchedInPart: "shield.lefthalf.filled"
    case .attention: "exclamationmark.triangle"
    case .stale: "clock"
    case .cannotRead: "questionmark.circle"
    }
  }

  /// Whether this is an old answer, whatever its time.
  public var isStale: Bool { if case .stale = self { true } else { false } }

  /// The headline before the panel says how many need the person now; see `Panel.headline`.
  public var headline: String {
    switch self {
    case .nothingToReport, .watchedInPart: "Nothing needs you"
    case .attention(let n): n == 1 ? "1 to look at" : "\(n) to look at"
    case .stale(let since): Light.staleWords(since)
    case .cannotRead: "I can't tell"
    }
  }

  /// "Not checked since 9:41": an old answer, and since when, as short as `now` allows.
  public static func staleWords(_ since: Date?, now: Date? = nil) -> String {
    since.map { d in "Not checked since " + (now.map { Clock.at(d, now: $0) } ?? Clock.full(d)) }
      ?? "No full check has finished"
  }
}

public enum Interpret {
  // The reasons in the owner's words.
  static let notStarted = "the program could not be started"
  static let tooSlow = "the program did not answer in time"
  static let notUnderstood = "the program's answer is not one this app understands"
  static let stopped = "the program stopped unexpectedly"
  static let cannotReadRecords = "the program cannot read its records"
  static let reported = "the program reported a problem"

  /// Immune's raw output, turned into what the app knows. Any doubt is a failure. An answer is
  /// taken only when it is the message asked for: an object of the right format is not yet a
  /// status, it must be the contract's `Status` (`Decoding.isStatus`).
  public static func reading(from o: ImmuneOutput) -> Reading {
    if let why = o.launchFailure {
      return .failed(reason: "immune could not be started.", detailText: why, plain: notStarted)
    }
    if o.timedOut {
      return .failed(
        reason: "immune did not answer in time and was stopped.", detailText: nil, plain: tooSlow)
    }
    if o.tooLarge {
      return .failed(
        reason: "immune printed more than the app reads.", detailText: nil, plain: notUnderstood)
    }
    let stderrText = String(decoding: o.stderr.prefix(2000), as: UTF8.self)
    let said = stderrText.isEmpty ? nil : stderrText
    if let sig = o.signal {
      return .failed(
        reason: "immune was stopped by signal \(sig).", detailText: said, plain: stopped)
    }
    let exit = o.exitCode ?? -1
    guard case .success(let env) = Decoding.envelope(from: o.stdout) else {
      return .failed(
        reason: exit == 0
          ? "immune's answer is not understood."
          : "immune failed with exit code \(exit) and its answer is not understood.",
        detailText: said, plain: notUnderstood)
    }
    if env.ok == false || exit != 0 {
      return .failed(
        reason: exit != 0 ? "immune failed with exit code \(exit)." : "immune reported a failure.",
        detailText: env.errors.first.map(words) ?? said,
        plain: env.errors.first?.code == "store_unreadable" ? cannotReadRecords : reported)
    }
    guard env.format == Decoding.knownFormat else {
      let f = env.format.map { "format \($0)" } ?? "no format"
      return .failed(
        reason: "immune's answer has \(f), which this app does not know.", detailText: nil,
        plain: notUnderstood)
    }
    // Only the status is taken: an object that is not one is not read as an empty status.
    guard env.ok == true, let status = env.result else {
      return .failed(
        reason: "immune's answer is not the status.", detailText: nil, plain: notUnderstood)
    }
    return .read(status, errors: env.errors)
  }

  /// An error as one line: its code, its message, and what it said from the machine.
  public static func words(_ e: ImmuneError) -> String {
    let head = [e.code, e.message].compactMap { $0 }.joined(separator: ": ")
    guard let d = e.detailText, !d.isEmpty else { return head }
    return head + " (" + d + ")"
  }
}
