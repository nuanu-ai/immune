// What the app knows after asking soc, and the icon's state derived from it.
// The false-calm rule applies here: "nothing to report" is shown only when every
// piece the icon judges by was reported. Anything unknown is "cannot be read".

import Foundation

public enum Reading: Sendable, Equatable {
  case notYetRead
  /// soc could not be read. `reason` is the app's own words; `detailText` is
  /// what soc said, which is data and is shown inert; `plain` is the reason in
  /// words for the owner, which ends the headline "I can't tell: …".
  case failed(reason: String, detailText: String?, plain: String)
  case read(Status, errors: [SocError])

  public var status: Status? {
    if case .read(let s, _) = self { return s }
    return nil
  }
}

/// The levels of how bad, as soc names them (OCSF's), from least to worst.
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
  case attention(Int)
  case cannotRead(String)

  public static func of(_ reading: Reading) -> Light {
    switch reading {
    case .notYetRead: return .cannotRead("The program has not been read yet.")
    case .failed(let reason, _, _): return .cannotRead(reason)
    case .read(let s, _): return of(s)
    }
  }

  static func of(_ s: Status) -> Light {
    switch s.store?.exists {
    case true?: break
    case false?: return .cannotRead("There is no store yet. Run a full run to create it.")
    case nil: return .cannotRead("Whether the store exists is not reported.")
    }
    guard s.lastFinishedRun != nil else {
      if s.running == true { return .cannotRead("The first run is in progress.") }
      return .cannotRead("No run has finished yet.")
    }
    // What needs a look is soc's to say. Not computed, or not said, is not calm.
    if let nc = s.notComputed?.first(where: { $0.section == "needs_a_look" }) {
      return .cannotRead(
        "What needs a look is not computed yet: " + Inert.text(nc.reason ?? "no reason given") + "."
      )
    }
    guard let total = s.needsALookTotal, let items = s.needsALook else {
      return .cannotRead("What needs a look is not reported.")
    }
    guard total >= items.count else {
      return .cannotRead("What needs a look does not add up.")
    }
    return total == 0 ? .nothingToReport : .attention(total)
  }

  /// The menu-bar symbol: filled when the worst thing shown is high or critical, or
  /// when soc marked something urgent.
  public static func menuSymbol(_ light: Light, worst: String?, urgent: Bool = false) -> String {
    if case .attention = light, urgent || Severity.isStrong(worst) { return light.symbol + ".fill" }
    return light.symbol
  }

  /// One SF Symbol per state, each a different shape, so the states are told
  /// apart without colour.
  public var symbol: String {
    switch self {
    case .nothingToReport: "checkmark.shield"
    case .attention: "exclamationmark.triangle"
    case .cannotRead: "questionmark.circle"
    }
  }

  /// The filled symbol for the panel's headline: the same shapes as `symbol`.
  public var panelSymbol: String { symbol + ".fill" }

  public var headline: String {
    switch self {
    case .nothingToReport: "Nothing needs you."
    case .attention(let n): n == 1 ? "1 thing needs a look." : "\(n) things need a look."
    case .cannotRead: "I can't tell."
    }
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

  /// soc's raw output, turned into what the app knows. Any doubt is a failure.
  public static func reading(from o: SocOutput) -> Reading {
    if let why = o.launchFailure {
      return .failed(reason: "soc could not be started.", detailText: why, plain: notStarted)
    }
    if o.timedOut {
      return .failed(
        reason: "soc did not answer in time and was stopped.", detailText: nil, plain: tooSlow)
    }
    if o.tooLarge {
      return .failed(
        reason: "soc printed more than the app reads.", detailText: nil, plain: notUnderstood)
    }
    let stderrText = String(decoding: o.stderr.prefix(2000), as: UTF8.self)
    let said = stderrText.isEmpty ? nil : stderrText
    if let sig = o.signal {
      return .failed(reason: "soc was stopped by signal \(sig).", detailText: said, plain: stopped)
    }
    let exit = o.exitCode ?? -1
    guard case .success(let env) = Decoding.envelope(from: o.stdout) else {
      return .failed(
        reason: exit == 0
          ? "soc's answer is not understood."
          : "soc failed with exit code \(exit) and its answer is not understood.",
        detailText: said, plain: notUnderstood)
    }
    guard env.format == Decoding.knownFormat else {
      let f = env.format.map { "format \($0)" } ?? "no format"
      return .failed(
        reason: "soc's answer has \(f), which this app does not know.", detailText: nil,
        plain: notUnderstood)
    }
    if env.ok == false || exit != 0 {
      return .failed(
        reason: exit != 0 ? "soc failed with exit code \(exit)." : "soc reported a failure.",
        detailText: env.errors.first.map(words) ?? said,
        plain: env.errors.first?.code == "store_unreadable" ? cannotReadRecords : reported)
    }
    guard env.ok == true else {
      return .failed(
        reason: "soc's answer does not say whether it succeeded.", detailText: nil,
        plain: notUnderstood)
    }
    guard let status = env.result else {
      return .failed(reason: "soc's answer has no result.", detailText: nil, plain: notUnderstood)
    }
    return .read(status, errors: env.errors)
  }

  /// An error as one line: its code, its message, and what it said from the machine.
  public static func words(_ e: SocError) -> String {
    let head = [e.code, e.message].compactMap { $0 }.joined(separator: ": ")
    guard let d = e.detailText, !d.isEmpty else { return head }
    return head + " (" + d + ")"
  }
}
