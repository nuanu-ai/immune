// The owner's answers to a finding: the first things the app does that change the
// store. Each is one `immune finding` command, run without a shell, with every value
// as one argument of its own. Health items take no answer.

import Foundation

/// The "Expected…" form on one card: a short reason (required) and how long. Which other finding
/// it is sent with, and the read it rests on, are taken when it is sent, from what the card then
/// shows.
public struct ExpectedForm: Sendable, Equatable {
  public var id: String
  public var reason: String
  public var days: Int

  public init(id: String, reason: String = "", days: Int = Answer.defaultDays) {
    self.id = id
    self.reason = reason
    self.days = days
  }

  /// The form can be sent: a reason that is not blank, and one of the offered lengths.
  public var isComplete: Bool {
    Answer.expectedArguments(id: id, reason: reason, days: days) != nil
  }
}

/// What an answer to the row on the screen is sent with: the finding alone, the other finding of
/// the pair the row shows as one thing, or nothing, when what the panel folded and what the opened
/// message names are not the same finding.
public enum Pairing: Sendable, Equatable {
  case alone
  case with(String)
  case disagree
}

public enum Answer {
  /// How long an expected finding stays quiet, in days, as the panel offers it.
  public static let days = [7, 30, 90]
  public static let defaultDays = 30
  /// Immune's ids are short; anything longer is not one.
  static let idLimit = 64

  /// An id the app passes to Immune: short, letters, digits, dots, underscores and
  /// dashes only, and not starting with a dash, so it can never be read as a flag.
  public static func isUsable(id: String?) -> Bool {
    guard let id, !id.isEmpty, id.count <= idLimit, !id.hasPrefix("-") else { return false }
    return id.unicodeScalars.allSatisfy {
      ("a"..."z").contains($0) || ("A"..."Z").contains($0) || ("0"..."9").contains($0)
        || $0 == "." || $0 == "_" || $0 == "-"
    }
  }

  /// What Immune tells an agent about answering, in its fixed words; the request copied
  /// for the agent carries the same sentence.
  public static let agentNote =
    "Answer a finding only after the owner has agreed in this conversation, having been told"
    + " what it is and what the options are. Pass --via agent and the reason the owner agreed"
    + " to. The app shows every answer given this way."

  /// `immune finding <id> seen [--with <other>] [--journal-seq <n>] --via app --json`, or nil for
  /// an id that is not usable. `with` names the other finding of a pair the app shows as one
  /// thing: the core answers both in one transaction, or neither. Nil when the other id is given
  /// and not usable: the app never answers half of what it showed. `journalSeq` is the
  /// `journal_seq` of the message the card was drawn from; without one (an older Immune) none is
  /// sent and Immune decides.
  public static func seenArguments(
    id: String, with other: String? = nil, journalSeq: Int? = nil
  ) -> [String]? {
    guard isUsable(id: id), let pair = pairArguments(id: id, other) else { return nil }
    return ["finding", id, "seen"] + pair + readArguments(journalSeq) + ["--via", "app", "--json"]
  }

  /// `--journal-seq <n>`, or nothing without a number Immune could have given.
  static func readArguments(_ seq: Int?) -> [String] {
    guard let seq, seq >= 0 else { return [] }
    return ["--journal-seq", String(seq)]
  }

  /// What an answer to the row with this id is sent with. `names` is the finding the message the
  /// card was drawn from names as the response layer's finding about this one; `rows` are the
  /// rows of the status the panel shows. The other finding is sent only when it is both the one
  /// the panel folded under this row and the one the message names, and no other row of the core
  /// names it too. A finding the panel shows folded under another row is not a row of its own,
  /// and takes no answer by itself.
  public static func pairing(id: String, names: String?, rows: [Row]) -> Pairing {
    let entries = Panel.entries(rows)
    guard let entry = entries.first(where: { $0.row.item.id == id }) else {
      return entries.contains { $0.children.contains { $0.item.id == id } } ? .disagree : .alone
    }
    let folded = entry.children.map(\.item.id)
    // Nothing folded under the row, and the finding the message names is not in the list at
    // all (answered already, or raised after the list was read): the person sees this finding
    // alone and answers it alone. The other stays as it is, open or answered.
    if folded.isEmpty, names.map({ n in !rows.contains { $0.item.id == n } }) ?? true {
      return .alone
    }
    guard folded.count == 1, let named = names, folded[0] == named, named != id,
      isUsable(id: named),
      rows.filter({ !$0.isVerdictFinding && $0.item.verdict?.finding == named }).count == 1
    else { return .disagree }
    return .with(named)
  }

  /// What the card says when the panel and the opened finding do not agree on the other finding
  /// of the pair: nothing was sent.
  public static let disagree =
    "Not saved: the list and this finding do not name the same response layer finding with it,"
    + " so nothing was answered. Both are read again; look at it again, then answer."

  /// What the card says when Immune refused an answer because the finding changed after the card
  /// was drawn.
  public static let changedSinceRead =
    "Not saved: this finding changed since it was shown, and nothing was saved. Look at it"
    + " again, then answer."

  /// `--with <other>`, nothing without another, or nil when the other is not an id the app passes
  /// or is the finding itself.
  static func pairArguments(id: String, _ other: String?) -> [String]? {
    guard let other else { return [] }
    guard isUsable(id: other), other != id else { return nil }
    return ["--with", other]
  }

  /// A machine the app passes to Immune: its full id, `machine:` and a name of letters,
  /// digits and the marks host names and addresses use, so it is one argument that can
  /// never be read as a flag.
  public static func isUsable(machine: String?) -> Bool {
    guard let machine, machine.count <= 300, machine.hasPrefix("machine:"),
      machine.count > "machine:".count
    else { return false }
    return machine.unicodeScalars.allSatisfy {
      ("a"..."z").contains($0) || ("A"..."Z").contains($0) || ("0"..."9").contains($0)
        || ".-_:[]%@/".unicodeScalars.contains($0)
    }
  }

  /// `immune owner <machine> withdraw --via app --json`: the owner takes back a statement
  /// that set a machine aside. Nil for a machine that is not usable.
  public static func withdrawArguments(machine: String) -> [String]? {
    guard isUsable(machine: machine) else { return nil }
    return ["owner", machine, "withdraw", "--via", "app", "--json"]
  }

  /// `immune finding <id> reopen [--with <other>] [--journal-seq <n>] --via app --json`: the owner
  /// takes an answer back, and with `with` the answer given to the pair. Nil for an id that is not
  /// usable, or an other that is not.
  public static func reopenArguments(
    id: String, with other: String? = nil, journalSeq: Int? = nil
  ) -> [String]? {
    guard isUsable(id: id), let pair = pairArguments(id: id, other) else { return nil }
    return ["finding", id, "reopen"] + pair + readArguments(journalSeq) + [
      "--via", "app", "--json",
    ]
  }

  /// `immune finding <id> expected --reason <reason> --days <n> [--with <other>] [--journal-seq
  /// <n>] --via app --json`, or nil when the id is not usable, the reason is blank or the length
  /// is not one offered.
  ///
  /// The reason is the value of `--reason`, one argument exactly as typed: Immune takes
  /// the argument after `--reason` as the reason whatever it starts with, so a reason
  /// that starts with `--` stays a reason and never becomes a flag.
  public static func expectedArguments(
    id: String, reason: String, days: Int, with other: String? = nil, journalSeq: Int? = nil
  ) -> [String]? {
    guard isUsable(id: id), Self.days.contains(days),
      !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      let pair = pairArguments(id: id, other)
    else { return nil }
    return ["finding", id, "expected", "--reason", reason, "--days", String(days)] + pair
      + readArguments(journalSeq) + ["--via", "app", "--json"]
  }

  /// What the card says when Immune did not take the answer: Immune's own message when it sent
  /// one, inert, and the app's words for a finding that changed since it was shown; otherwise the
  /// app's plain words.
  static func refusal(_ out: ImmuneOutput) -> String {
    if out.launchFailure != nil { return "Not saved: the program could not be started." }
    if out.timedOut { return "Not saved: the program did not finish in time." }
    if case .success(let env) = Decoding.envelope(from: out.stdout), let error = env.errors.first {
      if error.code == "changed_since_read" { return changedSinceRead }
      if let message = error.message {
        return "Not saved. The program said: " + Inert.text(message, limit: 200)
      }
    }
    let said = String(decoding: out.stderr.prefix(300), as: UTF8.self)
      .split(separator: "\n").first.map(String.init)
    return said.map { "Not saved. The program said: " + Inert.text($0, limit: 200) }
      ?? "Not saved: the program reported a problem."
  }
}
