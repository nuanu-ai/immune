// The owner's answers to a finding: the first things the app does that change the
// store. Each is one `immune finding` command, run without a shell, with every value
// as one argument of its own. Health items take no answer.

import Foundation

/// The "Expected…" form on one card: a short reason (required) and how long.
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

  /// `immune finding <id> seen --via app --json`, or nil for an id that is not usable.
  public static func seenArguments(id: String) -> [String]? {
    guard isUsable(id: id) else { return nil }
    return ["finding", id, "seen", "--via", "app", "--json"]
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

  /// `immune finding <id> reopen --via app --json`: the owner takes an answer back. Nil for
  /// an id that is not usable.
  public static func reopenArguments(id: String) -> [String]? {
    guard isUsable(id: id) else { return nil }
    return ["finding", id, "reopen", "--via", "app", "--json"]
  }

  /// `immune finding <id> expected --reason <reason> --days <n> --via app --json`, or nil when the
  /// id is not usable, the reason is blank or the length is not one offered.
  ///
  /// The reason is the value of `--reason`, one argument exactly as typed: Immune takes
  /// the argument after `--reason` as the reason whatever it starts with, so a reason
  /// that starts with `--` stays a reason and never becomes a flag.
  public static func expectedArguments(id: String, reason: String, days: Int) -> [String]? {
    guard isUsable(id: id), Self.days.contains(days),
      !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else { return nil }
    return [
      "finding", id, "expected", "--reason", reason, "--days", String(days), "--via", "app",
      "--json",
    ]
  }

  /// What the card says when Immune did not take the answer: its own message when it
  /// sent one, inert; otherwise the app's plain words.
  static func refusal(_ out: ImmuneOutput) -> String {
    if out.launchFailure != nil { return "Not saved: the program could not be started." }
    if out.timedOut { return "Not saved: the program did not finish in time." }
    if case .success(let env) = Decoding.envelope(from: out.stdout),
      let message = env.errors.first?.message
    {
      return "Not saved. The program said: " + Inert.text(message, limit: 200)
    }
    let said = String(decoding: out.stderr.prefix(300), as: UTF8.self)
      .split(separator: "\n").first.map(String.init)
    return said.map { "Not saved. The program said: " + Inert.text($0, limit: 200) }
      ?? "Not saved: the program reported a problem."
  }
}
