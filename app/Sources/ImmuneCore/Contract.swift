// The one message of the contract the app reads: `immune finding <id> --json`, the finding
// whole, and the contract's `Failure` printed in its place. The schema is
// `contract/immune/v1/findings.proto`; its JSON is the one the generated types print (enum
// values as lower-case words, times as seconds since the epoch, an absent optional as null, a
// one-of as an object with one key). As in `Decoding.swift`, every field is optional: what is
// missing or of another type is nil, shown as not given, never as zero or as fine. Text from
// the Mac or a source is only in fields ending in `Text`.

import Foundation

public enum Contract {
  /// The version of the contract this app reads.
  public static let format = 1

  /// `Finding`: one finding whole.
  public struct Finding: Sendable, Equatable {
    public var format: Int?
    public var finding: FindingRef?
    /// The core's own words for every finding of its rule.
    public var kind: String?
    public var title: String?
    public var meaning: String?
    public var advice: String?
    public var techniqueText: String?
    public var whereText: String?
    public var firstSeenAt: Date?
    public var lastSeenAt: Date?
    public var answer: Answer?
    public var evidence: Evidence?
    public var restsOn: [JournalEntry] = []
    public var verdicts: Verdicts?
  }

  public struct FindingRef: Sendable, Equatable {
    public var id: String?
    public var rule: String?
    public var aboutText: String?
    /// open, expected, seen, cleared; a word the app does not know is shown as it is.
    public var state: String?
    public var severity: String?
    public var confidence: String?
    /// Immune's own mark; missing or not a boolean is false.
    public var urgent = false
  }

  /// The person's answer.
  public struct Answer: Sendable, Equatable {
    /// `expected` or `seen`.
    public var given: String?
    /// `app`, `agent`, `command` or `unknown`.
    public var via: String?
    public var givenAt: Date?
    public var reasonText: String?
    public var untilAt: Date?
    /// It hides the finding now. Missing or not a boolean is nil: not known, and so never taken
    /// to be over.
    public var inForce: Bool?
  }

  /// What a finding rests on, by its kind. A kind this app does not shape is `.other` with
  /// its key; the journal entries are still there.
  public enum Evidence: Sendable, Equatable {
    case placeChanged(change: String?, presenceOnly: Bool?)
    case changedInPlace(becameText: String?)
    case indicatorMatched(indicatorsText: String?)
    case detachedProcess(pid: Int?, startMicros: Int?)
    case vulnerablePackage(VulnerablePackage)
    case publishedRule(rule: Rule?, matches: Int?, events: [Event], source: String?)
    case verdictGiven(rule: String?, events: [Event])
    case other(String)
  }

  public struct VulnerablePackage: Sendable, Equatable {
    public var projectText: String?
    public var ecosystem: String?
    public var packageText: String?
    /// Each release with the lockfile line that declares it.
    public var releases: [PackageRelease] = []
    public var records: [PackageRecord] = []
  }

  public struct PackageRelease: Sendable, Equatable {
    public var versionText: String?
    public var atText: String?
  }

  public struct PackageRecord: Sendable, Equatable {
    public var idText: String?
    public var source: String?
    public var label: String?
    public var exploited: Bool?
    public var summaryText: String?
    public var fixedText: [String] = []
  }

  /// A published rule, as it describes itself.
  public struct Rule: Sendable, Equatable {
    public var name: String?
    public var titleText: String?
    public var level: String?
    public var techniquesText: [String] = []
    public var authorText: String?
    /// The set in words, such as `SigmaHQ`.
    public var set: String?
  }

  /// An event a rule matched.
  public enum Event: Sendable, Equatable {
    case programStart(ProgramStart)
    case fileEvent(FileEvent)
    /// A kind this app does not know.
    case other
  }

  public struct ProgramStart: Sendable, Equatable {
    public var happenedAt: Date?
    public var executableText: String?
    public var signingIdText: String?
    public var teamIdText: String?
    public var pid: Int?
    /// The process before its `exec`: what started this program, in the core's words.
    public var instigatorText: String?
    public var argsText: [String] = []
    public var workingDirectoryText: String?
    public var scriptText: String?
  }

  public struct FileEvent: Sendable, Equatable {
    public var happenedAt: Date?
    /// `create` or `rename`.
    public var action: String?
    public var pathText: String?
    public var sourceText: String?
    public var instigatorText: String?
    public var signingIdText: String?
  }

  /// One journal entry the finding rests on.
  public struct JournalEntry: Sendable, Equatable {
    public var seq: Int?
    public var recordedAt: Date?
    /// The store's word: `added`, `changed`, `removed`, `matched`, `verdict`, …
    public var entry: String?
    public var kind: String?
    public var predicate: String?
    public var subjectText: String?
    public var oldValueText: String?
    public var newValueText: String?
  }

  public struct Verdicts: Sendable, Equatable {
    public var total: Int?
    public var suspicious: Int?
    /// The first and the latest 20 at most, oldest first.
    public var listed: [RecordedVerdict] = []
    /// For a finding of the core: its `verdict.suspicious` finding, open or expected.
    public var verdictFinding: FindingRef?
  }

  public struct RecordedVerdict: Sendable, Equatable {
    /// `suspicious` or `harmless`; anything else is shown as it is.
    public var kind: String?
    public var reasonText: String?
    public var caseText: String?
    public var severity: String?
    public var confidence: String?
    public var recordedAt: Date?
  }

  /// `Failure`: why a command of the contract did not answer.
  public struct Failure: Sendable, Equatable {
    public var operation: String?
    public var errors: [ImmuneError]
  }
}

/// What the app knows of one finding it opened.
public enum FindingReading: Sendable, Equatable {
  case loading
  case read(Contract.Finding)
  /// Immune answered with the contract's `Failure`.
  case refused(Contract.Failure, exitCode: Int32?)
  /// Immune could not be run, or its answer is not one this app reads: the app's words, and
  /// what Immune said, as data.
  case failed(reason: String, detailText: String?)
}

extension Decoding {
  /// The output of `immune finding <id> --json` for the id `asked`, as the app reads it. An
  /// answer is taken only when it is the message asked for: a `Finding` of the known format
  /// whose own id is `asked`, with the fields a card cannot be without (its state, Immune's
  /// urgent mark, its kind and title). The contract's `Failure` is shown as one, whatever the
  /// exit code. Anything else is a failure in the app's words: never an empty card, and never
  /// another finding's message shown for the one clicked.
  public static func finding(from o: ImmuneOutput, asked: String) -> FindingReading {
    if let why = o.launchFailure {
      return .failed(reason: "immune could not be started.", detailText: why)
    }
    if o.timedOut { return .failed(reason: "immune did not answer in time.", detailText: nil) }
    if o.tooLarge {
      return .failed(reason: "immune printed more than the app reads.", detailText: nil)
    }
    let said = o.stderr.isEmpty ? nil : String(decoding: o.stderr.prefix(2000), as: UTF8.self)
    let any = try? JSONSerialization.jsonObject(with: o.stdout)
    let misfits = Misfits()
    let j = J(any, misfits: misfits)
    if let sig = o.signal {
      return .failed(reason: "immune was stopped by signal \(sig).", detailText: said)
    }
    if j.object != nil, j["ok"].bool == false, let errors = j["errors"].array, !errors.isEmpty {
      return .refused(
        Contract.Failure(operation: j["operation"].string, errors: errors.map(error)),
        exitCode: o.exitCode)
    }
    guard o.exitCode == 0 else {
      return .failed(
        reason: "immune failed with exit code \(o.exitCode.map(String.init) ?? "unknown").",
        detailText: said)
    }
    guard j.object != nil, j["format"].count == Contract.format else {
      return .failed(reason: "immune's answer is not one this app understands.", detailText: said)
    }
    let ref = j["finding"]
    guard ref["id"].string == asked else {
      return .failed(reason: "immune's answer is not the finding that was opened.", detailText: nil)
    }
    guard ref["state"].string != nil, ref["urgent"].bool != nil, j["kind"].string != nil,
      j["title"].string != nil
    else {
      return .failed(
        reason: "immune's answer lacks what a finding is shown with: its state, its urgent"
          + " mark, its kind or its title.", detailText: nil)
    }
    let finding = contractFinding(j)
    // Read whole first, so every field and list entry is looked at: one of another type than
    // the message has makes it a failure, never a smaller card.
    if let path = misfits.paths.first {
      return .failed(
        reason: "immune's answer does not have the shape this app reads at " + path + ".",
        detailText: nil)
    }
    return .read(finding)
  }

  static func error(_ e: J) -> ImmuneError {
    ImmuneError(
      code: e["code"].string, message: e["message"].string, example: e["example"].string,
      detailText: e["detail_text"].string)
  }

  static func contractFinding(_ j: J) -> Contract.Finding {
    Contract.Finding(
      format: j["format"].count, finding: j["finding"].object.map(findingRef),
      kind: j["kind"].string, title: j["title"].string, meaning: j["meaning"].string,
      advice: j["advice"].string, techniqueText: j["technique_text"].string,
      whereText: j["where_text"].string, firstSeenAt: j["first_seen_at"].seconds,
      lastSeenAt: j["last_seen_at"].seconds,
      answer: j["answer"].object.map {
        Contract.Answer(
          given: $0["given"].string, via: $0["via"].string, givenAt: $0["given_at"].seconds,
          reasonText: $0["reason_text"].string, untilAt: $0["until_at"].seconds,
          inForce: $0["in_force"].bool)
      },
      evidence: j["evidence"].object.map(evidence),
      restsOn: (j["rests_on"].array ?? []).compactMap { e in
        e.object.map {
          Contract.JournalEntry(
            seq: $0["seq"].count, recordedAt: $0["recorded_at"].seconds, entry: $0["entry"].string,
            kind: $0["kind"].string, predicate: $0["predicate"].string,
            subjectText: $0["subject_text"].string, oldValueText: $0["old_value_text"].string,
            newValueText: $0["new_value_text"].string)
        }
      },
      verdicts: j["verdicts"].object.map { v in
        Contract.Verdicts(
          total: v["total"].count, suspicious: v["suspicious"].count,
          listed: (v["listed"].array ?? []).compactMap { r in
            r.object.map {
              let verdict = $0["verdict"]
              return Contract.RecordedVerdict(
                kind: verdict["kind"].string, reasonText: verdict["reason_text"].string,
                caseText: verdict["case_text"].string, severity: verdict["severity"].string,
                confidence: verdict["confidence"].string, recordedAt: $0["recorded_at"].seconds)
            }
          },
          verdictFinding: v["verdict_finding"].object.map(findingRef))
      })
  }

  static func findingRef(_ f: J) -> Contract.FindingRef {
    Contract.FindingRef(
      id: f["id"].string, rule: f["rule"].string, aboutText: f["about_text"].string,
      state: f["state"].string, severity: f["severity"].string, confidence: f["confidence"].string,
      urgent: f["urgent"].bool ?? false)
  }

  static func evidence(_ e: J) -> Contract.Evidence {
    if let p = e["place_changed"].object {
      return .placeChanged(change: p["change"].string, presenceOnly: p["presence_only"].bool)
    }
    if let c = e["changed_in_place"].object {
      return .changedInPlace(becameText: c["became_text"].string)
    }
    if let i = e["indicator_matched"].object {
      return .indicatorMatched(indicatorsText: i["indicators_text"].string)
    }
    if let d = e["detached_process"].object {
      return .detachedProcess(pid: d["pid"].count, startMicros: d["start_micros"].count)
    }
    if let v = e["vulnerable_package"].object {
      return .vulnerablePackage(
        Contract.VulnerablePackage(
          projectText: v["project_text"].string, ecosystem: v["ecosystem"].string,
          packageText: v["package_text"].string,
          releases: (v["releases"].array ?? []).map {
            Contract.PackageRelease(
              versionText: $0["version_text"].string, atText: $0["at_text"].string)
          },
          records: (v["records"].array ?? []).map {
            Contract.PackageRecord(
              idText: $0["id_text"].string, source: $0["source"].string, label: $0["label"].string,
              exploited: $0["exploited"].bool, summaryText: $0["summary_text"].string,
              fixedText: $0["fixed_text"].array?.compactMap(\.string) ?? [])
          }))
    }
    if let p = e["published_rule_matched"].object {
      return .publishedRule(
        rule: p["rule"].object.map {
          Contract.Rule(
            name: $0["name"].string, titleText: $0["title_text"].string, level: $0["level"].string,
            techniquesText: $0["techniques_text"].array?.compactMap(\.string) ?? [],
            authorText: $0["author_text"].string, set: $0["set"].string)
        }, matches: p["matches"].count, events: (p["events"].array ?? []).map(event),
        source: p["source"].string)
    }
    if let v = e["verdict_given"].object {
      return .verdictGiven(rule: v["rule"].string, events: (v["events"].array ?? []).map(event))
    }
    let keys = (e.value as? [String: Any])?.keys.sorted() ?? []
    return .other(keys.first ?? "")
  }

  static func event(_ e: J) -> Contract.Event {
    if let s = e["program_start"].object {
      return .programStart(
        Contract.ProgramStart(
          happenedAt: s["happened_at"].seconds,
          executableText: s["process"]["executable_text"].string,
          signingIdText: s["process"]["signing_id_text"].string,
          teamIdText: s["process"]["team_id_text"].string, pid: s["process"]["pid"].count,
          instigatorText: s["instigator"]["executable_text"].string,
          argsText: s["args_text"].array?.compactMap(\.string) ?? [],
          workingDirectoryText: s["working_directory_text"].string,
          scriptText: s["script_text"].string))
    }
    if let f = e["file_event"].object {
      return .fileEvent(
        Contract.FileEvent(
          happenedAt: f["happened_at"].seconds, action: f["action"].string,
          pathText: f["path_text"].string, sourceText: f["source_text"].string,
          instigatorText: f["instigator"]["executable_text"].string,
          signingIdText: f["instigator"]["signing_id_text"].string))
    }
    return .other
  }
}

extension J {
  /// A time of the contract: whole seconds since the epoch, UTC.
  var seconds: Date? { count.map { Date(timeIntervalSince1970: TimeInterval($0)) } }
}
