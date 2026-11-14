// All decoding of what `immune status --json` and `immune watch` print lives in this one file,
// so a change of shape is cheap. The status is the contract's `Status`
// (`contract/immune/v1/status.proto`), a failure its `Failure`. Every field is optional: a
// missing field becomes nil and is shown as "not reported", never as zero or as fine. A field or
// a list entry that is there with another type is not missing: it is recorded (`Misfits`), and
// an answer with one is not read as a smaller valid one: the status says it cannot tell, the
// opened finding fails. Unknown fields are ignored. Times are whole seconds since the epoch.

import Foundation

/// What `immune status --json` printed: the contract's `Status`, or its `Failure`. `ok` is
/// false for a failure, true for an object that is a `Status`, and nil for any other object.
public struct Envelope: Sendable, Equatable {
  public var format: Int?
  public var operation: String?
  public var ok: Bool?
  public var errors: [ImmuneError]
  public var result: Status?
}

public struct ImmuneError: Sendable, Equatable {
  public var code: String?
  public var message: String?
  public var example: String?
  public var detailText: String?
}

public struct Status: Sendable, Equatable {
  public var generatedAt: Date?
  /// A run is in progress now; every other section describes the last finished run.
  public var running: Bool?
  public var store: Store?
  public var lastRun: LastRun?
  public var lastFinishedRun: FinishedRun?
  public var estate: Estate?
  public var watched: Watched?
  public var threats: Threats?
  public var coverage: Coverage?
  public var cannotJudge: [String]?
  public var noReaderFor: [NoReader]?
  public var notComputed: [NotComputed]?
  /// What needs the owner's look, as Immune serves it, urgent first, then most severe; at most 50
  /// of the core's findings and 50 of the response layer's.
  public var needsALook: [Item]?
  public var needsALookTotal: Int?
  /// How many of all of them Immune marked urgent, listed or not.
  public var needsALookUrgent: Int?
  public var answersNote: String?
  /// Whether this Mac is watched, and how.
  public var thisMac: ThisMac?
  /// What the program does not cover, a handful of items in its fixed words.
  public var notCovered: [Uncovered]?
  /// Answers that hide a finding now and were not given in the app.
  public var answeredOutsideApp: AnsweredOutside?
  /// The owner's statements that set a machine aside and were not given in the app.
  public var statementsOutsideApp: StatementsOutside?
  /// Known vulnerabilities in packages the projects use: distinct records that affect
  /// something, each counted once however many projects it affects. Nil from an immune binary that
  /// does not count them.
  public var knownVulnerabilities: Int?
  /// The published detection rules the program ships, and how many of them watch
  /// program starts. Nil from an immune binary that has none.
  public var rules: Rules?
  /// The event level: every program start on this Mac. Nil from an immune binary that has none, or
  /// before it was first looked for.
  public var eventLevel: EventLevel?
  /// The journal's latest sequence number in the store this status was read from: an answer
  /// given on what it shows passes it back as `--journal-seq`. Nil from an Immune that does not
  /// give it.
  public var journalSeq: Int? = nil
  /// Where the answer was not the shape this app reads: a field or a list entry present with
  /// another type, by its path ("result.needs_a_look[0]"). Not empty means the app cannot tell.
  public var misfits: [String] = []
}

/// `result.event_level`, as much as the panel draws: the state, the count of the last
/// day, the same day hour by hour, and Immune's words for it.
public struct EventLevel: Sendable, Equatable {
  /// not_installed, running, refused, failing, silent or failed.
  public var state: String?
  /// Program starts read in the last day.
  public var startsLastDay: Int?
  /// The last day hour by hour, oldest first (`program_starts_by_hour.counts`); nil
  /// unless every one of them is a count.
  public var startsByHour: [Int]?
  /// Immune's short state ("on", "not installed").
  public var stateWords: String?
  /// Immune's caveats, each a sentence: empty means none, nil means not said.
  public var notes: [String]?
  /// The last hour minute by minute, oldest first (`program_starts_by_minute.counts`); nil
  /// unless every one of them is a count.
  public var startsByMinute: [Int]? = nil
  /// Program starts read in the last hour, as Immune counts them.
  public var startsLastHour: Int? = nil
  /// When the level was last read.
  public var readAt: Date? = nil
  /// The same caveats in a few words each ("2 restarts"): empty means none, nil means not
  /// said.
  public var caveats: [Caveat]? = nil
}

/// A caveat as Immune says it in a few words, under a stable name.
public struct Caveat: Sendable, Equatable {
  public var kind: String?
  public var short: String?
}

/// `published_rule` of a finding a published rule raised: the rule's title and authors,
/// and the latest event it matched. Every field is text from a source but `action`.
/// The response layer's leading verdict about a finding, as Immune chooses it. `said` is
/// Immune's fixed words for the finding's verdicts; `reasonText` is the response layer's, data,
/// whole. No verdict closes the finding.
public struct Verdict: Sendable, Equatable {
  /// `suspicious` or `harmless`.
  public var kind: String?
  public var said: String?
  public var reasonText: String?
  /// What Immune cut out of the reason.
  public var reasonCuts: [Contract.Cut] = []
  /// For a finding of the core: how many verdicts name it, how many of them are `suspicious`, and
  /// the id of its `verdict.suspicious` finding while one is open or expected. Nil for a
  /// `verdict.suspicious` finding, and from an Immune that does not give them.
  public var total: Int? = nil
  public var suspicious: Int? = nil
  public var finding: String? = nil
}

public struct PublishedRule: Sendable, Equatable {
  public var titleText: String?
  public var authorText: String?
  /// The latest start: the program, and the program that started it; for a file event, the
  /// program that created or renamed the file.
  public var executableText: String?
  public var parentExecutableText: String?
  /// The latest file event: the file, and Immune's fixed name of what was done, `create` or
  /// `rename`. Absent for a program start.
  public var fileText: String? = nil
  public var action: String? = nil
  /// The latest start's arguments, each whole as Immune gives it but for a secret it cut, which
  /// shows as Immune's mark; nil when not given.
  public var argsText: [String]? = nil
  /// What Immune cut out of them.
  public var cuts: [Contract.Cut] = []
  /// The folder it was started in, and who signed it.
  public var workingDirectoryText: String? = nil
  public var signingIdText: String? = nil
}

/// `result.rules`: how many published rules are shipped, how many are evaluated whole,
/// in part or not at all, and whether they watch program starts now.
public struct Rules: Sendable, Equatable {
  public var shipped: Int?
  public var evaluated: Int?
  public var inPart: Int?
  public var notEvaluated: Int?
  public var watching: Bool?
  /// How many program starts the rules matched in the last day.
  public var matchesLastDay: Int?
}

/// The statements that stand and were given outside the app: Immune's total and the latest.
public struct StatementsOutside: Sendable, Equatable {
  public var total: Int?
  public var items: [StatementItem]
}

/// One statement given outside the app. `*_text` is data.
public struct StatementItem: Sendable, Equatable {
  /// The machine's name, and its full id, which Immune takes back by.
  public var machineText: String?
  public var entityText: String?
  /// `retired` or `not mine`.
  public var said: String?
  /// `agent` or `command`.
  public var via: String?
  public var at: Date?
  public var reasonText: String?
  /// What Immune cut out of the reason.
  public var reasonCuts: [Contract.Cut] = []
}

/// The answers given outside the app that are in force: Immune's total and the latest few.
public struct AnsweredOutside: Sendable, Equatable {
  public var total: Int?
  public var items: [AnsweredItem]
}

/// One answer given outside the app. `title` is Immune's fixed words; `*_text` is data.
public struct AnsweredItem: Sendable, Equatable {
  public var id: String?
  public var title: String?
  /// `seen` or `expected`.
  public var answer: String?
  public var until: Date?
  /// `agent` or `command`.
  public var via: String?
  public var at: Date?
  public var reasonText: String?
  public var whereText: String?
  /// What Immune cut out of the reason.
  public var reasonCuts: [Contract.Cut] = []
}

/// The state of this Mac as Immune judges it.
public struct ThisMac: Sendable, Equatable {
  /// watched, watched_in_part or not_checked.
  public var state: String?
  /// A watcher holds the store: changes show within seconds.
  public var live: Bool?
  /// The last full check.
  public var checkedAt: Date?
  public var watched: [WatchedPart]?
  /// Immune says what it answers is fresh: its last finished check is recent enough. Missing,
  /// or not a boolean, is nil: not said, which is never calm.
  public var fresh: Bool? = nil
  /// Why it is not fresh, in Immune's words.
  public var staleReason: String? = nil
  /// How long after the last full check Immune calls what it knows fresh, in seconds. A status
  /// held longer than that after its check is old, whatever it said when it was read.
  public var freshFor: Int? = nil
}

/// One kind of place on this Mac that is watched: the program's words, how many,
/// and whether live or by the hourly check.
public struct WatchedPart: Sendable, Equatable {
  public var what: String?
  public var count: Int?
  /// live or hourly.
  public var how: String?
}

/// Something the program does not cover, in its fixed words; `*_text` is data.
public struct Uncovered: Sendable, Equatable {
  public var id: String?
  /// this_mac, projects, servers or threats.
  public var scope: String?
  public var kind: String?
  public var title: String?
  public var meaning: String?
  public var advice: String?
  public var count: Int?
  public var since: Date?
  public var valueText: String?
  /// "you" when the owner can change it; anything else, or missing, is nothing for
  /// him to do (a limit of this version, or it resolves by itself).
  public var who: String?
  /// The first few things it is about, such as paths, each as data.
  public var examplesText: [String]? = nil
  /// `every_mac` for a limit of this version that holds on every Mac; anything else, or
  /// missing, is of this Mac and is shown.
  public var holdsOn: String? = nil

  /// A limit of this version, the same on every Mac: left out of what a person is shown.
  public var everyMac: Bool { holdsOn == "every_mac" }
}

/// One thing that needs a look: a finding the owner can answer. (Health items have
/// left this list for `not_covered`; the app still never answers one.)
/// `title`, `meaning` and `advice` are the program's fixed words; `*_text` is data.
public struct Item: Sendable, Equatable {
  public var id: String?
  /// `finding` or `health`.
  public var type: String?
  public var kind: String?
  /// informational, low, medium, high, critical.
  public var severity: String?
  public var state: String?
  public var firstSeen: Date?
  public var lastSeen: Date?
  public var title: String?
  public var meaning: String?
  public var advice: String?
  public var valueText: String?
  public var whereText: String?
  public var rule: String?
  public var confidence: String?
  public var change: String?
  public var technique: String?
  /// Present only for a finding a published rule raised.
  public var publishedRule: PublishedRule?
  /// Present only when the response layer gave a verdict about it.
  public var verdict: Verdict? = nil
  /// Immune decided this needs the owner now, from how bad and how sure. Missing, or
  /// not a boolean, is false: the app never decides it.
  public var urgent = false
  /// `kind` as a person reads it, in Immune's words (`kind_title`); nil from an Immune that does
  /// not give it.
  public var kindTitle: String? = nil
  /// What it is about, in Immune's words, for a finding whose thing no name from the Mac says
  /// (`thing`); nil for every other finding.
  public var thing: String? = nil
}

public struct Store: Sendable, Equatable {
  public var pathText: String?
  public var exists: Bool?
  /// The pages `immune view` writes for sections of its summary, by the section's name
  /// (`view_sections`). Only an absolute path to an HTML file is kept.
  public var viewSections: [String: URL] = [:]
}

public struct LastRun: Sendable, Equatable {
  public var id: String?
  public var startedAt: Date?
  public var finishedAt: Date?
  public var finished: Bool?
}

public struct FinishedRun: Sendable, Equatable {
  public var id: String?
  public var startedAt: Date?
  public var finishedAt: Date?
  public var firstRun: Bool?
  public var readings: RunReadings?
  public var sinceStated: Bool  // false when the key is missing; null is stated
  public var since: SinceRun?
  public var unknown: [String]?
}

public struct RunReadings: Sendable, Equatable {
  public var partial: Int?
  public var failed: Int?
  public var notRepeated: Int?
  public var machinesUnread: Int?
}

public struct SinceRun: Sendable, Equatable {
  public var added: Int?
  public var changed: Int?
  public var removed: Int?
}

public struct Estate: Sendable, Equatable {
  public var machines: Int?
  public var servers: Int?
  public var serversOffered: Int?
  public var serversRead: Int?
  public var machinesSetAside: Int?
  public var machinesSeenAfterOwnerWord: Int?
  public var checkouts: Int?
  public var components: Int?
}

public struct Watched: Sendable, Equatable {
  public var files: Int?
  public var firstReading: Bool?
  public var sinceLastReading: Counts?
  public var kinds: [WatchedKind]?
  public var contentNotRead: Int?
  public var changes: [WatchedChange]?
  public var changesTotal: Int?
}

public struct Counts: Sendable, Equatable {
  public var new: Int?
  public var changed: Int?
  public var gone: Int?
}

public struct WatchedKind: Sendable, Equatable {
  public var kind: String?
  public var files: Int?
  public var coverage: String?
  public var readings: KindReadings?
  public var reasonText: String?
}

public struct KindReadings: Sendable, Equatable {
  public var full: Int?
  public var partial: Int?
  public var none: Int?
}

public struct WatchedChange: Sendable, Equatable {
  public var at: Date?
  public var runId: String?
  public var change: String?
  public var kind: String?
  public var pathText: String?
}

public struct Threats: Sendable, Equatable {
  public var source: String?
  /// `read`, `unchanged`, `failed` or `never_read`.
  public var outcome: String?
  public var entries: Int?
  public var firstReading: Bool?
  public var new: Int?
  public var gone: Int?
  public var matched: Bool?
  public var readAt: Date?
  public var checkedAt: Date?
  public var reasonText: String?
}

public struct Coverage: Sendable, Equatable {
  public var readings: Int?
  public var full: Int?
  public var readNothing: Int?
  public var notGiven: Int?
  public var partial: Int?
  public var failed: Int?
  public var problems: [Problem]?
  public var problemsTotal: Int?
  public var unreached: [Unreached]?
  public var unreachedTotal: Int?
}

/// Readings of one class, reader, kind and reason, counted.
public struct Problem: Sendable, Equatable {
  public var `class`: String?
  public var reader: String?
  public var kind: String?
  public var reasonText: String?
  public var count: Int?
  public var examplesText: [String]?
}

/// A machine whose visit failed.
public struct Unreached: Sendable, Equatable {
  public var scopeText: String?
  public var since: Date?
  public var reasonText: String?
}

/// Something this build has no reader for, and in how many places it was seen.
public struct NoReader: Sendable, Equatable {
  /// The program's fixed words for the kind of thing.
  public var what: String?
  /// A name from the machine, when there is one.
  public var whatText: String?
  public var whereCount: Int?
}

public struct NotComputed: Sendable, Equatable {
  public var section: String?
  public var reason: String?
}

/// One line from `immune watch`.
public enum WatchEvent: Sendable, Equatable {
  /// Subscribed to the watched places.
  case watching(places: Int?)
  /// Re-read the watched places after something changed.
  case read
  /// A sample of running programs opened a finding.
  case sample
  /// A reading of program starts took some or changed the level's state: the level as it
  /// left it, in numbers and Immune's fixed words.
  case programStarts(EventLevel)
  case alive
  /// Something it survived, with what the failure said as text from a source.
  case problem(code: String?, detailText: String? = nil)
  /// It cannot watch: the error envelope it prints before it exits.
  case failure(ImmuneError?)
}

public enum DecodeFailure: Error, Equatable {
  case notJSON
  case notAnObject
}

public enum Decoding {
  /// The envelope format this app understands.
  public static let knownFormat = 1

  /// The status, or the failure printed in its place. An object that is neither is taken as
  /// neither: no result, and `ok` not said.
  public static func envelope(from data: Data) -> Result<Envelope, DecodeFailure> {
    guard let any = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    else { return .failure(.notJSON) }
    guard any is [String: Any] else { return .failure(.notAnObject) }
    let misfits = Misfits()
    let j = J(any, misfits: misfits)
    // The contract's `Failure`: `ok` false and its errors. `ok` is never in a `Status`, so an
    // object with `ok` of any other value is neither.
    if j["ok"].isPresent {
      return .success(
        Envelope(
          format: Self.knownFormat, operation: j["operation"].string,
          ok: j["ok"].bool == false ? false : nil, errors: (j["errors"].array ?? []).map(error),
          result: nil))
    }
    // Only the message asked for is a status: anything else, such as a `Finding`, is not read
    // as an empty one.
    guard isStatus(j) else {
      return .success(
        Envelope(format: j["format"].count, operation: nil, ok: nil, errors: [], result: nil))
    }
    var status = status(j)
    // Errors beside a status, which the contract never prints, are kept so the app says it
    // cannot tell. Read after the status, so a misfit anywhere is recorded.
    let errors = (j["errors"].array ?? []).map(error)
    status.misfits = misfits.paths
    return .success(
      Envelope(format: j["format"].count, operation: nil, ok: true, errors: errors, result: status))
  }

  /// A `Status`: of a format, answered at a time, with its store. Anything else, such as a
  /// `Finding`, is not taken for one.
  static func isStatus(_ j: J) -> Bool {
    j["format"].count != nil && j["answered_at"].int64 != nil && j["store"].object != nil
  }

  /// One line of `immune watch`, or nil when it is not understood.
  public static func watchLine(_ data: Data) -> WatchEvent? {
    guard let any = try? JSONSerialization.jsonObject(with: data),
      any is [String: Any]
    else { return nil }
    let j = J(any)
    guard j["format"].count == knownFormat else { return nil }
    if j["ok"].bool == false {
      let e = j["errors"].array?.first.map {
        ImmuneError(
          code: $0["code"].string, message: $0["message"].string,
          example: $0["example"].string, detailText: $0["detail_text"].string)
      }
      return .failure(e)
    }
    switch j["event"].string {
    case "watching": return .watching(places: j["places"].count)
    case "read": return .read
    case "sample": return .sample
    case "program_starts": return .programStarts(programStarts(j))
    case "alive": return .alive
    // `immune watch` as built puts the code beside `event`; a nested `problem` object is
    // read too, so either shape is understood.
    case "problem":
      return .problem(
        code: j["problem"]["code"].string ?? j["code"].string,
        detailText: j["problem"]["detail_text"].string ?? j["detail_text"].string)
    default: return nil
    }
  }

  static func status(_ r: J) -> Status {
    let look = r["needs_a_look"].object
    return Status(
      generatedAt: r["answered_at"].seconds,
      running: r["running"].bool,
      store: r["store"].object.map {
        Store(
          pathText: $0["path_text"].string, exists: $0["exists"].bool,
          viewSections: Dictionary(
            ($0["view_sections"].array ?? []).compactMap { s in
              guard let name = s["section"].string,
                let path = s["path_text"].string.flatMap(AppModel.htmlFile)
              else { return nil }
              return (name, path)
            }, uniquingKeysWith: { first, _ in first }))
      },
      lastRun: r["last_run"].object.map(checkMark),
      lastFinishedRun: r["last_finished_run"].object.map(finishedRun),
      estate: r["estate"].object.map {
        Estate(
          machines: $0["machines"].count, servers: $0["servers"].count,
          serversOffered: $0["servers_offered"].count, serversRead: $0["servers_read"].count,
          machinesSetAside: $0["machines_set_aside"].count,
          machinesSeenAfterOwnerWord: $0["machines_seen_after_owner_word_text"].array?.count,
          checkouts: $0["checkouts"].count, components: $0["components"].count)
      },
      watched: r["watched"].object.map(watched),
      threats: r["threats"].object.map {
        Threats(
          source: $0["source"].string, outcome: $0["outcome"].string,
          entries: $0["entries"].count, firstReading: $0["first_reading"].bool,
          new: $0["new"].count, gone: $0["gone"].count, matched: $0["matched"].bool,
          readAt: $0["read_at"].seconds, checkedAt: $0["checked_at"].seconds,
          reasonText: $0["reason_text"].string)
      },
      coverage: r["coverage"].object.map(coverage),
      cannotJudge: r["cannot_judge"].array?.compactMap(\.string),
      noReaderFor: r["no_reader_for"]["items"].array?.compactMap { n in
        n.object.map {
          NoReader(
            what: $0["what"].string, whatText: $0["what_text"].string,
            whereCount: $0["where_count"].count)
        }
      },
      notComputed: r["not_computed"].array?.compactMap { n in
        n.object.map { NotComputed(section: $0["section"].string, reason: $0["reason"].string) }
      },
      needsALook: look?["items"].array?.compactMap { i in i.object.map(item) },
      needsALookTotal: look?["total"].count,
      needsALookUrgent: look?["urgent_total"].count,
      answersNote: r["answers_note"].string,
      thisMac: r["this_mac"].object.map { m in
        ThisMac(
          state: m["state"].string, live: m["live"].bool, checkedAt: m["checked_at"].seconds,
          watched: m["watched"].array?.compactMap { w in
            w.object.map {
              WatchedPart(what: $0["what"].string, count: $0["count"].count, how: $0["how"].string)
            }
          }, fresh: m["fresh"].bool, staleReason: m["stale_reason"].string,
          freshFor: m["fresh_for_seconds"].count)
      },
      notCovered: r["not_covered"].array?.compactMap { n in
        n.object.map {
          Uncovered(
            id: $0["id"].string, scope: $0["scope"].string, kind: $0["kind"].string,
            title: $0["title"].string, meaning: $0["meaning"].string, advice: $0["advice"].string,
            count: $0["count"].count, since: $0["since_at"].seconds,
            valueText: $0["value_text"].string, who: $0["who"].string,
            examplesText: $0["examples_text"].array?.compactMap(\.string),
            holdsOn: $0["holds_on"].string)
        }
      },
      answeredOutsideApp: r["answered_outside_app"].object.map { a in
        AnsweredOutside(
          total: a["total"].count,
          items: (a["items"].array ?? []).compactMap { i in
            i.object.map {
              AnsweredItem(
                id: $0["finding"]["id"].string, title: $0["title"].string,
                answer: $0["answer"]["given"].string, until: $0["answer"]["until_at"].seconds,
                via: $0["answer"]["via"].string, at: $0["answer"]["given_at"].seconds,
                reasonText: $0["answer"]["reason_text"].string, whereText: $0["where_text"].string,
                reasonCuts: cuts($0["answer"]["reason_cuts"]))
            }
          })
      },
      statementsOutsideApp: r["statements_outside_app"].object.map { a in
        StatementsOutside(
          total: a["total"].count,
          items: (a["items"].array ?? []).compactMap { i in
            i.object.map {
              StatementItem(
                machineText: $0["machine_text"].string, entityText: $0["entity_text"].string,
                said: $0["said"].string, via: $0["via"].string, at: $0["at"].seconds,
                reasonText: $0["reason_text"].string, reasonCuts: cuts($0["reason_cuts"]))
            }
          })
      },
      knownVulnerabilities: r["vulnerabilities"]["affected_records"].count,
      rules: r["rules"].object.map {
        Rules(
          shipped: $0["shipped"].count, evaluated: $0["evaluated"].count,
          inPart: $0["in_part"].count, notEvaluated: $0["not_evaluated"].count,
          watching: $0["watching"].bool, matchesLastDay: $0["matches_last_day"].count)
      },
      eventLevel: r["event_level"].object.map(eventLevel),
      journalSeq: r["journal_seq"].int64)
  }

  static func checkMark(_ c: J) -> LastRun {
    LastRun(
      id: c["id"].string, startedAt: c["started_at"].seconds, finishedAt: c["finished_at"].seconds,
      finished: c["finished_at"].int64 != nil)
  }

  static func eventLevel(_ e: J) -> EventLevel {
    EventLevel(
      state: e["state"].string, startsLastDay: e["program_starts"]["last_day"].count,
      startsByHour: counts(e["program_starts_by_hour"]["counts"]),
      stateWords: e["in_words"]["state"].string,
      notes: e["in_words"]["notes"].array.map { $0.compactMap(\.string) },
      startsByMinute: counts(e["program_starts_by_minute"]["counts"]),
      startsLastHour: counts(e["program_starts_by_minute"]["counts"])?.reduce(0, +),
      readAt: e["read_at"].seconds,
      caveats: caveats(e["in_words"]["caveats"]))
  }

  /// A series of counts, or nil unless every one is a count.
  static func counts(_ a: J) -> [Int]? {
    let all = a.array
    let counts = all?.compactMap(\.count)
    return counts?.count == all?.count ? counts : nil
  }

  static func caveats(_ a: J) -> [Caveat]? {
    a.array.map { $0.map { Caveat(kind: $0["kind"].string, short: $0["short"].string) } }
  }

  /// The `program_starts` line of `immune watch`: the level as that reading left it, as far as
  /// the line says it; what it does not say (the day by the hour, the caveats' sentences) is
  /// nil.
  static func programStarts(_ j: J) -> EventLevel {
    EventLevel(
      state: j["state"].string, startsLastDay: j["program_starts_last_day"].count,
      startsByHour: nil, stateWords: j["in_words"]["state"].string, notes: nil,
      startsByMinute: counts(j["program_starts_by_minute"]["counts"]),
      startsLastHour: j["program_starts_by_minute"]["last_hour"].count,
      readAt: j["read_at"].date,
      caveats: caveats(j["in_words"]["caveats"]))
  }

  /// One `LookFinding`: the finding as listed, and its words and evidence. Every item of
  /// `needs_a_look` is a finding. Of its evidence the row reads only what it shows, a published
  /// rule and the latest event it matched, so only a misfit there is one of the status; the
  /// rest is read, and a misfit in it told, on the card that shows it.
  static func item(_ i: J) -> Item {
    let listed = i["finding"]
    let ref = listed["finding"]
    let matched = i["evidence"]["published_rule_matched"]
    let latest: Contract.Event? = matched["events"].array?.first.map(event)
    let rule = matched["rule"]
    let verdicts = listed["verdicts"].object
    let first = verdicts?["listed"].array?.first?["verdict"]
    return Item(
      id: ref["id"].string, type: listed.object == nil ? nil : "finding",
      kind: listed["kind"].string, severity: ref["severity"].string, state: ref["state"].string,
      firstSeen: listed["first_seen_at"].seconds, lastSeen: listed["last_seen_at"].seconds,
      title: listed["title"].string, meaning: i["meaning"].string, advice: i["advice"].string,
      valueText: i["value_text"].string, whereText: listed["where_text"].string,
      rule: ref["rule"].string, confidence: ref["confidence"].string, change: i["change"].string,
      technique: i["technique_text"].string,
      publishedRule: rule.object.map {
        var p = PublishedRule(
          titleText: $0["title_text"].string, authorText: $0["author_text"].string,
          executableText: nil, parentExecutableText: nil)
        switch latest {
        case .programStart(let s)?:
          p.executableText = s.executableText
          p.parentExecutableText = s.instigatorText
          p.argsText = s.argsText
          p.cuts = s.cuts
          p.workingDirectoryText = s.workingDirectoryText
          p.signingIdText = s.signingIdText
        case .fileEvent(let f)?:
          p.executableText = f.instigatorText
          p.fileText = f.pathText
          p.action = f.action
          p.signingIdText = f.signingIdText
        default: break
        }
        return p
      },
      verdict: verdicts.map {
        Verdict(
          kind: first?["kind"].string, said: nil, reasonText: first?["reason_text"].string,
          reasonCuts: cuts(verdicts?["listed"].array?.first?["reason_cuts"] ?? J(nil)),
          total: $0["total"].count, suspicious: $0["suspicious"].count,
          finding: $0["verdict_finding"]["id"].string)
      },
      urgent: ref["urgent"].bool ?? false, kindTitle: listed["kind_title"].string,
      thing: listed["thing"].string)
  }

  static func finishedRun(_ f: J) -> FinishedRun {
    FinishedRun(
      id: f["check"]["id"].string, startedAt: f["check"]["started_at"].seconds,
      finishedAt: f["check"]["finished_at"].seconds,
      firstRun: f["first_run"].bool,
      readings: f["readings"].object.map {
        RunReadings(
          partial: $0["partial"].count, failed: $0["failed"].count,
          notRepeated: $0["not_repeated"].count, machinesUnread: $0["machines_unread"].count)
      },
      sinceStated: f["since_previous_run"].isPresent,
      since: f["since_previous_run"].object.map {
        SinceRun(
          added: $0["added"].count, changed: $0["changed"].count, removed: $0["removed"].count)
      },
      unknown: f["unknown"].array?.compactMap(\.string))
  }

  static func watched(_ w: J) -> Watched {
    Watched(
      files: w["files"].count,
      firstReading: w["first_reading"].bool,
      sinceLastReading: w["since_last_reading"].object.map {
        Counts(new: $0["new"].count, changed: $0["changed"].count, gone: $0["gone"].count)
      },
      kinds: w["kinds"].array?.compactMap { k in
        k.object.map {
          WatchedKind(
            kind: $0["kind"].string, files: $0["files"].count, coverage: $0["coverage"].string,
            readings: $0["readings"].object.map {
              KindReadings(
                full: $0["full"].count, partial: $0["partial"].count, none: $0["none"].count)
            },
            reasonText: $0["reason_text"].string)
        }
      },
      contentNotRead: w["content_not_read"].count,
      changes: w["changes"].array?.compactMap { c in
        c.object.map {
          WatchedChange(
            at: $0["at"].seconds, runId: $0["run_id"].string, change: $0["change"].string,
            kind: $0["kind"].string, pathText: $0["path_text"].string)
        }
      },
      changesTotal: w["changes_total"].count)
  }

  static func coverage(_ c: J) -> Coverage {
    Coverage(
      readings: c["readings"].count, full: c["full"].count, readNothing: c["read_nothing"].count,
      notGiven: c["not_given"].count, partial: c["partial"].count, failed: c["failed"].count,
      problems: c["problems"].array?.compactMap { p in
        p.object.map {
          Problem(
            class: $0["class"].string, reader: $0["reader"].string, kind: $0["kind"].string,
            reasonText: $0["reason_text"].string, count: $0["count"].count,
            examplesText: $0["examples_text"].array?.compactMap(\.string))
        }
      },
      problemsTotal: c["problems_total"].count,
      unreached: c["unreached"].array?.compactMap { u in
        u.object.map {
          Unreached(
            scopeText: $0["scope_text"].string, since: $0["since_at"].seconds,
            reasonText: $0["reason_text"].string)
        }
      },
      unreachedTotal: c["unreached_total"].count)
  }
}

/// The places in one answer where a value was there with another type than the one read.
final class Misfits {
  private(set) var paths: [String] = []
  func note(_ path: String) {
    if !paths.contains(path) { paths.append(path) }
  }
}

/// A view of one JSON value that answers nil for anything missing or of another type. Every
/// field and every list entry the app reads goes through these accessors, so the one rule holds
/// for all of them: a value that is there with another type is recorded in `misfits`, and is
/// never taken for one that is missing. A field that is null is missing; an entry of a list
/// that is null is not, since a list has no missing entries.
struct J {
  let value: Any?
  let path: String
  let misfits: Misfits?
  let inList: Bool

  init(_ value: Any?, path: String = "", misfits: Misfits? = nil, inList: Bool = false) {
    self.value = value
    self.path = path
    self.misfits = misfits
    self.inList = inList
  }

  /// There is a value to read: present, and not a null field.
  private var given: Bool { value != nil && (inList || !(value is NSNull)) }

  /// Answers nil, and records the value when it is there with another type.
  private func misfit<T>() -> T? {
    if given { misfits?.note(path.isEmpty ? "the answer" : path) }
    return nil
  }

  subscript(_ key: String) -> J {
    let child = path.isEmpty ? key : path + "." + key
    guard let o = value as? [String: Any] else {
      let _: J? = misfit()
      return J(nil, path: child, misfits: misfits)
    }
    return J(o[key], path: child, misfits: misfits)
  }

  /// The key is there, even with the value null.
  var isPresent: Bool { value != nil }
  /// Present only when the value is a JSON object.
  var object: J? { value is [String: Any] ? self : misfit() }
  var array: [J]? {
    guard let a = value as? [Any] else { return misfit() }
    return a.enumerated().map {
      J($0.element, path: path + "[\($0.offset)]", misfits: misfits, inList: true)
    }
  }
  var string: String? { value as? String ?? misfit() }

  /// JSON `true`/`false` only: the numbers 0 and 1 are not booleans.
  var bool: Bool? {
    guard let n = value as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else {
      return misfit()
    }
    return n.boolValue
  }

  /// The largest whole number JSON carries exactly: 2^53.
  static let wholeLimit: Double = 9_007_199_254_740_992

  /// A whole number up to 2^53 either way, as a JSON number carries an `int64` of the schema:
  /// a time, a pid, a start in microseconds. Booleans and fractions are not.
  var int64: Int? {
    guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else {
      return misfit()
    }
    let d = n.doubleValue
    guard abs(d) <= Self.wholeLimit, d.rounded() == d else { return misfit() }
    return Int(d)
  }

  /// A `uint64` or `uint32` of the schema: a whole number from 0 up to 2^53. Negatives are not
  /// counts.
  var count: Int? {
    guard let n = int64 else { return nil }
    return n >= 0 ? n : misfit()
  }

  /// An RFC 3339 time, with or without fractional seconds.
  var date: Date? {
    guard let s = string else { return nil }
    let plain = ISO8601DateFormatter()
    if let d = plain.date(from: s) { return d }
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fractional.date(from: s) ?? misfit()
  }
}
