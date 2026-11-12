// All decoding of what `soc ... --json` prints lives in this one file, so a change
// of shape is cheap. Every field is optional: a missing or mistyped field becomes
// nil and is shown as "not reported", never as zero or as fine. Unknown fields are
// ignored. The shape is the one `src/status.rs` writes.

import Foundation

public struct Envelope: Sendable, Equatable {
  public var format: Int?
  public var operation: String?
  public var ok: Bool?
  public var errors: [SocError]
  public var result: Status?
}

public struct SocError: Sendable, Equatable {
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
  /// What needs the owner's look, as soc serves it, most severe first; at most 50.
  public var needsALook: [Item]?
  public var needsALookTotal: Int?
  public var answersNote: String?
  /// Whether this Mac is watched, and how.
  public var thisMac: ThisMac?
  /// What the program does not cover, a handful of items in its fixed words.
  public var notCovered: [Uncovered]?
  public var notCoveredTotal: Int?
  /// Answers that hide a finding now and were not given in the app.
  public var answeredOutsideApp: AnsweredOutside?
  /// The owner's statements that set a machine aside and were not given in the app.
  public var statementsOutsideApp: StatementsOutside?
  /// Known vulnerabilities in packages the projects use: distinct records that affect
  /// something, each counted once however many projects it affects. Nil from a soc that
  /// does not count them.
  public var knownVulnerabilities: Int?
  /// The published detection rules the program ships, and how many of them watch
  /// program starts. Nil from a soc that has none.
  public var rules: Rules?
}

/// `result.rules`: how many published rules are shipped, how many are evaluated whole,
/// in part or not at all, and whether they watch program starts now.
public struct Rules: Sendable, Equatable {
  public var shipped: Int?
  public var evaluated: Int?
  public var inPart: Int?
  public var notEvaluated: Int?
  public var watching: Bool?
}

/// The statements that stand and were given outside the app: soc's total and the latest.
public struct StatementsOutside: Sendable, Equatable {
  public var total: Int?
  public var items: [StatementItem]
}

/// One statement given outside the app. `*_text` is data.
public struct StatementItem: Sendable, Equatable {
  /// The machine's name, and its full id, which soc takes back by.
  public var machineText: String?
  public var entityText: String?
  /// `retired` or `not mine`.
  public var said: String?
  /// `agent` or `command`.
  public var via: String?
  public var at: Date?
  public var reasonText: String?
}

/// The answers given outside the app that are in force: soc's total and the latest few.
public struct AnsweredOutside: Sendable, Equatable {
  public var total: Int?
  public var items: [AnsweredItem]
}

/// One answer given outside the app. `title` is soc's fixed words; `*_text` is data.
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
}

/// The state of this Mac as soc judges it.
public struct ThisMac: Sendable, Equatable {
  /// watched, watched_in_part or not_checked.
  public var state: String?
  /// A watcher holds the store: changes show within seconds.
  public var live: Bool?
  /// The last full check.
  public var checkedAt: Date?
  public var watched: [WatchedPart]?
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
  /// soc decided this needs the owner now, from how bad and how sure. Missing, or
  /// not a boolean, is false: the app never decides it.
  public var urgent = false
}

public struct Store: Sendable, Equatable {
  public var pathText: String?
  public var exists: Bool?
  /// The pages `soc view` writes for sections of its summary, by the section's name
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

/// One line from `soc watch`.
public enum WatchEvent: Sendable, Equatable {
  /// Subscribed to the watched places.
  case watching(places: Int?)
  /// Re-read the watched places after something changed.
  case read
  /// A sample of running programs opened a finding.
  case sample
  case alive
  /// Something it survived, with what the failure said as text from a source.
  case problem(code: String?, detailText: String? = nil)
  /// It cannot watch: the error envelope it prints before it exits.
  case failure(SocError?)
}

public enum DecodeFailure: Error, Equatable {
  case notJSON
  case notAnObject
}

public enum Decoding {
  /// The envelope format this app understands.
  public static let knownFormat = 1

  public static func envelope(from data: Data) -> Result<Envelope, DecodeFailure> {
    guard let any = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    else { return .failure(.notJSON) }
    guard any is [String: Any] else { return .failure(.notAnObject) }
    let j = J(any)
    return .success(
      Envelope(
        format: j["format"].count,
        operation: j["operation"].string,
        ok: j["ok"].bool,
        errors: (j["errors"].array ?? []).map {
          SocError(
            code: $0["code"].string, message: $0["message"].string,
            example: $0["example"].string, detailText: $0["detail_text"].string)
        },
        result: j["result"].object.map(status)
      ))
  }

  /// One line of `soc watch`, or nil when it is not understood.
  public static func watchLine(_ data: Data) -> WatchEvent? {
    guard let any = try? JSONSerialization.jsonObject(with: data),
      any is [String: Any]
    else { return nil }
    let j = J(any)
    guard j["format"].count == knownFormat else { return nil }
    if j["ok"].bool == false {
      let e = j["errors"].array?.first.map {
        SocError(
          code: $0["code"].string, message: $0["message"].string,
          example: $0["example"].string, detailText: $0["detail_text"].string)
      }
      return .failure(e)
    }
    switch j["event"].string {
    case "watching": return .watching(places: j["places"].count)
    case "read": return .read
    case "sample": return .sample
    case "alive": return .alive
    // `soc watch` as built puts the code beside `event`; a nested `problem` object is
    // read too, so either shape is understood.
    case "problem":
      return .problem(
        code: j["problem"]["code"].string ?? j["code"].string,
        detailText: j["problem"]["detail_text"].string ?? j["detail_text"].string)
    default: return nil
    }
  }

  static func status(_ r: J) -> Status {
    Status(
      generatedAt: r["generated_at"].date,
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
      lastRun: r["last_run"].object.map {
        LastRun(
          id: $0["id"].string, startedAt: $0["started_at"].date,
          finishedAt: $0["finished_at"].date, finished: $0["finished"].bool)
      },
      lastFinishedRun: r["last_finished_run"].object.map(finishedRun),
      estate: r["estate"].object.map {
        Estate(
          machines: $0["machines"].count, servers: $0["servers"].count,
          serversOffered: $0["servers_offered"].count, serversRead: $0["servers_read"].count,
          machinesSetAside: $0["machines_set_aside"].count,
          machinesSeenAfterOwnerWord: $0["machines_seen_after_owner_word"].count,
          checkouts: $0["checkouts"].count, components: $0["components"].count)
      },
      watched: r["watched"].object.map(watched),
      threats: r["threats"].object.map {
        Threats(
          source: $0["source"].string, outcome: $0["outcome"].string,
          entries: $0["entries"].count, firstReading: $0["first_reading"].bool,
          new: $0["new"].count, gone: $0["gone"].count, matched: $0["matched"].bool,
          readAt: $0["read_at"].date, checkedAt: $0["checked_at"].date,
          reasonText: $0["reason_text"].string)
      },
      coverage: r["coverage"].object.map(coverage),
      cannotJudge: r["cannot_judge"].array?.compactMap(\.string),
      noReaderFor: r["no_reader_for"].array?.compactMap { n in
        n.object.map {
          NoReader(
            what: $0["what"].string, whatText: $0["what_text"].string,
            whereCount: $0["where_count"].count)
        }
      },
      notComputed: r["not_computed"].array?.compactMap { n in
        n.object.map { NotComputed(section: $0["section"].string, reason: $0["reason"].string) }
      },
      needsALook: r["needs_a_look"].array?.compactMap { i in i.object.map(item) },
      needsALookTotal: r["needs_a_look_total"].count,
      answersNote: r["answers_note"].string,
      thisMac: r["this_mac"].object.map { m in
        ThisMac(
          state: m["state"].string, live: m["live"].bool, checkedAt: m["checked_at"].date,
          watched: m["watched"].array?.compactMap { w in
            w.object.map {
              WatchedPart(what: $0["what"].string, count: $0["count"].count, how: $0["how"].string)
            }
          })
      },
      notCovered: r["not_covered"].array?.compactMap { n in
        n.object.map {
          Uncovered(
            id: $0["id"].string, scope: $0["scope"].string, kind: $0["kind"].string,
            title: $0["title"].string, meaning: $0["meaning"].string, advice: $0["advice"].string,
            count: $0["count"].count, since: $0["since"].date, valueText: $0["value_text"].string,
            who: $0["who"].string)
        }
      },
      notCoveredTotal: r["not_covered_total"].count,
      answeredOutsideApp: r["answered_outside_app"].object.map { a in
        AnsweredOutside(
          total: a["total"].count,
          items: (a["items"].array ?? []).compactMap { i in
            i.object.map {
              AnsweredItem(
                id: $0["id"].string, title: $0["title"].string, answer: $0["answer"].string,
                until: $0["until"].date, via: $0["via"].string, at: $0["at"].date,
                reasonText: $0["reason_text"].string, whereText: $0["where_text"].string)
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
                said: $0["said"].string, via: $0["via"].string, at: $0["at"].date,
                reasonText: $0["reason_text"].string)
            }
          })
      },
      knownVulnerabilities: r["vulnerabilities"]["affected_records"].count,
      rules: r["rules"].object.map {
        Rules(
          shipped: $0["shipped"].count, evaluated: $0["evaluated"].count,
          inPart: $0["in_part"].count, notEvaluated: $0["not_evaluated"].count,
          watching: $0["watching"].bool)
      })
  }

  static func item(_ i: J) -> Item {
    Item(
      id: i["id"].string, type: i["type"].string, kind: i["kind"].string,
      severity: i["severity"].string, state: i["state"].string, firstSeen: i["first_seen"].date,
      lastSeen: i["last_seen"].date, title: i["title"].string, meaning: i["meaning"].string,
      advice: i["advice"].string, valueText: i["value_text"].string,
      whereText: i["where_text"].string, rule: i["rule"].string,
      confidence: i["confidence"].string, change: i["change"].string,
      technique: i["technique"].string, urgent: i["urgent"].bool ?? false)
  }

  static func finishedRun(_ f: J) -> FinishedRun {
    FinishedRun(
      id: f["id"].string, startedAt: f["started_at"].date, finishedAt: f["finished_at"].date,
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
            at: $0["at"].date, runId: $0["run_id"].string, change: $0["change"].string,
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
            scopeText: $0["scope_text"].string, since: $0["since"].date,
            reasonText: $0["reason_text"].string)
        }
      },
      unreachedTotal: c["unreached_total"].count)
  }
}

/// A view of one JSON value that answers nil for anything missing or of another type.
struct J {
  let value: Any?
  init(_ value: Any?) { self.value = value }

  subscript(_ key: String) -> J { J((value as? [String: Any])?[key]) }

  /// The key is there, even with the value null.
  var isPresent: Bool { value != nil }
  /// Present only when the value is a JSON object.
  var object: J? { value is [String: Any] ? self : nil }
  var array: [J]? { (value as? [Any])?.map(J.init) }
  var string: String? { value as? String }

  /// JSON `true`/`false` only: the numbers 0 and 1 are not booleans.
  var bool: Bool? {
    guard let n = value as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }
    return n.boolValue
  }

  /// A whole, non-negative number. Booleans, fractions and negatives are not counts.
  var count: Int? {
    guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
    let d = n.doubleValue
    guard d >= 0, d <= 1e15, d.rounded() == d else { return nil }
    return Int(d)
  }

  /// An RFC 3339 time, with or without fractional seconds.
  var date: Date? {
    guard let s = string else { return nil }
    let plain = ISO8601DateFormatter()
    if let d = plain.date(from: s) { return d }
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fractional.date(from: s)
  }
}
