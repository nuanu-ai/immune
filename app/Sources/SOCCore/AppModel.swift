// The app's only state: the latest reading of `soc status --json`, and whether a
// run started from the app is in progress. No logic of the program lives here.

import Combine
import Foundation

@MainActor
public final class AppModel: ObservableObject {
  public static let statusTimeout: TimeInterval = 30
  public static let runTimeout: TimeInterval = 30 * 60
  public static let viewTimeout: TimeInterval = 60
  public static let answerTimeout: TimeInterval = 60

  @Published public private(set) var reading: Reading = .notYetRead
  @Published public private(set) var readAt: Date?
  @Published public private(set) var refreshing = false
  /// A run started from this app is in progress.
  @Published public private(set) var runInProgress = false
  /// Why the last run started from the app failed, in the app's words plus what
  /// soc said (inert). Cleared when the next run starts.
  @Published public private(set) var runFailure: String?
  /// What happened to the last press of Run now when it was not a failure.
  @Published public private(set) var runNote: String?
  /// The program's page is being written and opened by `soc view`.
  @Published public private(set) var pageOpening = false
  /// Why the page could not be opened, in plain words. Cleared on the next try.
  @Published public private(set) var pageFailure: String?
  /// The "Expected…" form, open on one finding's card, or nil.
  @Published public var form: ExpectedForm?
  /// The id of the finding whose answer is being saved now.
  @Published public private(set) var answering: String?
  /// Why soc did not take the last answer to a finding, by its id, in plain words.
  @Published public private(set) var refusals: [String: String] = [:]

  private let soc: any SocRunning
  private let launchedAt: Date
  /// When the app last started a check by itself.
  private var lastAutoCheck: Date?
  /// Appended to every command; empty except in trials (`--store <path>`).
  private let extraArguments: [String]

  public init(soc: any SocRunning, extraArguments: [String] = [], launchedAt: Date = Date()) {
    self.soc = soc
    self.extraArguments = extraArguments
    self.launchedAt = launchedAt
  }

  /// The full check every hour while the app is open. Called on a timer and after
  /// the Mac wakes; starts a check only when `HourlyCheck.isDue` says so. Returns
  /// whether it started one.
  @discardableResult
  public func checkIfDue(now: Date = Date()) async -> Bool {
    let due = HourlyCheck.isDue(
      known: reading != .notYetRead,
      lastFinished: reading.status?.lastFinishedRun?.finishedAt,
      lastAutoCheck: lastAutoCheck, launchedAt: launchedAt, now: now,
      running: !canRun)
    guard due else { return false }
    lastAutoCheck = now
    return await runNow()
  }

  public var light: Light { Light.of(reading) }

  /// soc said a run is in progress, started here or anywhere else.
  public var socSaysRunning: Bool { reading.status?.running == true }

  public var canRun: Bool { !runInProgress && !socSaysRunning }

  /// Runs `soc status --json`. Not while another refresh is in flight, and not
  /// while a run started here is in progress: the run refreshes when it ends.
  public func refresh() async {
    guard !runInProgress, !refreshing else { return }
    refreshing = true
    let out = await soc.run(["status", "--json"] + extraArguments, timeout: Self.statusTimeout)
    reading = Interpret.reading(from: out)
    readAt = Date()
    refreshing = false
  }

  /// Runs `soc run --json`, then refreshes. Returns false, and starts nothing,
  /// when a run is in progress, here or as soc last said.
  @discardableResult
  public func runNow() async -> Bool {
    guard canRun else { return false }
    runInProgress = true
    runFailure = nil
    runNote = nil
    let out = await soc.run(["run", "--json"] + extraArguments, timeout: Self.runTimeout)
    if Self.otherRunInProgress(out) {
      runNote = "A check was already running; its result will show when it ends."
    } else if case .failed(let reason, let detail, _) = Interpret.reading(from: out) {
      runFailure = reason + (detail.map { " " + Inert.text($0) } ?? "")
    }
    runInProgress = false
    await refresh()
    return true
  }

  /// Details: `soc view` writes the program's own page and opens it. The app opens
  /// no window of its own and builds no path or URL. Returns false, and starts
  /// nothing, while the page is already being opened. A failure is a plain line and
  /// never changes what the icon says.
  @discardableResult
  public func openPage(at id: String? = nil) async -> Bool {
    guard !pageOpening else { return false }
    pageOpening = true
    pageFailure = nil
    let out = await soc.run(
      Self.viewArguments(at: id) + extraArguments, timeout: Self.viewTimeout)
    if out.exitCode != 0 {
      pageFailure = "Details could not be opened. " + Self.viewFailure(out)
    }
    pageOpening = false
    return true
  }

  /// The seam for opening the page at one item: today `soc view` takes no item,
  /// so the item's id is not passed yet.
  static func viewArguments(at id: String?) -> [String] { ["view"] }

  static func viewFailure(_ out: SocOutput) -> String {
    if out.launchFailure != nil { return "The program could not be started." }
    if out.timedOut { return "The program did not finish in time." }
    let said = String(decoding: out.stderr.prefix(300), as: UTF8.self)
      .split(separator: "\n").first.map(String.init)
    return said.map { "The program said: " + Inert.text($0, limit: 200) }
      ?? "The program reported a problem."
  }

  /// The owner's "Seen" on a finding: `soc finding <id> seen`, then a refresh.
  /// Returns false, and runs nothing, for an id the app does not pass or while
  /// another answer is being saved.
  @discardableResult
  public func answerSeen(_ id: String) async -> Bool {
    guard let args = Answer.seenArguments(id: id) else { return false }
    return await answer(id, args)
  }

  /// The owner's "Expected…" on a finding, from the open form: `soc finding <id>
  /// expected --reason <reason> --days <n>`, then a refresh. Returns false, and runs
  /// nothing, unless the form is complete.
  @discardableResult
  public func answerExpected(_ form: ExpectedForm) async -> Bool {
    guard let args = Answer.expectedArguments(id: form.id, reason: form.reason, days: form.days)
    else { return false }
    return await answer(form.id, args)
  }

  private func answer(_ id: String, _ args: [String]) async -> Bool {
    // Only a finding the panel shows takes an answer; a health item never does.
    let shown = reading.status?.needsALook ?? []
    guard answering == nil, shown.contains(where: { $0.id == id && $0.type == "finding" })
    else { return false }
    answering = id
    refusals[id] = nil
    let out = await soc.run(args + extraArguments, timeout: Self.answerTimeout)
    // Saved only when soc finished by itself with 0: a timed-out soc may still exit 0.
    if out.exitCode == 0, !out.timedOut {
      if form?.id == id { form = nil }
    } else {
      refusals[id] = Answer.refusal(out)
    }
    answering = nil
    await refresh()
    return true
  }

  /// The plain lines the panel shows about the last Check now and Details.
  public var notes: [String] {
    [runFailure.map { "The last check could not finish. " + $0 }, runNote, pageFailure].compactMap {
      $0
    }
  }

  /// soc refused to start because a run is already in progress: not a failure.
  static func otherRunInProgress(_ out: SocOutput) -> Bool {
    guard case .success(let env) = Decoding.envelope(from: out.stdout) else { return false }
    return env.ok == false && env.errors.contains { $0.code == "run_in_progress" }
  }
}

/// When the app starts a full check by itself.
public enum HourlyCheck {
  public static let every: TimeInterval = 3600
  /// The first check waits this long after launch, so the app settles first.
  public static let afterLaunch: TimeInterval = 60

  /// Due when the last finished check is an hour old or there is none, the app has
  /// not itself tried within the hour (so a failing check, or a Mac that slept
  /// through many hours, gives one check and not a burst), nothing is running, and
  /// the app has been up a minute and knows the status.
  public static func isDue(
    known: Bool, lastFinished: Date?, lastAutoCheck: Date?, launchedAt: Date, now: Date,
    running: Bool
  ) -> Bool {
    guard known, !running, now.timeIntervalSince(launchedAt) >= afterLaunch else { return false }
    if let f = lastFinished, now.timeIntervalSince(f) < every { return false }
    if let a = lastAutoCheck, now.timeIntervalSince(a) < every { return false }
    return true
  }
}
