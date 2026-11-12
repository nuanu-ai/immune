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
  /// The program's page is being brought up to date by `soc view` and opened.
  @Published public private(set) var pageOpening = false
  /// Why the page could not be opened, in plain words. Cleared on the next try.
  @Published public private(set) var pageFailure: String?
  /// Where the program's page is, as `soc view` last said.
  @Published public private(set) var pagePath: URL?
  /// Opens the page file; the app gives the system's opener, tests a recorder.
  public var opener: @MainActor (URL) -> Bool = { _ in false }
  /// Have soc keep the page current ahead of a click: once a store is read, then at most
  /// every `PageAhead.every`. soc writes only when the page is not current, so a quiet
  /// interval costs one quick look. On in the app, off in tests.
  public var writePageAhead = false
  /// When the app last had the page written ahead.
  private var lastAhead: Date?
  private var pageTask: Task<SocOutput, Never>?
  /// "More" is open in the panel.
  @Published public var moreOpen = false
  /// The card the owner opened, by its place in the order soc served; nil is the first.
  @Published public var openRow: Int?
  /// The answers given through the owner's agent are open in the panel.
  @Published public var answeredOpen = false
  /// The "Expected…" form, open on one finding's card, or nil.
  @Published public var form: ExpectedForm?
  /// The id of the finding whose answer is being saved now.
  @Published public private(set) var answering: String?
  /// Why soc did not take the last answer to a finding, by its id, in plain words.
  @Published public private(set) var refusals: [String: String] = [:]
  /// Notifications cannot reach the owner: the panel says so in one quiet line.
  @Published public private(set) var notificationsOff = false
  /// The soc this app runs, for "Copy for my agent".
  public var socCommand: SocCommand?
  /// Tells the owner about urgent things; nil in tests, renders and `--print-panel`.
  public var announcer: Announcer?

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
    return await runNow(for: .app)
  }

  public var light: Light { Light.of(reading) }

  /// soc said a run is in progress, started here or anywhere else.
  public var socSaysRunning: Bool { reading.status?.running == true }

  public var canRun: Bool { !runInProgress && !socSaysRunning }

  /// Runs `soc status --json`. Not while another refresh is in flight, and not
  /// while a run started here is in progress: the run refreshes when it ends. By
  /// default it is the app's own reading and yields to the owner's work; opening the
  /// panel reads for the owner.
  public func refresh(for whom: RunFor = .app) async {
    guard !runInProgress, !refreshing else { return }
    refreshing = true
    let out = await soc.run(
      ["status", "--json"] + extraArguments, timeout: Self.statusTimeout, for: whom)
    reading = Interpret.reading(from: out)
    readAt = Date()
    if let announcer {
      await announcer.checkPermission()
      notificationsOff = announcer.off
      if let s = reading.status { await announcer.saw(s) }
    }
    if writePageAhead, reading.status?.store?.exists == true,
      PageAhead.isDue(lastAhead: lastAhead, now: Date())
    {
      lastAhead = Date()
      Task { _ = await writePage(for: .app) }
    }
    refreshing = false
  }

  /// Takes what the watcher said after a reading of program starts into the status read
  /// last, as soc said it: the panel's row shows it without a run of `soc status`. What the
  /// line does not carry stays as the status said it; the caveats' sentences stay only while
  /// the caveats are the same, and the next status brings them back.
  public func took(_ said: EventLevel) {
    guard case .read(var s, let errors) = reading else { return }
    let before = s.eventLevel
    var e = said
    e.startsByHour = before?.startsByHour
    e.notes = before?.caveats == said.caveats ? before?.notes : nil
    s.eventLevel = e
    reading = .read(s, errors: errors)
  }

  /// Runs `soc run --json`, then refreshes. Returns false, and starts nothing,
  /// when a run is in progress, here or as soc last said. Check now is the owner's;
  /// the hourly check passes `.app`.
  @discardableResult
  public func runNow(for whom: RunFor = .owner) async -> Bool {
    guard canRun else { return false }
    runInProgress = true
    runFailure = nil
    runNote = nil
    let out = await soc.run(
      ["run", "--json"] + extraArguments, timeout: Self.runTimeout, for: whom)
    if Self.otherRunInProgress(out) {
      runNote = "A check was already running; its result will show when it ends."
    } else if case .failed(let reason, let detail, _) = Interpret.reading(from: out) {
      runFailure = reason + (detail.map { " " + Inert.text($0) } ?? "")
    }
    runInProgress = false
    await refresh(for: whom)
    return true
  }

  /// Details and Show open the program's page as the store is now, never an older one.
  /// Each click asks `soc view --no-open --if-stale`, which says where the page is and
  /// answers at once when nothing on it changed since it was written; otherwise it writes
  /// it first, and the panel shows that it is opening. A page being written ahead is
  /// waited for, not written twice. Returns false, and starts nothing, while an opening
  /// runs. A failure is a plain line and never changes what the icon says.
  @discardableResult
  public func openPage(at id: String? = nil, section: String? = nil) async -> Bool {
    guard !pageOpening else { return false }
    pageOpening = true
    pageFailure = nil
    if let ahead = pageTask {
      _ = await ahead.value
      // Ended: the click asks soc itself, whatever ran meanwhile.
      if pageTask == ahead { pageTask = nil }
    }
    let out = await writePage(for: .owner)
    if out.exitCode != 0 {
      pageFailure = "Details could not be opened. " + Self.viewFailure(out)
    } else if let page = pagePath {
      if !opener(target(page, section: section)) { pageFailure = "Details could not be opened." }
    } else {
      pageFailure = "Details could not be opened. The program did not say where its page is."
    }
    pageOpening = false
    return true
  }

  /// `soc view --no-open --if-stale` on the same store: brings the page up to date and
  /// learns where it is. One at a time; a second caller waits for the one running.
  /// Written ahead, it is the app's own; a click's is the owner's.
  func writePage(for whom: RunFor) async -> SocOutput {
    let task: Task<SocOutput, Never>
    if let running = pageTask {
      task = running
    } else {
      let soc = self.soc
      let args = ["view", "--no-open", "--if-stale"] + extraArguments
      task = Task { await soc.run(args, timeout: Self.viewTimeout, for: whom) }
      pageTask = task
    }
    let out = await task.value
    if pageTask == task { pageTask = nil }
    // Every waiter learns the page, whoever started the run.
    if out.exitCode == 0, let page = Self.pagePath(out.stdout) { pagePath = page }
    return out
  }

  /// What a click opens: the file soc names for the section when it is there, otherwise
  /// the summary. A file is opened as it is, never with a `#section`: macOS can lose
  /// that on the way to the browser.
  func target(_ page: URL, section: String?) -> URL {
    guard let section, let file = reading.status?.store?.viewSections[section],
      FileManager.default.fileExists(atPath: file.path)
    else { return page }
    return file
  }

  /// The page `soc view` printed first: an absolute path to an HTML file, as a file
  /// URL, or nil for anything else.
  static func pagePath(_ stdout: Data) -> URL? {
    String(decoding: stdout.prefix(4096), as: UTF8.self)
      .split(separator: "\n").first.map(String.init).flatMap(htmlFile)
  }

  /// An absolute path to an HTML file, as a file URL, or nil for anything else.
  nonisolated static func htmlFile(_ path: String) -> URL? {
    guard path.hasPrefix("/"), path.hasSuffix(".html"), Inert.text(path, limit: 4096) == path
    else { return nil }
    return URL(fileURLWithPath: path)
  }

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

  /// The owner's "Take back" on an answer given outside the app: `soc finding <id>
  /// reopen --via app`, then a refresh. Returns false, and runs nothing, for an answer
  /// the panel does not list or while another answer is being saved.
  @discardableResult
  public func takeBack(_ id: String) async -> Bool {
    let listed = reading.status?.answeredOutsideApp?.items ?? []
    guard let args = Answer.reopenArguments(id: id), listed.contains(where: { $0.id == id })
    else { return false }
    return await save(id, args)
  }

  /// The owner's "Take back" on a statement given outside the app: `soc owner <machine>
  /// withdraw --via app`, then a refresh. Returns false, and runs nothing, for a machine
  /// the panel does not list or while another change is being saved.
  @discardableResult
  public func withdrawStatement(_ machine: String) async -> Bool {
    let listed = reading.status?.statementsOutsideApp?.items ?? []
    guard let args = Answer.withdrawArguments(machine: machine),
      listed.contains(where: { $0.entityText == machine })
    else { return false }
    return await save(machine, args)
  }

  private func answer(_ id: String, _ args: [String]) async -> Bool {
    // Only a finding the panel shows takes an answer; a health item never does.
    let shown = reading.status?.needsALook ?? []
    guard shown.contains(where: { $0.id == id && $0.type == "finding" }) else { return false }
    return await save(id, args)
  }

  /// Runs one change to a finding and reads the status again; one at a time.
  private func save(_ id: String, _ args: [String]) async -> Bool {
    guard answering == nil else { return false }
    answering = id
    refusals[id] = nil
    let out = await soc.run(args + extraArguments, timeout: Self.answerTimeout, for: .owner)
    // Saved only when soc finished by itself with 0: a timed-out soc may still exit 0.
    if out.exitCode == 0, !out.timedOut {
      if form?.id == id { form = nil }
    } else {
      refusals[id] = Answer.refusal(out)
    }
    answering = nil
    await refresh(for: .owner)
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

/// When the app has the page written ahead of a click. A change read by the watcher can
/// come every few seconds and writing the page costs seconds of processor time, so it is
/// not written after each; a click on a page that is not current waits for it instead.
public enum PageAhead {
  public static let every: TimeInterval = 30 * 60

  /// Due when the app has not had it written ahead within the interval, or never.
  public static func isDue(lastAhead: Date?, now: Date) -> Bool {
    guard let last = lastAhead else { return true }
    return now.timeIntervalSince(last) >= every
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
