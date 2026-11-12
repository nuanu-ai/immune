// Keeping `soc watch` running while the app is open. The app starts it, reads what
// it says line by line, refreshes the status when it re-read the watched places,
// and starts it again with a growing delay when it stops or falls silent. No
// logic of the program lives here: the watcher decides what changed.
//
// The watchdog stops a watcher that fell silent without waiting for it: TERM now,
// KILL after a grace from another queue, so a child that ignores TERM never holds up
// the main thread. Quitting stops the watcher and waits for it (TERM, then KILL after
// the grace), since nothing is left afterwards to send the KILL. If the app is killed
// outright, `soc watch` stops by itself within a second or two: it looks for its
// parent every second and stops when its stdout closes.
//
// A watcher that runs but whose reading, sample or look at what to watch failed is
// not watching: what it said stays shown until a line of the same kind says it
// succeeded. The status says so too, where the store could record it; the store may
// be what failed, so the app keeps what the watcher said.

import Foundation

/// Splits a byte stream into lines, with a cap per line. A longer line is dropped
/// whole and counted, so an endless line can neither fill memory nor be shown.
public struct LineSplitter: Sendable {
  public let cap: Int
  private var buffer = Data()
  private var dropping = false

  public init(cap: Int = 64 * 1024) { self.cap = cap }

  /// The whole lines in `data`, and how many lines were dropped as too long.
  public mutating func feed(_ data: Data) -> (lines: [Data], dropped: Int) {
    var lines: [Data] = []
    var dropped = 0
    var rest = data[...]
    while let nl = rest.firstIndex(of: UInt8(ascii: "\n")) {
      let piece = rest[rest.startIndex..<nl]
      if dropping || buffer.count + piece.count > cap {
        dropped += 1
      } else {
        lines.append(buffer + piece)
      }
      buffer = Data()
      dropping = false
      rest = rest[rest.index(after: nl)...]
    }
    if !dropping {
      if buffer.count + rest.count > cap {
        dropping = true
        buffer = Data()
      } else {
        buffer.append(contentsOf: rest)
      }
    }
    return (lines, dropped)
  }
}

/// A running watcher process.
public protocol WatchChild: AnyObject, Sendable {
  /// SIGTERM now, then SIGKILL when it has not stopped within `grace` seconds.
  /// Returns at once: the SIGKILL is sent from another queue.
  func stop(grace: TimeInterval)
  /// The same, and returns only when it is gone: for quitting.
  func stopAndWait(grace: TimeInterval)
}

public protocol WatchLaunching: Sendable {
  /// Starts `soc` with `arguments`. Lines and the exit arrive on the main queue,
  /// in order.
  @MainActor
  func launch(
    _ arguments: [String], onLine: @escaping @MainActor (Data) -> Void,
    onDropped: @escaping @MainActor (Int) -> Void,
    onExit: @escaping @MainActor (Int32?) -> Void
  ) -> Result<any WatchChild, LaunchFailure>
}

public struct LaunchFailure: Error, Equatable, Sendable {
  public let words: String
  public init(_ words: String) { self.words = words }
}

/// The real launcher: `soc` by its absolute path, an argument list, no shell.
public struct ProcessWatchLauncher: WatchLaunching {
  public let executable: URL
  public let lineCap: Int
  /// Added to the app's own environment; empty in the app, used by tests.
  public let environment: [String: String]

  public init(executable: URL, lineCap: Int = 64 * 1024, environment: [String: String] = [:]) {
    self.executable = executable
    self.lineCap = lineCap
    self.environment = environment
  }

  @MainActor
  public func launch(
    _ arguments: [String], onLine: @escaping @MainActor (Data) -> Void,
    onDropped: @escaping @MainActor (Int) -> Void,
    onExit: @escaping @MainActor (Int32?) -> Void
  ) -> Result<any WatchChild, LaunchFailure> {
    let child = ProcessWatchChild(
      executable: executable, arguments: arguments, cap: lineCap, environment: environment)
    child.onLine = onLine
    child.onDropped = onDropped
    child.onExit = onExit
    do {
      try child.start()
    } catch {
      return .failure(LaunchFailure(error.localizedDescription))
    }
    return .success(child)
  }
}

final class ProcessWatchChild: WatchChild, @unchecked Sendable {
  private let process = Process()
  private let out = Pipe()
  private let lock = NSLock()
  private var splitter: LineSplitter
  var onLine: (@MainActor (Data) -> Void)?
  var onDropped: (@MainActor (Int) -> Void)?
  var onExit: (@MainActor (Int32?) -> Void)?

  init(executable: URL, arguments: [String], cap: Int, environment: [String: String]) {
    splitter = LineSplitter(cap: cap)
    process.executableURL = executable
    process.arguments = arguments
    process.environment = ProcessInfo.processInfo.environment.merging(environment) { $1 }
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = out
    process.standardError = FileHandle.nullDevice
  }

  func start() throws {
    out.fileHandleForReading.readabilityHandler = { [self] h in
      let data = h.availableData
      if data.isEmpty {
        h.readabilityHandler = nil
        return
      }
      let (lines, dropped) = lock.withLock { splitter.feed(data) }
      let onLine = self.onLine
      let onDropped = self.onDropped
      // The main queue keeps the order of the lines.
      DispatchQueue.main.async {
        MainActor.assumeIsolated {
          for l in lines { onLine?(l) }
          if dropped > 0 { onDropped?(dropped) }
        }
      }
    }
    process.terminationHandler = { [self] p in
      let code: Int32? = p.terminationReason == .exit ? p.terminationStatus : nil
      let onExit = self.onExit
      DispatchQueue.main.async { MainActor.assumeIsolated { onExit?(code) } }
    }
    try process.run()
  }

  var pid: Int32 { process.processIdentifier }

  func stop(grace: TimeInterval) {
    guard process.isRunning else { return }
    process.terminate()
    DispatchQueue.global().asyncAfter(deadline: .now() + grace) { [self] in
      if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    }
  }

  func stopAndWait(grace: TimeInterval) {
    guard process.isRunning else { return }
    process.terminate()
    let deadline = Date().addingTimeInterval(grace)
    while process.isRunning, Date() < deadline { usleep(20_000) }
    if process.isRunning {
      kill(process.processIdentifier, SIGKILL)
      process.waitUntilExit()
    }
  }
}

/// Keeps one watcher running and says, in plain words, when it is not.
@MainActor
public final class Watcher: ObservableObject {
  public enum State: Equatable, Sendable {
    /// Started, not yet subscribed. Nothing is said.
    case starting
    case watching
    /// Running, but what it watches with failed: not watching, with the plain reason.
    /// Said as one quiet line; the watcher is not restarted for it.
    case failing(String)
    /// Not watching, with the plain reason. Said as one quiet line.
    case down(String)
    /// Another watcher already watches this store. Nothing is said.
    case elsewhere
  }

  /// No line for this long means the watcher is dead.
  public static let silenceLimit: TimeInterval = 180
  /// A watcher that ran this long before it stopped starts again from the shortest delay.
  public static let healthyRun: TimeInterval = 300
  /// How often a watcher that found another one on its store looks again.
  public static let elsewhereRetry: TimeInterval = 300

  /// 5 s, 10 s, 20 s … up to five minutes.
  public static func delay(attempt: Int) -> TimeInterval {
    min(300, 5 * pow(2, Double(min(attempt, 10))))
  }

  @Published public private(set) var state: State = .starting
  /// Lines not understood, or too long: counted, never shown.
  public private(set) var ignoredLines = 0
  public private(set) var starts = 0

  private let launcher: any WatchLaunching
  private let arguments: [String]
  private let onRead: @MainActor () -> Void
  private let schedule: @MainActor (TimeInterval, @escaping @MainActor () -> Void) -> Void
  private let clock: @MainActor () -> Date

  private var child: (any WatchChild)?
  private var generation = 0
  private var attempt = 0
  private var startedAt = Date.distantPast
  private var lastLineAt = Date.distantPast
  private var failure: SocError?
  /// What failed and has not succeeded since, by kind, in the order said.
  private var failing: [(kind: String, reason: String)] = []
  private var sawWatching = false
  private var stopped = false

  /// The `problem` codes that mean the watcher is not watching, the kind each is
  /// of, what it is in plain words, and the line that says the kind succeeded again:
  /// `read`, `sample`, or `watching` after a look at what to watch.
  static let failures: [String: (kind: String, words: String)] = [
    "read_failed": ("read", "a reading of the watched places failed"),
    "sample_failed": ("sample", "a sample of running programs failed"),
    "resubscribe_failed": ("watching", "the watcher could not look again at what to watch"),
  ]

  public init(
    launcher: any WatchLaunching, arguments: [String],
    onRead: @escaping @MainActor () -> Void,
    schedule: @escaping @MainActor (TimeInterval, @escaping @MainActor () -> Void) -> Void,
    clock: @escaping @MainActor () -> Date = { Date() }
  ) {
    self.launcher = launcher
    self.arguments = arguments
    self.onRead = onRead
    self.schedule = schedule
    self.clock = clock
  }

  /// The quiet line for the panel, or nil while watching or starting.
  public var notWatching: String? {
    switch state {
    case .down(let reason), .failing(let reason):
      return "Not watching for changes right now: \(reason)."
    case .starting, .watching, .elsewhere:
      return nil
    }
  }

  public func start() {
    guard !stopped, child == nil else { return }
    generation += 1
    let gen = generation
    starts += 1
    startedAt = clock()
    lastLineAt = startedAt
    failure = nil
    failing = []
    sawWatching = false
    if state != .elsewhere { state = .starting }
    switch launcher.launch(
      arguments,
      onLine: { [weak self] in self?.line($0, gen) },
      onDropped: { [weak self] n in if self?.generation == gen { self?.ignoredLines += n } },
      onExit: { [weak self] in self?.exited($0, gen) })
    {
    case .success(let c): child = c
    case .failure: down("the watcher could not be started")
    }
  }

  func line(_ data: Data, _ gen: Int) {
    guard gen == generation else { return }
    guard let event = Decoding.watchLine(data) else {
      ignoredLines += 1
      return
    }
    lastLineAt = clock()
    switch event {
    case .watching:
      sawWatching = true
      succeeded("watching")
    case .read:
      sawWatching = true
      succeeded("read")
      onRead()
    case .sample:
      sawWatching = true
      succeeded("sample")
      onRead()
    case .problem(let code, let detail):
      // Another problem (a place it cannot watch, a view it could not bring up to date)
      // is news of life: the watcher still watches.
      guard let code, let f = Self.failures[code] else { break }
      // What the failure said is text from a source: shown inert, and only in brackets.
      let said = detail.flatMap { $0.isEmpty ? nil : " (" + Inert.text($0, limit: 160) + ")" }
      let reason = f.words + (said ?? "")
      failing.removeAll { $0.kind == f.kind }
      failing.append((f.kind, reason))
      state = .failing(failing.map(\.reason).joined(separator: "; "))
    case .alive:
      break
    case .failure(let e):
      failure = e
    }
  }

  /// A line of this kind says it succeeded: its failure, if any, is over.
  private func succeeded(_ kind: String) {
    failing.removeAll { $0.kind == kind }
    state = failing.isEmpty ? .watching : .failing(failing.map(\.reason).joined(separator: "; "))
  }

  func exited(_ code: Int32?, _ gen: Int) {
    guard gen == generation, child != nil else { return }
    child = nil
    if stopped { return }
    if failure?.code == "watch_in_progress" {
      state = .elsewhere
      schedule(Self.elsewhereRetry) { [weak self] in self?.start() }
      return
    }
    let reason: String
    if let f = failure {
      reason =
        "the watcher stopped (" + Inert.text(f.message ?? f.code ?? "no reason given", limit: 160)
        + ")"
    } else if sawWatching {
      reason = "the watcher stopped unexpectedly"
    } else {
      reason = "the watcher could not start"
    }
    down(reason)
  }

  /// The watchdog, called every half minute or so: silence counts as death.
  public func tick() {
    guard !stopped, let c = child, clock().timeIntervalSince(lastLineAt) > Self.silenceLimit
    else { return }
    child = nil  // so its own exit is no longer news
    c.stop(grace: 2)  // returns at once; a child that ignores TERM is killed later
    down("the watcher stopped answering")
  }

  private func down(_ reason: String) {
    if clock().timeIntervalSince(startedAt) >= Self.healthyRun { attempt = 0 }
    state = .down(reason)
    let wait = Self.delay(attempt: attempt)
    attempt += 1
    schedule(wait) { [weak self] in self?.start() }
  }

  /// When the app quits: the watcher is stopped and not started again.
  public func stop() {
    stopped = true
    generation += 1
    // Waits: once the app is gone nothing is left to send the KILL.
    child?.stopAndWait(grace: 2)
    child = nil
  }
}
