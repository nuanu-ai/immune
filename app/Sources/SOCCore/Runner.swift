// Running `soc`: by its absolute path, with an explicit argument list, never
// through a shell, with a time limit and a cap on what is read back.

import Foundation

/// What one run of `soc` gave back, before anything is decoded.
public struct SocOutput: Sendable, Equatable {
  public var exitCode: Int32?
  public var signal: Int32?
  public var stdout: Data
  public var stderr: Data
  public var timedOut: Bool
  public var tooLarge: Bool
  public var launchFailure: String?

  public init(
    exitCode: Int32? = nil, signal: Int32? = nil, stdout: Data = Data(), stderr: Data = Data(),
    timedOut: Bool = false, tooLarge: Bool = false, launchFailure: String? = nil
  ) {
    self.exitCode = exitCode
    self.signal = signal
    self.stdout = stdout
    self.stderr = stderr
    self.timedOut = timedOut
    self.tooLarge = tooLarge
    self.launchFailure = launchFailure
  }
}

public protocol SocRunning: Sendable {
  func run(_ arguments: [String], timeout: TimeInterval) async -> SocOutput
}

/// Where `soc` is, and which store it is pointed at. The binary inside the bundle
/// and soc's own default store, unless a test passes absolute paths with
/// `--soc-path <path>` / `PERSONAL_SOC_SOC_PATH` and `--store <path>` /
/// `PERSONAL_SOC_STORE`. The app honours these only in a debug build (see
/// main.swift). A relative path is refused, so `soc` is never looked up through
/// PATH or the working folder.
public enum SocLocation {
  public static let argument = "--soc-path"
  public static let environment = "PERSONAL_SOC_SOC_PATH"
  public static let storeArgument = "--store"
  public static let storeEnvironment = "PERSONAL_SOC_STORE"

  /// The arguments that point soc at a store other than its default: none, or
  /// `--store <absolute path>`.
  public static func store(arguments: [String], environment env: [String: String]) -> Result<
    [String], LocationProblem
  > {
    var path: String? = env[storeEnvironment]
    if let i = arguments.firstIndex(of: storeArgument) {
      guard i + 1 < arguments.count else { return .failure(.missingValue) }
      path = arguments[i + 1]
    }
    guard let path else { return .success([]) }
    guard path.hasPrefix("/") else { return .failure(.notAbsolute) }
    return .success(["--store", path])
  }

  public static func resolve(
    arguments: [String], environment env: [String: String], executableDirectory: URL?
  ) -> Result<URL, LocationProblem> {
    var override: String? = env[environment]
    if let i = arguments.firstIndex(of: argument) {
      guard i + 1 < arguments.count else { return .failure(.missingValue) }
      override = arguments[i + 1]
    }
    if let path = override {
      guard path.hasPrefix("/") else { return .failure(.notAbsolute) }
      return .success(URL(fileURLWithPath: path))
    }
    guard let dir = executableDirectory else { return .failure(.noBundle) }
    return .success(dir.appendingPathComponent("soc"))
  }
}

public enum LocationProblem: Error, Equatable, Sendable {
  case missingValue, notAbsolute, noBundle

  public var words: String {
    switch self {
    case .missingValue: "A path option was given without a path."
    case .notAbsolute: "A path given for a trial is not absolute, so it is not used."
    case .noBundle: "The app cannot find its own folder, so it cannot find soc."
    }
  }
}

/// A runner that always fails, for when `soc` cannot be located at all.
public struct UnlocatedSoc: SocRunning {
  public let problem: LocationProblem
  public init(problem: LocationProblem) { self.problem = problem }
  public func run(_ arguments: [String], timeout: TimeInterval) async -> SocOutput {
    SocOutput(launchFailure: problem.words)
  }
}

public struct ProcessRunner: SocRunning {
  public let executable: URL
  /// More than this from `soc` is not read; the run is stopped and reported.
  public let outputLimit: Int

  public init(executable: URL, outputLimit: Int = 8 << 20) {
    self.executable = executable
    self.outputLimit = outputLimit
  }

  public func run(_ arguments: [String], timeout: TimeInterval) async -> SocOutput {
    let job = Job(executable: executable, arguments: arguments, limit: outputLimit)
    return await withCheckedContinuation { job.start(timeout: timeout, then: $0) }
  }
}

/// One child process. All state is behind the lock; the continuation is resumed once.
private final class Job: @unchecked Sendable {
  private let lock = NSLock()
  private let process = Process()
  private let outPipe = Pipe()
  private let errPipe = Pipe()
  private let limit: Int
  private var out = Data()
  private var err = Data()
  private var outDone = false
  private var errDone = false
  private var exited = false
  private var result = SocOutput()
  private var continuation: CheckedContinuation<SocOutput, Never>?

  init(executable: URL, arguments: [String], limit: Int) {
    self.limit = limit
    process.executableURL = executable
    process.arguments = arguments
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = outPipe
    process.standardError = errPipe
  }

  func start(timeout: TimeInterval, then continuation: CheckedContinuation<SocOutput, Never>) {
    lock.withLock { self.continuation = continuation }
    outPipe.fileHandleForReading.readabilityHandler = { [self] h in take(h.availableData, out: true)
    }
    errPipe.fileHandleForReading.readabilityHandler = { [self] h in
      take(h.availableData, out: false)
    }
    process.terminationHandler = { [self] p in
      lock.withLock {
        exited = true
        if p.terminationReason == .uncaughtSignal {
          result.signal = p.terminationStatus
        } else {
          result.exitCode = p.terminationStatus
        }
      }
      finishIfDone()
    }
    do {
      try process.run()
    } catch {
      lock.withLock { result.launchFailure = error.localizedDescription }
      finish()
      return
    }
    DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [self] in timeUp() }
  }

  private func take(_ data: Data, out isOut: Bool) {
    var stop = false
    lock.withLock {
      if data.isEmpty {
        if isOut { outDone = true } else { errDone = true }
        return
      }
      if out.count + err.count + data.count > limit {
        result.tooLarge = true
        stop = true
      } else if isOut {
        out.append(data)
      } else {
        err.append(data)
      }
    }
    if data.isEmpty {
      (isOut ? outPipe : errPipe).fileHandleForReading.readabilityHandler = nil
      finishIfDone()
    } else if stop {
      process.terminate()
    }
  }

  private func timeUp() {
    let running: Bool = lock.withLock {
      guard continuation != nil else { return false }
      result.timedOut = true
      return true
    }
    guard running else { return }
    process.terminate()
    let pid = process.processIdentifier
    DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [self] in
      if process.isRunning { kill(pid, SIGKILL) }
      // A grandchild may still hold the pipes open; do not wait for it forever.
      DispatchQueue.global().asyncAfter(deadline: .now() + 1) { [self] in finish() }
    }
  }

  private func finishIfDone() {
    let done = lock.withLock { exited && outDone && errDone }
    if done { finish() }
  }

  private func finish() {
    let pending: (CheckedContinuation<SocOutput, Never>, SocOutput)? = lock.withLock {
      guard let c = continuation else { return nil }
      continuation = nil
      result.stdout = out
      result.stderr = err
      return (c, result)
    }
    guard let (c, output) = pending else { return }
    outPipe.fileHandleForReading.readabilityHandler = nil
    errPipe.fileHandleForReading.readabilityHandler = nil
    process.terminationHandler = nil
    c.resume(returning: output)
  }
}
