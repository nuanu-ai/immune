// The menu-bar app: an AppKit status item and a popover around a SwiftUI view.
// While it is open it keeps the program running: `soc watch` as a child process,
// and a full check every hour (`HourlyCheck`).
// AppKit owns the icon so that opening the panel is one known call (which
// refreshes) and the count beside the icon is plain button text. There is no
// window of the app's own: Details is the program's page, written and opened by
// `soc view`.

import AppKit
import Combine
import SOCCore
import SwiftUI

/// The app's name, from Info.plist: kept there and nowhere else.
let appName =
  Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String
  ?? ProcessInfo.processInfo.processName

@MainActor
final class Delegate: NSObject, NSApplicationDelegate {
  let model: AppModel
  let watcher: Watcher
  private var item: NSStatusItem?
  private let popover = NSPopover()
  private var timers: [Timer] = []
  private var watching: AnyCancellable?
  private var termination: DispatchSourceSignal?

  init(model: AppModel, watcher: Watcher) {
    self.model = model
    self.watcher = watcher
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    item.button?.target = self
    item.button?.action = #selector(toggle)
    item.button?.imagePosition = .imageLeading
    self.item = item

    let panel = NSHostingController(
      rootView: PanelView(
        model: model, watcher: WatcherBox(watcher), openSettings: { openNotificationSettings() }))
    panel.sizingOptions = [.preferredContentSize]
    popover.contentViewController = panel
    popover.behavior = .transient

    // @Published sends the new value before it is stored; paint from the value.
    watching = model.$reading.sink { [weak self] reading in
      let items = reading.status?.needsALook ?? []
      self?.paint(
        Light.of(reading), worst: Severity.worst(items), urgent: items.contains { $0.urgent })
    }

    // Every minute: read the status, then start the hourly check if it is due.
    timers.append(
      Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
        Task { @MainActor in await self?.minute() }
      })
    // Every half minute: the watcher's watchdog.
    timers.append(
      Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
        MainActor.assumeIsolated { self?.watcher.tick() }
      })
    // After the Mac wakes: one look soon after, never a burst (see `HourlyCheck`).
    NSWorkspace.shared.notificationCenter.addObserver(
      forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
    ) { [weak self] _ in
      log("woke")
      DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
        Task { @MainActor in await self?.minute() }
      }
    }
    // SIGTERM quits like Quit does, so the watcher is stopped too.
    signal(SIGTERM, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    source.setEventHandler { NSApp.terminate(nil) }
    source.resume()
    termination = source

    // The only place the app may ask for notifications: the running app. The
    // question is asked once in the app's life (see `Announcer.askOnce`).
    let announcer = Announcer(
      notifier: SystemNotifier(onOpen: { [weak self] in self?.showPanel() }),
      memory: UserDefaults.standard)
    model.announcer = announcer
    Task { await model.refresh() }
    Task {
      await announcer.askOnce()
      await model.refresh()
    }
    watcher.start()

    // Test-only convenience, so the panel can be looked at without clicking.
    if CommandLine.arguments.contains("--open-panel") {
      // The status item needs a moment to be placed before a popover can hang from it.
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in self?.toggle() }
    }
  }

  func applicationWillTerminate(_ notification: Notification) {
    watcher.stop()
    log("quit: watcher stopped")
  }

  private func minute() async {
    await model.refresh()
    if await model.checkIfDue() { log("hourly check done") }
  }

  private func paint(_ light: Light, worst: String?, urgent: Bool) {
    guard let button = item?.button else { return }
    let words: String
    switch light {
    case .nothingToReport: words = "nothing needs you"
    case .attention(let n): words = n == 1 ? "1 thing needs a look" : "\(n) things need a look"
    case .cannotRead(let reason): words = "can't tell. " + reason
    }
    // The worst severity shown decides the weight: filled for high or critical.
    let symbol = Light.menuSymbol(light, worst: worst, urgent: urgent)
    let image = NSImage(
      systemSymbolName: symbol, accessibilityDescription: "\(appName): \(words)")
    image?.isTemplate = true
    button.image = image
    if case .attention(let n) = light { button.title = " \(n)" } else { button.title = "" }
    button.toolTip = "\(appName): \(words)"
    log("state: \(symbol) \(words)")
  }

  /// Opens the panel, as a click on a notification does.
  func showPanel() {
    if !popover.isShown { toggle() }
  }

  @objc private func toggle() {
    guard let button = item?.button else { return }
    if popover.isShown {
      popover.performClose(nil)
      return
    }
    Task { await model.refresh() }
    popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
    NSApp.activate()
    log("panel shown: \(popover.isShown)")
  }
}

/// System Settings, Notifications, at this app. The one thing the app opens.
@MainActor
func openNotificationSettings() {
  guard let url = Announcer.settingsURL(bundleId: Bundle.main.bundleIdentifier ?? "") else {
    return
  }
  NSWorkspace.shared.open(url)
}

/// One line per change of state on stderr, for whoever started the app from a
/// terminal. No text taken from a source goes here.
func log(_ line: String) {
  let at = Date().formatted(.iso8601)
  FileHandle.standardError.write(Data("personal-soc: \(at) \(line)\n".utf8))
}

// Overrides of where soc is and which store it reads are for tests and trials, and
// only a debug build honours them. A release bundle always runs its own soc on
// soc's default store.
#if DEBUG
  let overrides = (CommandLine.arguments, ProcessInfo.processInfo.environment)
  log("debug build: --soc-path, --store and their environment variables are honoured")
#else
  let overrides: ([String], [String: String]) = ([], [:])
#endif

/// The soc to run and the arguments that point it at a store.
func locate(_ arguments: [String], _ environment: [String: String]) -> (
  any SocRunning, [String], URL?
) {
  let soc: any SocRunning
  let found: URL
  switch SocLocation.resolve(
    arguments: arguments, environment: environment,
    executableDirectory: Bundle.main.executableURL?.deletingLastPathComponent())
  {
  case .success(let url):
    log("soc: \(url.path)")
    soc = ProcessRunner(executable: url)
    found = url
  case .failure(let problem):
    log("soc: not located: \(problem.words)")
    return (UnlocatedSoc(problem: problem), [], nil)
  }
  switch SocLocation.store(arguments: arguments, environment: environment) {
  case .success(let extra):
    log(extra.isEmpty ? "store: soc's default" : "store: \(extra[1])")
    return (soc, extra, found)
  case .failure(let problem):
    // Never fall back to the default store when a trial asked for another one.
    log("store: refused: \(problem.words)")
    return (UnlocatedSoc(problem: problem), [], nil)
  }
}

/// A launcher that cannot start anything, for when soc was not located.
struct NoWatch: WatchLaunching {
  @MainActor
  func launch(
    _ arguments: [String], onLine: @escaping @MainActor (Data) -> Void,
    onDropped: @escaping @MainActor (Int) -> Void, onExit: @escaping @MainActor (Int32?) -> Void
  ) -> Result<any WatchChild, LaunchFailure> { .failure(LaunchFailure("soc was not located")) }
}

@MainActor
func makeWatcher(_ url: URL?, _ extra: [String], _ model: AppModel) -> Watcher {
  let launcher: any WatchLaunching = url.map { ProcessWatchLauncher(executable: $0) } ?? NoWatch()
  return Watcher(
    launcher: launcher, arguments: ["watch"] + extra,
    onRead: { Task { await model.refresh() } },
    schedule: { wait, action in
      log("watcher: next start in \(Int(wait)) s")
      DispatchQueue.main.asyncAfter(deadline: .now() + wait) { MainActor.assumeIsolated(action) }
    })
}

/// Debug only: prints the lines the panel shows for soc's current answer, as plain
/// text on stdout, and exits. Lets the panel be read without a screen.
func printPanel(_ soc: any SocRunning, _ extra: [String]) -> Never {
  final class Box: @unchecked Sendable {
    var out: SocOutput?
  }
  let box = Box()
  Task.detached {
    let out = await soc.run(["status", "--json"] + extra, timeout: AppModel.statusTimeout)
    DispatchQueue.main.async { box.out = out }
  }
  // Keep the main run loop turning while soc answers.
  while box.out == nil { RunLoop.main.run(until: Date() + 0.05) }
  let panel = Panel.of(Interpret.reading(from: box.out ?? SocOutput()), now: Date())
  print(panel.lines.joined(separator: "\n"))
  exit(0)
}

/// Debug only: a system that has notifications turned off.
@MainActor
final class SilentNotifier: Notifying {
  func permission() async -> NotifyPermission { .off }
  func requestPermission() async {}
  func deliver(_ note: Note) {}
}

/// Debug only: draws the panel's own view off-screen, at the popover's width and
/// at 2x, in light and dark appearance, to `<folder>/light.png` and `dark.png`,
/// and the same panel as text to `panel.txt`, and exits. No screen capture: the view hierarchy is drawn into a bitmap. The
/// popover's translucent material cannot be drawn this way; the window background
/// colour stands in for it.
///
/// `--render-seen` first presses Seen on the first finding (so a refusal from the
/// stand-in shows on its card); `--render-form <reason>` opens the Expected form on
/// it with that reason typed.
@MainActor
func renderPanel(_ model: AppModel, _ watcher: Watcher, to folder: URL) async -> Never {
  // `--render-notify-off` draws the line shown when notifications are off, with a
  // stand-in for the system: a render never asks the system anything.
  if CommandLine.arguments.contains("--render-notify-off") {
    let memory = Forgetful()
    memory.set(true, forKey: "notify.asked")
    model.announcer = Announcer(notifier: SilentNotifier(), memory: memory)
  }
  await model.refresh()
  let first = model.reading.status?.needsALook?.first { $0.type == "finding" }?.id
  if CommandLine.arguments.contains("--render-seen"), let first {
    await model.answerSeen(first)
  }
  if let i = CommandLine.arguments.firstIndex(of: "--render-form"),
    i + 1 < CommandLine.arguments.count, let first
  {
    model.form = ExpectedForm(id: first, reason: CommandLine.arguments[i + 1])
  }
  // Give the watcher a moment, so the panel shows what it says.
  watcher.start()
  try? await Task.sleep(for: .milliseconds(1500))
  try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
  for (name, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
    guard let appearance = NSAppearance(named: look) else { continue }
    let host = NSHostingView(
      rootView: PanelView(model: model, watcher: WatcherBox(watcher))
        .background(Color(nsColor: .windowBackgroundColor)))
    host.appearance = appearance
    // Lay out twice: the rows' measured height settles after the first pass.
    for _ in 0..<3 {
      host.frame = NSRect(origin: .zero, size: host.fittingSize)
      host.layoutSubtreeIfNeeded()
      try? await Task.sleep(for: .milliseconds(150))
    }
    let size = host.bounds.size
    guard
      let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: Int(size.width * 2), pixelsHigh: Int(size.height * 2),
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
    else { continue }
    rep.size = size
    appearance.performAsCurrentDrawingAppearance { host.cacheDisplay(in: host.bounds, to: rep) }
    let file = folder.appendingPathComponent("\(name).png")
    try? rep.representation(using: .png, properties: [:])?.write(to: file)
    log("rendered \(file.lastPathComponent): \(Int(size.width))x\(Int(size.height)) pt")
  }
  // The same panel as text, beside the pictures.
  let panel = Panel.of(
    model.reading, now: Date(), checking: model.runInProgress, notes: model.notes,
    notWatching: watcher.notWatching, form: model.form, answering: model.answering,
    refusals: model.refusals, notificationsOff: model.notificationsOff)
  try? (panel.lines.joined(separator: "\n") + "\n").write(
    to: folder.appendingPathComponent("panel.txt"), atomically: true, encoding: .utf8)
  watcher.stop()
  exit(0)
}

let (soc, extra, socURL) = locate(overrides.0, overrides.1)
#if DEBUG
  if CommandLine.arguments.contains("--print-panel") { printPanel(soc, extra) }
  if let i = CommandLine.arguments.firstIndex(of: "--render-panel"),
    i + 1 < CommandLine.arguments.count
  {
    let folder = URL(fileURLWithPath: CommandLine.arguments[i + 1])
    let model = AppModel(soc: soc, extraArguments: extra)
    let watcher = makeWatcher(socURL, extra, model)
    NSApplication.shared.setActivationPolicy(.prohibited)
    Task { @MainActor in await renderPanel(model, watcher, to: folder) }
    NSApplication.shared.run()
  }
#endif
let model = AppModel(soc: soc, extraArguments: extra)
let delegate = Delegate(model: model, watcher: makeWatcher(socURL, extra, model))
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
app.delegate = delegate
app.run()
