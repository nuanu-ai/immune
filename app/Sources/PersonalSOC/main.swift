// The menu-bar app: an AppKit status item and a popover around a SwiftUI view.
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
  private var item: NSStatusItem?
  private let popover = NSPopover()
  private var timer: Timer?
  private var watching: AnyCancellable?

  init(model: AppModel) {
    self.model = model
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    item.button?.target = self
    item.button?.action = #selector(toggle)
    item.button?.imagePosition = .imageLeading
    self.item = item

    let panel = NSHostingController(rootView: PanelView(model: model))
    panel.sizingOptions = [.preferredContentSize]
    popover.contentViewController = panel
    popover.behavior = .transient

    // @Published sends the new value before it is stored; paint from the value.
    watching = model.$reading.sink { [weak self] reading in self?.paint(Light.of(reading)) }

    timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
      Task { @MainActor in await self?.model.refresh() }
    }
    Task { await model.refresh() }

    // Test-only convenience, so the panel can be looked at without clicking.
    if CommandLine.arguments.contains("--open-panel") {
      // The status item needs a moment to be placed before a popover can hang from it.
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in self?.toggle() }
    }
  }

  private func paint(_ light: Light) {
    guard let button = item?.button else { return }
    let words: String
    switch light {
    case .nothingToReport: words = "nothing needs you"
    case .attention(let n): words = n == 1 ? "1 thing needs a look" : "\(n) things need a look"
    case .cannotRead(let reason): words = "can't tell. " + reason
    }
    let image = NSImage(
      systemSymbolName: light.symbol, accessibilityDescription: "\(appName): \(words)")
    image?.isTemplate = true
    button.image = image
    if case .attention(let n) = light { button.title = " \(n)" } else { button.title = "" }
    button.toolTip = "\(appName): \(words)"
    log("state: \(light.symbol) \(words)")
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
func locate(_ arguments: [String], _ environment: [String: String]) -> (any SocRunning, [String]) {
  let soc: any SocRunning
  switch SocLocation.resolve(
    arguments: arguments, environment: environment,
    executableDirectory: Bundle.main.executableURL?.deletingLastPathComponent())
  {
  case .success(let url):
    log("soc: \(url.path)")
    soc = ProcessRunner(executable: url)
  case .failure(let problem):
    log("soc: not located: \(problem.words)")
    return (UnlocatedSoc(problem: problem), [])
  }
  switch SocLocation.store(arguments: arguments, environment: environment) {
  case .success(let extra):
    log(extra.isEmpty ? "store: soc's default" : "store: \(extra[1])")
    return (soc, extra)
  case .failure(let problem):
    // Never fall back to the default store when a trial asked for another one.
    log("store: refused: \(problem.words)")
    return (UnlocatedSoc(problem: problem), [])
  }
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

let (soc, extra) = locate(overrides.0, overrides.1)
#if DEBUG
  if CommandLine.arguments.contains("--print-panel") { printPanel(soc, extra) }
#endif
let delegate = Delegate(model: AppModel(soc: soc, extraArguments: extra))
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
app.delegate = delegate
app.run()
