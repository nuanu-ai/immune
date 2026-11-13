// The panel under the icon: a status line and a list. It shows exactly what `Panel` holds, in
// the order of `Panel.lines`: the state and the line under it; the findings in two groups,
// each a row that starts with the thing itself; the answers given outside the app; what is not
// seen on this Mac; what is watched; what was not judged on this Mac; the footer. A click on a
// finding opens it in place (`FindingView`). Every line of text goes through
// `Text(verbatim:)`, which never interprets markup.
//
// Design: plain native macOS. System fonts from 11 pt up, text from the Mac in monospace,
// semantic colours and SF Symbols only, one spacing scale (4/8/12/16). Colour is never the only
// signal: shapes and words carry it.

import AppKit
import Combine
import ImmuneCore
import SwiftUI

enum Metrics {
  static let width: CGFloat = 344
  static let padding: CGFloat = 16
  /// The height of a quiet row.
  static let row: CGFloat = 32
}

/// A line of text shown exactly as given: no markdown, no links, no localisation.
struct Plain: View {
  let text: String
  init(_ text: String) { self.text = text }
  var body: some View { Text(verbatim: text).fixedSize(horizontal: false, vertical: true) }
}

/// A value from the Mac on one line in monospace, cut to the width it is given by `Inert.fit`: a
/// path so its last component stays whole, anything else in its middle. Measured with the font
/// it is drawn in. The app cuts it, never the text system: a cut made by the text system on a
/// line of isolated pieces can draw them out of order, and a cut made here leaves the isolation
/// whole (`Inert.display`).
///
/// With `program`, `text` is that program's arguments, and the line is cut by `Evidence.fit`:
/// the program's last component stays whole and the arguments take what is left.
struct DataLine: View {
  let text: String
  var path = true
  var program: String? = nil
  var size: CGFloat = 12.5
  var font: NSFont { NSFont.monospacedSystemFont(ofSize: size, weight: .regular) }

  var body: some View {
    let f = font
    Color.clear
      .frame(maxWidth: .infinity, minHeight: ceil(f.ascender - f.descender + f.leading))
      .overlay(alignment: .leading) {
        GeometryReader { g in
          let width = g.size.width
          let fits = { (s: String) in
            (Inert.display(s) as NSString).size(withAttributes: [.font: f]).width <= width
          }
          Text(
            verbatim: Inert.display(
              program.map { Evidence.fit(program: $0, arguments: text, fits: fits) }
                ?? Inert.fit(text, path: path, fits: fits))
          )
          .font(.system(size: size, design: .monospaced))
          .lineLimit(1).fixedSize()
          .frame(maxHeight: .infinity, alignment: .leading)
        }
      }
  }
}

/// Text from the Mac or a source: monospace, selectable, shown exactly as given, each piece
/// isolated so a right-to-left letter cannot reorder it (`Inert.display`).
struct DataText: View {
  let text: String
  var size: CGFloat = 11.5
  var weight: Font.Weight = .regular
  var body: some View {
    Text(verbatim: Inert.display(text)).font(
      .system(size: size, weight: weight, design: .monospaced)
    )
    .fixedSize(horizontal: false, vertical: true)
    .textSelection(.enabled)
  }
}

extension Light {
  var tint: Color {
    switch self {
    case .nothingToReport: .green
    case .watchedInPart, .stale, .cannotRead: Color(nsColor: .systemGray)
    case .attention: .orange
    }
  }

  var spoken: String {
    switch self {
    case .nothingToReport: "Calm"
    case .watchedInPart: "Watched in part"
    case .attention: "Needs a look"
    case .stale: "Old"
    case .cannotRead: "Unknown"
    }
  }
}

/// The colour of a row's symbol: red when Immune marked it urgent, orange for high and
/// critical, otherwise none of its own. Its group and words say the same.
func markTint(_ row: Row) -> AnyShapeStyle {
  row.urgent
    ? AnyShapeStyle(Color.red)
    : row.strong ? AnyShapeStyle(Color.orange) : AnyShapeStyle(.secondary)
}

// MARK: - The state

struct HeadlineView: View {
  let panel: Panel
  let openSettings: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack(alignment: .center, spacing: 12) {
        glyph.frame(width: 40, height: 40).accessibilityLabel(panel.light.spoken)
        VStack(alignment: .leading, spacing: 2) {
          HStack(alignment: .firstTextBaseline, spacing: 8) {
            Plain(panel.headline).font(.system(size: 17, weight: .semibold))
            // While a check runs, something moves, so the panel never looks frozen.
            if panel.busy {
              ProgressView().controlSize(.small).alignmentGuide(.firstTextBaseline) {
                $0[.bottom] - 3
              }
            }
          }
          if let glance = panel.glance {
            Text(verbatim: glance)
              .font(.system(size: 12)).foregroundStyle(.secondary)
              .lineLimit(2).fixedSize(horizontal: false, vertical: true)
              .help(panel.checkedAt ?? "")
          }
        }
        Spacer(minLength: 0)
      }
      .accessibilityElement(children: .combine)
      // Under the state, what it rests on and what the owner must act on.
      if !panel.help.isEmpty || panel.reason != nil || panel.notWatching != nil
        || panel.notificationsOff != nil
      {
        VStack(alignment: .leading, spacing: 6) {
          ForEach(Array(panel.help.enumerated()), id: \.offset) { _, line in
            HelpLine(line: line)
          }
          if let reason = panel.reason {
            Plain(reason).font(.system(size: 11)).foregroundStyle(.secondary)
              .textSelection(.enabled)
          }
          if let line = panel.notWatching {
            WarningLine(symbol: "pause.circle", text: line)
          }
          if let line = panel.notificationsOff {
            WarningLine(symbol: "bell.slash", text: line) {
              Button("Open Settings", action: openSettings)
                .buttonStyle(.link).font(.system(size: 12)).fixedSize()
            }
          }
        }
        .padding(.leading, 52)
      }
    }
  }

  /// A filled disc for calm, a finding or can't tell, its mark white; a grey ring for a Mac
  /// watched in part (with a check) and for an old answer (a clock), quieter than calm and never
  /// an alarm.
  @ViewBuilder var glyph: some View {
    if panel.light == .watchedInPart || panel.light.isStale {
      Image(systemName: panel.light.panelSymbol)
        .font(.system(size: 36, weight: .regular)).foregroundStyle(panel.light.tint)
    } else {
      Image(systemName: panel.light.panelSymbol)
        .font(.system(size: 36))
        .symbolRenderingMode(.palette)
        .foregroundStyle(.white, panel.urgent ? Color.red : panel.light.tint)
    }
  }
}

/// A line under the state the owner should know about: a symbol, the app's words, and
/// what to do about it, if anything. Quiet colours: it informs, it is not an alarm.
struct WarningLine<Action: View>: View {
  let symbol: String
  let text: String
  @ViewBuilder var action: () -> Action

  init(symbol: String, text: String, @ViewBuilder action: @escaping () -> Action) {
    self.symbol = symbol
    self.text = text
    self.action = action
  }

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: 6) {
      Image(systemName: symbol).font(.system(size: 12)).foregroundStyle(.secondary)
        .accessibilityHidden(true)
      VStack(alignment: .leading, spacing: 2) {
        Plain(text).font(.system(size: 12)).foregroundStyle(.secondary)
        action()
      }
    }
  }
}

extension WarningLine where Action == EmptyView {
  init(symbol: String, text: String) {
    self.init(symbol: symbol, text: text) { EmptyView() }
  }
}

/// A sentence of the app's own, with the terminal command in it set in monospace.
struct HelpLine: View {
  let line: String
  var body: some View {
    let parts = line.components(separatedBy: Panel.statusCommand)
    let text: Text =
      parts.count == 2
      ? Text(verbatim: parts[0])
        + Text(verbatim: Panel.statusCommand).font(.system(size: 12, design: .monospaced))
        + Text(verbatim: parts[1])
      : Text(verbatim: line)
    text.font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
  }
}

// MARK: - The list

/// A group's header: "NEEDS YOU NOW".
struct GroupTitle: View {
  let text: String
  var body: some View {
    Text(verbatim: text.uppercased())
      .font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
      .padding(.horizontal, 18).padding(.top, 6).padding(.bottom, 2)
      .accessibilityAddTraits(.isHeader)
  }
}

/// The outline of a pill, drawn as a path. `Capsule().strokeBorder` drew a short straight tick
/// at each end, where its two arcs meet, in every AppKit drawing of the view (at 1x and 2x,
/// whole and fractional heights, 1 pt and 0.75 pt strokes); a path of the same shape does not.
struct PillOutline: InsettableShape {
  var inset: CGFloat = 0
  func path(in rect: CGRect) -> Path {
    let r = rect.insetBy(dx: inset, dy: inset)
    return Path(roundedRect: r, cornerRadius: r.height / 2, style: .circular)
  }
  func inset(by amount: CGFloat) -> PillOutline { PillOutline(inset: inset + amount) }
}

/// A word beside a row, in an outline: what the response layer said; Immune's urgent mark is
/// filled.
struct BadgeView: View {
  let badge: Badge
  var body: some View {
    let colour: Color =
      switch badge.tone {
      case .suspicious, .urgent: .red
      case .harmless: .green
      }
    Text(verbatim: badge.word)
      .font(.system(size: 10.5, weight: .semibold))
      .foregroundStyle(badge.tone == .urgent ? Color.white : colour)
      .padding(.horizontal, 6).padding(.vertical, 1)
      .background(
        badge.tone == .urgent ? AnyShapeStyle(colour) : AnyShapeStyle(.clear), in: PillOutline()
      )
      .overlay(PillOutline().strokeBorder(colour, lineWidth: badge.tone == .urgent ? 0 : 0.75))
      .fixedSize()
  }
}

/// One finding: its symbol; the thing itself as data, one line, cut in the middle; its kind and
/// what happened, and the response layer's word; the time; a chevron. The whole row opens it.
struct FindingRow: View {
  let row: Row
  let badges: [Badge]
  let open: () -> Void

  var body: some View {
    Button(action: open) {
      HStack(alignment: .center, spacing: 10) {
        Image(systemName: row.symbol).font(.system(size: 15)).foregroundStyle(markTint(row))
          .frame(width: 20).accessibilityHidden(true)
        VStack(alignment: .leading, spacing: 2) {
          if let command = row.command {
            DataLine(text: command.arguments, program: command.program)
          } else if row.objectIsData {
            DataLine(text: row.object, path: row.objectIsPath)
          } else {
            Text(verbatim: row.object).font(.system(size: 12.5))
              .lineLimit(1).truncationMode(.middle)
          }
          // The name it was started under, when that is not the program that ran: the app's
          // label, then the value as data.
          if let startedAs = row.startedAs {
            HStack(alignment: .center, spacing: 4) {
              Text(verbatim: "started as").font(.system(size: 11.5)).foregroundStyle(.secondary)
                .fixedSize()
              DataLine(text: startedAs, path: Inert.isPath(startedAs), size: 11.5)
                .foregroundStyle(.secondary)
            }
          }
          // The kind and the response layer's word on one line when they fit, else the word
          // under the kind: neither is cut.
          ViewThatFits(in: .horizontal) {
            HStack(spacing: 6) {
              meta
              ForEach(badges, id: \.self) { BadgeView(badge: $0) }
            }
            VStack(alignment: .leading, spacing: 2) {
              meta
              HStack(spacing: 6) { ForEach(badges, id: \.self) { BadgeView(badge: $0) } }
            }
          }
        }
        Spacer(minLength: 4)
        if let when = row.when {
          Text(verbatim: when).font(.system(size: 11).monospacedDigit())
            .foregroundStyle(.secondary).lineLimit(1).fixedSize()
            .help(row.whenFull ?? "")
        }
        Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold))
          .foregroundStyle(.tertiary).accessibilityHidden(true)
      }
      .padding(.horizontal, 10).padding(.vertical, 6)
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .disabled(!row.canOpen)
    .help((row.objectIsData ? Inert.display(row.object) : row.object) + "\n" + row.title)
  }

  var meta: some View {
    Text(verbatim: row.meta).font(.system(size: 11.5)).foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
  }
}

/// The response layer's own finding, nested under the finding of the core it is about.
struct NestedRow: View {
  let row: Row
  let open: () -> Void

  var body: some View {
    Button(action: open) {
      HStack(spacing: 8) {
        Image(systemName: "exclamationmark.bubble")
          .font(.system(size: 13)).foregroundStyle(markTint(row)).frame(width: 16)
          .accessibilityHidden(true)
        VStack(alignment: .leading, spacing: 2) {
          Text(verbatim: "The response layer's own finding").font(.system(size: 12))
          HStack(spacing: 6) {
            ForEach(Entry.childBadges(row), id: \.self) { BadgeView(badge: $0) }
          }
        }
        Spacer(minLength: 4)
        if let when = row.when {
          Text(verbatim: when).font(.system(size: 11).monospacedDigit())
            .foregroundStyle(.secondary).lineLimit(1).fixedSize()
        }
        Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold))
          .foregroundStyle(.tertiary).accessibilityHidden(true)
      }
      .padding(.leading, 40).padding(.trailing, 10).padding(.vertical, 4)
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .disabled(!row.canOpen)
    .help(row.title)
  }
}

/// An answer given through the agent or the command line that hides a finding now, or a
/// statement that set a machine aside: what was said and by whom, the thing as data, the
/// reason as the person gave it, and Take back.
struct AnsweredBox: View {
  let line: AnsweredLine
  let panel: Panel
  @ObservedObject var model: AppModel

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      HStack(alignment: .firstTextBaseline, spacing: 6) {
        Image(systemName: "person.badge.clock").font(.system(size: 12))
          .foregroundStyle(Color.accentColor).accessibilityHidden(true)
        Plain([line.answer, line.by].compactMap { $0 }.joined(separator: ", "))
          .font(.system(size: 12))
        Spacer(minLength: 4)
        if let id = line.target {
          if panel.answering == id {
            Text(verbatim: "Saving…").font(.system(size: 12)).foregroundStyle(.secondary)
          } else {
            Button("Take back") {
              Task {
                if line.finding != nil {
                  await model.takeBack(id)
                } else {
                  await model.withdrawStatement(id)
                }
              }
            }
            .buttonStyle(.link).font(.system(size: 12)).fixedSize()
            .disabled(panel.answering != nil)
            .help(
              line.finding != nil
                ? "Show it again as something that needs a look."
                : "Check this machine again at the next server check.")
          }
        }
      }
      Group {
        if let finding = line.finding {
          Button {
            Task { await model.openFinding(finding) }
          } label: {
            DataText(text: line.title).multilineTextAlignment(.leading)
          }
          .buttonStyle(.plain)
        } else {
          DataText(text: line.title)
        }
      }
      .padding(.leading, 18)
      if let reason = line.reason {
        DataText(text: reason).foregroundStyle(.secondary).padding(.leading, 18)
      }
      if let id = line.target, let refused = panel.refusals[id] {
        Plain(refused).font(.system(size: 12)).textSelection(.enabled)
      }
    }
    .padding(8)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(
      Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 8, style: .continuous)
    )
    .overlay(
      RoundedRectangle(cornerRadius: 8, style: .continuous)
        .strokeBorder(Color.accentColor.opacity(0.3), lineWidth: 0.5))
  }
}

/// One thing not seen on this Mac that the person can fix: the first thing it is about as data,
/// Immune's title under it, and "Ask agent", which copies a request about it.
struct NotSeenView: View {
  let row: NotSeenRow
  let open: () -> Void

  var body: some View {
    HStack(alignment: .center, spacing: 10) {
      Button(action: open) {
        HStack(spacing: 10) {
          Image(systemName: "eye.slash").font(.system(size: 13)).foregroundStyle(.secondary)
            .frame(width: 20).accessibilityHidden(true)
          VStack(alignment: .leading, spacing: 2) {
            if let example = row.example {
              HStack(spacing: 6) {
                DataLine(text: example, path: Inert.isPath(example))
                if row.more > 0 {
                  Text(verbatim: "+\(row.more)").font(.system(size: 12.5, design: .monospaced))
                    .fixedSize()
                }
              }
              .foregroundStyle(.secondary)
              Plain(row.title).font(.system(size: 11.5)).foregroundStyle(.secondary)
            } else {
              Plain(row.title).font(.system(size: 12.5)).foregroundStyle(.secondary)
            }
          }
          Spacer(minLength: 0)
        }
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      if let request = row.request {
        CopyForAgent(text: request, label: "Ask agent").buttonStyle(.link)
          .font(.system(size: 12))
      }
    }
    .padding(.horizontal, 10).padding(.vertical, 5)
  }
}

/// Puts a request for the owner's coding agent on the clipboard, only on their click.
struct CopyForAgent: View {
  let text: String
  var label = "Copy for my agent"
  var prominent = false
  @State private var copied = false
  var body: some View {
    let button = Button {
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(text, forType: .string)
      copied = true
      DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
    } label: {
      Text(verbatim: copied ? "Copied" : label)
    }
    .fixedSize()
    .help("Copies a request for your coding agent to read it and tell you what it is.")
    if prominent { button.buttonStyle(.borderedProminent) } else { button }
  }
}

/// What is watched, as Immune says it: all the time and every hour, and program starts. Only
/// the kinds and their counts: whether each was read in full is not in the status.
struct WatchedBox: View {
  let panel: Panel
  var body: some View {
    Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 8, verticalSpacing: 3) {
      ForEach(panel.watched, id: \.title) { g in
        GridRow {
          Text(verbatim: g.title).fontWeight(.semibold)
          Plain(g.lines.joined(separator: " · "))
        }
      }
      if let starts = panel.programStarts {
        GridRow {
          Text(verbatim: "Program starts").fontWeight(.semibold)
          Plain(starts)
        }
      }
    }
    .font(.system(size: 11.5)).foregroundStyle(.secondary)
    .padding(.horizontal, 10).padding(.vertical, 8)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
  }
}

/// A quiet line to a section of the report, never styled as a problem.
struct QuietRow: View {
  let symbol: String
  let label: String
  var help: String? = nil
  let open: () -> Void

  var body: some View {
    Button(action: open) {
      HStack(spacing: 10) {
        Image(systemName: symbol).font(.system(size: 13)).foregroundStyle(.secondary)
          .frame(width: 20).accessibilityHidden(true)
        Text(verbatim: label).font(.system(size: 13)).lineLimit(1)
        Spacer(minLength: 0)
        Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold))
          .foregroundStyle(.tertiary).accessibilityHidden(true)
      }
      .padding(.horizontal, 10)
      .frame(height: Metrics.row)
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .help(help ?? label)
  }
}

// MARK: - The panel

public struct PanelView: View {
  @ObservedObject var model: AppModel
  /// nil when nothing is watched (an off-screen render or `--print-panel`).
  @ObservedObject var watcher: WatcherBox
  /// Fixed for an off-screen render; nil means now.
  var now: Date?
  /// Opens the system's notification settings for this app.
  var openSettings: () -> Void

  public init(
    model: AppModel, watcher: WatcherBox, now: Date? = nil, openSettings: @escaping () -> Void = {}
  ) {
    self.model = model
    self.watcher = watcher
    self.now = now
    self.openSettings = openSettings
  }

  public var body: some View {
    let p = Panel.of(
      model.reading, now: now ?? Date(), checking: model.runInProgress, notes: model.notes,
      notWatching: watcher.watcher?.notWatching, answering: model.answering,
      refusals: model.refusals, notificationsOff: model.notificationsOff,
      immune: model.immuneCommand)
    Group {
      if let opened = model.opened {
        FindingView(opened: opened, panel: p, model: model, now: now ?? Date())
      } else {
        list(p)
      }
    }
    .frame(width: Metrics.width)
  }

  @ViewBuilder func list(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      HeadlineView(panel: p, openSettings: openSettings)
        .padding(.horizontal, Metrics.padding)
        .padding(.top, Metrics.padding)
        .padding(.bottom, 10)
      VStack(alignment: .leading, spacing: 6) {
        if let first = p.firstDay {
          HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "info.circle").foregroundStyle(Color.accentColor)
              .accessibilityHidden(true)
            Plain(first)
          }
          .font(.system(size: 12))
          .padding(8)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(
            Color.accentColor.opacity(0.08),
            in: RoundedRectangle(cornerRadius: 8, style: .continuous)
          )
          .padding(.horizontal, 10)
        }
        findings(p)
        if let a = p.answered {
          VStack(alignment: .leading, spacing: 6) {
            ForEach(a.lines) { AnsweredBox(line: $0, panel: p, model: model) }
            if let more = a.moreText {
              QuietRow(symbol: "person.badge.clock", label: more) {
                Task { await model.openPage(section: AnsweredRow.section) }
              }
            }
          }
          .padding(.horizontal, 10)
        }
        if !p.notSeen.isEmpty {
          VStack(alignment: .leading, spacing: 0) {
            GroupTitle(text: "Not seen on this Mac · you can fix")
            ForEach(p.notSeen) { n in
              NotSeenView(row: n) { Task { await model.openPage(section: "you-can-fix") } }
            }
          }
          .padding(.horizontal, 0)
        }
        if !p.watched.isEmpty || p.programStarts != nil {
          WatchedBox(panel: p).padding(.horizontal, Metrics.padding)
        }
        if let notJudged = p.notJudged {
          QuietRow(symbol: notJudged.symbol, label: notJudged.text) {
            Task { await model.openPage(section: notJudged.section) }
          }
          .padding(.horizontal, 6)
        }
        if !p.notes.isEmpty {
          VStack(alignment: .leading, spacing: 4) {
            ForEach(Array(p.notes.enumerated()), id: \.offset) { _, line in
              Plain(line).font(.system(size: 12)).foregroundStyle(.secondary)
                .textSelection(.enabled)
            }
          }
          .padding(.horizontal, Metrics.padding)
        }
      }
      .padding(.bottom, 10)
      Divider()
      footer(p)
        .padding(.horizontal, Metrics.padding)
        .padding(.vertical, 12)
    }
  }

  /// The two groups of findings, each row with what is nested under it, and how many more the
  /// report lists.
  @ViewBuilder func findings(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(
        [("Needs you now", p.needsYou), ("To look at", p.toLook)].filter { !$0.1.isEmpty },
        id: \.0
      ) { title, group in
        GroupTitle(text: title)
        ForEach(group) { e in
          FindingRow(row: e.row, badges: e.badges) { open(e.row) }
          ForEach(e.children) { c in NestedRow(row: c) { open(c) } }
        }
      }
      if let more = p.moreText {
        QuietRow(symbol: "list.bullet", label: more) {
          Task { await model.openPage() }
        }
      }
    }
    .padding(.horizontal, 6)
  }

  func open(_ row: Row) {
    guard let id = row.item.id else { return }
    Task { await model.openFinding(id) }
  }

  @ViewBuilder func footer(_ p: Panel) -> some View {
    HStack(spacing: 8) {
      Button(p.footer[0]) { Task { await model.openPage() } }
        .disabled(model.pageOpening)
      Spacer()
      Button {
        Task { await model.runNow() }
      } label: {
        HStack(spacing: 6) {
          if !p.canCheck { ProgressView().controlSize(.small) }
          Text(verbatim: p.footer[1])
        }
      }
      .disabled(!p.canCheck)
      Menu {
        Button(p.menu[0]) { NSApp.terminate(nil) }
      } label: {
        Image(systemName: "ellipsis")
      }
      .menuStyle(.borderedButton)
      .menuIndicator(.hidden)
      .fixedSize()
      .accessibilityLabel("More")
    }
  }
}

/// Lets the panel observe a watcher that may not exist (renders, `--print-panel`).
@MainActor
public final class WatcherBox: ObservableObject {
  public let watcher: Watcher?
  private var forward: AnyCancellable?
  public init(_ watcher: Watcher?) {
    self.watcher = watcher
    forward = watcher?.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }
  }
}
