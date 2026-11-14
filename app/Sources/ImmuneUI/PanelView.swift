// The panel under the icon: a header, a list and a footer. It shows exactly what `Panel` holds,
// in the order of `Panel.lines`: the state and the line under it; the app's own messages; the
// findings in two groups, each one row that starts with the thing itself; the answers given
// through the agent; what is not seen on this Mac; what is watched; what was not judged on this
// Mac; the footer. A click on a finding opens it in place (`FindingView`). Every line of text
// goes through `Text(verbatim:)`, which never interprets markup.
//
// Design: the design sheet's components, plain native macOS. Every measure, text style, colour
// and symbol comes from `Style.swift`; no view chooses its own. One signal of importance: only
// what needs the person now is red, and only in the header's glyph; rows carry no colour.
//
// The panel never grows past the screen it opens on: given a height, the header and the footer
// stay whole and the list between them scrolls.

import AppKit
import Combine
import ImmuneCore
import SwiftUI

/// A line of text shown exactly as given: no markdown, no links, no localisation.
struct Plain: View {
  let text: String
  init(_ text: String) { self.text = text }
  var body: some View { Text(verbatim: text).fixedSize(horizontal: false, vertical: true) }
}

/// A value from the Mac on one line in monospace, cut to the width it is given by `Inert`: a
/// path so its last component stays whole, with `end` at its end, anything else in its middle.
/// Measured with the font it is drawn in. The app cuts it, never the text system: a cut made by
/// the text system on a line of isolated pieces can draw them out of order, and a cut made here
/// leaves the isolation whole (`Inert.display`).
///
/// With `program`, `text` is that program's arguments, and the line is cut by `Evidence.fit`:
/// the program's last component stays whole and the arguments take what is left.
struct DataLine: View {
  let text: String
  var path = true
  var end = false
  var program: String? = nil
  var style = TextStyle.data

  var body: some View {
    let f = style.nsFont
    // As wide as the whole value at most, so what follows it on its line stands right after it.
    let whole = Inert.display(program.map { $0 + " " + text } ?? text)
    let wholeWidth = ceil((whole as NSString).size(withAttributes: [.font: f]).width)
    let rise = (f.ascender + f.descender) / 2
    Color.clear
      .frame(maxWidth: wholeWidth, minHeight: style.line, maxHeight: style.line)
      .overlay(alignment: .leading) {
        GeometryReader { g in
          let width = g.size.width
          let fits = { (s: String) in
            (Inert.display(s) as NSString).size(withAttributes: [.font: f]).width <= width
          }
          Text(verbatim: Inert.display(cut(fits)))
            .font(style.font).foregroundStyle(style.role.style)
            .lineLimit(1).fixedSize()
            .frame(maxHeight: .infinity, alignment: .leading)
        }
      }
      // The text's own baseline, so a label or "+3 more" beside it stands on the same line: the
      // text is centred in the line's height.
      .alignmentGuide(.firstTextBaseline) { d in d.height / 2 + rise }
      .alignmentGuide(.lastTextBaseline) { d in d.height / 2 + rise }
  }

  func cut(_ fits: (String) -> Bool) -> String {
    if let program { return Evidence.fit(program: program, arguments: text, fits: fits) }
    if end && !path { return Inert.end(text, fits: fits) }
    return Inert.fit(text, path: path, fits: fits)
  }
}

/// Text from the Mac or a source, whole: monospace, selectable, shown exactly as given, each
/// piece isolated so a right-to-left letter cannot reorder it (`Inert.display`).
struct DataText: View {
  let text: String
  var style = TextStyle.data
  var body: some View {
    Text(verbatim: Inert.display(text))
      .textStyle(style)
      .fixedSize(horizontal: false, vertical: true)
      .textSelection(.enabled)
  }
}

extension Text {
  /// A piece of a line in a style, to be joined with others: font and colour only; the line's
  /// height is the whole line's (`textStyle`).
  func styled(_ s: TextStyle) -> Text {
    font(s.font).foregroundStyle(s.role.style)
  }
}

extension PanelState {
  /// The state in words, for VoiceOver: the glyph's shape and colour say it to the eye.
  var spoken: String {
    switch self {
    case .calm: "Calm"
    case .now: "Needs you now"
    case .look: "To look at"
    case .part: "Watched in part"
    case .stale: "Old"
    case .cant: "Unknown"
    case .busy: "Checking"
    }
  }
}

// MARK: - The header

/// The state glyph: a disc for calm (green), for what needs the person now (red) and for what is
/// to look at (grey), its mark white; a grey ring for a Mac watched in part and for an old answer;
/// a dashed ring for can't tell; a turning indicator on a fill while a check runs.
struct StateGlyph: View {
  let state: PanelState
  var filled: Bool { state == .calm || state == .now || state == .look }

  var body: some View {
    ZStack {
      switch state {
      case .calm: Circle().fill(Palette.calm)
      case .now: Circle().fill(Palette.now)
      case .look: Circle().fill(Palette.quiet)
      case .part, .stale: Circle().strokeBorder(Palette.quiet, lineWidth: Metrics.ring)
      case .cant:
        Circle().strokeBorder(
          Palette.quiet, style: StrokeStyle(lineWidth: Metrics.ring, dash: Metrics.ringDash))
      case .busy: Circle().fill(Palette.circle)
      }
      if let mark = Symbols.glyph(state) {
        Image(systemName: mark).font(SymbolStyle.glyph.font)
          .foregroundStyle(filled ? Palette.onFill : Palette.quiet)
      } else {
        ProgressView().controlSize(.small)
      }
    }
    .frame(width: Metrics.leading, height: Metrics.leading)
    .accessibilityElement()
    .accessibilityLabel(state.spoken)
  }
}

struct HeaderView: View {
  let panel: Panel

  var body: some View {
    HStack(alignment: .top, spacing: Metrics.gap) {
      StateGlyph(state: panel.state).padding(.top, Metrics.glyphTop)
      VStack(alignment: .leading, spacing: 0) {
        Plain(panel.headline).textStyle(.title)
        if let glance = panel.glance {
          Text(verbatim: glance).textStyle(.caption)
            .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            .padding(.top, Metrics.lineGap)
            .help(panel.checkedAt ?? glance)
        }
        // What the owner can do, and what it rests on, under the state.
        ForEach(Array(panel.help.enumerated()), id: \.offset) { _, line in
          HelpLine(line: line).padding(.top, Metrics.helpTop)
        }
        if let reason = panel.reason {
          Plain(reason).textStyle(.caption).textSelection(.enabled)
            .padding(.top, Metrics.lineGap)
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
    .padding(.horizontal, Metrics.inset)
    .padding(.top, Metrics.headerTop).padding(.bottom, Metrics.headerBottom)
  }
}

/// A sentence of the app's own, with the terminal command in it set in monospace.
struct HelpLine: View {
  let line: String
  var body: some View {
    let parts = line.components(separatedBy: Panel.statusCommand)
    let text: Text =
      parts.count == 2
      ? Text(verbatim: parts[0]) + Text(verbatim: Panel.statusCommand).styled(.data)
        + Text(verbatim: parts[1])
      : Text(verbatim: line)
    text.textStyle(.body).fixedSize(horizontal: false, vertical: true)
  }
}

// MARK: - The list

/// A group's heading, on the edge, in sentence case.
struct GroupTitle: View {
  let text: String
  var body: some View {
    Text(verbatim: text)
      .textStyle(.captionStrong)
      .lineLimit(1)
      .padding(.horizontal, Metrics.inset)
      .padding(.top, Metrics.groupTop).padding(.bottom, Metrics.groupBottom)
      .frame(maxWidth: .infinity, alignment: .leading)
      .accessibilityAddTraits(.isHeader)
  }
}

/// A row of the list: the symbol in its circle in the leading column, the lines from the text
/// edge to the text's right edge, and the chevron column on the right edge, the chevron centred
/// on the circle. 44 high with two lines, 60 with three. Its highlight starts 8 in from the side.
struct RowFrame<Lines: View>: View {
  let symbol: String
  var chevron = true
  var hover = true
  @ViewBuilder var lines: () -> Lines

  var body: some View {
    let row = HStack(alignment: .top, spacing: Metrics.gap) {
      RowIcon(symbol: symbol).padding(.top, Metrics.circleTop)
      VStack(alignment: .leading, spacing: Metrics.lineGap) { lines() }
        .frame(maxWidth: .infinity, alignment: .leading)
      Group {
        if chevron { Chevron() } else { Color.clear.frame(width: Metrics.chevron) }
      }
      .padding(.top, Metrics.chevronTop)
    }
    .padding(.horizontal, Metrics.highlightPadding).padding(.vertical, Metrics.rowVertical)
    .frame(minHeight: Metrics.row, alignment: .top)
    .contentShape(Rectangle())
    Group {
      if hover { row.modifier(Hover()) } else { row }
    }
    .padding(.horizontal, Metrics.highlight)
  }
}

/// A row's second line: words on the left, cut at their end, and what stands at the right: the
/// time, or a link.
struct MetaLine<Right: View>: View {
  let text: String
  @ViewBuilder var right: () -> Right
  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: Metrics.gap) {
      Text(verbatim: text).textStyle(.caption).lineLimit(1).truncationMode(.tail)
      Spacer(minLength: 0)
      right()
    }
  }
}

extension MetaLine where Right == EmptyView {
  init(text: String) { self.init(text: text) { EmptyView() } }
}

/// The time at a row's right.
struct Time: View {
  let when: String?
  var full: String? = nil
  var body: some View {
    if let when {
      Text(verbatim: when).textStyle(.caption).lineLimit(1).fixedSize().help(full ?? when)
    }
  }
}

/// A link at a row's right, a button of its own on the row.
struct RowLink: View {
  let label: String
  let action: () -> Void
  var body: some View {
    Button(action: action) { Text(verbatim: label).textStyle(.link) }
      .buttonStyle(.plain).fixedSize()
  }
}

/// One finding, with what the response layer said of it, as one row: the kind's symbol; the
/// thing itself as data, one line; its kind and what happened, with the time at the right; the
/// response layer's word on a third line. No colour: the group says what needs the person now.
/// The whole row opens it.
struct FindingRow: View {
  let entry: Entry
  let open: () -> Void
  var row: Row { entry.row }

  var body: some View {
    Button(action: open) {
      RowFrame(symbol: row.symbol) {
        if let command = row.command {
          DataLine(text: command.arguments, program: command.program)
        } else if row.objectIsData {
          DataLine(text: row.object, path: row.objectIsPath)
        } else {
          Text(verbatim: row.object).textStyle(.body).lineLimit(1).truncationMode(.tail)
        }
        MetaLine(text: row.meta) { Time(when: row.when, full: row.whenFull) }
        if let words = entry.responseLayer {
          Text(verbatim: words).textStyle(.caption).lineLimit(1)
        }
      }
    }
    .buttonStyle(.plain)
    .disabled(!row.canOpen)
    .help((row.objectIsData ? Inert.display(row.object) : row.object) + "\n" + row.title)
  }
}

/// An answer given through the agent or the command line that hides a finding now, or a
/// statement that set a machine aside, as a row: the thing as data, what was said, and Take
/// back at the right. The reason as the person gave it is in the tooltip and in the opened
/// finding.
struct AnsweredRowView: View {
  let line: AnsweredLine
  let panel: Panel
  @ObservedObject var model: AppModel

  var body: some View {
    RowFrame(symbol: Icons.answered, chevron: line.finding != nil, hover: line.finding != nil) {
      DataLine(text: line.title, path: Inert.isPath(line.title))
      MetaLine(text: line.answer + (line.finding == nil ? ", " + (line.by ?? "") : "")) {
        takeBack
      }
      if let id = line.target, let refused = panel.refusals[id] {
        Plain(refused).textStyle(.caption).textSelection(.enabled)
      }
    }
    .onTapGesture { open() }
    .accessibilityAddTraits(line.finding != nil ? .isButton : [])
    .help([line.answer, line.by, line.reason].compactMap { $0 }.joined(separator: "\n"))
  }

  func open() {
    guard let finding = line.finding else { return }
    Task { await model.openFinding(finding) }
  }

  @ViewBuilder var takeBack: some View {
    if let id = line.target {
      if panel.answering == id {
        Text(verbatim: "Saving…").textStyle(.caption)
      } else {
        RowLink(label: "Take back") {
          Task {
            if line.finding != nil {
              await model.takeBack(id)
            } else {
              await model.withdrawStatement(id)
            }
          }
        }
        .disabled(panel.answering != nil)
        .help(
          line.finding != nil
            ? "Show it again as something that needs a look."
            : "Check this machine again at the next server check.")
      }
    }
  }
}

/// One thing not seen on this Mac that the person can fix: the first thing it is about as data
/// and how many more, Immune's title under it, and "Ask agent", which copies a request about it.
/// Without an example: Immune's title, and its kind and since when under it.
struct NotSeenView: View {
  let row: NotSeenRow
  let open: () -> Void

  var body: some View {
    RowFrame(symbol: Icons.notSeen) {
      if let example = row.example {
        HStack(alignment: .firstTextBaseline, spacing: Metrics.moreGap) {
          DataLine(
            text: example, path: row.examplePath, end: true,
            style: TextStyle.data.role(.secondary))
          if let more = row.moreText {
            Text(verbatim: more).textStyle(.caption).fixedSize()
          }
          Spacer(minLength: 0)
        }
      } else {
        Text(verbatim: row.kind).textStyle(TextStyle.body.role(.secondary))
          .lineLimit(1).truncationMode(.tail)
      }
      MetaLine(text: row.second) {
        if let request = row.request {
          CopyForAgent(text: request, label: "Ask agent", style: .link)
        }
      }
    }
    // The row opens the report's section; "Ask agent" is a button of its own on it.
    .onTapGesture(perform: open)
    .accessibilityAddTraits(.isButton)
    .accessibilityAction(named: "Open in report", open)
    .help(row.title)
  }
}

/// Puts a request for the owner's coding agent on the clipboard, only on their click: a link in
/// a row, or a button of the opened finding's footer.
struct CopyForAgent: View {
  enum Look { case link, button, primary }
  let text: String
  var label = "Copy for my agent"
  var style = Look.button
  @State private var copied = false

  var body: some View {
    let button = Button {
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(text, forType: .string)
      copied = true
      DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
    } label: {
      if style == .link {
        Text(verbatim: copied ? "Copied" : label).textStyle(.link)
      } else {
        Text(verbatim: copied ? "Copied" : label)
      }
    }
    .fixedSize()
    .help("Copies a request for your coding agent to read it and tell you what it is.")
    switch style {
    case .link: button.buttonStyle(.plain)
    case .button: button
    case .primary: button.buttonStyle(.borderedProminent)
    }
  }
}

/// The dot of program starts: filled when they are seen, a ring when they are not.
struct Dot: View {
  let on: Bool
  var body: some View {
    Group {
      if on {
        Circle().fill(Palette.quiet)
      } else {
        Circle().strokeBorder(Palette.quiet, lineWidth: Metrics.dotLine)
      }
    }
    .frame(width: Metrics.dot, height: Metrics.dot)
  }
}

/// What is watched, as one row of two lines: how many kinds are seen all the time and how many
/// are read every hour, and program starts with a dot on the line they are read on. The kinds by
/// name are in the tooltip and in the report, which a click opens.
struct CoverageRow: View {
  let lines: [CoverageLine]
  let open: () -> Void

  var body: some View {
    Button(action: open) {
      RowFrame(symbol: Icons.watched) {
        Grid(
          alignment: .leadingFirstTextBaseline, horizontalSpacing: Metrics.gap,
          verticalSpacing: Metrics.lineGap
        ) {
          ForEach(lines, id: \.title) { line in
            GridRow {
              Text(verbatim: line.title).textStyle(.caption)
                .frame(width: Metrics.label, alignment: .leading)
              value(line).gridColumnAlignment(.leading)
            }
          }
        }
        .padding(.top, Metrics.coverageTop)
      }
    }
    .buttonStyle(.plain)
    .help(lines.map(tooltip).joined(separator: "\n"))
  }

  /// Each kind in Immune's words with its count, and program starts with Immune's word for the
  /// event level's state when they are not seen.
  func tooltip(_ line: CoverageLine) -> String {
    var parts = line.detail
    if let starts = line.starts {
      let words = starts.words.map { " (" + $0 + ")" } ?? ""
      parts.append(starts.text + words)
    }
    return line.title + ": " + parts.joined(separator: ", ")
  }

  @ViewBuilder func value(_ line: CoverageLine) -> some View {
    if let none = line.none {
      Text(verbatim: none).textStyle(TextStyle.caption.role(.primary)).lineLimit(1)
    } else {
      HStack(alignment: .firstTextBaseline, spacing: 0) {
        if let kinds = line.kindsText {
          Text(verbatim: kinds + (line.starts != nil ? " · " : ""))
            .textStyle(TextStyle.caption.role(.primary))
        }
        if let starts = line.starts {
          Dot(on: starts.on)
            .alignmentGuide(.firstTextBaseline) { $0[.bottom] + Metrics.dotRise }
            .padding(.trailing, Metrics.dotGap)
          Text(verbatim: starts.text).textStyle(TextStyle.caption.role(.primary))
        }
      }
      .lineLimit(1)
    }
  }
}

/// A quiet line to a section of the report: words at the text edge and a chevron, never styled
/// as a problem.
struct QuietRow: View {
  let label: String
  var help: String? = nil
  let open: () -> Void

  var body: some View {
    Button(action: open) {
      HStack(spacing: Metrics.gap) {
        Text(verbatim: label).textStyle(.caption).lineLimit(1).truncationMode(.tail)
        Spacer(minLength: 0)
        Chevron()
      }
      .padding(.leading, Metrics.textEdge - Metrics.highlight)
      .padding(.trailing, Metrics.highlightPadding)
      .frame(height: Metrics.quietRow)
      .contentShape(Rectangle())
      .modifier(Hover())
      .padding(.horizontal, Metrics.highlight)
    }
    .buttonStyle(.plain)
    .help(help ?? label)
  }
}

/// A message of the app's own as a row: its symbol in a circle, what it is, a word on it and,
/// for notifications that are off, the way to turn them on. Nothing to open.
struct MessageRowView: View {
  let message: MessageRow
  let openSettings: () -> Void

  var body: some View {
    RowFrame(symbol: message.symbol, chevron: false, hover: false) {
      Plain(message.title).textStyle(.body)
      MetaLine(text: message.detail) {
        if message.kind == .notificationsOff {
          RowLink(label: "Open Settings", action: openSettings)
        }
      }
    }
  }
}

// MARK: - The panel

/// The fixed parts of the panel, for a test to find where they are drawn.
public enum PanelPart: String, Sendable {
  case headline, footer
}

public struct PanelView: View {
  @ObservedObject var model: AppModel
  /// nil when nothing is watched (an off-screen render or `--print-panel`).
  @ObservedObject var watcher: WatcherBox
  /// Fixed for an off-screen render; nil means now.
  var now: Date?
  /// The most the panel may be high: the visible height of the screen it opens on, less a
  /// margin. nil draws it whole, however high (an off-screen render).
  var maxHeight: CGFloat?
  /// Opens the system's notification settings for this app.
  var openSettings: () -> Void
  /// Told where the headline and the footer are drawn in the panel, for a test.
  var probe: (@MainActor (PanelPart, CGRect) -> Void)?

  @State private var headerHeight: CGFloat = 0
  @State private var footerHeight: CGFloat = 0
  @State private var middleHeight: CGFloat = 0
  @State private var openedHeight: CGFloat = 0
  @State private var openedFooterHeight: CGFloat = 0

  nonisolated static let space = "immune.panel"

  /// The most the panel may be high on a screen whose visible part is this high.
  public static func maxHeight(visible: CGFloat) -> CGFloat {
    max(0, visible - Metrics.screenMargin)
  }

  public init(
    model: AppModel, watcher: WatcherBox, now: Date? = nil, maxHeight: CGFloat? = nil,
    openSettings: @escaping () -> Void = {},
    probe: (@MainActor (PanelPart, CGRect) -> Void)? = nil
  ) {
    self.model = model
    self.watcher = watcher
    self.now = now
    self.maxHeight = maxHeight
    self.openSettings = openSettings
    self.probe = probe
  }

  public var body: some View {
    let p = Panel.of(
      model.reading, now: now ?? Date(), checking: model.runInProgress, notes: model.notes,
      notWatching: watcher.watcher?.notWatching, answering: model.answering,
      refusals: model.refusals, notificationsOff: model.notificationsOff,
      immune: model.immuneCommand)
    Group {
      if let opened = model.opened {
        VStack(alignment: .leading, spacing: 0) {
          scrolling(height: $openedHeight, room: openedRoom) {
            FindingView(opened: opened, panel: p, model: model, now: now ?? Date())
          }
          FindingFooter(opened: opened, panel: p, model: model, now: now ?? Date())
            .onGeometryChange(for: CGFloat.self) {
              $0.size.height
            } action: {
              openedFooterHeight = $0
            }
        }
      } else {
        list(p)
      }
    }
    .frame(width: Metrics.width)
    .coordinateSpace(.named(Self.space))
  }

  /// The room the list has between the header and the footer, or nil when it has no limit.
  var room: CGFloat? {
    maxHeight.map { max(0, $0 - headerHeight - footerHeight - 2 * Metrics.separator) }
  }

  /// The room the opened finding has above its footer.
  var openedRoom: CGFloat? {
    maxHeight.map { max(0, $0 - openedFooterHeight) }
  }

  @ViewBuilder func list(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      HeaderView(panel: p)
        .onGeometryChange(for: CGRect.self) {
          $0.frame(in: .named(Self.space))
        } action: {
          headerHeight = $0.height
          probe?(.headline, $0)
        }
      Separator()
      scrolling(height: $middleHeight, room: room) { middle(p) }
      Separator()
      footer(p)
        .padding(.horizontal, Metrics.inset)
        .padding(.vertical, Metrics.footerVertical)
        .onGeometryChange(for: CGRect.self) {
          $0.frame(in: .named(Self.space))
        } action: {
          footerHeight = $0.height
          probe?(.footer, $0)
        }
    }
  }

  /// Content as high as it is, or, when a room is given, in a scroll view no higher than the
  /// room and no higher than the content.
  @ViewBuilder func scrolling<Content: View>(
    height: Binding<CGFloat>, room: CGFloat?, @ViewBuilder _ content: () -> Content
  ) -> some View {
    if let room {
      ScrollView(.vertical) {
        content()
          .onGeometryChange(for: CGFloat.self) {
            $0.size.height
          } action: {
            height.wrappedValue = $0
          }
      }
      .scrollBounceBehavior(.basedOnSize)
      .frame(height: min(height.wrappedValue, room))
    } else {
      content()
    }
  }

  @ViewBuilder func middle(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(p.messages, id: \.kind) { MessageRowView(message: $0, openSettings: openSettings) }
      findings(p)
      if let a = p.answered {
        GroupTitle(text: a.heading)
        ForEach(a.lines) { AnsweredRowView(line: $0, panel: p, model: model) }
        if let more = a.moreText {
          QuietRow(label: more) { Task { await model.openPage(section: AnsweredRow.section) } }
        }
      }
      if !p.notSeen.isEmpty {
        GroupTitle(text: Panel.notSeenHeading)
        ForEach(p.notSeen) { n in
          NotSeenView(row: n) { Task { await model.openPage(section: "you-can-fix") } }
        }
      }
      if !p.watched.isEmpty {
        CoverageRow(lines: p.watched) {
          Task { await model.openPage(section: "watched-here") }
        }
        .padding(.top, standsAlone(p) ? 0 : Metrics.coverageGap)
      }
      if let notJudged = p.notJudged {
        QuietRow(label: notJudged.text) {
          Task { await model.openPage(section: notJudged.section) }
        }
      }
      if !p.notes.isEmpty {
        VStack(alignment: .leading, spacing: Metrics.lineGap) {
          ForEach(Array(p.notes.enumerated()), id: \.offset) { _, line in
            Plain(line).textStyle(.caption).textSelection(.enabled)
          }
        }
        .padding(.horizontal, Metrics.inset).padding(.top, Metrics.gap)
      }
    }
    .padding(.top, Metrics.listTop).padding(.bottom, Metrics.listBottom)
  }

  /// Nothing stands above what is watched in the list.
  func standsAlone(_ p: Panel) -> Bool {
    p.messages.isEmpty && p.needsYou.isEmpty && p.toLook.isEmpty && p.moreText == nil
      && p.answered == nil && p.notSeen.isEmpty
  }

  /// The two groups of findings, and how many more the report lists.
  @ViewBuilder func findings(_ p: Panel) -> some View {
    ForEach(
      [("Needs you now", p.needsYou), ("To look at", p.toLook)].filter { !$0.1.isEmpty },
      id: \.0
    ) { title, group in
      GroupTitle(text: title)
      ForEach(group) { e in
        FindingRow(entry: e) { open(e.row) }
      }
    }
    if let more = p.moreText {
      QuietRow(label: more) { Task { await model.openPage() } }
    }
  }

  func open(_ row: Row) {
    guard let id = row.item.id else { return }
    Task { await model.openFinding(id) }
  }

  @ViewBuilder func footer(_ p: Panel) -> some View {
    HStack(spacing: Metrics.footerGap) {
      Button(p.footer[0]) { Task { await model.openPage() } }
        .disabled(model.pageOpening)
      Spacer(minLength: 0)
      Button {
        Task { await model.runNow() }
      } label: {
        HStack(spacing: Metrics.gap) {
          if !p.canCheck { ProgressView().controlSize(.mini) }
          Text(verbatim: p.footer[1])
        }
      }
      .disabled(!p.canCheck)
      Menu {
        Button(p.menu[0]) { NSApp.terminate(nil) }
      } label: {
        Image(systemName: Symbols.menu).font(SymbolStyle.more.font)
      }
      .menuStyle(.borderedButton)
      .menuIndicator(.hidden)
      .frame(width: Metrics.more)
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
