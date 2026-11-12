// The panel under the icon. It shows exactly what `Panel` holds, in the order of
// `Panel.lines`, in five zones: the state, with what to act on under it; what needs a
// look, one card open and the others one line each; quiet rows with a count; "More",
// closed, with how this Mac is watched; the footer. Every line of text goes through
// `Text(verbatim:)`, which never interprets markup.
//
// Design: plain native macOS. System fonts from 11 pt up (13 pt body), semantic
// colours and SF Symbols only, one spacing scale (4/8/12/16), hairlines between zones
// and not between lines. Colour is never the only signal: shapes and words carry it.

import AppKit
import Combine
import SOCCore
import SwiftUI

enum Metrics {
  static let width: CGFloat = 344
  static let padding: CGFloat = 16
  /// The height of a quiet row and of a finding's one-line row.
  static let row: CGFloat = 36
}

/// A line of text shown exactly as given: no markdown, no links, no localisation.
struct Plain: View {
  let text: String
  init(_ text: String) { self.text = text }
  var body: some View { Text(verbatim: text).fixedSize(horizontal: false, vertical: true) }
}

extension Light {
  var tint: Color {
    switch self {
    case .nothingToReport: .green
    case .attention: .orange
    case .cannotRead: Color(nsColor: .systemGray)
    }
  }

  var spoken: String {
    switch self {
    case .nothingToReport: "Calm"
    case .attention: "Needs a look"
    case .cannotRead: "Unknown"
    }
  }
}

/// The colour of a finding's mark: red when soc marked it urgent, orange for high and
/// critical, otherwise none of its own. Its words and symbol say the same.
func markTint(_ row: Row) -> AnyShapeStyle {
  row.urgent
    ? AnyShapeStyle(Color.red)
    : row.strong ? AnyShapeStyle(Light.attention(1).tint) : AnyShapeStyle(.secondary)
}

// MARK: - The state

struct HeadlineView: View {
  let panel: Panel
  let openSettings: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack(alignment: .center, spacing: 12) {
        Image(systemName: panel.light.panelSymbol)
          .font(.system(size: 40))
          .symbolRenderingMode(.palette)
          .foregroundStyle(.white, panel.urgent ? Color.red : panel.light.tint)
          .frame(width: 44, height: 44)
          .accessibilityLabel(panel.light.spoken)
        VStack(alignment: .leading, spacing: 3) {
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
              .lineLimit(1).truncationMode(.tail)
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
        .padding(.leading, 56)
      }
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

// MARK: - What needs a look

/// "Urgent", in words: soc marked it so.
struct UrgentPill: View {
  var body: some View {
    Text(verbatim: "Urgent")
      .font(.system(size: 11, weight: .bold))
      .foregroundStyle(.white)
      .padding(.horizontal, 6).padding(.vertical, 2)
      .background(Color.red, in: RoundedRectangle(cornerRadius: 4, style: .continuous))
  }
}

/// The one open card: what it is, where, why, and what the owner can do.
struct FindingCard: View {
  let row: Row
  let panel: Panel
  @ObservedObject var model: AppModel
  let show: () -> Void

  private var formOpen: Bool { row.canAnswer && panel.form?.id == row.item.id }

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack(spacing: 8) {
        if row.urgent {
          UrgentPill()
        } else {
          Image(systemName: row.symbol).font(.system(size: 12))
            .foregroundStyle(markTint(row)).accessibilityHidden(true)
        }
        if let when = row.when {
          Text(verbatim: when).font(.system(size: 12).monospacedDigit())
            .foregroundStyle(.secondary).lineLimit(1)
            .help(row.whenFull ?? "")
        }
        Spacer(minLength: 0)
        Button("Show", action: show)
          .buttonStyle(.link).font(.system(size: 12)).fixedSize()
          .help("Show it on the program's page")
      }
      Plain(row.title)
        .font(.system(size: 14, weight: .semibold))
      if let value = row.value, let shown = row.shownValue {
        // A path is already cut at its head at a folder boundary; anything still
        // too long loses its head too, never the file's name.
        Text(verbatim: shown)
          .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
          .lineLimit(1).truncationMode(.head)
          .textSelection(.enabled)
          .help(value)
      }
      if let reason = row.reason {
        // The app's label, then the machine's words as data.
        (Text("Reason: ").fontWeight(.medium) + Text(verbatim: reason))
          .font(.system(size: 12)).foregroundStyle(.secondary)
          .lineLimit(2).truncationMode(.tail)
          .fixedSize(horizontal: false, vertical: true)
          .textSelection(.enabled)
          .help(reason)
      }
      if !row.means.isEmpty {
        Plain(row.means).font(.system(size: 12)).foregroundStyle(.secondary)
      }
      if let id = row.item.id, let refused = panel.refusals[id] {
        Plain(refused).font(.system(size: 12)).textSelection(.enabled)
      }
      Group {
        if formOpen { expectedForm } else { buttons }
      }
      .padding(.top, 4)
    }
    .padding(12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(
      row.urgent ? AnyShapeStyle(Color.red.opacity(0.07)) : AnyShapeStyle(.quaternary.opacity(0.5)),
      in: RoundedRectangle(cornerRadius: 10, style: .continuous)
    )
    .overlay(
      RoundedRectangle(cornerRadius: 10, style: .continuous)
        .strokeBorder(row.urgent ? Color.red.opacity(0.3) : Color.primary.opacity(0.06))
    )
    .accessibilityElement(children: .contain)
  }

  var buttons: some View {
    HStack(spacing: 6) {
      if row.canAnswer, let id = row.item.id {
        if panel.answering == id {
          ProgressView().controlSize(.small)
          Text(verbatim: "Saving…").font(.system(size: 13)).foregroundStyle(.secondary)
        } else {
          Button("Expected…") { model.form = ExpectedForm(id: id) }.fixedSize()
            .help("Mark it expected for a while, with a short reason.")
          Button("Seen") { Task { await model.answerSeen(id) } }.fixedSize()
            .help("Mark it seen: it stops asking for a look.")
        }
      }
      Spacer(minLength: 0)
      CopyForAgent(text: row.agentRequest)
    }
    .disabled(panel.answering != nil)
  }

  /// One required text field for the reason and how long; nothing else.
  @ViewBuilder var expectedForm: some View {
    let reason = Binding(
      get: { model.form?.reason ?? "" }, set: { model.form?.reason = $0 })
    let days = Binding(
      get: { model.form?.days ?? Answer.defaultDays }, set: { model.form?.days = $0 })
    let complete = panel.form?.isComplete == true
    VStack(alignment: .leading, spacing: 8) {
      TextField("Why is it expected? (required)", text: reason)
        .textFieldStyle(.roundedBorder)
        .font(.system(size: 13))
        .onSubmit { send() }
      HStack(spacing: 8) {
        Text(verbatim: "For").font(.system(size: 12)).foregroundStyle(.secondary)
        Picker("For", selection: days) {
          ForEach(Answer.days, id: \.self) { n in Text(verbatim: "\(n) days").tag(n) }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
      }
      HStack(spacing: 8) {
        if panel.answering == panel.form?.id {
          ProgressView().controlSize(.small)
          Text(verbatim: "Saving…").font(.system(size: 13)).foregroundStyle(.secondary)
        }
        Spacer(minLength: 0)
        Button("Cancel") { model.form = nil }.fixedSize()
        Button("Mark expected") { send() }
          .buttonStyle(.borderedProminent)
          .fixedSize()
          .disabled(!complete || panel.answering != nil)
      }
    }
  }

  private func send() {
    guard let form = model.form, form.isComplete else { return }
    Task { await model.answerExpected(form) }
  }
}

/// Every other finding: its title alone, on two lines at most, which opens into the card.
struct FindingLine: View {
  let row: Row
  let open: () -> Void
  var body: some View {
    Button(action: open) {
      HStack(spacing: 10) {
        Image(systemName: row.urgent ? "exclamationmark.circle.fill" : row.symbol)
          .font(.system(size: 13)).foregroundStyle(markTint(row))
          .frame(width: 20).accessibilityHidden(true)
        if row.urgent {
          Text(verbatim: "Urgent:").font(.system(size: 13, weight: .semibold))
        }
        Text(verbatim: row.title)
          .font(.system(size: 13, weight: row.strong ? .medium : .regular))
          .foregroundStyle(row.quiet ? .secondary : .primary)
          .lineLimit(2).truncationMode(.tail).multilineTextAlignment(.leading)
          .fixedSize(horizontal: false, vertical: true)
        Spacer(minLength: 4)
        Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold))
          .foregroundStyle(.tertiary).accessibilityHidden(true)
      }
      .padding(.horizontal, 8).padding(.vertical, 6)
      .frame(minHeight: Metrics.row)
      .background(
        .quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8, style: .continuous)
      )
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .help(row.title)
  }
}

/// "Copy for my agent": puts a request for the owner's coding agent on the clipboard,
/// only on their click.
struct CopyForAgent: View {
  let text: String
  @State private var copied = false
  var body: some View {
    Button(copied ? "Copied" : "Copy for my agent") {
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(text, forType: .string)
      copied = true
      DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
    }
    .fixedSize()
  }
}

// MARK: - Quiet rows

/// A fixed-height row: a symbol, a short label, a count, a chevron. Never styled as a
/// problem. `trailing` sits between the label and the count, outside the row's own
/// button, so it keeps its own click.
struct QuietRow<Trailing: View>: View {
  let symbol: String
  let label: String
  var count: Int? = nil
  /// The whole sentence, for help and for VoiceOver.
  var help: String? = nil
  var chevron = "chevron.right"
  let open: () -> Void
  @ViewBuilder var trailing: () -> Trailing

  var body: some View {
    HStack(spacing: 8) {
      Button(action: open) {
        HStack(spacing: 10) {
          Image(systemName: symbol).font(.system(size: 14)).foregroundStyle(.secondary)
            .frame(width: 20).accessibilityHidden(true)
          Text(verbatim: label).font(.system(size: 13)).lineLimit(1)
          Spacer(minLength: 0)
        }
        .frame(maxHeight: .infinity)
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .accessibilityLabel(help ?? label)
      trailing()
      Button(action: open) {
        HStack(spacing: 8) {
          if let count {
            Text(verbatim: String(count)).font(.system(size: 13).monospacedDigit())
              .foregroundStyle(.secondary)
          }
          Image(systemName: chevron).font(.system(size: 11, weight: .semibold))
            .foregroundStyle(.tertiary)
        }
        .frame(maxHeight: .infinity)
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .accessibilityHidden(true)
    }
    .padding(.horizontal, 8)
    .frame(height: Metrics.row)
    .help(help ?? "")
  }
}

extension QuietRow where Trailing == EmptyView {
  init(
    symbol: String, label: String, count: Int? = nil, help: String? = nil,
    chevron: String = "chevron.right", open: @escaping () -> Void
  ) {
    self.init(
      symbol: symbol, label: label, count: count, help: help, chevron: chevron, open: open
    ) { EmptyView() }
  }
}

// MARK: - The panel

struct PanelView: View {
  @ObservedObject var model: AppModel
  /// nil when nothing is watched (an off-screen render or `--print-panel`).
  @ObservedObject var watcher: WatcherBox
  /// Fixed for an off-screen render; nil means now.
  var now: Date? = nil
  /// Opens the system's notification settings for this app.
  var openSettings: () -> Void = {}

  var body: some View {
    let p = Panel.of(
      model.reading, now: now ?? Date(), checking: model.runInProgress, notes: model.notes,
      notWatching: watcher.watcher?.notWatching, form: model.form, answering: model.answering,
      refusals: model.refusals, notificationsOff: model.notificationsOff,
      soc: model.socCommand, moreOpen: model.moreOpen, answeredOpen: model.answeredOpen,
      openRow: model.openRow)
    let quiet = !p.gaps.isEmpty || p.answered != nil || p.hasMore
    VStack(alignment: .leading, spacing: 0) {
      HeadlineView(panel: p, openSettings: openSettings)
        .padding(.horizontal, Metrics.padding)
        .padding(.top, Metrics.padding)
        .padding(.bottom, 14)
      if !p.shown.isEmpty { findings(p).padding(.bottom, 12) }
      if quiet {
        Divider().padding(.horizontal, Metrics.padding)
        quietRows(p).padding(.vertical, 6)
      }
      if !p.notes.isEmpty {
        VStack(alignment: .leading, spacing: 4) {
          ForEach(Array(p.notes.enumerated()), id: \.offset) { _, line in
            Plain(line).font(.system(size: 12)).foregroundStyle(.secondary)
              .textSelection(.enabled)
          }
        }
        .padding(.horizontal, Metrics.padding)
        .padding(.bottom, 12)
      }
      Divider()
      footer(p)
        .padding(.horizontal, Metrics.padding)
        .padding(.vertical, 12)
    }
    .frame(width: Metrics.width)
  }

  /// The open card, the others one line each, and how many more the page lists.
  @ViewBuilder func findings(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 6) {
      ForEach(p.shown) { row in
        if row == p.opened {
          FindingCard(row: row, panel: p, model: model) {
            Task { await model.openPage(at: row.item.id) }
          }
        } else {
          FindingLine(row: row) {
            if model.form?.id != row.item.id { model.form = nil }
            model.openRow = row.id
          }
        }
      }
      if p.more > 0 {
        QuietRow(symbol: "list.bullet", label: "\(p.more) more in Details") {
          Task { await model.openPage() }
        }
      }
    }
    .padding(.horizontal, 10)
  }

  /// What is not covered, the answers given outside the app, and "More".
  @ViewBuilder func quietRows(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(p.gaps) { row in
        QuietRow(symbol: row.symbol, label: row.label, count: row.count, help: row.text) {
          Task { await model.openPage(section: row.section) }
        } trailing: {
          // The row still opens the page; the hand-over to the agent is beside it.
          if row.section == "you-can-fix", let request = p.fixRequest {
            CopyForAgent(text: request).buttonStyle(.link).font(.system(size: 12))
          }
        }
      }
      if let answered = p.answered { answeredRows(p, answered) }
      if p.hasMore { more(p) }
    }
    .padding(.horizontal, 10)
  }

  /// "Answered through your agent", opening in place: each answer with what it is
  /// about, what was said, by whom and why, and Take back.
  @ViewBuilder func answeredRows(_ p: Panel, _ a: AnsweredRow) -> some View {
    QuietRow(
      symbol: "person.badge.clock", label: a.label, count: a.count, help: a.text,
      chevron: p.answeredOpen ? "chevron.down" : "chevron.right"
    ) { model.answeredOpen.toggle() }
    if p.answeredOpen {
      VStack(alignment: .leading, spacing: 10) {
        ForEach(a.lines) { line in
          VStack(alignment: .leading, spacing: 2) {
            Plain(line.title).font(.system(size: 12, weight: .semibold))
            Plain([line.answer, line.by].compactMap { $0 }.joined(separator: ", "))
              .font(.system(size: 12)).foregroundStyle(.secondary)
            if let reason = line.reason {
              Text(verbatim: reason).font(.system(size: 12)).foregroundStyle(.secondary)
                .lineLimit(2).truncationMode(.tail).textSelection(.enabled).help(reason)
            }
            if let id = line.target, let refused = p.refusals[id] {
              Plain(refused).font(.system(size: 12)).textSelection(.enabled)
            }
            if let id = line.target {
              if p.answering == id {
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
                .buttonStyle(.link).font(.system(size: 12))
                .fixedSize().disabled(p.answering != nil)
                .help(
                  line.finding != nil
                    ? "Show it again as something that needs a look."
                    : "Check this machine again at the next server check.")
              }
            }
          }
        }
        if a.more > 0 {
          Button("\(a.more) more in Details") {
            Task { await model.openPage(section: AnsweredRow.section) }
          }
          .buttonStyle(.link).font(.system(size: 12))
        }
      }
      .padding(.leading, 38)
      .padding(.trailing, 8)
      .padding(.bottom, 8)
    }
  }

  /// "More": how this Mac is watched and what is watched, closed until asked for.
  @ViewBuilder func more(_ p: Panel) -> some View {
    QuietRow(
      symbol: "ellipsis.circle", label: "More",
      chevron: p.moreOpen ? "chevron.down" : "chevron.right"
    ) { model.moreOpen.toggle() }
    if p.moreOpen {
      VStack(alignment: .leading, spacing: 10) {
        if let checked = p.checked {
          Plain(checked).font(.system(size: 12)).foregroundStyle(.secondary)
        }
        ForEach(p.watched, id: \.title) { group in
          VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: group.title).font(.system(size: 12, weight: .semibold))
            ForEach(Array(group.lines.enumerated()), id: \.offset) { _, line in
              Plain(line).font(.system(size: 12)).foregroundStyle(.secondary)
            }
          }
        }
        if !p.watched.isEmpty {
          Button(p.toldAbout.text) {
            Task { await model.openPage(section: p.toldAbout.section) }
          }
          .buttonStyle(.link).font(.system(size: 12))
        }
      }
      .padding(.leading, 38)
      .padding(.trailing, 8)
      .padding(.bottom, 8)
    }
  }

  @ViewBuilder func footer(_ p: Panel) -> some View {
    let check = Button {
      Task { await model.runNow() }
    } label: {
      HStack(spacing: 6) {
        if !p.canCheck { ProgressView().controlSize(.small) }
        Text(verbatim: p.footer[0])
      }
    }
    .disabled(!p.canCheck)
    HStack(spacing: 8) {
      // The strongest button is the one thing to do: Check now when nothing needs a
      // look, otherwise the card's own buttons.
      if p.shown.isEmpty {
        check.buttonStyle(.borderedProminent)
      } else {
        check
      }
      Button(p.footer[1]) { Task { await model.openPage() } }
        .disabled(model.pageOpening)
      Spacer()
      Button(p.footer[2]) { NSApp.terminate(nil) }
    }
  }
}

/// Lets the panel observe a watcher that may not exist (renders, `--print-panel`).
@MainActor
final class WatcherBox: ObservableObject {
  let watcher: Watcher?
  private var forward: AnyCancellable?
  init(_ watcher: Watcher?) {
    self.watcher = watcher
    forward = watcher?.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }
  }
}
