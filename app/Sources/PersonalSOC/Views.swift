// The panel under the icon. It shows exactly what `Panel` holds, in the order of
// `Panel.lines`: the headline, when it was checked, what needs a look with what to
// do, one quiet line for blind spots, and the footer. Every line of text goes
// through `Text(verbatim:)`, which never interprets markup.
//
// Design: plain native macOS. System fonts, semantic colours and SF Symbols only,
// one spacing scale (4/8/12/16), no colours, gradients or shadows of our own.

import AppKit
import Combine
import SOCCore
import SwiftUI

enum Metrics {
  static let width: CGFloat = 352
  static let padding: CGFloat = 16
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
    case .cannotRead: .secondary
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

struct HeadlineView: View {
  let panel: Panel
  var body: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: panel.light.panelSymbol)
        .font(.system(size: 22))
        .foregroundStyle(panel.light.tint)
        .frame(width: 26)
        .accessibilityLabel(panel.light.spoken)
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
          Plain(panel.headline).font(.system(size: 15, weight: .semibold))
          // While a check runs, something moves, so the panel never looks frozen.
          if panel.busy {
            ProgressView().controlSize(.small).alignmentGuide(.firstTextBaseline) {
              $0[.bottom] - 3
            }
          }
        }
        if let checked = panel.checked {
          Text(verbatim: checked)
            .font(.system(size: 12)).foregroundStyle(.secondary)
            .help(panel.checkedAt ?? "")
        }
        ForEach(Array(panel.help.enumerated()), id: \.offset) { _, line in
          HelpLine(line: line).padding(.top, 4)
        }
        if let reason = panel.reason {
          Plain(reason).font(.system(size: 11)).foregroundStyle(.secondary)
            .textSelection(.enabled).padding(.top, 4)
        }
      }
      Spacer(minLength: 0)
    }
    .accessibilityElement(children: .combine)
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
        + Text(verbatim: Panel.statusCommand).font(.system(size: 12.5, design: .monospaced))
        + Text(verbatim: parts[1])
      : Text(verbatim: line)
    text.font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
  }
}

struct RowCard: View {
  let row: Row
  let panel: Panel
  @ObservedObject var model: AppModel
  let show: () -> Void
  @State private var copied = false

  private var formOpen: Bool { row.canAnswer && panel.form?.id == row.item.id }

  var body: some View {
    HStack(alignment: .top, spacing: 8) {
      Image(systemName: row.symbol)
        .font(.system(size: 13))
        .foregroundStyle(
          row.strong ? AnyShapeStyle(Light.attention(1).tint) : AnyShapeStyle(.secondary)
        )
        .frame(width: 16, height: 17)
        .accessibilityHidden(true)
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
          Plain(row.title)
            .font(.system(size: 13, weight: row.strong ? .semibold : .regular))
            .foregroundStyle(row.quiet ? .secondary : .primary)
          Spacer(minLength: 0)
          if let when = row.when {
            Text(verbatim: when).font(.system(size: 11).monospacedDigit())
              .foregroundStyle(.tertiary).lineLimit(1).layoutPriority(1)
              .help(row.whenFull ?? "")
          }
        }
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
          Plain(refused).font(.system(size: 12)).textSelection(.enabled).padding(.top, 4)
        }
        if formOpen { expectedForm.padding(.top, 4) } else { buttons.padding(.top, 4) }
      }
    }
    .padding(12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    .accessibilityElement(children: .contain)
  }

  var buttons: some View {
    HStack(spacing: 10) {
      if row.canAnswer, let id = row.item.id {
        if panel.answering == id {
          ProgressView().controlSize(.mini)
          Text(verbatim: "Saving…").foregroundStyle(.secondary)
        } else {
          Button("Seen") { Task { await model.answerSeen(id) } }.fixedSize()
            .help("Mark it seen: it stops asking for a look.")
          Button("Expected…") { model.form = ExpectedForm(id: id) }.fixedSize()
            .help("Mark it expected for a while, with a short reason.")
        }
      }
      Spacer(minLength: 0)
      Button("Show", action: show).fixedSize()
      Button(copied ? "Copied" : "Copy for my agent") {
        // Only on the owner's click.
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(row.agentRequest, forType: .string)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
      }
      .fixedSize()
    }
    .buttonStyle(.borderless)
    .foregroundStyle(.tint)
    .font(.system(size: 12))
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
        .font(.system(size: 12))
        .onSubmit { send() }
      HStack(spacing: 8) {
        Text(verbatim: "For").foregroundStyle(.secondary)
        Picker("For", selection: days) {
          ForEach(Answer.days, id: \.self) { n in Text(verbatim: "\(n) days").tag(n) }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
      }
      .controlSize(.small)
      .font(.system(size: 12))
      HStack(spacing: 8) {
        if panel.answering == panel.form?.id {
          ProgressView().controlSize(.mini)
          Text(verbatim: "Saving…").foregroundStyle(.secondary)
        }
        Spacer(minLength: 0)
        Button("Cancel") { model.form = nil }.fixedSize()
        Button("Mark expected") { send() }
          .buttonStyle(.borderedProminent)
          .fixedSize()
          .disabled(!complete || panel.answering != nil)
      }
      .controlSize(.small)
      .font(.system(size: 12))
    }
  }

  private func send() {
    guard let form = model.form, form.isComplete else { return }
    Task { await model.answerExpected(form) }
  }
}

/// A whole-row link: a small symbol, the text, a chevron. Used for "N more" and
/// for the blind spots, which is never styled as a problem.
struct LinkLine: View {
  let symbol: String
  let text: String
  var primary = false
  var chevron = "chevron.right"
  let open: () -> Void
  var body: some View {
    Button(action: open) {
      HStack(spacing: 8) {
        Image(systemName: symbol).font(.system(size: 12)).frame(width: 16)
          .accessibilityHidden(true)
        Text(verbatim: text).font(.system(size: 12))
          .foregroundStyle(primary ? .primary : .secondary)
          .fixedSize(horizontal: false, vertical: true)
        Spacer(minLength: 0)
        Image(systemName: chevron).font(.system(size: 11, weight: .semibold))
          .foregroundStyle(.tertiary)
          .accessibilityHidden(true)
      }
      .foregroundStyle(.secondary)
      .padding(.horizontal, 12)
      .frame(minHeight: 22)
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
  }
}

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
      soc: model.socCommand, watchedOpen: model.watchedOpen)
    VStack(alignment: .leading, spacing: 0) {
      HeadlineView(panel: p)
        .padding(Metrics.padding)
      if !p.shown.isEmpty { cards(p) }
      if p.more > 0 || !p.watched.isEmpty || !p.gaps.isEmpty || p.notWatching != nil
        || p.notificationsOff != nil || !p.notes.isEmpty
      {
        quiet(p).padding(.top, p.shown.isEmpty ? 0 : 4)
      }
      Divider()
      footer(p)
        .padding(.horizontal, Metrics.padding)
        .padding(.vertical, 12)
    }
    .frame(width: Metrics.width)
  }

  @ViewBuilder func cards(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 8) {
      ForEach(p.shown) { row in
        RowCard(row: row, panel: p, model: model) { Task { await model.openPage(at: row.item.id) } }
      }
    }
    .padding(.horizontal, Metrics.padding)
    .padding(.bottom, 12)
  }

  /// Below the cards: how many more, what is watched, what is not covered, whether
  /// the watcher runs, notes.
  @ViewBuilder func quiet(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 8) {
      if p.more > 0 {
        LinkLine(symbol: "ellipsis.circle", text: "\(p.more) more in Details", primary: true) {
          Task { await model.openPage() }
        }
      }
      if !p.watched.isEmpty {
        LinkLine(
          symbol: "eye", text: "What is watched",
          chevron: p.watchedOpen ? "chevron.down" : "chevron.right"
        ) { model.watchedOpen.toggle() }
        if p.watchedOpen {
          VStack(alignment: .leading, spacing: 6) {
            ForEach(p.watched, id: \.title) { group in
              VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: group.title).font(.system(size: 11, weight: .semibold))
                  .foregroundStyle(.secondary)
                ForEach(Array(group.lines.enumerated()), id: \.offset) { _, line in
                  Plain(line).font(.system(size: 11)).foregroundStyle(.secondary)
                }
              }
            }
            Button {
              Task { await model.openPage(section: p.toldAbout.section) }
            } label: {
              Text(verbatim: p.toldAbout.text).font(.system(size: 11)).underline()
                .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
          }
          .padding(.leading, 36)
          .padding(.trailing, 12)
        }
      }
      ForEach(p.gaps) { row in
        LinkLine(symbol: row.symbol, text: row.text) {
          Task { await model.openPage(section: row.section) }
        }
      }
      if let line = p.notWatching {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
          Image(systemName: "pause.circle").font(.system(size: 12)).frame(width: 16)
            .accessibilityHidden(true)
          Plain(line).font(.system(size: 12))
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
      }
      if let line = p.notificationsOff {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
          Image(systemName: "bell.slash").font(.system(size: 12)).frame(width: 16)
            .accessibilityHidden(true)
          Plain(line).font(.system(size: 12))
          Spacer(minLength: 0)
          Button("Open Settings", action: openSettings)
            .buttonStyle(.borderless).foregroundStyle(.tint).font(.system(size: 12)).fixedSize()
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
      }
      ForEach(Array(p.notes.enumerated()), id: \.offset) { _, line in
        Plain(line).font(.system(size: 12)).foregroundStyle(.secondary)
          .padding(.horizontal, 12)
      }
    }
    .padding(.horizontal, Metrics.padding)
    .padding(.bottom, 12)
  }

  @ViewBuilder func footer(_ p: Panel) -> some View {
    HStack(spacing: 8) {
      Button {
        Task { await model.runNow() }
      } label: {
        HStack(spacing: 6) {
          if !p.canCheck { ProgressView().controlSize(.mini) }
          Text(verbatim: p.footer[0])
        }
      }
      .buttonStyle(.borderedProminent)
      .disabled(!p.canCheck)
      Spacer()
      Button(p.footer[1]) { Task { await model.openPage() } }
        .disabled(model.pageOpening)
      Button(p.footer[2]) { NSApp.terminate(nil) }
    }
    .controlSize(.small)
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
