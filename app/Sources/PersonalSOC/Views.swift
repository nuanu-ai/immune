// The panel under the icon. It shows exactly what `Panel` holds, in the order of
// `Panel.lines`: the headline, when it was checked, what needs a look with what to
// do, one quiet line for blind spots, and the footer. Every line of text goes
// through `Text(verbatim:)`, which never interprets markup.
//
// Design: plain native macOS. System fonts, semantic colours and SF Symbols only,
// one spacing scale (4/8/12/16), no colours, gradients or shadows of our own.

import AppKit
import SOCCore
import SwiftUI

enum Metrics {
  static let width: CGFloat = 352
  static let padding: CGFloat = 16
  /// The rows scroll beyond this height; headline and footer stay put.
  static let rowsMaxHeight: CGFloat = 340
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
        Plain(panel.headline).font(.system(size: 15, weight: .semibold))
        if let checked = panel.checked {
          Text(verbatim: checked)
            .font(.system(size: 12)).foregroundStyle(.secondary)
            .help(panel.checkedAt ?? "")
        }
        ForEach(Array(panel.help.enumerated()), id: \.offset) { _, line in
          HelpLine(line: line).padding(.top, 4)
        }
        if let reason = panel.reason {
          Plain(reason).font(.system(size: 11)).foregroundStyle(.tertiary)
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
  let show: () -> Void
  @State private var copied = false

  var body: some View {
    HStack(alignment: .top, spacing: 8) {
      Image(systemName: row.kind.symbol)
        .font(.system(size: 13))
        .foregroundStyle(.secondary)
        .frame(width: 16, height: 17)
        .accessibilityHidden(true)
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
          Plain(row.sentence + ".").font(.system(size: 13))
          Spacer(minLength: 0)
          if let when = row.when {
            Text(verbatim: when).font(.system(size: 11).monospacedDigit())
              .foregroundStyle(.tertiary).lineLimit(1).layoutPriority(1)
              .help(row.whenFull ?? "")
          }
        }
        if let value = row.value {
          Text(verbatim: value)
            .font(.system(size: 11.5, design: .monospaced)).foregroundStyle(.secondary)
            .lineLimit(1).truncationMode(.middle)
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
        Plain(row.means + " " + row.todo).font(.system(size: 12)).foregroundStyle(.secondary)
        HStack(spacing: 12) {
          Spacer(minLength: 0)
          Button("Show", action: show)
          Button(copied ? "Copied" : "Copy for my agent") {
            // Only on the owner's click.
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(row.agentRequest, forType: .string)
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
          }
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.tint)
        .font(.system(size: 12))
        .padding(.top, 4)
      }
    }
    .padding(12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    .accessibilityElement(children: .contain)
  }
}

/// A whole-row link: a small symbol, the text, a chevron. Used for "N more" and
/// for the blind spots, which is never styled as a problem.
struct LinkLine: View {
  let symbol: String
  let text: String
  var primary = false
  let open: () -> Void
  var body: some View {
    Button(action: open) {
      HStack(spacing: 8) {
        Image(systemName: symbol).font(.system(size: 12)).frame(width: 16)
          .accessibilityHidden(true)
        Text(verbatim: text).font(.system(size: 12))
          .foregroundStyle(primary ? .primary : .secondary)
        Spacer(minLength: 0)
        Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold))
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
  /// Fixed for an off-screen render; nil means now.
  var now: Date? = nil

  var body: some View {
    let p = Panel.of(
      model.reading, now: now ?? Date(), checking: model.runInProgress, notes: model.notes)
    VStack(alignment: .leading, spacing: 0) {
      HeadlineView(panel: p)
        .padding(Metrics.padding)
      if !p.shown.isEmpty {
        // The cards take their natural height up to the maximum, then scroll.
        ScrollView(.vertical) { cards(p) }
          .scrollBounceBehavior(.basedOnSize)
          .frame(maxHeight: Metrics.rowsMaxHeight)
          .fixedSize(horizontal: false, vertical: true)
      }
      if p.more > 0 || p.blind != nil || !p.notes.isEmpty {
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
        RowCard(row: row) { Task { await model.openPage(at: row.fields) } }
      }
    }
    .padding(.horizontal, Metrics.padding)
    .padding(.bottom, 12)
  }

  /// Below the cards, outside the scrolling: how many more, the blind spots, notes.
  @ViewBuilder func quiet(_ p: Panel) -> some View {
    VStack(alignment: .leading, spacing: 8) {
      if p.more > 0 {
        LinkLine(symbol: "ellipsis.circle", text: "\(p.more) more in Details", primary: true) {
          Task { await model.openPage() }
        }
      }
      if let blind = p.blind {
        LinkLine(symbol: "eye.slash", text: blind) { Task { await model.openPage() } }
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
