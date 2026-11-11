// The panel under the icon. It shows exactly what `Panel` holds, in the order of
// `Panel.lines`: the headline, when it was checked, what needs a look with what to
// do, one quiet line for blind spots, and the footer. Every line goes through
// `Plain`, which never interprets markup.

import AppKit
import SOCCore
import SwiftUI

/// A line of text shown exactly as given: no markdown, no links, no localisation.
struct Plain: View {
  let text: String
  init(_ text: String) { self.text = text }
  var body: some View { Text(verbatim: text).fixedSize(horizontal: false, vertical: true) }
}

struct RowView: View {
  let row: Row
  let show: () -> Void
  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      HStack(alignment: .firstTextBaseline, spacing: 6) {
        if let when = row.when {
          Text(verbatim: when).font(.callout.monospacedDigit()).foregroundStyle(.secondary)
        }
        Plain(row.sentence + ".").font(.body.weight(.medium))
      }
      if let value = row.value {
        Plain(value).font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
      }
      Plain(row.means + " " + row.todo).font(.callout)
      HStack {
        Button("Show", action: show)
        Button("Copy for my agent") {
          // Only on the owner's click.
          NSPasteboard.general.clearContents()
          NSPasteboard.general.setString(row.agentRequest, forType: .string)
        }
      }
      .controlSize(.small)
    }
  }
}

struct PanelView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    let p = Panel.of(
      model.reading, now: Date(), checking: model.runInProgress, notes: model.notes)
    VStack(alignment: .leading, spacing: 10) {
      VStack(alignment: .leading, spacing: 4) {
        HStack(spacing: 8) {
          Image(systemName: p.light.symbol).font(.title2)
          Plain(p.headline).font(.headline)
          Spacer()
          if model.refreshing || model.runInProgress { ProgressView().controlSize(.small) }
        }
        if let checked = p.checked { Plain(checked).font(.callout).foregroundStyle(.secondary) }
        ForEach(Array(p.help.enumerated()), id: \.offset) { _, line in Plain(line) }
        if let reason = p.reason { Plain(reason).font(.caption).foregroundStyle(.secondary) }
      }
      if !p.shown.isEmpty || p.blind != nil {
        Divider()
        ForEach(p.shown) { row in
          RowView(row: row) { Task { await model.openPage(at: row.fields) } }
        }
        if p.more > 0 {
          Button("\(p.more) more in Details") { Task { await model.openPage() } }
            .buttonStyle(.link)
        }
        if let blind = p.blind {
          Button {
            Task { await model.openPage() }
          } label: {
            Label {
              Plain(blind)
            } icon: {
              Image(systemName: "eye.slash")
            }
          }
          .buttonStyle(.plain).foregroundStyle(.secondary)
        }
      }
      ForEach(Array(p.notes.enumerated()), id: \.offset) { _, line in
        Plain(line).font(.callout).foregroundStyle(.secondary)
      }
      Divider()
      HStack {
        Button(p.footer[0]) { Task { await model.runNow() } }
          .disabled(!p.canCheck)
        Spacer()
        Button(p.footer[1]) { Task { await model.openPage() } }
          .disabled(model.pageOpening)
        Button(p.footer[2]) { NSApp.terminate(nil) }
      }
    }
    .padding(14)
    .frame(width: 420, alignment: .leading)
  }
}
