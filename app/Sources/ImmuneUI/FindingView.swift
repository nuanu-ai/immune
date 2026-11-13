// The opened finding, inside the popover: an evidence card from `immune finding <id> --json`
// alone. An answer given outside the app on top, with Take back; the kind and what happened;
// the thing large, in monospace; a table of facts for its kind; the response layer's verdicts
// in a box of their own, each reason as data; the meaning in one line; the buttons, the primary
// one following Immune's `urgent`; what to do, on request; a short history. A failure of the
// command is the contract's `Failure`, shown as one, never an empty card.

import AppKit
import ImmuneCore
import SwiftUI

struct FindingView: View {
  let opened: OpenedFinding
  let panel: Panel
  @ObservedObject var model: AppModel
  let now: Date
  @State private var adviceOpen = false

  /// The finding as the status lists it: only such a finding takes an answer here.
  var row: Row? { panel.rows.first { $0.item.id == opened.id } }

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack(spacing: 6) {
        Button {
          model.closeFinding()
        } label: {
          Label("Back", systemImage: "chevron.left").labelStyle(.titleAndIcon)
        }
        .buttonStyle(.link).font(.system(size: 13))
        Spacer()
        Button("Show in report") { Task { await model.openPage(at: opened.id) } }
          .buttonStyle(.link).font(.system(size: 12))
          .disabled(model.pageOpening)
      }
      .padding(.horizontal, 12).padding(.top, 10)
      VStack(alignment: .leading, spacing: 10) {
        switch opened.reading {
        case .loading:
          HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(verbatim: "Reading the finding…").foregroundStyle(.secondary)
          }
          .font(.system(size: 13))
        case .refused(let failure, let exit):
          FailureBox(failure: failure, exitCode: exit)
        case .failed(let reason, let detail):
          VStack(alignment: .leading, spacing: 6) {
            Plain("I can't show this finding: " + reason).font(.system(size: 13, weight: .semibold))
            if let detail { DataText(text: Inert.text(detail)).foregroundStyle(.secondary) }
          }
        case .read(let f):
          card(f)
        }
      }
      .padding(.horizontal, 16).padding(.top, 8).padding(.bottom, 14)
    }
  }

  @ViewBuilder func card(_ f: Contract.Finding) -> some View {
    let id = opened.id
    if FindingFacts.answeredOutside(f), let a = f.answer {
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
          Image(systemName: "person.badge.clock").foregroundStyle(Color.accentColor)
            .accessibilityHidden(true)
          Plain(FindingFacts.answer(a)).font(.system(size: 12, weight: .semibold))
          Spacer(minLength: 4)
          if model.answering == id {
            Text(verbatim: "Saving…").foregroundStyle(.secondary)
          } else {
            Button("Take back") { Task { await model.takeBack(id) } }
              .disabled(model.answering != nil).fixedSize()
          }
        }
        .font(.system(size: 12))
        if let reason = a.reasonText { Quote(text: Inert.text(reason, limit: 1000)) }
      }
      .padding(8)
      .background(
        Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 8, style: .continuous)
      )
      .overlay(
        RoundedRectangle(cornerRadius: 8, style: .continuous)
          .strokeBorder(Color.accentColor.opacity(0.3), lineWidth: 0.5))
    }
    HStack(spacing: 6) {
      Image(systemName: Words.symbol(f.kind)).foregroundStyle(.secondary).accessibilityHidden(true)
      Text(verbatim: Words.kind(f.kind) ?? "Finding")
      if let change = FindingFacts.change(f) { Chip(text: change) }
      if case .publishedRule = f.evidence { Chip(text: "published rule") }
      if let state = f.finding?.state, state != "open" {
        Chip(text: Inert.text(state, limit: 20).capitalized)
      }
    }
    .font(.system(size: 12)).foregroundStyle(.secondary)
    DataText(text: FindingFacts.object(f), size: 14, weight: .semibold)
    if let levels = Levels.words(severity: f.finding?.severity, confidence: f.finding?.confidence) {
      Text(verbatim: levels).font(.system(size: 12)).foregroundStyle(.secondary)
    }
    let facts = FindingFacts.facts(f)
    if !facts.isEmpty {
      Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 4) {
        ForEach(Array(facts.enumerated()), id: \.offset) { _, fact in
          GridRow {
            Text(verbatim: fact.label).font(.system(size: 12)).foregroundStyle(.secondary)
              .gridColumnAlignment(.leading)
            if fact.isData {
              DataText(text: fact.value)
            } else {
              Plain(fact.value).font(.system(size: 12))
            }
          }
        }
      }
    }
    // Shown unless the response layer is said to have given none: a total not given is not zero.
    if let v = f.verdicts, v.total != 0 || !v.listed.isEmpty || v.verdictFinding != nil {
      VerdictsBox(verdicts: v, model: model, panel: panel)
    }
    if let meaning = f.meaning {
      Plain(Inert.text(meaning, limit: 600)).font(.system(size: 12)).foregroundStyle(.secondary)
        .lineLimit(3).help(meaning)
    }
    buttons(f)
    if let refused = model.refusals[id] {
      Plain(refused).font(.system(size: 12)).textSelection(.enabled)
    }
    if let advice = f.advice {
      Button(adviceOpen ? "Hide what to do" : "What to do") { adviceOpen.toggle() }
        .buttonStyle(.link).font(.system(size: 12))
      if adviceOpen { Plain(Inert.text(advice, limit: 1000)).font(.system(size: 12)) }
    }
    let history = FindingFacts.history(f, now: now)
    if !history.isEmpty {
      Divider()
      Plain(history).font(.system(size: 11)).foregroundStyle(.secondary)
    }
  }

  /// Seen, Expected… and Ask my agent. The primary one follows Immune's `urgent`: for an urgent
  /// finding, asking the agent; otherwise Seen. A finding the status does not list takes no
  /// answer here.
  @ViewBuilder func buttons(_ f: Contract.Finding) -> some View {
    let id = opened.id
    let canAnswer = row?.canAnswer == true
    let urgent = f.finding?.urgent == true
    let request =
      row?.agentRequest
      ?? AgentRequest.text(
        readCommand: (model.immuneCommand ?? ImmuneCommand(path: "immune")).line([
          "finding", id, "--json",
        ]), byId: true,
        fields: [
          ("id", id), ("rule", f.finding?.rule), ("kind", f.kind),
          ("severity", f.finding?.severity), ("state", f.finding?.state), ("title", f.title),
          ("where_text", f.whereText),
        ])
    if canAnswer, model.form?.id == id {
      ExpectedFormView(model: model, id: id)
    } else if model.answering == id {
      HStack(spacing: 6) {
        ProgressView().controlSize(.small)
        Text(verbatim: "Saving…").foregroundStyle(.secondary)
      }
      .font(.system(size: 13))
    } else {
      let actions = FindingFacts.actions(urgent: urgent, canAnswer: canAnswer)
      HStack(spacing: 6) {
        ForEach(Array(actions.enumerated()), id: \.offset) { index, action in
          let primary = index == 0
          switch action {
          case .askAgent:
            CopyForAgent(text: request, label: "Ask my agent", prominent: primary)
          case .seen:
            let seen = Button("Seen") { Task { await model.answerSeen(id) } }
              .help("Mark it seen: it stops asking for a look.")
            if primary { seen.buttonStyle(.borderedProminent) } else { seen }
          case .expected:
            Button("Expected…") { model.form = ExpectedForm(id: id) }
              .help("Mark it expected for a while, with a short reason.")
          }
        }
      }
      .disabled(model.answering != nil)
      .fixedSize()
    }
  }
}

/// What the response layer said: how many verdicts and how many suspicious, each listed verdict
/// with its kind, its levels and its reason as data, and its own finding with Seen.
struct VerdictsBox: View {
  let verdicts: Contract.Verdicts
  @ObservedObject var model: AppModel
  let panel: Panel
  static let shown = 3

  var body: some View {
    let tone = VerdictTone.of(total: verdicts.total, suspicious: verdicts.suspicious)
    let colour: Color =
      switch tone {
      case .suspicious: .red
      case .harmless: .green
      case .unknown: .secondary
      }
    VStack(alignment: .leading, spacing: 6) {
      HStack(spacing: 6) {
        Image(
          systemName: tone == .suspicious
            ? "exclamationmark.bubble" : tone == .harmless ? "checkmark.bubble" : "bubble"
        )
        .foregroundStyle(colour).accessibilityHidden(true)
        Text(verbatim: "Response layer").fontWeight(.semibold)
        Spacer(minLength: 4)
        Text(
          verbatim: (verdicts.total.map { $0 == 1 ? "1 verdict" : "\($0) verdicts" }
            ?? "verdicts not counted")
            + ", " + (verdicts.suspicious.map(String.init) ?? "?") + " suspicious"
        )
        .foregroundStyle(.secondary)
      }
      ForEach(Array(verdicts.listed.suffix(Self.shown).enumerated()), id: \.offset) { _, v in
        VStack(alignment: .leading, spacing: 3) {
          HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(
              verbatim: v.kind == "suspicious"
                ? "Suspicious"
                : v.kind == "harmless"
                  ? "Harmless" : Inert.text(v.kind ?? "No kind given", limit: 40)
            )
            .foregroundStyle(
              v.kind == "suspicious"
                ? Color.red : v.kind == "harmless" ? Color.green : Color.secondary
            )
            .fontWeight(.medium).fixedSize()
            // The levels beside the verdict's word, wrapped rather than cut.
            if let levels = Levels.words(severity: v.severity, confidence: v.confidence) {
              Text(verbatim: levels).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 4)
            if let at = v.recordedAt {
              Text(verbatim: Clock.at(at, now: Date())).foregroundStyle(.secondary).fixedSize()
            }
          }
          if let reason = v.reasonText { Quote(text: Inert.text(reason, limit: 1000)) }
          if let c = FindingFacts.caseFact(v) {
            HStack(alignment: .firstTextBaseline, spacing: 4) {
              Text(verbatim: c.label).foregroundStyle(.secondary).fixedSize()
              DataText(text: c.value, size: 11).foregroundStyle(.secondary)
            }
          }
        }
      }
      if verdicts.listed.count > Self.shown {
        Text(verbatim: "\(verdicts.listed.count - Self.shown) earlier verdicts in report")
          .foregroundStyle(.secondary)
      }
      if let own = verdicts.verdictFinding, let id = own.id {
        HStack(spacing: 6) {
          if own.urgent { BadgeView(badge: .urgent) }
          Text(verbatim: "Raised its own finding").foregroundStyle(.secondary).fixedSize()
          // Its state as given; none is invented.
          if let state = own.state {
            Text(verbatim: Inert.display(Inert.text(state, limit: 20)))
              .font(.system(size: 11.5, design: .monospaced)).foregroundStyle(.secondary)
              .fixedSize()
          } else {
            Text(verbatim: "state not given").foregroundStyle(.secondary)
          }
          Spacer(minLength: 4)
          Button("Open") { Task { await model.openFinding(id) } }.buttonStyle(.link).fixedSize()
          if panel.rows.contains(where: { $0.item.id == id && $0.canAnswer }) {
            Button("Seen") { Task { await model.answerSeen(id) } }
              .disabled(model.answering != nil).fixedSize()
          }
        }
      }
    }
    .font(.system(size: 12))
    .padding(8)
    .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    .overlay(
      RoundedRectangle(cornerRadius: 8, style: .continuous)
        .strokeBorder(
          tone == .unknown ? Color.secondary.opacity(0.4) : colour.opacity(0.5), lineWidth: 0.75))
  }
}

/// Text a source wrote, set apart: monospace, a rule at its left, never in the app's voice.
struct Quote: View {
  let text: String
  var body: some View {
    HStack(spacing: 0) {
      Rectangle().fill(.tertiary).frame(width: 2)
      DataText(text: text).padding(.leading, 8)
    }
    .fixedSize(horizontal: false, vertical: true)
  }
}

/// A small word in an outline: what happened, the tag of the kind, a state. Never a level: a
/// level is said in words (`Levels`).
struct Chip: View {
  let text: String
  var body: some View {
    Text(verbatim: text)
      .font(.system(size: 11)).foregroundStyle(Color.secondary)
      .padding(.horizontal, 7).padding(.vertical, 1)
      .overlay(PillOutline().strokeBorder(Color.secondary.opacity(0.5)))
      .fixedSize()
  }
}

/// The contract's `Failure`, as it is: the core's words and its code, what it quotes as data,
/// and the call it suggests.
struct FailureBox: View {
  let failure: Contract.Failure
  let exitCode: Int32?
  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      Plain(
        "immune finding did not answer"
          + (exitCode.map { " (exit code \($0))" } ?? "") + "."
      )
      .font(.system(size: 13, weight: .semibold))
      ForEach(Array(failure.errors.enumerated()), id: \.offset) { _, e in
        VStack(alignment: .leading, spacing: 2) {
          if let message = e.message { Plain(Inert.text(message, limit: 400)) }
          if let code = e.code {
            DataText(text: Inert.text(code, limit: 80)).foregroundStyle(.secondary)
          }
          if let detail = e.detailText { Quote(text: Inert.text(detail, limit: 1000)) }
          if let example = e.example {
            Plain("Try: " + Inert.text(example, limit: 400)).foregroundStyle(.secondary)
          }
        }
      }
    }
    .font(.system(size: 12))
  }
}

/// One required text field for the reason and how long; nothing else.
struct ExpectedFormView: View {
  @ObservedObject var model: AppModel
  let id: String

  var body: some View {
    let reason = Binding(get: { model.form?.reason ?? "" }, set: { model.form?.reason = $0 })
    let days = Binding(
      get: { model.form?.days ?? Answer.defaultDays }, set: { model.form?.days = $0 })
    let complete = model.form?.isComplete == true
    VStack(alignment: .leading, spacing: 8) {
      TextField("Why is it expected? (required)", text: reason)
        .textFieldStyle(.roundedBorder).font(.system(size: 13))
        .onSubmit { send() }
      HStack(spacing: 8) {
        Text(verbatim: "For").font(.system(size: 12)).foregroundStyle(.secondary)
        Picker("For", selection: days) {
          ForEach(Answer.days, id: \.self) { n in Text(verbatim: "\(n) days").tag(n) }
        }
        .pickerStyle(.segmented).labelsHidden().fixedSize()
      }
      HStack(spacing: 8) {
        Spacer(minLength: 0)
        Button("Cancel") { model.form = nil }.fixedSize()
        Button("Mark expected") { send() }
          .buttonStyle(.borderedProminent).fixedSize()
          .disabled(!complete || model.answering != nil)
      }
    }
  }

  private func send() {
    guard let form = model.form, form.isComplete else { return }
    Task { await model.answerExpected(form) }
  }
}
