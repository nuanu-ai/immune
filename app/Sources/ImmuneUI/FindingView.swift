// The opened finding, inside the popover, from `immune finding <id> --json` alone, as the design
// sheet draws it: Back and Show in report; the thing as the title, wrapped after its slashes; a
// line with its kind, what happened and when, led by "Needs you now" in red only when Immune
// marked it urgent; the facts; "Who said what": the published rule, the response layer, the
// person's answer and Immune; a short history. One set of answers in a footer that does not
// scroll (`FindingFooter`). A failure of the command is the contract's `Failure`, shown as one,
// never an empty card.

import AppKit
import ImmuneCore
import SwiftUI

struct FindingView: View {
  let opened: OpenedFinding
  let panel: Panel
  @ObservedObject var model: AppModel
  let now: Date
  @State private var adviceOpen = false

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      nav
      switch opened.reading {
      case .loading:
        HStack(spacing: Metrics.gap) {
          ProgressView().controlSize(.small)
          Text(verbatim: "Reading the finding…").textStyle(TextStyle.body.role(.secondary))
        }
        .padding(.horizontal, Metrics.inset).padding(.vertical, Metrics.thingVertical)
      case .refused(let failure, let exit):
        FailureBox(failure: failure, exitCode: exit)
          .padding(.horizontal, Metrics.inset).padding(.vertical, Metrics.thingVertical)
      case .failed(let reason, let detail):
        VStack(alignment: .leading, spacing: Metrics.lineGap) {
          Plain("I can't show this finding: " + reason).textStyle(.body)
          if let detail {
            DataText(text: Inert.text(detail), style: TextStyle.data.role(.secondary))
          }
        }
        .padding(.horizontal, Metrics.inset).padding(.vertical, Metrics.thingVertical)
      case .read(let f):
        card(f)
      }
    }
  }

  var nav: some View {
    HStack(spacing: Metrics.gap) {
      Button {
        model.closeFinding()
      } label: {
        HStack(spacing: Metrics.navGap) {
          Image(systemName: Symbols.back).font(SymbolStyle.chevron.font)
          Text(verbatim: "Back")
        }
        .textStyle(.navLink)
      }
      .buttonStyle(.plain)
      Spacer(minLength: 0)
      Button {
        Task { await model.openPage(at: opened.id) }
      } label: {
        Text(verbatim: "Show in report").textStyle(.navLink)
      }
      .buttonStyle(.plain)
      .disabled(model.pageOpening)
    }
    .padding(.horizontal, Metrics.inset).padding(.top, Metrics.navTop)
  }

  @ViewBuilder func card(_ f: Contract.Finding) -> some View {
    let urgent = FindingFacts.urgent(f)
    VStack(alignment: .leading, spacing: Metrics.lineGap) {
      // The thing as data, whole, broken after its slashes when it wraps.
      Text(verbatim: Inert.wrapping(Inert.display(FindingFacts.object(f))))
        .textStyle(.titleData)
        .fixedSize(horizontal: false, vertical: true)
      let caption = FindingFacts.caption(f, now: now)
      Group {
        if urgent {
          Text(verbatim: "Needs you now").styled(TextStyle.captionStrong.role(.now))
            + Text(verbatim: caption.isEmpty ? "" : " · " + caption)
        } else {
          Text(verbatim: caption)
        }
      }
      .textStyle(.caption)
      .fixedSize(horizontal: false, vertical: true)
    }
    .padding(.horizontal, Metrics.inset).padding(.vertical, Metrics.thingVertical)
    Separator()
    let facts = FindingFacts.facts(f)
    if !facts.isEmpty {
      Grid(
        alignment: .leadingFirstTextBaseline, horizontalSpacing: Metrics.gap,
        verticalSpacing: Metrics.factsRowGap
      ) {
        ForEach(Array(facts.enumerated()), id: \.offset) { _, fact in
          GridRow {
            Text(verbatim: fact.label).textStyle(.factLabel)
              .frame(width: Metrics.label, alignment: .leading)
            Group {
              if fact.oneLine {
                DataLine(text: fact.value, path: false).help(fact.value)
              } else if fact.isData {
                DataText(text: fact.value)
              } else {
                Plain(fact.value).textStyle(.body)
              }
            }
            .gridColumnAlignment(.leading)
          }
        }
      }
      .padding(.horizontal, Metrics.inset).padding(.top, Metrics.factsTop)
    }
    let voices = FindingFacts.voices(f, now: now)
    if !voices.isEmpty {
      Text(verbatim: "Who said what").textStyle(.captionStrong)
        .padding(.horizontal, Metrics.inset).padding(.top, Metrics.voicesHeadingTop)
        .accessibilityAddTraits(.isHeader)
      VStack(alignment: .leading, spacing: Metrics.voiceGap) {
        ForEach(Array(voices.enumerated()), id: \.offset) { _, voice in
          VoiceView(voice: voice, adviceOpen: $adviceOpen)
        }
      }
      .padding(.horizontal, Metrics.inset).padding(.top, Metrics.voicesTop)
    }
    let history = FindingFacts.history(f, now: now)
    Group {
      if history.isEmpty {
        Color.clear.frame(height: Metrics.historyBottom)
      } else {
        Plain(history).textStyle(.caption)
          .padding(.horizontal, Metrics.inset)
          .padding(.top, Metrics.historyTop).padding(.bottom, Metrics.historyBottom)
      }
    }
  }
}

/// One voice of "Who said what": who, what they said, what it rests on, their reason quoted,
/// and for Immune what to do, behind a link.
struct VoiceView: View {
  let voice: Voice
  @Binding var adviceOpen: Bool

  var body: some View {
    VStack(alignment: .leading, spacing: Metrics.lineGap) {
      Group {
        if let data = voice.whoData {
          Text(verbatim: voice.who + " · ") + Text(verbatim: Inert.display(data))
        } else {
          Text(verbatim: voice.who)
        }
      }
      .textStyle(.caption)
      if !voice.said.isEmpty {
        if voice.saidIsData {
          DataText(text: voice.said)
        } else {
          Plain(voice.said).textStyle(.body)
        }
      }
      if voice.data != nil || voice.detail != nil {
        Group {
          if let data = voice.data, let detail = voice.detail {
            Text(verbatim: Inert.display(data)) + Text(verbatim: " · " + detail)
          } else if let data = voice.data {
            Text(verbatim: Inert.display(data))
          } else {
            Text(verbatim: voice.detail ?? "")
          }
        }
        .textStyle(.caption)
        .fixedSize(horizontal: false, vertical: true)
      }
      if let quote = voice.quote {
        Quote(text: quote).padding(.top, Metrics.quoteTop - Metrics.lineGap)
      }
      ForEach(Array(voice.facts.enumerated()), id: \.offset) { _, fact in
        HStack(alignment: .firstTextBaseline, spacing: Metrics.navGap) {
          Text(verbatim: fact.label).textStyle(.caption).fixedSize()
          DataText(text: fact.value, style: TextStyle.caption.role(.secondary))
        }
      }
      if let advice = voice.advice {
        Button {
          adviceOpen.toggle()
        } label: {
          Text(verbatim: adviceOpen ? "Hide what to do" : "What to do").textStyle(.link)
        }
        .buttonStyle(.plain)
        .padding(.top, Metrics.quoteTop - Metrics.lineGap)
        if adviceOpen { Plain(advice).textStyle(.body) }
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

/// Text a source wrote, set apart: monospace, a rule at its left, never in the app's voice.
struct Quote: View {
  let text: String
  var body: some View {
    HStack(spacing: Metrics.gap) {
      Rectangle().fill(.tertiary).frame(width: Metrics.quoteRule)
      DataText(text: text)
    }
    .fixedSize(horizontal: false, vertical: true)
  }
}

/// The opened finding's footer, which does not scroll: one set of answers for the one thing on
/// the screen, the primary one following Immune's `urgent`; the answer given outside the app, with
/// Take back; Saving…; or the Expected form in its place.
///
/// A thing shown as one is sometimes two findings: the core's and the response layer's own about
/// it. Then each answer is one command for both, the opened finding by its id and the other with
/// `--with` (`FindingFacts.pair`), and the core answers both or neither.
struct FindingFooter: View {
  let opened: OpenedFinding
  let panel: Panel
  @ObservedObject var model: AppModel
  let now: Date

  /// The finding as the status lists it: only such a finding takes an answer here.
  var row: Row? { panel.rows.first { $0.item.id == opened.id } }

  var body: some View {
    if case .read(let f) = opened.reading {
      VStack(alignment: .leading, spacing: 0) {
        Separator()
        content(f)
          .padding(.horizontal, Metrics.inset).padding(.vertical, Metrics.footerVertical)
      }
    }
  }

  @ViewBuilder func content(_ f: Contract.Finding) -> some View {
    let id = opened.id
    let canAnswer = row?.canAnswer == true
    let pair = FindingFacts.pair(f, id: id, rows: panel.rows)
    if canAnswer, model.form?.id == id {
      ExpectedFormView(model: model, id: id)
    } else if model.answering == id {
      HStack(spacing: Metrics.gap) {
        ProgressView().controlSize(.small)
        Text(verbatim: "Saving…").textStyle(TextStyle.body.role(.secondary))
      }
    } else if FindingFacts.answeredOutside(f), let a = f.answer {
      // One line: the answer, the year only when it is not this one; who gave it in the tooltip.
      HStack(spacing: Metrics.gap) {
        Text(verbatim: FindingFacts.answeredLine(a, now: now)).textStyle(.caption)
          .lineLimit(1).truncationMode(.tail).help(FindingFacts.answeredHelp(a, now: now))
        Spacer(minLength: 0)
        Button("Take back") { Task { await model.takeBack(id) } }
          .disabled(model.answering != nil).fixedSize()
      }
    } else {
      VStack(alignment: .leading, spacing: Metrics.footerGap) {
        if let refused = model.refusals[id] {
          Plain(refused).textStyle(.caption).textSelection(.enabled)
        }
        answers(f, canAnswer: canAnswer, pair: pair)
      }
    }
  }

  /// Seen, Expected… and Ask my agent, the primary first: for an urgent finding, asking the
  /// agent; otherwise Seen. A finding the status does not list takes no answer here.
  @ViewBuilder func answers(_ f: Contract.Finding, canAnswer: Bool, pair: String?) -> some View {
    let id = opened.id
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
    let actions = FindingFacts.actions(urgent: FindingFacts.urgent(f), canAnswer: canAnswer)
    HStack(spacing: Metrics.footerGap) {
      ForEach(Array(actions.enumerated()), id: \.offset) { index, action in
        let primary = index == 0
        switch action {
        case .askAgent:
          CopyForAgent(text: request, label: "Ask my agent", style: primary ? .primary : .button)
        case .seen:
          let seen = Button("Seen") { Task { await model.answerSeen(id, with: pair) } }
            .help("Mark it seen: it stops asking for a look.")
          if primary { seen.buttonStyle(.borderedProminent) } else { seen }
        case .expected:
          Button("Expected…") { model.form = ExpectedForm(id: id, with: pair) }
            .help("Mark it expected for a while, with a short reason.")
        }
      }
    }
    .disabled(model.answering != nil)
    .fixedSize()
  }
}

/// The contract's `Failure`, as it is: the core's words and its code, what it quotes as data,
/// and the call it suggests.
struct FailureBox: View {
  let failure: Contract.Failure
  let exitCode: Int32?
  var body: some View {
    VStack(alignment: .leading, spacing: Metrics.lineGap) {
      Plain(
        "immune finding did not answer"
          + (exitCode.map { " (exit code \($0))" } ?? "") + "."
      )
      .textStyle(.body)
      ForEach(Array(failure.errors.enumerated()), id: \.offset) { _, e in
        VStack(alignment: .leading, spacing: Metrics.lineGap) {
          if let message = e.message { Plain(Inert.text(message, limit: 400)).textStyle(.body) }
          if let code = e.code {
            DataText(text: Inert.text(code, limit: 80), style: TextStyle.data.role(.secondary))
          }
          if let detail = e.detailText { Quote(text: Inert.text(detail, limit: 1000)) }
          if let example = e.example {
            Plain("Try: " + Inert.text(example, limit: 400)).textStyle(.caption)
          }
        }
      }
    }
  }
}

/// One required text field for the reason and how long, in place of the footer; nothing else.
struct ExpectedFormView: View {
  @ObservedObject var model: AppModel
  let id: String

  var body: some View {
    let reason = Binding(get: { model.form?.reason ?? "" }, set: { model.form?.reason = $0 })
    let days = Binding(
      get: { model.form?.days ?? Answer.defaultDays }, set: { model.form?.days = $0 })
    let complete = model.form?.isComplete == true
    VStack(alignment: .leading, spacing: Metrics.gap) {
      TextField("Why is it expected? (required)", text: reason)
        .textFieldStyle(.roundedBorder).font(TextStyle.body.font)
        .frame(height: Metrics.field)
        .onSubmit { send() }
      HStack(spacing: Metrics.gap) {
        Text(verbatim: "For").textStyle(.caption)
        Picker("For", selection: days) {
          ForEach(Answer.days, id: \.self) { n in Text(verbatim: "\(n) days").tag(n) }
        }
        .pickerStyle(.menu).labelsHidden().fixedSize()
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
