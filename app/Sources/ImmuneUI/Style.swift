// The panel's measures, text styles, colours and symbols, in one place, as the design sheet
// gives them ("Основа" and the one table of measures). Every view of the panel and of the opened
// finding takes its measures from here and writes none of its own.
//
// The grid: a step of 4. One left edge and one right edge, 16 pt in from the popover's sides
// (16 and 328). A leading column of 28 holds the state glyph and every row's circle; after a gap
// of 8 the text starts at 52. A chevron column of 8 ends on the right edge, so text ends at 312.

import AppKit
import ImmuneCore
import SwiftUI

enum Metrics {
  /// The popover's width.
  static let width: CGFloat = 344
  /// The grid's step.
  static let step: CGFloat = 4
  /// The one left and right edge.
  static let inset: CGFloat = 16
  /// The leading column: the state glyph and a row's circle.
  static let leading: CGFloat = 28
  /// Between columns.
  static let gap: CGFloat = 8
  /// Where text starts: 52.
  static var textEdge: CGFloat { inset + leading + gap }
  /// The chevron column at the right edge.
  static let chevron: CGFloat = 8
  /// Where text ends: 312.
  static var textRight: CGFloat { width - inset - chevron - gap }
  /// Between the lines of a block.
  static let lineGap: CGFloat = 2
  /// Between a thing and "+3 more" after it.
  static let moreGap: CGFloat = 6

  /// A separator's thickness: under the header and above the footer, always.
  static let separator: CGFloat = 1

  // The header: 16 above, 12 below; the glyph 4 below the top of the title.
  static let headerTop: CGFloat = 16
  static let headerBottom: CGFloat = 12
  static let glyphTop: CGFloat = 4
  /// The ring of a glyph that is not filled, and the dashes of can't tell's.
  static let ring: CGFloat = 1.5
  static let ringDash: [CGFloat] = [3, 2]
  /// Above the help line and the reason under the glance.
  static let helpTop: CGFloat = 8

  // The list, inside the scroll view: 4 above, 8 below.
  static let listTop: CGFloat = 4
  static let listBottom: CGFloat = 8
  /// A group heading: 10 above, 4 below, 28 in all.
  static let groupTop: CGFloat = 10
  static let groupBottom: CGFloat = 4
  /// A row: 6 above and below; 44 with two lines, 60 with three.
  static let rowVertical: CGFloat = 6
  static let row: CGFloat = 44
  /// A row's highlight starts 8 in from the popover's side and pads its content by 8, which puts
  /// the content on the edge.
  static let highlight: CGFloat = 8
  static var highlightPadding: CGFloat { inset - highlight }
  static let radius: CGFloat = 6
  /// The circle under a row's symbol sits 2 below the row's first line top; the chevron 10, which
  /// centres it on the circle.
  static let circleTop: CGFloat = 2
  static let chevronTop: CGFloat = 10
  static let chevronHeight: CGFloat = 12
  /// A quiet row.
  static let quietRow: CGFloat = 28
  /// Above the coverage row when something stands before it.
  static let coverageGap: CGFloat = 8
  /// The labels of the coverage row and of the facts.
  static let label: CGFloat = 72
  /// The coverage row's grid lies 1 below the row's text top.
  static let coverageTop: CGFloat = 1
  /// The dot of program starts, its line when hollow, and the gap after it.
  static let dot: CGFloat = 6
  static let dotLine: CGFloat = 1
  static let dotGap: CGFloat = 4
  /// How far a dot sits above the baseline of an 11 pt line, at the middle of its small letters.
  static let dotRise: CGFloat = 1

  // The footer: 12 above and below, 8 between buttons, 22 high, the "⋯" button 28 wide.
  static let footerVertical: CGFloat = 12
  static let footerGap: CGFloat = 8
  static let more: CGFloat = 28

  /// How far the panel stays from the bottom of the visible part of its screen.
  static let screenMargin: CGFloat = 20

  // The opened finding.
  static let navTop: CGFloat = 12
  /// Between Back's chevron and its word.
  static let navGap: CGFloat = 4
  static let thingVertical: CGFloat = 12
  static let factsTop: CGFloat = 12
  static let factsRowGap: CGFloat = 4
  static let voicesHeadingTop: CGFloat = 16
  static let voicesTop: CGFloat = 8
  static let voiceGap: CGFloat = 12
  static let quoteTop: CGFloat = 4
  static let quoteRule: CGFloat = 2
  static let historyTop: CGFloat = 16
  static let historyBottom: CGFloat = 12
  /// The Expected form: the field's height and the space around its rows.
  static let field: CGFloat = 22
}

/// A colour role. Three state colours only: red for what needs the person now, green for calm,
/// grey for everything quiet. Accent is for controls and links; text has three levels.
enum Role {
  case primary, secondary, tertiary, accent, now

  var style: AnyShapeStyle {
    switch self {
    case .primary: AnyShapeStyle(.primary)
    case .secondary: AnyShapeStyle(.secondary)
    case .tertiary: AnyShapeStyle(.tertiary)
    case .accent: AnyShapeStyle(Color.accentColor)
    case .now: AnyShapeStyle(Palette.now)
    }
  }
}

enum Palette {
  /// Needs you now.
  static let now = Color(nsColor: .systemRed)
  /// Calm.
  static let calm = Color(nsColor: .systemGreen)
  /// Everything quiet: to look at, watched in part, old, can't tell.
  static let quiet = Color(nsColor: .systemGray)
  /// The mark on a filled glyph.
  static let onFill = Color.white
  /// The circle under a row's symbol and the fill of the busy glyph.
  static let circle = AnyShapeStyle(.quaternary)
  /// A row under the pointer.
  static let highlight = AnyShapeStyle(.quinary)
}

/// A text style: size, line height, weight, monospace or not, tabular digits and colour role.
/// The sheet's four sizes: 15, 13, 12 monospaced, 11.
struct TextStyle {
  var size: CGFloat
  var line: CGFloat
  var weight: Font.Weight = .regular
  var mono = false
  var tabular = false
  var role: Role = .primary

  var font: Font {
    let f = Font.system(size: size, weight: weight, design: mono ? .monospaced : .default)
    return tabular ? f.monospacedDigit() : f
  }

  var nsFont: NSFont {
    let w: NSFont.Weight = weight == .semibold ? .semibold : weight == .bold ? .bold : .regular
    return mono
      ? NSFont.monospacedSystemFont(ofSize: size, weight: w)
      : NSFont.systemFont(ofSize: size, weight: w)
  }

  /// What SwiftUI gives a line of this font, before the style's own line height: its ascender and
  /// descender each rounded up, as measured off screen (15 pt 19, 13 pt 16, 12 pt monospaced 15,
  /// 11 pt 14).
  var natural: CGFloat {
    let f = nsFont
    return ceil(f.ascender) + ceil(-f.descender) + f.leading
  }

  /// The same style in another colour role.
  func role(_ r: Role) -> TextStyle {
    var s = self
    s.role = r
    return s
  }

  /// Title: the header's state (15/20 semibold).
  static let title = TextStyle(size: 15, line: 20, weight: .semibold)
  /// Title as data: the opened thing (15/20 semibold, monospaced).
  static let titleData = TextStyle(size: 15, line: 20, weight: .semibold, mono: true)
  /// Body: words (13/16).
  static let body = TextStyle(size: 13, line: 16)
  /// Data: a value from the Mac (12/16 monospaced).
  static let data = TextStyle(size: 12, line: 16, mono: true)
  /// Caption: kind lines, the glance, the time, quiet rows (11/14, secondary, tabular digits).
  static let caption = TextStyle(size: 11, line: 14, tabular: true, role: .secondary)
  /// Caption strong: group headings and "Needs you now" (11/14 semibold, secondary).
  static let captionStrong = TextStyle(size: 11, line: 14, weight: .semibold, role: .secondary)
  /// A fact's label (11/16, secondary): on the line of its value.
  static let factLabel = TextStyle(size: 11, line: 16, role: .secondary)
  /// A link in a row (11/14, accent).
  static let link = TextStyle(size: 11, line: 14, role: .accent)
  /// A link of the opened finding's navigation (13/16, accent).
  static let navLink = TextStyle(size: 13, line: 16, role: .accent)
}

extension View {
  /// Draws text in a style: its font and colour, and its line height, as the extra space split
  /// above and below a line and between lines.
  func textStyle(_ s: TextStyle) -> some View {
    let extra = max(0, s.line - s.natural)
    return font(s.font).foregroundStyle(s.role.style).lineSpacing(extra)
      .padding(.vertical, extra / 2)
  }
}

/// A symbol and the one size and weight of its role. The symbols of the kinds of thing are in
/// `Words.kinds`, drawn in the row role.
struct SymbolStyle {
  var size: CGFloat
  var weight: Font.Weight
  var font: Font { .system(size: size, weight: weight) }

  /// A row's symbol, in its circle (13 regular).
  static let row = SymbolStyle(size: 13, weight: .regular)
  /// The mark of the state glyph (13 bold).
  static let glyph = SymbolStyle(size: 13, weight: .bold)
  /// A row's chevron and Back's (11 semibold).
  static let chevron = SymbolStyle(size: 11, weight: .semibold)
  /// The "⋯" button's (13 regular).
  static let more = SymbolStyle(size: 13, weight: .regular)
}

/// The symbols of the controls and of the state glyph. The icon table's symbols for things are
/// in `ImmuneCore`, where the plain text of the panel names them too: a kind's in `Words.kinds`,
/// the rest in `Icons`.
enum Symbols {
  static let chevron = "chevron.right"
  static let back = "chevron.left"
  static let menu = "ellipsis"

  /// The mark of the state glyph, or nil for the busy one, which turns.
  static func glyph(_ state: PanelState) -> String? {
    switch state {
    case .calm, .part: "checkmark"
    case .now: "exclamationmark"
    case .look: "eye"
    case .stale: "clock"
    case .cant: "questionmark"
    case .busy: nil
    }
  }
}

/// A symbol in its circle in the leading column.
struct RowIcon: View {
  let symbol: String
  var body: some View {
    Image(systemName: symbol)
      .font(SymbolStyle.row.font)
      .foregroundStyle(.secondary)
      .frame(width: Metrics.leading, height: Metrics.leading)
      .background(Palette.circle, in: Circle())
      .accessibilityHidden(true)
  }
}

/// The chevron at a row's right edge, in its column.
struct Chevron: View {
  var body: some View {
    Image(systemName: Symbols.chevron)
      .font(SymbolStyle.chevron.font)
      .foregroundStyle(.tertiary)
      .frame(width: Metrics.chevron, height: Metrics.chevronHeight)
      .accessibilityHidden(true)
  }
}

/// A separator from edge to edge, as under the header and above the footer.
struct Separator: View {
  var body: some View { Divider().padding(.horizontal, Metrics.inset) }
}

/// A row's fill under the pointer, as a list in macOS draws it.
struct Hover: ViewModifier {
  @State private var over = false
  func body(content: Content) -> some View {
    content
      .background(
        over ? Palette.highlight : AnyShapeStyle(.clear),
        in: RoundedRectangle(cornerRadius: Metrics.radius, style: .continuous)
      )
      .onHover { over = $0 }
  }
}
