// The menu-bar icon: one SF Symbol per state, drawn in the state's colour (red, orange or green,
// as the panel's glyph) or, for an old answer and can't tell, as a template image so macOS colours
// it for a light or a dark bar; and the count beside it.
//
// Size. With no configuration a symbol is drawn at the 13 pt body size: a shield 14 by 15 pt
// whose strokes are thin beside the system's own extras. The configuration below draws it at
// 15 pt, medium weight and medium scale. Measured with AppKit, the image of the shield is then
// 17 by 18 pt, the triangle 19 by 18 pt and the circle with a question mark 19 by 19 pt, each
// with its padding, inside a bar 22 pt high (24 pt on Macs with a notch). Off-screen renders
// beside Wi-Fi and the clock are how this size was chosen; 16 pt regular was the other one
// drawn.

import AppKit
import ImmuneCore

@MainActor
public enum MenuIcon {
  /// What the status item's image is drawn with.
  public static let configuration = NSImage.SymbolConfiguration(
    pointSize: 15, weight: .medium, scale: .medium)

  /// The count beside the icon: the menu bar's own size, digits of one width, a weight that
  /// matches the symbol's.
  public static let countFont = NSFont.monospacedDigitSystemFont(
    ofSize: NSFont.menuBarFont(ofSize: 0).pointSize, weight: .medium)

  /// The image for a state, with its words for VoiceOver: filled only when something needs the
  /// person now. In the state's colour where it has one (`tint`); a template image, which macOS
  /// colours for the bar, where it has none.
  public static func image(
    _ light: Light, urgent: Bool, words: String,
    configuration: NSImage.SymbolConfiguration = configuration
  ) -> NSImage? {
    let name = Light.menuSymbol(light, urgent: urgent)
    let tint = tint(light, urgent: urgent)
    // A filled symbol's mark is its first layer: white on the filled shape, so it stays seen.
    let palette = { (c: NSColor) in name.hasSuffix(".fill") ? [NSColor.white, c] : [c] }
    let drawn =
      tint.map { configuration.applying(.init(paletteColors: palette($0))) } ?? configuration
    let image = NSImage(systemSymbolName: name, accessibilityDescription: words)?
      .withSymbolConfiguration(drawn)
    image?.isTemplate = tint == nil
    return image
  }

  /// The icon's colour, the same roles as the panel's glyph and the report's band: red when
  /// something needs the person now, orange when there are things to look at and none is urgent
  /// and when the Mac is watched in part, green when nothing is to look at on a Mac watched in
  /// full; none, so the bar's own colour, when the answer is old or cannot be told.
  public static func tint(_ light: Light, urgent: Bool) -> NSColor? {
    switch light {
    case .attention: urgent ? .systemRed : .systemOrange
    case .watchedInPart: .systemOrange
    case .nothingToReport: .systemGreen
    case .stale, .cannotRead: nil
    }
  }

  /// The count beside the icon: the things the headline counts (`Panel.counts`, a pair as one),
  /// and nothing in any other state.
  public static func count(_ light: Light, things: Int) -> String? {
    if case .attention = light { return Number.grouped(things) }
    return nil
  }

  /// The status button's title: a thin space and the count, or empty.
  public static func title(_ light: Light, things: Int) -> NSAttributedString {
    guard let n = count(light, things: things) else { return NSAttributedString(string: "") }
    return NSAttributedString(string: " " + n, attributes: [.font: countFont])
  }
}
