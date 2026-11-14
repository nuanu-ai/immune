// The menu-bar icon: one SF Symbol per state, a template image so macOS colours it for a
// light or a dark bar and for the selected state, and the count beside it.
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

  /// The template image for a state, with its words for VoiceOver: filled only when something
  /// needs the person now.
  public static func image(
    _ light: Light, urgent: Bool, words: String,
    configuration: NSImage.SymbolConfiguration = configuration
  ) -> NSImage? {
    let name = Light.menuSymbol(light, urgent: urgent)
    let image = NSImage(systemSymbolName: name, accessibilityDescription: words)?
      .withSymbolConfiguration(configuration)
    image?.isTemplate = true
    return image
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
