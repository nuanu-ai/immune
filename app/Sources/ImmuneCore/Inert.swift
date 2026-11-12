// Text taken from a source (every `*_text` field, and anything Immune printed on
// failure) is data. It is shown as plain characters: invisible and control
// characters are spelled out instead of obeyed, its length is capped, and it is
// never turned into markup, a command, a path to open or a URL. The views show
// every line with `Text(verbatim:)`, which never interprets markup.

import Foundation

public enum Inert {
  public static let defaultLimit = 300

  public static func text(_ raw: String, limit: Int = defaultLimit) -> String {
    var shown = ""
    for scalar in raw.unicodeScalars {
      shown += spelled(scalar)
    }
    guard shown.count > limit else { return shown }
    return String(shown.prefix(limit)) + "… (cut, \(shown.count) characters in all)"
  }

  /// A scalar as it is shown: itself, or its code spelled out when it would be
  /// invisible or would change how the text around it is laid out or read.
  static func spelled(_ s: Unicode.Scalar) -> String {
    switch s {
    case "\n": return "\\n"
    case "\r": return "\\r"
    case "\t": return "\\t"
    default: break
    }
    switch s.properties.generalCategory {
    case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .unassigned:
      return "\\u{" + String(s.value, radix: 16, uppercase: true) + "}"
    default:
      return String(s)
    }
  }
}
