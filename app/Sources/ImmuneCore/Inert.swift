// Text taken from a source (every `*_text` field, and anything Immune printed on
// failure) is data. It is shown as plain characters: invisible and control
// characters are spelled out instead of obeyed, its length is capped, and it is
// never turned into markup, a command, a path to open or a URL. The views show
// every line with `Text(verbatim:)`, which never interprets markup.

import Foundation

public enum Inert {
  public static let defaultLimit = 300

  /// The most combining marks kept on one character; the rest are spelled out, so a mark cannot
  /// pile up past the cap on length (which counts characters) or over the lines around it.
  public static let marksKept = 3

  public static func text(_ raw: String, limit: Int = defaultLimit) -> String {
    var shown = ""
    var marks = 0
    for scalar in raw.unicodeScalars {
      switch scalar.properties.generalCategory {
      case .nonspacingMark, .spacingMark, .enclosingMark:
        marks += 1
        shown += marks > marksKept ? code(scalar) : spelled(scalar)
      default:
        marks = 0
        shown += spelled(scalar)
      }
    }
    guard shown.count > limit else { return shown }
    return String(shown.prefix(limit)) + "… (cut, \(shown.count) characters in all)"
  }

  /// The same, for a thing's name or path: too long, it loses its middle and keeps both ends,
  /// so neither the project at its head nor the file's name at its tail is lost.
  public static func whole(_ raw: String, limit: Int = 1000) -> String {
    let shown = text(raw, limit: .max)
    guard shown.count > limit else { return shown }
    let half = max(limit / 2, 1)
    return String(shown.prefix(half)) + " … (cut, \(shown.count) characters in all) … "
      + String(shown.suffix(half))
  }

  /// Whether a value already shown inert is a path: it starts at the root or at the home folder
  /// and names something after its last `/`. Nothing else is read into it.
  public static func isPath(_ shown: String) -> Bool {
    (shown.hasPrefix("/") || shown.hasPrefix("~/")) && !shown.hasSuffix("/")
  }

  /// A value already shown inert, cut to fit one line, where `fits` says whether a candidate
  /// fits. A path keeps its last component whole whenever "…/" and it fit, and its start keeps
  /// as much as is left: `~/dev/…/example-colors`. When the last component alone does not fit,
  /// it is cut in its own middle after "…/". A path of one component, and any other value, is
  /// cut in the middle. The cut only splits on the last `/`; nothing in the value is read.
  public static func fit(_ shown: String, path: Bool, fits: (String) -> Bool) -> String {
    if fits(shown) { return shown }
    guard path, isPath(shown), let slash = shown.lastIndex(of: "/"), slash > shown.startIndex
    else { return middle(shown, fits: fits) }
    let head = Array(shown[..<slash])
    let tail = String(shown[slash...])
    guard fits("…" + tail) else {
      // Too narrow for even "…/…": the plain cut in the middle.
      guard fits("…/…") else { return middle(shown, fits: fits) }
      let last = String(shown[shown.index(after: slash)...])
      return "…/" + middle(last) { fits("…/" + $0) }
    }
    // The longest start that fits beside the last component.
    let keep = largest(head.count) { fits(String(head.prefix($0)) + "…" + tail) }
    return String(head.prefix(keep)) + "…" + tail
  }

  /// Cut in the middle to the most characters that fit, both ends kept.
  static func middle(_ shown: String, fits: (String) -> Bool) -> String {
    let chars = Array(shown)
    func cut(_ n: Int) -> String {
      String(chars.prefix((n + 1) / 2)) + "…" + String(chars.suffix(n / 2))
    }
    return cut(largest(chars.count - 1) { fits(cut($0)) })
  }

  /// The largest n in 0...upper for which `ok` holds, taking `ok` to hold for every smaller
  /// n as well; 0 when none does.
  static func largest(_ upper: Int, _ ok: (Int) -> Bool) -> Int {
    var low = 0
    var high = max(upper, 0)
    while low < high {
      let mid = (low + high + 1) / 2
      if ok(mid) { low = mid } else { high = mid - 1 }
    }
    return low
  }

  /// A scalar as it is shown: itself, or its code spelled out when it would be
  /// invisible or would change how the text around it is laid out or read.
  /// Spelled out besides control and format characters: every default-ignorable code point
  /// (drawn as nothing, as U+3164 or a variation selector is), the blank braille pattern, and
  /// every space but the plain one, which would pass for a space between words or arguments.
  static func spelled(_ s: Unicode.Scalar) -> String {
    switch s {
    case "\n": return "\\n"
    case "\r": return "\\r"
    case "\t": return "\\t"
    case " ": return " "
    case "\u{2800}": return code(s)
    default: break
    }
    if s.properties.isDefaultIgnorableCodePoint || s.properties.isWhitespace { return code(s) }
    switch s.properties.generalCategory {
    case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .unassigned,
      .spaceSeparator:
      return code(s)
    default:
      return String(s)
    }
  }

  static func code(_ s: Unicode.Scalar) -> String {
    "\\u{" + String(s.value, radix: 16, uppercase: true) + "}"
  }

  /// A value already shown inert, as it is drawn: it starts left to right, and each piece
  /// between a `/` or a space is isolated, so letters written right to left reorder only inside
  /// their own piece and never move a component or an argument. A source cannot end an isolate:
  /// Inert has spelled out every format character it held. For drawing only; the value itself
  /// is unchanged everywhere else.
  public static func display(_ shown: String) -> String {
    var out = "\u{200E}"
    var piece = ""
    func flush() {
      if !piece.isEmpty { out += "\u{2066}" + piece + "\u{2069}" }
      piece = ""
    }
    for c in shown {
      if c == "/" || c == " " {
        flush()
        out.append(c)
      } else {
        piece.append(c)
      }
    }
    flush()
    return out
  }
}
