// Draws a view off screen into a PNG at 2x, for review: the view hierarchy is drawn into a
// bitmap, nothing is captured from the screen. The popover's translucent material cannot be
// drawn this way; the window background colour stands in for it.

import AppKit
import SwiftUI

@MainActor
public enum Snapshot {
  /// A SwiftUI view at its own fitting size, in one appearance.
  public static func png<V: View>(_ view: V, appearance name: NSAppearance.Name) async -> Data? {
    guard let appearance = NSAppearance(named: name) else { return nil }
    let host = NSHostingView(
      rootView: view.fixedSize(horizontal: false, vertical: true)
        .background(Color(nsColor: .windowBackgroundColor)))
    host.appearance = appearance
    // Lay out a few times: measured heights settle after the first passes.
    for _ in 0..<5 {
      host.frame = NSRect(origin: .zero, size: host.fittingSize)
      host.layoutSubtreeIfNeeded()
      try? await Task.sleep(for: .milliseconds(100))
    }
    return png(host, appearance: appearance)
  }

  /// An AppKit view as it is laid out now.
  public static func png(_ view: NSView, appearance: NSAppearance) -> Data? {
    let size = view.bounds.size
    guard size.width > 0, size.height > 0,
      let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: Int(size.width * 2), pixelsHigh: Int(size.height * 2),
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
    else { return nil }
    rep.size = size
    appearance.performAsCurrentDrawingAppearance { view.cacheDisplay(in: view.bounds, to: rep) }
    return rep.representation(using: .png, properties: [:])
  }
}
