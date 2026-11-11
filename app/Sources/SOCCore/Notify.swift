// The owner hears about urgent things: a notification when an item soc marked
// `urgent` is seen for the first time. soc decides what is urgent; the app only
// decides when it is new. The system's notification centre sits behind
// `Notifying`, so tests use a recording stand-in and never ask the system anything.

import Foundation

/// Whether the system lets the app show notifications.
public enum NotifyPermission: Sendable, Equatable {
  /// The owner has not been asked yet.
  case notAsked
  case allowed
  /// Declined, or turned off in System Settings.
  case off
}

/// One notification: fixed words or soc's title, and at most the place.
public struct Note: Sendable, Equatable {
  public let id: String
  public let title: String
  public let body: String?
}

/// The system's notification centre, or a stand-in.
@MainActor
public protocol Notifying: AnyObject {
  func permission() async -> NotifyPermission
  /// Shows the system's question. Called at most once in the app's life.
  func requestPermission() async
  func deliver(_ note: Note)
}

/// Where the app remembers what it notified. `UserDefaults` in the app, a
/// dictionary in tests.
public protocol Remembering: AnyObject {
  func object(forKey key: String) -> Any?
  func set(_ value: Any?, forKey key: String)
}

extension UserDefaults: Remembering {}

/// Memory that lasts only as long as the process: for tests and renders.
public final class Forgetful: Remembering {
  private var values: [String: Any] = [:]
  public init() {}
  public func object(forKey key: String) -> Any? { values[key] }
  public func set(_ value: Any?, forKey key: String) { values[key] = value }
}

/// Decides what to notify from soc's reading, and remembers it.
@MainActor
public final class Announcer {
  /// Ids remembered as notified, newest last. Past the cap the oldest are
  /// forgotten; ids still served are moved to the newest on every reading, so only
  /// an item gone from soc's list long ago could ever be notified again.
  nonisolated public static let rememberedIds = 1000
  /// Stores already read once, the first reading being the baseline.
  nonisolated public static let rememberedStores = 20
  /// More new urgent things than this at once make one notification, not many.
  nonisolated public static let burst = 3
  nonisolated public static let offLine = "Notifications are off, so urgent things show only here"

  /// System Settings, Notifications, at this app (macOS 13 and later).
  nonisolated public static func settingsURL(bundleId: String) -> URL? {
    var c = URLComponents()
    c.scheme = "x-apple.systempreferences"
    c.path = "com.apple.Notifications-Settings.extension"
    c.queryItems = [URLQueryItem(name: "id", value: bundleId)]
    return c.url
  }

  nonisolated static let idsKey = "notify.delivered"
  nonisolated static let storesKey = "notify.stores"
  nonisolated static let askedKey = "notify.asked"

  private let notifier: any Notifying
  private let memory: any Remembering
  /// The panel's quiet line: notifications cannot reach the owner.
  public private(set) var off = false

  public init(notifier: any Notifying, memory: any Remembering) {
    self.notifier = notifier
    self.memory = memory
  }

  /// On the app's first real launch: ask the system once, ever. A declined or
  /// dismissed question is never asked again by the app.
  public func askOnce() async {
    if memory.object(forKey: Self.askedKey) as? Bool != true,
      await notifier.permission() == .notAsked
    {
      // Remembered before asking, so even a crash in between never asks twice.
      memory.set(true, forKey: Self.askedKey)
      await notifier.requestPermission()
    }
    await checkPermission()
  }

  /// Reads the permission again, without asking: the owner may have changed it in
  /// System Settings.
  public func checkPermission() async {
    let p = await notifier.permission()
    let asked = memory.object(forKey: Self.askedKey) as? Bool == true
    off = p == .off || (asked && p == .notAsked)
  }

  /// Called with every status read. Returns what was delivered.
  @discardableResult
  public func saw(_ s: Status) async -> [Note] {
    guard let items = s.needsALook else { return [] }
    let store = s.store?.pathText ?? ""
    var stores = memory.object(forKey: Self.storesKey) as? [String] ?? []
    var known = memory.object(forKey: Self.idsKey) as? [String] ?? []
    let urgent = items.filter { $0.urgent && $0.id != nil }
    let ids = urgent.compactMap(\.id)
    let fresh = stores.contains(store) ? urgent.filter { !known.contains($0.id!) } : []
    if !stores.contains(store) {
      // The first reading of a store is the baseline: what is already there was
      // there before the app, and is not news.
      stores = Array((stores + [store]).suffix(Self.rememberedStores))
      memory.set(stores, forKey: Self.storesKey)
    }
    known = Array((known.filter { !ids.contains($0) } + ids).suffix(Self.rememberedIds))
    memory.set(known, forKey: Self.idsKey)

    let notes = Self.notes(fresh)
    if !notes.isEmpty, await notifier.permission() == .allowed {
      notes.forEach(notifier.deliver)
      return notes
    }
    return []
  }

  /// One per item, or one for all when more than `burst` are new at once. Only
  /// soc's title and the place go in, both inert; nothing else from a source.
  nonisolated static func notes(_ fresh: [Item]) -> [Note] {
    if fresh.count > burst {
      return [
        Note(id: "needs-a-look-now", title: "\(fresh.count) things need a look now", body: nil)
      ]
    }
    return fresh.map {
      Note(
        id: $0.id ?? "", title: Inert.text($0.title ?? "", limit: 200),
        body: $0.whereText.map { Inert.text($0, limit: 200) })
    }
  }
}
