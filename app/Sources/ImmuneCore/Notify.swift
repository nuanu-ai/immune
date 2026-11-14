// The owner hears about urgent things: a notification when an item Immune marked
// `urgent` is seen for the first time, and when more urgent findings than before are beyond
// the list Immune serves, so a count the person cannot see still reaches them. Immune
// decides what is urgent; the app only decides when it is new. The system's notification centre sits behind
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

/// One notification: "Needs you now"; under it the kind and what happened, in the app's words;
/// then the thing itself, inert.
public struct Note: Sendable, Equatable {
  public let id: String
  public let title: String
  public var subtitle: String? = nil
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

/// Decides what to notify from Immune's reading, and remembers it.
@MainActor
public final class Announcer {
  /// Ids remembered as notified, newest last. Past the cap the oldest are
  /// forgotten; ids still served are moved to the newest on every reading, so only
  /// an item gone from Immune's list long ago could ever be notified again.
  nonisolated public static let rememberedIds = 1000
  /// Stores already read once, the first reading being the baseline.
  nonisolated public static let rememberedStores = 20
  /// More new urgent things than this at once make one notification, not many.
  nonisolated public static let burst = 3
  nonisolated public static let offLine = "Notifications are off, so urgent things show only here"
  /// The same, as the panel's row: what it is, and a word on it.
  nonisolated public static let offTitle = "Notifications are off"
  nonisolated public static let offDetail = "Urgent things show only here"
  /// Every notification's title: the app notifies only what needs the person now.
  nonisolated public static let title = "Needs you now"

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
  nonisolated static let unlistedKey = "notify.unlisted"

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

    // Urgent findings beyond the list: told when there are more than at the last reading of
    // this store, once for each number; the first reading of a store is the baseline.
    let unlisted = max(0, (s.needsALookUrgent ?? urgent.count) - urgent.count)
    var counted = memory.object(forKey: Self.unlistedKey) as? [String: Int] ?? [:]
    let before = counted[store]
    counted[store] = unlisted
    memory.set(counted, forKey: Self.unlistedKey)
    var notes = Self.notes(fresh, among: items)
    if let before, unlisted > before { notes.append(Self.unlistedNote(unlisted)) }
    if !notes.isEmpty, await notifier.permission() == .allowed {
      notes.forEach(notifier.deliver)
      return notes
    }
    return []
  }

  /// "3 urgent findings are not in the list": how many, never which, since the list does not
  /// hold them.
  nonisolated static func unlistedNote(_ n: Int) -> Note {
    let subtitle =
      n == 1 ? "1 urgent finding is not in the list" : "\(n) urgent findings are not in the list"
    return Note(
      id: "urgent-not-listed", title: title, subtitle: subtitle,
      body: "Open the report to see every finding.")
  }

  /// One per thing, or one for all when more than `burst` things are new at once. Each says the
  /// kind and what happened in the app's words, as the panel's row does, and the thing itself,
  /// inert, cut in the middle; nothing else from a source.
  ///
  /// Things are counted as the panel's rows show them (`Panel.entries`): the response layer's
  /// own finding about a finding of the core that `items` lists is that one thing, told by the
  /// core finding's kind and thing, and a pair new at once is one note. `fresh` is of `items`.
  nonisolated public static func notes(_ fresh: [Item], among items: [Item]) -> [Note] {
    let entries = Panel.entries(
      items.enumerated().map { Row(id: $0.offset, item: $0.element, now: Date()) })
    // Each new thing once, by the entry that holds it, with the first new finding's id.
    var things: [(id: String, row: Row)] = []
    var told: Set<Int> = []
    for urgent in fresh {
      guard let i = items.firstIndex(of: urgent),
        let e = entries.first(where: { e in e.id == i || e.children.contains { $0.id == i } })
      else { continue }
      if told.insert(e.id).inserted { things.append((urgent.id ?? "", e.row)) }
    }
    if things.count > burst {
      return [
        Note(id: "needs-a-look-now", title: title, subtitle: "\(things.count) things", body: nil)
      ]
    }
    return things.map { thing in
      let row = thing.row
      let said = Entry.said(row).map { "response layer: " + $0 }
      let subtitle = [row.meta.isEmpty ? nil : row.meta, said].compactMap { $0 }
        .joined(separator: " · ")
      return Note(
        id: thing.id, title: title, subtitle: subtitle.isEmpty ? nil : subtitle,
        body: Inert.whole(row.object, limit: 200))
    }
  }
}
