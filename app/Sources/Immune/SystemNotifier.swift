// The system's notification centre, as thin as it can be: what to notify and when
// is decided by `Announcer` in ImmuneCore. Made only by the running app, never by
// tests, renders or `--print-panel`, so nothing else can ask the system.

import Foundation
import ImmuneCore
import UserNotifications

@MainActor
final class SystemNotifier: NSObject, Notifying, UNUserNotificationCenterDelegate {
  private let center = UNUserNotificationCenter.current()
  private let onOpen: @MainActor () -> Void

  /// `onOpen` runs when the owner clicks a notification: it opens the panel.
  init(onOpen: @escaping @MainActor () -> Void) {
    self.onOpen = onOpen
    super.init()
    center.delegate = self
  }

  func permission() async -> NotifyPermission {
    let settings = await center.notificationSettings()
    switch settings.authorizationStatus {
    case .notDetermined: return .notAsked
    case .denied: return .off
    default: return settings.alertSetting == .disabled ? .off : .allowed
    }
  }

  func requestPermission() async {
    do {
      let granted = try await center.requestAuthorization(options: [.alert])
      log("notifications: \(granted ? "allowed" : "declined")")
    } catch {
      log("notifications: the system refused the request: \(error.localizedDescription)")
    }
  }

  func deliver(_ note: Note) {
    let content = UNMutableNotificationContent()
    content.title = note.title
    if let subtitle = note.subtitle { content.subtitle = subtitle }
    if let body = note.body { content.body = body }
    center.add(UNNotificationRequest(identifier: note.id, content: content, trigger: nil))
    log("notified")
  }

  nonisolated func userNotificationCenter(
    _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
  ) async {
    await MainActor.run { onOpen() }
  }

  /// Shown even while the app is in front.
  nonisolated func userNotificationCenter(
    _ center: UNUserNotificationCenter, willPresent notification: UNNotification
  ) async -> UNNotificationPresentationOptions { [.banner, .list] }
}
