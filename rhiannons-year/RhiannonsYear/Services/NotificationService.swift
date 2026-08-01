import Foundation
import UserNotifications

enum NotificationService {
    private static let identifier = "rhiannons-year-daily-reminder"

    static func requestAuthorizationIfNeeded() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    @MainActor
    static func reschedule(settings: AppSettings) {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [identifier])

        guard settings.reminderEnabled else { return }

        var date = DateComponents()
        date.hour = settings.reminderHour
        date.minute = settings.reminderMinute

        let content = UNMutableNotificationContent()
        content.title = settings.brandTitle
        content.body = "Time for today's 5 seconds!"
        content.sound = .default

        let trigger = UNCalendarNotificationTrigger(dateMatching: date, repeats: true)
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: trigger)
        center.add(request)
    }
}
