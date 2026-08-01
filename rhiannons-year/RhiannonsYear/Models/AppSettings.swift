import Foundation
import Combine

@MainActor
final class AppSettings: ObservableObject {
    private enum Keys {
        static let parentPIN = "parentPIN"
        static let reminderEnabled = "reminderEnabled"
        static let reminderHour = "reminderHour"
        static let reminderMinute = "reminderMinute"
        static let yearStart = "yearStart"
        static let childName = "childName"
    }

    @Published var parentPIN: String {
        didSet { UserDefaults.standard.set(parentPIN, forKey: Keys.parentPIN) }
    }

    @Published var reminderEnabled: Bool {
        didSet {
            UserDefaults.standard.set(reminderEnabled, forKey: Keys.reminderEnabled)
            NotificationService.reschedule(settings: self)
        }
    }

    @Published var reminderHour: Int {
        didSet {
            UserDefaults.standard.set(reminderHour, forKey: Keys.reminderHour)
            NotificationService.reschedule(settings: self)
        }
    }

    @Published var reminderMinute: Int {
        didSet {
            UserDefaults.standard.set(reminderMinute, forKey: Keys.reminderMinute)
            NotificationService.reschedule(settings: self)
        }
    }

    @Published var yearStart: Date {
        didSet {
            UserDefaults.standard.set(yearStart.timeIntervalSince1970, forKey: Keys.yearStart)
        }
    }

    @Published var childName: String {
        didSet { UserDefaults.standard.set(childName, forKey: Keys.childName) }
    }

    var brandTitle: String {
        "\(childName)'s Year"
    }

    init() {
        let defaults = UserDefaults.standard
        parentPIN = defaults.string(forKey: Keys.parentPIN) ?? "1234"
        reminderEnabled = defaults.object(forKey: Keys.reminderEnabled) as? Bool ?? true
        reminderHour = defaults.object(forKey: Keys.reminderHour) as? Int ?? 18
        reminderMinute = defaults.object(forKey: Keys.reminderMinute) as? Int ?? 0
        childName = defaults.string(forKey: Keys.childName) ?? "Rhiannon"

        if let interval = defaults.object(forKey: Keys.yearStart) as? TimeInterval {
            yearStart = Date(timeIntervalSince1970: interval)
        } else {
            let calendar = Calendar.current
            let year = calendar.component(.year, from: Date())
            yearStart = calendar.date(from: DateComponents(year: year, month: 1, day: 1)) ?? Date()
        }
    }

    var reminderTimeLabel: String {
        let components = DateComponents(hour: reminderHour, minute: reminderMinute)
        let date = Calendar.current.date(from: components) ?? Date()
        let formatter = DateFormatter()
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}
