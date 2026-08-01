import Foundation

struct DayClip: Identifiable, Codable, Equatable, Hashable {
    var id: String { dayKey }
    let dayKey: String
    let fileName: String
    let createdAt: Date
    let durationSeconds: Double

    var date: Date {
        DayClip.dayFormatter.date(from: dayKey) ?? createdAt
    }

    static let dayFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.calendar = Calendar.current
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter
    }()

    static func dayKey(for date: Date = Date()) -> String {
        dayFormatter.string(from: Calendar.current.startOfDay(for: date))
    }

    static func fileName(for dayKey: String) -> String {
        "\(dayKey).mp4"
    }
}

struct ClipIndex: Codable {
    var clips: [DayClip]
}
