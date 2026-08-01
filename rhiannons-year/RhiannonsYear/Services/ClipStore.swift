import Foundation
import Combine

@MainActor
final class ClipStore: ObservableObject {
    @Published private(set) var clips: [DayClip] = []
    @Published var lastError: String?

    private let fileManager = FileManager.default
    private let indexFileName = "clip_index.json"

    var clipsDirectory: URL {
        let docs = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let dir = docs.appendingPathComponent("DailyClips", isDirectory: true)
        if !fileManager.fileExists(atPath: dir.path) {
            try? fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir
    }

    private var indexURL: URL {
        clipsDirectory.appendingPathComponent(indexFileName)
    }

    init() {
        load()
    }

    var recordedCount: Int { clips.count }

    var sortedClips: [DayClip] {
        clips.sorted { $0.dayKey < $1.dayKey }
    }

    func hasClip(for date: Date = Date()) -> Bool {
        clip(for: date) != nil
    }

    func clip(for date: Date) -> DayClip? {
        let key = DayClip.dayKey(for: date)
        return clips.first { $0.dayKey == key }
    }

    func url(for clip: DayClip) -> URL {
        clipsDirectory.appendingPathComponent(clip.fileName)
    }

    func currentStreak(endingOn date: Date = Date()) -> Int {
        var streak = 0
        var cursor = Calendar.current.startOfDay(for: date)
        while hasClip(for: cursor) {
            streak += 1
            guard let previous = Calendar.current.date(byAdding: .day, value: -1, to: cursor) else { break }
            cursor = previous
        }
        return streak
    }

    @discardableResult
    func saveTodayClip(from temporaryURL: URL, duration: Double = 5.0) throws -> DayClip {
        let dayKey = DayClip.dayKey()
        let fileName = DayClip.fileName(for: dayKey)
        let destination = clipsDirectory.appendingPathComponent(fileName)

        if fileManager.fileExists(atPath: destination.path) {
            try fileManager.removeItem(at: destination)
        }

        try fileManager.copyItem(at: temporaryURL, to: destination)

        let clip = DayClip(
            dayKey: dayKey,
            fileName: fileName,
            createdAt: Date(),
            durationSeconds: duration
        )

        clips.removeAll { $0.dayKey == dayKey }
        clips.append(clip)
        clips.sort { $0.dayKey < $1.dayKey }
        try persistIndex()
        return clip
    }

    func deleteClip(_ clip: DayClip) throws {
        let url = url(for: clip)
        if fileManager.fileExists(atPath: url.path) {
            try fileManager.removeItem(at: url)
        }
        clips.removeAll { $0.dayKey == clip.dayKey }
        try persistIndex()
    }

    func load() {
        do {
            guard fileManager.fileExists(atPath: indexURL.path) else {
                clips = []
                return
            }
            let data = try Data(contentsOf: indexURL)
            let index = try JSONDecoder().decode(ClipIndex.self, from: data)
            clips = index.clips
                .filter { fileManager.fileExists(atPath: url(for: $0).path) }
                .sorted { $0.dayKey < $1.dayKey }
        } catch {
            lastError = error.localizedDescription
            clips = []
        }
    }

    private func persistIndex() throws {
        let data = try JSONEncoder().encode(ClipIndex(clips: clips))
        try data.write(to: indexURL, options: [.atomic])
    }
}
