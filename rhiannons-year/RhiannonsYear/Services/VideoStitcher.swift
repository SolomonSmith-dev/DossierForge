import AVFoundation
import Photos
import UIKit

enum VideoStitcher {
    enum StitchError: LocalizedError {
        case noClips
        case exportFailed
        case photosDenied

        var errorDescription: String? {
            switch self {
            case .noClips: return "There are no daily clips to stitch yet."
            case .exportFailed: return "Could not create the year video."
            case .photosDenied: return "Photos access is needed to save the year video."
            }
        }
    }

    static func stitch(clips: [DayClip], store: ClipStore) async throws -> URL {
        let sorted = clips.sorted { $0.dayKey < $1.dayKey }
        guard !sorted.isEmpty else { throw StitchError.noClips }

        let composition = AVMutableComposition()
        guard
            let videoTrack = composition.addMutableTrack(
                withMediaType: .video,
                preferredTrackID: kCMPersistentTrackID_Invalid
            )
        else {
            throw StitchError.exportFailed
        }

        let audioTrack = composition.addMutableTrack(
            withMediaType: .audio,
            preferredTrackID: kCMPersistentTrackID_Invalid
        )

        var cursor = CMTime.zero
        var firstTransform: CGAffineTransform?

        for clip in sorted {
            let url = await MainActor.run { store.url(for: clip) }
            let asset = AVURLAsset(url: url)
            let duration = try await asset.load(.duration)
            let timeRange = CMTimeRange(start: .zero, duration: duration)

            if let assetVideo = try await asset.loadTracks(withMediaType: .video).first {
                try videoTrack.insertTimeRange(timeRange, of: assetVideo, at: cursor)
                if firstTransform == nil {
                    firstTransform = try await assetVideo.load(.preferredTransform)
                }
            }

            if let audioTrack,
               let assetAudio = try await asset.loadTracks(withMediaType: .audio).first {
                try audioTrack.insertTimeRange(timeRange, of: assetAudio, at: cursor)
            }

            cursor = CMTimeAdd(cursor, duration)
        }

        if let firstTransform {
            videoTrack.preferredTransform = firstTransform
        }

        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rhiannons-year-\(DayClip.dayKey()).mp4")
        if FileManager.default.fileExists(atPath: outputURL.path) {
            try FileManager.default.removeItem(at: outputURL)
        }

        guard let exporter = AVAssetExportSession(
            asset: composition,
            presetName: AVAssetExportPresetHighestQuality
        ) else {
            throw StitchError.exportFailed
        }

        exporter.outputURL = outputURL
        exporter.outputFileType = .mp4
        exporter.shouldOptimizeForNetworkUse = true

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            exporter.exportAsynchronously {
                continuation.resume()
            }
        }

        guard exporter.status == .completed else {
            throw exporter.error ?? StitchError.exportFailed
        }

        return outputURL
    }

    static func saveToPhotos(url: URL) async throws {
        let status = await PHPhotoLibrary.requestAuthorization(for: .addOnly)
        guard status == .authorized || status == .limited else {
            throw StitchError.photosDenied
        }

        try await PHPhotoLibrary.shared().performChanges {
            PHAssetChangeRequest.creationRequestForAssetFromVideo(atFileURL: url)
        }
    }
}
