import AVFoundation
import Combine
import UIKit

@MainActor
final class CameraService: NSObject, ObservableObject {
    @Published var isAuthorized = false
    @Published var isRecording = false
    @Published var countdown: Int?
    @Published var progress: Double = 0
    @Published var lastError: String?
    @Published var previewLayer: AVCaptureVideoPreviewLayer?

    let session = AVCaptureSession()
    private let movieOutput = AVCaptureMovieFileOutput()
    private var recordingStartedAt: Date?
    private var progressTimer: Timer?
    private var finishContinuation: CheckedContinuation<URL, Error>?

    static let clipDuration: Double = 5.0

    func requestAccessAndConfigure() async {
        let video = await AVCaptureDevice.requestAccess(for: .video)
        let audio = await AVCaptureDevice.requestAccess(for: .audio)
        isAuthorized = video && audio
        guard isAuthorized else {
            lastError = "Camera and microphone access are needed to record."
            return
        }
        configureSession()
    }

    private func configureSession() {
        session.beginConfiguration()
        session.sessionPreset = .high

        session.inputs.forEach { session.removeInput($0) }
        session.outputs.forEach { session.removeOutput($0) }

        guard
            let camera = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .front),
            let videoInput = try? AVCaptureDeviceInput(device: camera),
            session.canAddInput(videoInput)
        else {
            lastError = "Could not open the front camera."
            session.commitConfiguration()
            return
        }
        session.addInput(videoInput)

        if let mic = AVCaptureDevice.default(for: .audio),
           let audioInput = try? AVCaptureDeviceInput(device: mic),
           session.canAddInput(audioInput) {
            session.addInput(audioInput)
        }

        if session.canAddOutput(movieOutput) {
            session.addOutput(movieOutput)
            if let connection = movieOutput.connection(with: .video),
               connection.isVideoMirroringSupported {
                connection.isVideoMirrored = true
            }
        }

        session.commitConfiguration()

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        previewLayer = layer

        Task.detached(priority: .userInitiated) { [session] in
            session.startRunning()
        }
    }

    func stopSession() {
        progressTimer?.invalidate()
        progressTimer = nil
        if session.isRunning {
            session.stopRunning()
        }
    }

    func recordFiveSecondClip() async throws -> URL {
        guard !movieOutput.isRecording else {
            throw CameraError.alreadyRecording
        }

        for value in [3, 2, 1] {
            countdown = value
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        countdown = nil

        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("rhiannon-\(UUID().uuidString).mp4")

        return try await withCheckedThrowingContinuation { continuation in
            self.finishContinuation = continuation
            self.isRecording = true
            self.progress = 0
            self.recordingStartedAt = Date()
            self.movieOutput.startRecording(to: tempURL, recordingDelegate: self)

            self.progressTimer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] timer in
                Task { @MainActor in
                    guard let self, let started = self.recordingStartedAt else { return }
                    let elapsed = Date().timeIntervalSince(started)
                    self.progress = min(1, elapsed / Self.clipDuration)
                    if elapsed >= Self.clipDuration {
                        timer.invalidate()
                        self.progressTimer = nil
                        if self.movieOutput.isRecording {
                            self.movieOutput.stopRecording()
                        }
                    }
                }
            }
        }
    }

    enum CameraError: LocalizedError {
        case alreadyRecording
        case recordingFailed

        var errorDescription: String? {
            switch self {
            case .alreadyRecording: return "Already recording."
            case .recordingFailed: return "Recording failed. Please try again."
            }
        }
    }
}

extension CameraService: AVCaptureFileOutputRecordingDelegate {
    nonisolated func fileOutput(
        _ output: AVCaptureFileOutput,
        didFinishRecordingTo outputFileURL: URL,
        from connections: [AVCaptureConnection],
        error: Error?
    ) {
        Task { @MainActor in
            isRecording = false
            progressTimer?.invalidate()
            progressTimer = nil
            progress = 1

            if let error {
                finishContinuation?.resume(throwing: error)
            } else {
                finishContinuation?.resume(returning: outputFileURL)
            }
            finishContinuation = nil
        }
    }
}
