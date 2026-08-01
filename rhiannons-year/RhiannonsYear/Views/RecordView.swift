import AVKit
import SwiftUI

struct RecordView: View {
    @EnvironmentObject private var store: ClipStore
    @Environment(\.dismiss) private var dismiss

    @StateObject private var camera = CameraService()
    @State private var phase: Phase = .ready
    @State private var previewURL: URL?
    @State private var errorMessage: String?
    @State private var isBusy = false

    enum Phase {
        case ready
        case recording
        case review
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            switch phase {
            case .ready, .recording:
                cameraBody
            case .review:
                reviewBody
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Text("Today's 5 seconds")
                    .font(.custom(AppTheme.bodyFont, size: 18).weight(.bold))
                    .foregroundStyle(.white)
            }
        }
        .task {
            await camera.requestAccessAndConfigure()
        }
        .onDisappear {
            camera.stopSession()
        }
        .alert("Oops", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var cameraBody: some View {
        ZStack {
            CameraPreviewView(previewLayer: camera.previewLayer)
                .ignoresSafeArea()

            VStack {
                Spacer()

                if let countdown = camera.countdown {
                    Text("\(countdown)")
                        .font(.custom(AppTheme.brandFont, size: 120).weight(.heavy))
                        .foregroundStyle(.white)
                        .shadow(radius: 8)
                        .transition(.scale.combined(with: .opacity))
                }

                Spacer()

                progressBar
                    .padding(.horizontal, 40)
                    .padding(.bottom, 12)

                Button {
                    Task { await startRecording() }
                } label: {
                    ZStack {
                        Circle()
                            .strokeBorder(.white, lineWidth: 6)
                            .frame(width: 92, height: 92)
                        Circle()
                            .fill(camera.isRecording ? AppTheme.coral : .white)
                            .frame(width: camera.isRecording ? 36 : 72, height: camera.isRecording ? 36 : 72)
                            .animation(.easeInOut(duration: 0.2), value: camera.isRecording)
                    }
                }
                .disabled(isBusy || !camera.isAuthorized || camera.isRecording)
                .padding(.bottom, 40)
                .accessibilityLabel("Start recording")
            }

            if !camera.isAuthorized {
                permissionOverlay
            }
        }
    }

    private var reviewBody: some View {
        VStack(spacing: 20) {
            if let previewURL {
                VideoPlayer(player: AVPlayer(url: previewURL))
                    .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
                    .padding(.horizontal, 20)
                    .padding(.top, 12)
            }

            Text("Love it?")
                .font(.custom(AppTheme.brandFont, size: 34).weight(.bold))
                .foregroundStyle(.white)

            HStack(spacing: 16) {
                Button("Retake") {
                    previewURL = nil
                    phase = .ready
                    camera.progress = 0
                }
                .buttonStyle(KidButtonStyle(fill: AppTheme.softInk))

                Button("Save day") {
                    Task { await saveClip() }
                }
                .buttonStyle(KidButtonStyle(fill: AppTheme.meadow))
                .disabled(isBusy)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
        }
    }

    private var progressBar: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(.white.opacity(0.25))
                Capsule()
                    .fill(AppTheme.coral)
                    .frame(width: geo.size.width * camera.progress)
            }
        }
        .frame(height: 10)
    }

    private var permissionOverlay: some View {
        VStack(spacing: 16) {
            Text("Camera needs a yes")
                .font(.custom(AppTheme.brandFont, size: 28).weight(.bold))
            Text("Ask a grown-up to allow Camera and Microphone in Settings.")
                .font(.custom(AppTheme.bodyFont, size: 18))
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
        }
        .foregroundStyle(.white)
        .padding(28)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
        .padding(24)
    }

    private func startRecording() async {
        isBusy = true
        phase = .recording
        do {
            let url = try await camera.recordFiveSecondClip()
            previewURL = url
            withAnimation {
                phase = .review
            }
        } catch {
            errorMessage = error.localizedDescription
            phase = .ready
        }
        isBusy = false
    }

    private func saveClip() async {
        guard let previewURL else { return }
        isBusy = true
        do {
            try store.saveTodayClip(from: previewURL)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
        isBusy = false
    }
}

struct KidButtonStyle: ButtonStyle {
    let fill: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.custom(AppTheme.bodyFont, size: 20).weight(.bold))
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 18)
            .background(fill.opacity(configuration.isPressed ? 0.85 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}
