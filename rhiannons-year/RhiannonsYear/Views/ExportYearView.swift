import AVKit
import SwiftUI

struct ExportYearView: View {
    @EnvironmentObject private var store: ClipStore
    @EnvironmentObject private var settings: AppSettings

    @State private var isWorking = false
    @State private var statusMessage: String?
    @State private var exportedURL: URL?
    @State private var showShare = false
    @State private var errorMessage: String?

    var body: some View {
        ZStack {
            SkyBackground()

            VStack(spacing: 24) {
                Text("Make my year")
                    .font(.custom(AppTheme.brandFont, size: 40).weight(.heavy))
                    .foregroundStyle(AppTheme.ink)
                    .padding(.top, 12)

                Text("Stitch every saved day into one big movie.")
                    .font(.custom(AppTheme.bodyFont, size: 20).weight(.medium))
                    .foregroundStyle(AppTheme.softInk)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)

                VStack(spacing: 8) {
                    Text("\(store.recordedCount)")
                        .font(.custom(AppTheme.brandFont, size: 72).weight(.heavy))
                        .foregroundStyle(AppTheme.coral)
                    Text("days ready")
                        .font(.custom(AppTheme.bodyFont, size: 20).weight(.semibold))
                        .foregroundStyle(AppTheme.softInk)
                }
                .padding(.vertical, 20)

                if let exportedURL {
                    VideoPlayer(player: AVPlayer(url: exportedURL))
                        .frame(height: 240)
                        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
                        .padding(.horizontal, 28)
                }

                if let statusMessage {
                    Text(statusMessage)
                        .font(.custom(AppTheme.bodyFont, size: 17).weight(.medium))
                        .foregroundStyle(AppTheme.meadow)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }

                Spacer()

                VStack(spacing: 14) {
                    Button {
                        Task { await stitch() }
                    } label: {
                        Text(isWorking ? "Making movie…" : "Make \(settings.brandTitle) video")
                    }
                    .buttonStyle(KidButtonStyle(fill: AppTheme.coral))
                    .disabled(isWorking || store.recordedCount == 0)

                    if exportedURL != nil {
                        Button("Save to Photos") {
                            Task { await savePhotos() }
                        }
                        .buttonStyle(KidButtonStyle(fill: AppTheme.meadow))
                        .disabled(isWorking)

                        Button("Share / Files") {
                            showShare = true
                        }
                        .buttonStyle(KidButtonStyle(fill: AppTheme.ink))
                    }
                }
                .padding(.horizontal, 28)
                .padding(.bottom, 36)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showShare) {
            if let exportedURL {
                ShareSheet(items: [exportedURL])
            }
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

    private func stitch() async {
        isWorking = true
        statusMessage = "Sewing days together…"
        do {
            let url = try await VideoStitcher.stitch(clips: store.sortedClips, store: store)
            exportedURL = url
            statusMessage = "Your year video is ready!"
        } catch {
            errorMessage = error.localizedDescription
            statusMessage = nil
        }
        isWorking = false
    }

    private func savePhotos() async {
        guard let exportedURL else { return }
        isWorking = true
        do {
            try await VideoStitcher.saveToPhotos(url: exportedURL)
            statusMessage = "Saved to Photos!"
        } catch {
            errorMessage = error.localizedDescription
        }
        isWorking = false
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
