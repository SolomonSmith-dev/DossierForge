import AVKit
import SwiftUI

struct DayPlayerView: View {
    @EnvironmentObject private var store: ClipStore
    @Environment(\.dismiss) private var dismiss

    let clip: DayClip

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                VStack(spacing: 16) {
                    Text(friendlyDate)
                        .font(.custom(AppTheme.brandFont, size: 28).weight(.bold))
                        .foregroundStyle(.white)
                        .padding(.top, 8)

                    VideoPlayer(player: AVPlayer(url: store.url(for: clip)))
                        .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
                        .padding(.horizontal, 20)

                    Spacer()
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                        .font(.custom(AppTheme.bodyFont, size: 17).weight(.semibold))
                }
            }
        }
    }

    private var friendlyDate: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .full
        return formatter.string(from: clip.date)
    }
}
