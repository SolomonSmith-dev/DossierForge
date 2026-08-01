import SwiftUI

struct HomeView: View {
    @EnvironmentObject private var store: ClipStore
    @EnvironmentObject private var settings: AppSettings
    @Binding var showParent: Bool

    @State private var appearBrand = false
    @State private var pulseRecord = false

    private var todayDone: Bool { store.hasClip() }
    private var streak: Int { store.currentStreak() }

    var body: some View {
        ZStack {
            SkyBackground()

            VStack(spacing: 0) {
                HStack {
                    Spacer()
                    Button {
                        showParent = true
                    } label: {
                        Image(systemName: "gearshape.fill")
                            .font(.system(size: 22, weight: .semibold))
                            .foregroundStyle(AppTheme.softInk.opacity(0.55))
                            .padding(14)
                            .contentShape(Rectangle())
                    }
                    .accessibilityLabel("Parent corner")
                }

                Spacer(minLength: 12)

                VStack(spacing: 10) {
                    Text(settings.brandTitle)
                        .font(.custom(AppTheme.brandFont, size: 56).weight(.heavy))
                        .foregroundStyle(AppTheme.ink)
                        .multilineTextAlignment(.center)
                        .minimumScaleFactor(0.6)
                        .scaleEffect(appearBrand ? 1 : 0.92)
                        .opacity(appearBrand ? 1 : 0)

                    Text(todayDone ? "Today's 5 seconds are in!" : "One tiny video. Every day.")
                        .font(.custom(AppTheme.bodyFont, size: 22).weight(.medium))
                        .foregroundStyle(AppTheme.softInk)
                        .multilineTextAlignment(.center)
                        .opacity(appearBrand ? 1 : 0)
                }
                .padding(.horizontal, 28)

                Spacer(minLength: 24)

                NavigationLink {
                    RecordView()
                } label: {
                    ZStack {
                        Circle()
                            .fill(AppTheme.coral)
                            .frame(width: 220, height: 220)
                            .shadow(color: AppTheme.coral.opacity(0.35), radius: 24, y: 12)
                            .scaleEffect(pulseRecord && !todayDone ? 1.04 : 1)

                        VStack(spacing: 8) {
                            Image(systemName: todayDone ? "arrow.counterclockwise" : "video.fill")
                                .font(.system(size: 44, weight: .bold))
                            Text(todayDone ? "Retake today" : "Record today")
                                .font(.custom(AppTheme.bodyFont, size: 26).weight(.bold))
                        }
                        .foregroundStyle(.white)
                    }
                }
                .buttonStyle(.plain)
                .padding(.bottom, 28)

                HStack(spacing: 28) {
                    statChip(title: "Days saved", value: "\(store.recordedCount)")
                    statChip(title: "Streak", value: "\(streak)")
                }
                .padding(.bottom, 28)

                HStack(spacing: 16) {
                    NavigationLink {
                        YearCalendarView()
                    } label: {
                        secondaryButton(title: "My calendar", systemImage: "calendar")
                    }

                    NavigationLink {
                        ExportYearView()
                    } label: {
                        secondaryButton(title: "Make my year", systemImage: "film")
                    }
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 36)
            }
        }
        .onAppear {
            withAnimation(.spring(response: 0.7, dampingFraction: 0.78)) {
                appearBrand = true
            }
            withAnimation(.easeInOut(duration: 1.4).repeatForever(autoreverses: true)) {
                pulseRecord = true
            }
        }
    }

    private func statChip(title: String, value: String) -> some View {
        VStack(spacing: 4) {
            Text(value)
                .font(.custom(AppTheme.bodyFont, size: 32).weight(.bold))
                .foregroundStyle(AppTheme.ink)
            Text(title)
                .font(.custom(AppTheme.bodyFont, size: 15).weight(.semibold))
                .foregroundStyle(AppTheme.softInk)
        }
    }

    private func secondaryButton(title: String, systemImage: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage)
            Text(title)
                .font(.custom(AppTheme.bodyFont, size: 18).weight(.semibold))
        }
        .foregroundStyle(AppTheme.ink)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
        .background(AppTheme.cream.opacity(0.85))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}
