import SwiftUI

enum AppTheme {
    static let skyTop = Color(red: 0.72, green: 0.88, blue: 0.95)
    static let skyBottom = Color(red: 0.98, green: 0.93, blue: 0.78)
    static let meadow = Color(red: 0.45, green: 0.72, blue: 0.52)
    static let coral = Color(red: 0.93, green: 0.42, blue: 0.38)
    static let ink = Color(red: 0.18, green: 0.22, blue: 0.28)
    static let softInk = Color(red: 0.35, green: 0.40, blue: 0.48)
    static let cream = Color(red: 1.0, green: 0.98, blue: 0.94)
    static let sunshine = Color(red: 0.98, green: 0.78, blue: 0.28)

    static let brandFont = "Avenir Next"
    static let bodyFont = "Avenir Next"

    static var skyGradient: LinearGradient {
        LinearGradient(
            colors: [skyTop, skyBottom],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    static var meadowGradient: LinearGradient {
        LinearGradient(
            colors: [meadow.opacity(0.9), meadow],
            startPoint: .top,
            endPoint: .bottom
        )
    }
}

struct SkyBackground: View {
    var body: some View {
        ZStack {
            AppTheme.skyGradient.ignoresSafeArea()

            GeometryReader { geo in
                Circle()
                    .fill(AppTheme.sunshine.opacity(0.35))
                    .frame(width: geo.size.width * 0.45)
                    .blur(radius: 8)
                    .offset(x: geo.size.width * 0.55, y: -geo.size.height * 0.05)

                Ellipse()
                    .fill(AppTheme.meadow.opacity(0.18))
                    .frame(width: geo.size.width * 1.2, height: geo.size.height * 0.35)
                    .offset(x: -geo.size.width * 0.1, y: geo.size.height * 0.72)
            }
            .ignoresSafeArea()
        }
    }
}
