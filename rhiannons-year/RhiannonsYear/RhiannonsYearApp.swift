import SwiftUI
import UserNotifications

@main
struct RhiannonsYearApp: App {
    @StateObject private var store = ClipStore()
    @StateObject private var settings = AppSettings()

    init() {
        NotificationService.requestAuthorizationIfNeeded()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(store)
                .environmentObject(settings)
                .preferredColorScheme(.light)
        }
    }
}
