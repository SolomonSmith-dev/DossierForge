import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var store: ClipStore
    @EnvironmentObject private var settings: AppSettings
    @State private var showParent = false

    var body: some View {
        NavigationStack {
            HomeView(showParent: $showParent)
                .navigationBarHidden(true)
        }
        .sheet(isPresented: $showParent) {
            ParentCornerView()
                .environmentObject(store)
                .environmentObject(settings)
        }
        .onAppear {
            NotificationService.reschedule(settings: settings)
        }
    }
}
