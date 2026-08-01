import SwiftUI

struct ParentCornerView: View {
    @EnvironmentObject private var store: ClipStore
    @EnvironmentObject private var settings: AppSettings
    @Environment(\.dismiss) private var dismiss

    @State private var unlocked = false
    @State private var pinEntry = ""
    @State private var pinError = false
    @State private var clipToDelete: DayClip?
    @State private var newPIN = ""
    @State private var confirmMessage: String?
    @State private var showBackupShare = false

    var body: some View {
        NavigationStack {
            ZStack {
                SkyBackground()

                if unlocked {
                    settingsForm
                } else {
                    pinGate
                }
            }
            .navigationTitle("Parent corner")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
            .confirmationDialog(
                "Delete this day's video?",
                isPresented: Binding(
                    get: { clipToDelete != nil },
                    set: { if !$0 { clipToDelete = nil } }
                ),
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    if let clipToDelete {
                        try? store.deleteClip(clipToDelete)
                    }
                    self.clipToDelete = nil
                }
                Button("Cancel", role: .cancel) {
                    clipToDelete = nil
                }
            }
            .alert("Saved", isPresented: Binding(
                get: { confirmMessage != nil },
                set: { if !$0 { confirmMessage = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(confirmMessage ?? "")
            }
        }
    }

    private var pinGate: some View {
        VStack(spacing: 20) {
            Spacer()
            Text("Grown-ups only")
                .font(.custom(AppTheme.brandFont, size: 34).weight(.heavy))
                .foregroundStyle(AppTheme.ink)

            Text("Enter the parent PIN")
                .font(.custom(AppTheme.bodyFont, size: 18))
                .foregroundStyle(AppTheme.softInk)

            SecureField("PIN", text: $pinEntry)
                .keyboardType(.numberPad)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 220)
                .font(.title2)
                .multilineTextAlignment(.center)

            if pinError {
                Text("That PIN isn’t right.")
                    .foregroundStyle(AppTheme.coral)
                    .font(.custom(AppTheme.bodyFont, size: 16).weight(.semibold))
            }

            Button("Unlock") {
                if pinEntry == settings.parentPIN {
                    unlocked = true
                    pinError = false
                } else {
                    pinError = true
                }
            }
            .buttonStyle(KidButtonStyle(fill: AppTheme.meadow))
            .frame(maxWidth: 260)

            Text("Default PIN is 1234 — change it after unlock.")
                .font(.custom(AppTheme.bodyFont, size: 14))
                .foregroundStyle(AppTheme.softInk)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
        }
        .padding()
    }

    private var settingsForm: some View {
        Form {
            Section("About") {
                TextField("Child's name", text: $settings.childName)
                DatePicker("Year starts", selection: $settings.yearStart, displayedComponents: .date)
                LabeledContent("Days saved", value: "\(store.recordedCount)")
            }

            Section("Daily reminder") {
                Toggle("Remind to record", isOn: $settings.reminderEnabled)
                if settings.reminderEnabled {
                    HStack {
                        Text("Time")
                        Spacer()
                        Picker("Hour", selection: $settings.reminderHour) {
                            ForEach(0..<24, id: \.self) { hour in
                                Text(String(format: "%02d", hour)).tag(hour)
                            }
                        }
                        .pickerStyle(.wheel)
                        .frame(width: 80, height: 100)
                        .clipped()

                        Text(":")

                        Picker("Minute", selection: $settings.reminderMinute) {
                            ForEach([0, 15, 30, 45], id: \.self) { minute in
                                Text(String(format: "%02d", minute)).tag(minute)
                            }
                        }
                        .pickerStyle(.wheel)
                        .frame(width: 80, height: 100)
                        .clipped()
                    }
                }
            }

            Section("Parent PIN") {
                SecureField("New PIN", text: $newPIN)
                    .keyboardType(.numberPad)
                Button("Update PIN") {
                    let trimmed = newPIN.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard trimmed.count >= 4 else { return }
                    settings.parentPIN = trimmed
                    newPIN = ""
                    confirmMessage = "PIN updated."
                }
            }

            Section("Delete a day") {
                if store.sortedClips.isEmpty {
                    Text("No clips yet.")
                } else {
                    ForEach(store.sortedClips.reversed()) { clip in
                        Button(role: .destructive) {
                            clipToDelete = clip
                        } label: {
                            HStack {
                                Text(clip.dayKey)
                                Spacer()
                                Image(systemName: "trash")
                            }
                        }
                    }
                }
            }

            Section("Backup") {
                if store.sortedClips.isEmpty {
                    Text("No clips to export yet.")
                } else {
                    Button {
                        showBackupShare = true
                    } label: {
                        Label("Share all clips", systemImage: "square.and.arrow.up")
                    }
                }
            }
        }
        .scrollContentBackground(.hidden)
        .sheet(isPresented: $showBackupShare) {
            ShareSheet(items: store.sortedClips.map { store.url(for: $0) })
        }
    }
}
