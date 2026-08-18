import ControllerCore
import SwiftUI

@main
struct RemoteDavinciControllerApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = ControllerModel()

    var body: some Scene {
        WindowGroup {
            ControllerView(model: model)
                .onChange(of: scenePhase) { _, phase in
                    if phase == .background, model.isConnectionDesired {
                        model.disconnect()
                    }
                }
        }
    }
}

struct ControllerView: View {
    @ObservedObject var model: ControllerModel
    @State private var showingSettings = false

    private var pageSelection: Binding<ResolvePage> {
        Binding(
            get: { model.selectedPage },
            set: { model.requestPage($0) }
        )
    }

    var body: some View {
        NavigationStack {
            TabView(selection: pageSelection) {
                ForEach(ResolvePage.allCases, id: \.self) { page in
                    Color.clear
                        .accessibilityElement()
                        .accessibilityLabel("\(page.rawValue.capitalized) page")
                        .tabItem {
                            Label(page.rawValue.capitalized, systemImage: page.systemImage)
                        }
                        .tag(page)
                }
            }
            .navigationTitle("Remote DaVinci")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showingSettings = true
                    } label: {
                        Label("Settings", systemImage: "gearshape")
                    }
                    .accessibilityHint("Opens enrollment, connection, and host controls")
                }
            }
        }
        .sheet(isPresented: $showingSettings) {
            ControllerSettingsView(model: model)
        }
        .onAppear {
            if !model.isEnrolled {
                showingSettings = true
            }
        }
        .onChange(of: model.isEnrolled) { _, isEnrolled in
            if !isEnrolled {
                showingSettings = true
            }
        }
    }
}

private extension ResolvePage {
    var systemImage: String {
        switch self {
        case .cut: "scissors"
        case .edit: "slider.horizontal.3"
        case .fusion: "wand.and.stars"
        case .color: "circle.hexagongrid.fill"
        }
    }
}

private struct ControllerSettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: ControllerModel
    @State private var showingReenrollConfirmation = false
    @State private var showingLocalForgetConfirmation = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Trusted enrollment") {
                    TextField("Device label", text: $model.deviceLabel)
                        .textContentType(.name)
                        .accessibilityLabel("Controller device label")

                    if !model.hasLocalEnrollment {
                        Button("Create Enrollment Request") {
                            model.createEnrollmentRequest()
                        }
                    }

                    if !model.isEnrolled, !model.enrollmentRequestJSON.isEmpty {
                        Text(model.enrollmentRequestJSON)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .accessibilityLabel("Enrollment request JSON")

                        ShareLink("Share Enrollment Request", item: model.enrollmentRequestJSON)

                        Text("Paste the response from the trusted Mac companion:")
                            .font(.caption)
                        TextEditor(text: $model.enrollmentResponseJSON)
                            .font(.caption.monospaced())
                            .frame(minHeight: 110)
                            .accessibilityLabel("Enrollment response JSON")

                        Button("Import Enrollment Response") {
                            model.importEnrollmentResponse()
                        }
                        .disabled(model.enrollmentResponseJSON.isEmpty)
                    }

                    Text(model.enrollmentStatus)
                        .foregroundStyle(model.canConnect ? .green : .secondary)
                        .accessibilityLabel("Enrollment status: \(model.enrollmentStatus)")

                    if model.isEnrolled {
                        Button("Revoke and Re-enroll", role: .destructive) {
                            showingReenrollConfirmation = true
                        }
                        .disabled(model.isResetting)
                        .accessibilityHint("Revokes this controller and creates fresh enrollment credentials")
                    }

                    if model.hasLocalEnrollment {
                        Button("Forget Local Credentials and Re-enroll", role: .destructive) {
                            showingLocalForgetConfirmation = true
                        }
                        .disabled(model.isResetting)
                        .accessibilityHint(
                            "Deletes only this device's credentials; the old remote identity may remain"
                        )
                    }
                }

                Section("Relay") {
                    Button(model.isConnectionDesired ? "Disconnect" : "Connect") {
                        if model.isConnectionDesired {
                            model.disconnect()
                        } else {
                            model.connect()
                        }
                    }
                    .disabled(
                        (!model.isConnectionDesired && !model.canConnect) || model.isResetting
                    )

                    Text(model.connectionStatus)
                        .accessibilityLabel("Connection status: \(model.connectionStatus)")
                }

                Section("Host control") {
                    Button("Toggle Host Volume Mute") {
                        model.toggleHostMute()
                    }
                    .disabled(!model.canSend("host.volume.toggle-mute"))
                    .accessibilityLabel("Toggle Mac volume mute")
                    .accessibilityHint("Mutes or unmutes the enrolled Mac")

                    if !model.feedback.isEmpty {
                        Text(model.feedback)
                            .foregroundStyle(.secondary)
                            .accessibilityLabel("Command status: \(model.feedback)")
                    }
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
            .confirmationDialog(
                "Revoke this controller?",
                isPresented: $showingReenrollConfirmation,
                titleVisibility: .visible
            ) {
                Button("Revoke and Re-enroll", role: .destructive) {
                    model.revokeAndReenroll()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The current link and controller endpoint will stop working immediately.")
            }
            .confirmationDialog(
                "Forget only this device's credentials?",
                isPresented: $showingLocalForgetConfirmation,
                titleVisibility: .visible
            ) {
                Button("Forget Locally and Re-enroll", role: .destructive) {
                    model.forgetLocalEnrollmentAndReenroll()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The old remote identity may remain active. Use this only when remote revocation cannot complete.")
            }
        }
    }
}
