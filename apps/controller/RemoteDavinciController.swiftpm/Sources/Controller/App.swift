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

                Section("Controls") {
                    Button("Open Resolve Edit Page") {
                        model.perform("resolve.page.edit")
                    }
                    .disabled(!model.canSend("resolve.page.edit"))
                    .accessibilityLabel("Open DaVinci Resolve Edit page")
                    .accessibilityHint("Sends the Resolve Edit page command to the enrolled Mac")

                    Button("Toggle Host Volume Mute") {
                        model.perform("host.volume.toggle-mute")
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
            .navigationTitle("Remote DaVinci")
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
