import AppKit
import SwiftUI

@main
@MainActor
struct RemoteDavinciCompanionApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = CompanionModel.shared

    var body: some Scene {
        WindowGroup("Remote DaVinci Companion", id: "main") {
            CompanionView(model: model)
                .frame(minWidth: 560, minHeight: 660)
                .task { model.start() }
        }

        MenuBarExtra("Remote DaVinci Companion", systemImage: model.statusSymbol) {
            CompanionMenu(model: model)
        }
        .menuBarExtraStyle(.menu)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillTerminate(_ notification: Notification) {
        CompanionModel.shared.stop()
    }
}

struct CompanionView: View {
    @ObservedObject var model: CompanionModel
    @State private var showingResetConfirmation = false
    @State private var showingForgetConfirmation = false

    var body: some View {
        Form {
            Section("Server") {
                Label(model.hostStatus, systemImage: model.statusSymbol)
                    .accessibilityLabel("Server status: \(model.hostStatus)")

                if model.canRetry {
                    Button("Retry Server") { model.retryServer() }
                        .accessibilityHint("Attempts to restart the local server helper")
                }

                Toggle(
                    "Launch at Login",
                    isOn: Binding(
                        get: { model.launchAtLogin },
                        set: { model.setLaunchAtLogin($0) }
                    )
                )
                .accessibilityHint("Starts Remote DaVinci Companion after you log in")
            }

            Section("Connection") {
                Label(model.statusText, systemImage: model.statusSymbol)
                    .accessibilityLabel("Connection status: \(model.statusText)")

                if let state = model.state {
                    LabeledContent("Controller", value: state.controllerLabel ?? "No controller enrolled")
                    if let linkID = state.linkID {
                        LabeledContent("Link", value: linkID)
                            .textSelection(.enabled)
                    }
                    LabeledContent("Relay", value: state.relayURL)
                        .textSelection(.enabled)
                }
            }

            Section("Local Controls") {
                HStack {
                    Button("Open Resolve Edit Page") {
                        model.perform("resolve.page.edit")
                    }
                    .accessibilityLabel("Open DaVinci Resolve Edit page")
                    .accessibilityHint("Opens the Edit page on this Mac")

                    Button("Toggle Mac Mute") {
                        model.perform("host.volume.toggle-mute")
                    }
                    .accessibilityHint("Mutes or unmutes this Mac")
                }
                .disabled(model.isMutating || model.state == nil)
            }

            Section("Enroll iPhone or iPad") {
                Text("Paste the enrollment request from the controller, then import the response on that device.")
                    .foregroundStyle(.secondary)

                TextEditor(text: $model.enrollmentRequest)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 100)
                    .accessibilityLabel("Controller enrollment request")

                Button("Create Link") { model.enroll() }
                    .disabled(
                        model.isMutating || model.state?.configured == true ||
                            model.enrollmentRequest.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                    .accessibilityHint("Creates a trusted link for the pasted controller request")

                if !model.enrollmentResponse.isEmpty {
                    Text(model.enrollmentResponse)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .accessibilityLabel("Controller enrollment response")

                    Button("Copy Response") { model.copyEnrollmentResponse() }
                        .accessibilityHint("Copies the enrollment response to the clipboard")
                }
            }

            if model.state?.configured == true {
                Section("Reset Enrollment") {
                    Text("Revoke the controller link and remove this Mac’s local credentials.")
                        .foregroundStyle(.secondary)
                    Button("Revoke and Reset", role: .destructive) {
                        showingResetConfirmation = true
                    }
                    .disabled(model.isMutating)

                    Divider()

                    Text("Emergency recovery only: forgetting locally can leave the remote relay identity active.")
                        .foregroundStyle(.secondary)
                    Button("Forget Only on This Mac", role: .destructive) {
                        showingForgetConfirmation = true
                    }
                    .disabled(model.isMutating)
                }
            }

            if !model.feedback.isEmpty {
                Section("Last Result") {
                    Text(model.feedback)
                        .textSelection(.enabled)
                        .accessibilityLabel("Last result: \(model.feedback)")
                }
            }

            if let error = model.errorMessage {
                Section("Error") {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                        .accessibilityLabel("Error: \(error)")
                    Button("Dismiss") { model.errorMessage = nil }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Remote DaVinci Companion")
        .confirmationDialog(
            "Revoke this controller link?",
            isPresented: $showingResetConfirmation,
            titleVisibility: .visible
        ) {
            Button("Revoke and Reset", role: .destructive) { model.reset() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This revokes the active link and removes local credentials. It cannot be undone.")
        }
        .confirmationDialog(
            "Forget only this Mac’s credentials?",
            isPresented: $showingForgetConfirmation,
            titleVisibility: .visible
        ) {
            Button("Forget Only on This Mac", role: .destructive) { model.forget() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The remote relay identity may remain active and must then be revoked separately.")
        }
    }
}

struct CompanionMenu: View {
    @ObservedObject var model: CompanionModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.statusText)
            .accessibilityLabel("Connection status: \(model.statusText)")

        Button("Open Remote DaVinci Companion") {
            NSApp.activate(ignoringOtherApps: true)
            openWindow(id: "main")
        }

        if model.canRetry {
            Button("Retry Server") { model.retryServer() }
        }

        Toggle(
            "Launch at Login",
            isOn: Binding(
                get: { model.launchAtLogin },
                set: { model.setLaunchAtLogin($0) }
            )
        )

        Divider()

        Button("Quit Remote DaVinci Companion") {
            model.stop()
            NSApp.terminate(nil)
        }
        .keyboardShortcut("q")
    }
}
