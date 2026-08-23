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

            if model.state?.configured != true {
                PairingSection(model: model)
            }

            Section("Connection") {
                Label(model.statusText, systemImage: model.statusSymbol)
                    .accessibilityLabel("Connection status: \(model.statusText)")

                if let state = model.state {
                    LabeledContent(
                        "Controller",
                        value: state.configured ? state.controllerDisplayLabel : "No controller enrolled")
                    DisclosureGroup("Connection details") {
                        if let linkID = state.linkID {
                            LabeledContent("Link", value: linkID)
                                .textSelection(.enabled)
                        }
                        LabeledContent("Relay", value: state.relayURL)
                            .textSelection(.enabled)
                    }
                }
            }

            if model.state?.configured == true {
                Section("Test Controls") {
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

                    Text(
                        "Emergency recovery only: forgetting locally can leave the remote relay identity active."
                    )
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

private struct PairingSection: View {
    @ObservedObject var model: CompanionModel
    @State private var copiedPairID: String?
    @State private var pairingCodeCopyMessage = ""
    @State private var pairingCodeCopySucceeded = false

    var body: some View {
        Section("Pair iPhone or iPad") {
            if let pairing = model.state?.pairing, pairing.isAwaitingApproval {
                if let details = pairing.approvalDetails {
                    Text("Allow this controller?")
                        .font(.headline)
                    LabeledContent("Controller", value: details.controllerLabel)
                    LabeledContent("Security fingerprint", value: details.controllerFingerprint)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                    Text("Requested controls")
                        .font(.subheadline.weight(.semibold))
                    ForEach(details.requestedPermissions, id: \.self) { permission in
                        Label(permissionLabel(permission), systemImage: "checkmark.circle")
                    }
                    HStack {
                        Button("Approve") { model.approvePairing() }
                            .buttonStyle(.borderedProminent)
                            .disabled(model.isMutating || !pairing.isApprovable)
                        Button("Reject", role: .destructive) { model.rejectPairing() }
                            .disabled(model.isMutating)
                    }
                } else {
                    Label(
                        "Pairing details could not be verified.", systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(.red)
                    Text("Reject this request and create a new pairing code.")
                        .foregroundStyle(.secondary)
                    HStack {
                        Button("Reject", role: .destructive) { model.rejectPairing() }
                            .disabled(model.isMutating || pairing.validPairID == nil)
                        Button("Cancel Pairing", role: .cancel) { model.cancelPairing() }
                            .disabled(model.isMutating || !model.canCancelPairing)
                    }
                }
            } else if let image = model.pairingQRCode, let invite = model.pairingInvite {
                Text("On iPhone or iPad, tap Scan or Paste Pairing Code, then scan this QR or paste the copied code.")
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 320, height: 320)
                    .frame(maxWidth: .infinity)
                    .accessibilityLabel("Remote DaVinci one-time pairing QR code")
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let remaining = max(0, invite.expiresAt - Int64(context.date.timeIntervalSince1970))
                    Text(String(format: "Code expires in %d:%02d", remaining / 60, remaining % 60))
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                }
                Text(
                    "Anyone with this code can request pairing for five minutes. Approve only your device."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                HStack {
                    Button(copiedPairID == invite.pairID ? "Pairing Code Copied" : "Copy Pairing Code") {
                        do {
                            let payload = try invite.qrPayload()
                            NSPasteboard.general.clearContents()
                            if NSPasteboard.general.setString(payload, forType: .string) {
                                copiedPairID = invite.pairID
                                pairingCodeCopyMessage = "Pairing code copied."
                                pairingCodeCopySucceeded = true
                            } else {
                                copiedPairID = nil
                                pairingCodeCopyMessage = "The pairing code could not be copied."
                                pairingCodeCopySucceeded = false
                            }
                        } catch {
                            copiedPairID = nil
                            pairingCodeCopyMessage = "The pairing code could not be prepared. Generate a new code."
                            pairingCodeCopySucceeded = false
                        }
                    }
                    .accessibilityHint(
                        "Copies the one-time code for pasting on a device without camera access")
                    Button("Cancel Pairing", role: .cancel) { model.cancelPairing() }
                        .disabled(model.isMutating || !model.canCancelPairing)
                }
                .onChange(of: invite.pairID) { _, _ in
                    copiedPairID = nil
                    pairingCodeCopyMessage = ""
                    pairingCodeCopySucceeded = false
                }
                if !pairingCodeCopyMessage.isEmpty {
                    Text(pairingCodeCopyMessage)
                        .font(.caption)
                        .foregroundStyle(pairingCodeCopySucceeded ? Color.secondary : Color.red)
                        .accessibilityLabel(pairingCodeCopyMessage)
                }
            } else if let pairing = model.state?.pairing, !pairing.isTerminal {
                ProgressView(pairingStatus(pairing.phase))
                Button("Cancel Pairing", role: .cancel) { model.cancelPairing() }
                    .disabled(model.isMutating || !model.canCancelPairing)
            } else {
                Text("Create a one-time code, then scan or paste it in the Remote DaVinci app.")
                    .foregroundStyle(.secondary)
                Button("Generate Pairing Code") { model.startPairing() }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.isMutating || model.state == nil)
            }

        }
    }

    private func pairingStatus(_ phase: String) -> String {
        switch phase {
        case "creating": return "Creating one-time code…"
        case "handshaking", "authenticating": return "Authenticating controller…"
        case "committing": return "Saving secure pairing…"
        default: return "Waiting for iPhone or iPad…"
        }
    }

    private func permissionLabel(_ permission: String) -> String {
        switch permission {
        case "resolve.page.media": return "Open Resolve Media page"
        case "resolve.page.cut": return "Open Resolve Cut page"
        case "resolve.page.edit": return "Open Resolve Edit page"
        case "resolve.page.fusion": return "Open Resolve Fusion page"
        case "resolve.page.color": return "Open Resolve Color page"
        case "resolve.page.fairlight": return "Open Resolve Fairlight page"
        case "resolve.page.deliver": return "Open Resolve Deliver page"
        case "host.volume.toggle-mute": return "Toggle Mac mute"
        default: return permission
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
