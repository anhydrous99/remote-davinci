import ControllerCore
import Foundation
import SwiftUI

@main
struct RemoteDavinciControllerApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = ControllerModel(
        relayURL: ProcessInfo.processInfo.environment["REMOTE_DAVINCI_RELAY_URL"]
    )

    var body: some Scene {
        WindowGroup {
            ControllerView(model: model)
                .onChange(of: scenePhase) { _, phase in
                    if phase == .background {
                        if model.isPairing {
                            model.cancelPairing()
                        }
                        if model.isConnectionDesired {
                            model.disconnect()
                        }
                    } else if phase == .active {
                        model.refreshCredentialStoreIfNeeded()
                        if model.shouldAutomaticallyReconcilePendingActivation {
                            model.connect()
                        }
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
            get: { model.displayedPage },
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
                        .accessibilityHint("Opens this page in DaVinci Resolve on the Mac")
                        .tabItem {
                            Label(page.rawValue.capitalized, systemImage: page.systemImage)
                        }
                        .tag(page)
                }
            }
            .disabled(!model.isReady || model.pendingPage != nil)
            .overlay {
                if let page = model.pendingPage {
                    ProgressView("Opening \(page.rawValue.capitalized)…")
                        .accessibilityLabel(
                            "Opening \(page.rawValue.capitalized) page in DaVinci Resolve"
                        )
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
    @State private var showingPairingScanner = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Pair with Mac") {
                    TextField("Device label", text: $model.deviceLabel)
                        .textContentType(.name)
                        .accessibilityLabel("Controller device label")
                        .disabled(model.isPairing)

                    if model.isPairing {
                        ProgressView(model.pairingStatus)
                            .accessibilityLabel("Pairing status: \(model.pairingStatus)")

                        Button("Cancel Pairing", role: .cancel) {
                            model.cancelPairing()
                        }
                    } else if model.canStartPairing {
                        Button {
                            showingPairingScanner = true
                        } label: {
                            Label("Scan Mac QR Code", systemImage: "qrcode.viewfinder")
                        }
                        .buttonStyle(.borderedProminent)
                        .accessibilityHint("Opens the camera to scan the pairing code on your Mac")
                    }

                    Text(model.enrollmentStatus)
                        .foregroundStyle(model.isEnrolled ? .green : .secondary)
                        .accessibilityLabel("Enrollment status: \(model.enrollmentStatus)")

                    if !model.isEnrolled, !model.hasPendingPairingActivation {
                        DisclosureGroup("Advanced Manual Enrollment") {
                            if !model.hasLocalEnrollment {
                                Button("Create Enrollment Request") {
                                    model.createEnrollmentRequest()
                                }
                            }

                            if !model.enrollmentRequestJSON.isEmpty {
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
                        }
                        .disabled(model.isPairing)
                    }

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
                    .disabled(model.isPairing)
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
            .sheet(isPresented: $showingPairingScanner) {
                PairingScannerSheet(model: model)
            }
        }
    }
}
