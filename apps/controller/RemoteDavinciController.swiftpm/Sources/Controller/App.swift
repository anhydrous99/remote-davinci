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
                            model.cancelPairing(reconcilePendingActivation: true)
                        }
                        model.suspendConnectionForBackground()
                    } else if phase == .active {
                        model.refreshCredentialStoreIfNeeded()
                        model.resumeConnectionAfterBackground()
                    }
                }
        }
    }
}

struct ControllerView: View {
    @ObservedObject var model: ControllerModel
    @State private var showingSettings = false

    private var connectionSymbol: String {
        if model.isReady { return "checkmark.circle.fill" }
        if model.isConnectionDesired { return "arrow.triangle.2.circlepath" }
        return "wifi.slash"
    }

    private var connectionAction: String {
        if model.isConnectionDesired { return "Disconnect" }
        if model.canConnect { return "Connect" }
        return "Pair"
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    HStack(spacing: 12) {
                        Label(model.connectionStatus, systemImage: connectionSymbol)
                            .foregroundStyle(model.isReady ? Color.green : Color.primary)
                            .accessibilityLabel("Connection status: \(model.connectionStatus)")
                        Spacer()
                        Button(connectionAction) {
                            if model.isConnectionDesired {
                                model.disconnect()
                            } else if model.canConnect {
                                model.connect()
                            } else {
                                showingSettings = true
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(model.isResetting)
                    }
                    .padding(12)
                    .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))

                    Text("Resolve page")
                        .font(.headline)
                        .frame(maxWidth: .infinity, alignment: .leading)

                    LazyVGrid(
                        columns: [GridItem(.adaptive(minimum: 88), spacing: 8)],
                        spacing: 8
                    ) {
                        ForEach(ResolvePage.allCases, id: \.self) { page in
                            let available = model.isPageAvailable(page)
                            let selected = model.isReady && model.displayedPage == page
                            Button {
                                model.requestPage(page)
                            } label: {
                                VStack(spacing: 4) {
                                    Image(systemName: available ? page.systemImage : "lock.fill")
                                    Text(page.rawValue.capitalized)
                                        .font(.caption)
                                        .lineLimit(2)
                                        .multilineTextAlignment(.center)
                                }
                                .frame(maxWidth: .infinity, minHeight: 48)
                                .foregroundStyle(available ? Color.primary : Color.secondary)
                                .background(
                                    selected ? Color.accentColor.opacity(0.16) : Color.secondary.opacity(0.06),
                                    in: RoundedRectangle(cornerRadius: 10)
                                )
                                .overlay {
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(selected ? Color.accentColor : Color.clear)
                                }
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("\(page.rawValue.capitalized) page")
                            .accessibilityHint(
                                !model.isReady
                                    ? "Connect to the Mac to use this page"
                                    : available
                                        ? "Opens this page in DaVinci Resolve on the Mac"
                                        : "This page is not granted by the enrolled companion"
                            )
                            .accessibilityAddTraits(selected ? .isSelected : [])
                            .disabled(!model.canSend(page.operation))
                        }
                    }

                    if let page = model.pendingPage {
                        ProgressView("Opening \(page.rawValue.capitalized)…")
                            .accessibilityLabel(
                                "Opening \(page.rawValue.capitalized) page in DaVinci Resolve"
                            )
                    }

                    Button {
                        model.toggleHostMute()
                    } label: {
                        Label("Toggle Mac Mute", systemImage: "speaker.slash.fill")
                    }
                    .buttonStyle(.bordered)
                    .disabled(!model.canSend("host.volume.toggle-mute"))
                    .accessibilityHint("Mutes or unmutes the enrolled Mac")

                    if !model.feedback.isEmpty {
                        Text(model.feedback)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .accessibilityLabel("Command status: \(model.feedback)")
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .padding()
            .navigationTitle("Remote DaVinci")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showingSettings = true
                    } label: {
                        Label("Settings", systemImage: "gearshape")
                    }
                    .accessibilityHint("Opens enrollment and connection settings")
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
        case .media: "photo"
        case .cut: "scissors"
        case .edit: "slider.horizontal.3"
        case .fusion: "wand.and.stars"
        case .color: "circle.hexagongrid.fill"
        case .fairlight: "music.note"
        case .deliver: "rocket"
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

                        if !model.pairingFingerprint.isEmpty {
                            Text("Compare this fingerprint with the one shown on your Mac before approving:")
                                .font(.caption)
                            Text(model.pairingFingerprint)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                                .accessibilityLabel(
                                    "Controller pairing fingerprint: \(model.pairingFingerprint)"
                                )
                        }

                        Button("Cancel Pairing", role: .cancel) {
                            model.cancelPairing()
                        }
                    } else if model.canStartPairing {
                        Button {
                            showingPairingScanner = true
                        } label: {
                            Label("Scan or Paste Pairing Code", systemImage: "qrcode.viewfinder")
                        }
                        .buttonStyle(.borderedProminent)
                        .accessibilityHint("Opens camera scanning and pasted-code pairing options")
                    }

                    Text(model.enrollmentStatus)
                        .foregroundStyle(model.isEnrolled ? .green : .secondary)
                        .accessibilityLabel("Enrollment status: \(model.enrollmentStatus)")

                    if model.isEnrolled {
                        Button("Revoke and Pair Again", role: .destructive) {
                            showingReenrollConfirmation = true
                        }
                        .disabled(model.isResetting)
                        .accessibilityHint("Revokes this controller and returns to pairing")
                    }

                    if model.hasLocalEnrollment {
                        Button("Forget Local Credentials and Pair Again", role: .destructive) {
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
                Button("Revoke and Pair Again", role: .destructive) {
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
                Button("Forget Locally and Pair Again", role: .destructive) {
                    model.forgetLocalEnrollmentAndReenroll()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(
                    "The old remote identity may remain active. Use this only when remote revocation cannot complete."
                )
            }
            .sheet(isPresented: $showingPairingScanner) {
                PairingScannerSheet(model: model)
            }
        }
    }
}
