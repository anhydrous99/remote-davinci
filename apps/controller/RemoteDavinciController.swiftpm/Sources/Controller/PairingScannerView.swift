import ControllerCore
import SwiftUI

#if os(iOS) && !targetEnvironment(macCatalyst)
import AVFoundation
import UIKit
import Vision
import VisionKit
#endif

struct PairingScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @ObservedObject var model: ControllerModel
    @State private var pastedInvite = ""
    @State private var cameraError = ""
    @State private var codeError = ""
    @State private var scannerRefresh = 0

    #if os(iOS) && !targetEnvironment(macCatalyst)
    @State private var cameraAuthorization = AVCaptureDevice.authorizationStatus(for: .video)
    #endif

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    Text("Scan the QR code shown by the Remote DaVinci companion on your Mac.")
                        .multilineTextAlignment(.center)

                    cameraContent

                    Divider()

                    VStack(alignment: .leading, spacing: 10) {
                        Text("Paste pairing code")
                            .font(.headline)
                        TextEditor(text: $pastedInvite)
                            .font(.caption.monospaced())
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .frame(minHeight: 100)
                            .overlay {
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(.secondary.opacity(0.35))
                            }
                            .accessibilityLabel("Pasted pairing code")

                        Button("Use Pasted Code") {
                            submit(pastedInvite)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(pastedInvite.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }

                    if !codeError.isEmpty {
                        Text(codeError)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                            .accessibilityLabel("Pairing code error: \(codeError)")
                    }
                }
                .padding()
            }
            .navigationTitle("Pair with Mac")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            refreshCameraState()
        }
    }

    @ViewBuilder
    private var cameraContent: some View {
        #if os(iOS) && !targetEnvironment(macCatalyst)
        if !DataScannerViewController.isSupported {
            cameraMessage(
                "QR scanning is not supported on this device.",
                symbol: "camera.badge.ellipsis"
            )
        } else {
            switch cameraAuthorization {
            case .notDetermined:
                cameraMessage(
                    "Camera access is needed only while scanning the pairing code.",
                    symbol: "camera"
                )
                Button("Allow Camera Access") { requestCameraAccess() }
                    .buttonStyle(.borderedProminent)
            case .denied:
                cameraMessage(
                    "Camera access is off. Enable it in Settings, or paste the pairing code below.",
                    symbol: "camera.fill"
                )
                Button("Open Settings") { openSettings() }
                    .buttonStyle(.bordered)
            case .restricted:
                cameraMessage(
                    "Camera access is restricted on this device. Paste the pairing code below.",
                    symbol: "camera.fill"
                )
            case .authorized:
                if !DataScannerViewController.isAvailable {
                    cameraMessage(
                        "The camera is temporarily unavailable. Close other camera apps and try again.",
                        symbol: "camera.badge.clock"
                    )
                    Button("Try Camera Again") { refreshCameraState() }
                        .buttonStyle(.bordered)
                } else if cameraError.isEmpty {
                    QRDataScanner(
                        onCode: submit,
                        onUnavailable: { error in cameraError = error }
                    )
                    .id(scannerRefresh)
                    .frame(minHeight: 320)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .accessibilityLabel("QR code camera scanner")
                } else {
                    cameraMessage(cameraError, symbol: "exclamationmark.triangle")
                    Button("Try Camera Again") {
                        cameraError = ""
                        scannerRefresh += 1
                    }
                    .buttonStyle(.bordered)
                }
            @unknown default:
                cameraMessage("Camera access is unavailable.", symbol: "camera.fill")
            }
        }
        #else
        cameraMessage(
            "Camera scanning is available in the iPhone and iPad app. Paste the pairing code below.",
            symbol: "qrcode"
        )
        #endif
    }

    private func cameraMessage(_ message: String, symbol: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 38))
                .accessibilityHidden(true)
            Text(message)
                .multilineTextAlignment(.center)
        }
        .foregroundStyle(.secondary)
    }

    private func submit(_ value: String) {
        model.pair(inviteJSON: value.trimmingCharacters(in: .whitespacesAndNewlines))
        if model.isPairing {
            dismiss()
        } else {
            codeError = model.enrollmentStatus
        }
    }

    private func refreshCameraState() {
        #if os(iOS) && !targetEnvironment(macCatalyst)
        cameraAuthorization = AVCaptureDevice.authorizationStatus(for: .video)
        cameraError = ""
        scannerRefresh += 1
        #endif
    }

    #if os(iOS) && !targetEnvironment(macCatalyst)
    private func requestCameraAccess() {
        Task {
            _ = await AVCaptureDevice.requestAccess(for: .video)
            cameraAuthorization = AVCaptureDevice.authorizationStatus(for: .video)
        }
    }

    private func openSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }
    #endif
}

#if os(iOS) && !targetEnvironment(macCatalyst)
private struct QRDataScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    let onUnavailable: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCode: onCode, onUnavailable: onUnavailable)
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: true,
            isPinchToZoomEnabled: true,
            isGuidanceEnabled: true,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        do {
            try scanner.startScanning()
        } catch {
            context.coordinator.reportUnavailable()
        }
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
        guard !scanner.isScanning else { return }
        do {
            try scanner.startScanning()
        } catch {
            context.coordinator.reportUnavailable()
        }
    }

    static func dismantleUIViewController(
        _ scanner: DataScannerViewController,
        coordinator: Coordinator
    ) {
        scanner.stopScanning()
    }

    @MainActor
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onCode: (String) -> Void
        private let onUnavailable: (String) -> Void
        private var submitted = Set<String>()

        init(onCode: @escaping (String) -> Void, onUnavailable: @escaping (String) -> Void) {
            self.onCode = onCode
            self.onUnavailable = onUnavailable
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            for case let .barcode(barcode) in addedItems {
                guard let value = barcode.payloadStringValue,
                      submitted.insert(value).inserted
                else { continue }
                onCode(value)
            }
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable
        ) {
            reportUnavailable()
        }

        func reportUnavailable() {
            onUnavailable("The camera scanner became unavailable. Try again or paste the pairing code below.")
        }
    }
}
#endif
