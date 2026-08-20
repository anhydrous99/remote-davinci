import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins
import Darwin
import Foundation
import ServiceManagement

struct CompanionConnection: Equatable, Sendable {
    let helperVersion: String
    let baseURL: URL
    let token: String
}

private struct HelperReadiness: Decodable {
    let v: Int
    let version: String?
    let url: String?
    let error: HelperStartupError?
}

private struct HelperStartupError: Decodable {
    let code: String
}

enum ReadinessResult: Equatable {
    case ready(CompanionConnection)
    case startupFailure(String)
}

enum CompanionFailure: LocalizedError {
    case invalidReadiness
    case invalidEnrollment
    case invalidRelay
    case invalidResponse
    case server(String)

    var errorDescription: String? {
        switch self {
        case .invalidReadiness:
            return "The server helper returned an invalid startup response."
        case .invalidEnrollment:
            return "Paste a valid controller enrollment request."
        case .invalidRelay:
            return "REMOTE_DAVINCI_RELAY_URL must be a credential-free wss URL."
        case .invalidResponse:
            return "The server helper returned an invalid response."
        case let .server(message):
            return message
        }
    }
}

private func canonicalBase64URL32(_ value: String) -> Bool {
    guard value.count == 43 else { return false }
    let padded = value.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/") + "="
    guard let bytes = Data(base64Encoded: padded), bytes.count == 32 else { return false }
    return bytes.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .trimmingCharacters(in: CharacterSet(charactersIn: "=")) == value
}

private func canonicalUUID(_ value: String) -> Bool {
    guard let uuid = UUID(uuidString: value) else { return false }
    return uuid.uuidString.lowercased() == value
}

private func validDeviceLabel(_ value: String) -> Bool {
    guard value == value.trimmingCharacters(in: .whitespacesAndNewlines),
          (1...80).contains(value.unicodeScalars.count)
    else { return false }
    return value.unicodeScalars.allSatisfy { scalar in
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator:
            return false
        default:
            return true
        }
    }
}

private func validProtocolName(_ value: String) -> Bool {
    let scalars = value.unicodeScalars
    guard (1...128).contains(scalars.count),
          let first = scalars.first,
          (97...122).contains(first.value)
    else { return false }
    var separator = false
    for scalar in scalars.dropFirst() {
        let value = scalar.value
        if (97...122).contains(value) || (48...57).contains(value) {
            separator = false
        } else if value == 45 || value == 46 || value == 95 {
            if separator { return false }
            separator = true
        } else {
            return false
        }
    }
    return !separator
}

private func displayDeviceLabel(_ value: String?) -> String {
    guard let value, validDeviceLabel(value) else { return "Unknown controller" }
    return value
}

enum CompanionLaunchArguments {
    static let relayEnvironmentKey = "REMOTE_DAVINCI_RELAY_URL"

    static func make(environment: [String: String]) throws -> [String] {
        guard let relayURL = environment[relayEnvironmentKey] else { return ["-native"] }
        guard let components = URLComponents(string: relayURL),
              components.scheme == "wss",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              let url = components.url,
              url.absoluteString == relayURL
        else {
            throw CompanionFailure.invalidRelay
        }
        return ["-native", "-relay", relayURL]
    }
}

enum ReadinessValidator {
    static func parse(_ line: Data) throws -> ReadinessResult {
        let readiness = try JSONDecoder().decode(HelperReadiness.self, from: line)
        guard readiness.v == 1 else { throw CompanionFailure.invalidReadiness }
        if let error = readiness.error {
            guard readiness.version == nil, readiness.url == nil else {
                throw CompanionFailure.invalidReadiness
            }
            return .startupFailure(startupMessage(for: error.code))
        }
        guard let version = readiness.version,
              let launchURL = readiness.url,
              !version.isEmpty,
              version.count <= 64,
              var components = URLComponents(string: launchURL),
              components.scheme == "http",
              components.user == nil,
              components.password == nil,
              components.fragment == nil,
              components.path.isEmpty || components.path == "/",
              let host = components.host,
              isNumericLoopback(host),
              let port = components.port,
              (1...65_535).contains(port),
              let items = components.queryItems,
              items.count == 1,
              items[0].name == "token",
              let token = items[0].value,
              canonicalBase64URL32(token)
        else {
            throw CompanionFailure.invalidReadiness
        }

        components.query = nil
        guard let baseURL = components.url else {
            throw CompanionFailure.invalidReadiness
        }
        return .ready(CompanionConnection(helperVersion: version, baseURL: baseURL, token: token))
    }

    private static func startupMessage(for code: String) -> String {
        switch code {
        case "CONFIG_MISMATCH":
            return "Stored companion credentials do not match. No connection was started."
        case "KEYCHAIN_UNAVAILABLE":
            return "The macOS Keychain is unavailable. Unlock it or allow access, then retry."
        default:
            return "The server helper could not start."
        }
    }

    private static func isNumericLoopback(_ host: String) -> Bool {
        let host = host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast()) : host
        var ipv4 = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return UInt32(bigEndian: ipv4.s_addr) >> 24 == 127
        }

        var ipv6 = in6_addr()
        guard host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else {
            return false
        }
        var loopback = in6addr_loopback
        return withUnsafeBytes(of: &ipv6) { address in
            withUnsafeBytes(of: &loopback) { expected in
                address.elementsEqual(expected)
            }
        }
    }
}

struct CompanionState: Decodable, Equatable, Sendable {
    let configured: Bool
    let relayURL: String
    let endpointID: String?
    let linkID: String?
    let controllerLabel: String?
    let connected: Bool
    let secure: Bool
    let status: String
    let pairing: PairingSnapshot?
    let enrollmentResponse: EnrollmentReply?

    enum CodingKeys: String, CodingKey {
        case configured, connected, secure, status, pairing, enrollmentResponse
        case relayURL = "relayUrl"
        case endpointID = "endpointId"
        case linkID = "linkId"
        case controllerLabel
    }

    var connectionSummary: String {
        if secure { return "Secure controller session" }
        if connected { return "Connected to relay" }
        return status
    }

    var controllerDisplayLabel: String {
        displayDeviceLabel(controllerLabel)
    }
}

struct PairingApprovalDetails: Equatable, Sendable {
    let pairID: String
    let controllerLabel: String
    let controllerFingerprint: String
    let requestedPermissions: [String]
}

struct PairingSnapshot: Decodable, Equatable, Sendable {
    let phase: String
    let pairID: String?
    let expiresAt: Int64?
    let controllerLabel: String?
    let controllerFingerprint: String?
    let requestedPermissions: [String]?

    enum CodingKeys: String, CodingKey {
        case phase, expiresAt, controllerLabel, controllerFingerprint, requestedPermissions
        case pairID = "pairId"
    }

    private static let supportedPermissions: Set<String> = [
        "resolve.page.media",
        "resolve.page.cut",
        "resolve.page.edit",
        "resolve.page.fusion",
        "resolve.page.color",
        "resolve.page.fairlight",
        "resolve.page.deliver",
        "host.volume.toggle-mute",
    ]

    var isShowingInvite: Bool {
        phase == "showingQR"
    }

    var isAwaitingApproval: Bool {
        phase == "awaitingApproval"
    }

    var isTerminal: Bool {
        ["cancelled", "expired", "failed", "rejected"].contains(phase)
    }

    var validPairID: String? {
        guard let pairID, canonicalUUID(pairID) else { return nil }
        return pairID
    }

    var approvalDetails: PairingApprovalDetails? {
        guard isAwaitingApproval,
              let pairID = validPairID,
              let controllerLabel,
              validDeviceLabel(controllerLabel),
              let controllerFingerprint,
              controllerFingerprint.hasPrefix("sha256:"),
              canonicalBase64URL32(String(controllerFingerprint.dropFirst("sha256:".count))),
              let requestedPermissions,
              !requestedPermissions.isEmpty,
              requestedPermissions.count <= 64,
              Set(requestedPermissions).count == requestedPermissions.count,
              requestedPermissions.allSatisfy(validProtocolName),
              requestedPermissions.contains(where: Self.supportedPermissions.contains)
        else { return nil }
        return PairingApprovalDetails(
            pairID: pairID,
            controllerLabel: controllerLabel,
            controllerFingerprint: controllerFingerprint,
            requestedPermissions: requestedPermissions
        )
    }

    var isApprovable: Bool { approvalDetails != nil }
}

struct PairingInvite: Codable, Equatable, Sendable {
    let protocolName: String
    let v: Int
    let relayURL: String
    let pairID: String
    let creatorSideID: String
    let linkID: String
    let joinToken: String
    let psk: String
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case v, joinToken, psk, expiresAt
        case protocolName = "protocol"
        case relayURL = "relayUrl"
        case pairID = "pairId"
        case creatorSideID = "creatorSideId"
        case linkID = "linkId"
    }

    func qrPayload() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let payload = String(data: try encoder.encode(self), encoding: .utf8) else {
            throw CompanionFailure.invalidResponse
        }
        return payload
    }
}

struct PairingStartReply: Decodable, Equatable, Sendable {
    let invite: PairingInvite
}

enum QRCodeRenderer {
    static func image(for payload: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let code = filter.outputImage else { return nil }

        let scale = max(1, floor(300 / code.extent.width))
        let scaled = code.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let quietZone = 4 * scale
        let extent = scaled.extent.insetBy(dx: -quietZone, dy: -quietZone)
        let background = CIImage(color: .white).cropped(to: extent)
        let composed = scaled.composited(over: background)
        guard let image = CIContext().createCGImage(composed, from: extent) else { return nil }
        return NSImage(cgImage: image, size: extent.size)
    }
}

struct EnrollmentReply: Codable, Equatable, Sendable {
    let v: Int
    let relayURL: String
    let linkID: String
    let controllerEndpointID: String
    let companionEndpointID: String
    let companionNoiseKey: String
    let warning: String?

    enum CodingKeys: String, CodingKey {
        case v, warning
        case relayURL = "relayUrl"
        case linkID = "linkId"
        case controllerEndpointID = "controllerEndpointId"
        case companionEndpointID = "companionEndpointId"
        case companionNoiseKey
    }

    func formattedJSON() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let value = String(data: try encoder.encode(self), encoding: .utf8) else {
            throw CompanionFailure.invalidResponse
        }
        return value
    }
}

private struct APIErrorBody: Decodable {
    let error: String
}

private struct ResetReply: Decodable {
    let reset: Bool
}

private struct ForgetReply: Decodable {
    let forgotten: Bool
    let warning: String
}

private struct ActionReply: Decodable {
    let page: String?
    let muted: Bool?
}

private struct PairingActionReply: Decodable {
    let approved: Bool?
    let rejected: Bool?
    let cancelled: Bool?

    var succeeded: Bool { approved == true || rejected == true || cancelled == true }
}

struct CompanionAPI {
    let connection: CompanionConnection
    private let session: URLSession

    init(connection: CompanionConnection, session: URLSession? = nil) {
        self.connection = connection
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = 65
            configuration.urlCache = nil
            self.session = URLSession(configuration: configuration)
        }
    }

    func state() async throws -> CompanionState {
        try await request("/api/state")
    }

    func enroll(_ rawRequest: String) async throws -> EnrollmentReply {
        let input = Data(rawRequest.utf8)
        guard let object = try? JSONSerialization.jsonObject(with: input),
              object is [String: Any],
              JSONSerialization.isValidJSONObject(object),
              let body = try? JSONSerialization.data(withJSONObject: object)
        else {
            throw CompanionFailure.invalidEnrollment
        }
        return try await request("/api/enroll", method: "POST", body: body)
    }

    func startPairing() async throws -> PairingStartReply {
        try await request("/api/pairing/start", method: "POST", body: Data("{}".utf8))
    }

    func approvePairing(pairID: String) async throws {
        try await pairingAction("/api/pairing/approve", pairID: pairID)
    }

    func rejectPairing(pairID: String) async throws {
        try await pairingAction("/api/pairing/reject", pairID: pairID)
    }

    func cancelPairing(pairID: String) async throws {
        try await pairingAction("/api/pairing/cancel", pairID: pairID)
    }

    func reset(linkID: String) async throws {
        let body = try JSONEncoder().encode(["confirmation": linkID])
        let reply: ResetReply = try await request("/api/reset", method: "POST", body: body)
        guard reply.reset else { throw CompanionFailure.invalidResponse }
    }

    func forget(linkID: String) async throws -> String {
        let body = try JSONEncoder().encode(["confirmation": linkID])
        let reply: ForgetReply = try await request("/api/forget", method: "POST", body: body)
        guard reply.forgotten else { throw CompanionFailure.invalidResponse }
        return reply.warning
    }

    func perform(_ operation: String) async throws -> String {
        let body = try JSONEncoder().encode(["operation": operation])
        let reply: ActionReply = try await request("/api/action", method: "POST", body: body)
        if let page = reply.page { return "Resolve page: \(page)" }
        if let muted = reply.muted { return muted ? "Mac audio muted" : "Mac audio unmuted" }
        throw CompanionFailure.invalidResponse
    }

    private func pairingAction(_ path: String, pairID: String) async throws {
        let body = try JSONEncoder().encode(["pairId": pairID])
        let reply: PairingActionReply = try await request(path, method: "POST", body: body)
        guard reply.succeeded else { throw CompanionFailure.invalidResponse }
    }

    private func request<Response: Decodable>(
        _ path: String,
        method: String = "GET",
        body: Data? = nil
    ) async throws -> Response {
        guard var components = URLComponents(url: connection.baseURL, resolvingAgainstBaseURL: false) else {
            throw CompanionFailure.invalidResponse
        }
        components.path = path
        guard let url = components.url else { throw CompanionFailure.invalidResponse }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.setValue(connection.token, forHTTPHeaderField: "X-Remote-Davinci-Token")
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse else {
            throw CompanionFailure.invalidResponse
        }
        guard (200..<300).contains(response.statusCode) else {
            let message = (try? JSONDecoder().decode(APIErrorBody.self, from: data).error)
                ?? "Server request failed (HTTP \(response.statusCode))."
            throw CompanionFailure.server(message)
        }
        do {
            return try JSONDecoder().decode(Response.self, from: data)
        } catch {
            throw CompanionFailure.invalidResponse
        }
    }
}

struct CompanionHostSnapshot: Equatable {
    let connection: CompanionConnection?
    let status: String
    let canRetry: Bool
}

@MainActor
final class CompanionHost {
    var onChange: ((CompanionHostSnapshot) -> Void)?

    private let environment: [String: String]
    private let restartDelays: [TimeInterval] = [1, 2, 4, 8, 16]
    private var process: Process?
    private var inputPipe: Pipe?
    private var outputPipe: Pipe?
    private var readinessBuffer = Data()
    private var connection: CompanionConnection?
    private var status = "Server stopped"
    private var canRetry = false
    private var shouldRun = false
    private var restartAttempt = 0
    private var restartWorkItem: DispatchWorkItem?
    private var stableWorkItem: DispatchWorkItem?
    private var startupWorkItem: DispatchWorkItem?
    private var startupFailure: String?
    private var terminalStartupFailure: String?

    init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        self.environment = environment
    }

    func start() {
        guard !shouldRun else { return }
        shouldRun = true
        restartAttempt = 0
        launch()
    }

    func retry() {
        restartWorkItem?.cancel()
        restartWorkItem = nil
        shouldRun = true
        restartAttempt = 0
        canRetry = false
        launch()
    }

    func stop() {
        shouldRun = false
        restartWorkItem?.cancel()
        stableWorkItem?.cancel()
        startupWorkItem?.cancel()
        restartWorkItem = nil
        stableWorkItem = nil
        startupWorkItem = nil
        terminalStartupFailure = nil
        try? inputPipe?.fileHandleForWriting.close()
        if process?.isRunning == true { process?.terminate() }
        connection = nil
        canRetry = false
        status = "Server stopped"
        publish()
    }

    private func launch() {
        guard shouldRun, process == nil else { return }
        let arguments: [String]
        do {
            arguments = try CompanionLaunchArguments.make(environment: environment)
        } catch {
            shouldRun = false
            status = error.localizedDescription
            canRetry = false
            publish()
            return
        }
        guard let executable = Bundle.main.url(
            forAuxiliaryExecutable: "remote-davinci-companion"
        ), FileManager.default.isExecutableFile(atPath: executable.path) else {
            status = "The server helper is missing from the app bundle."
            canRetry = true
            publish()
            return
        }

        let process = Process()
        let input = Pipe()
        let output = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [weak self, weak process] terminated in
            DispatchQueue.main.async {
                guard let self, let process, process === terminated else { return }
                self.didExit(process)
            }
        }
        output.fileHandleForReading.readabilityHandler = { [weak self, weak process] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            DispatchQueue.main.async {
                guard let self, let process else { return }
                self.consume(data, from: process)
            }
        }

        self.process = process
        inputPipe = input
        outputPipe = output
        readinessBuffer.removeAll(keepingCapacity: true)
        connection = nil
        startupFailure = nil
        terminalStartupFailure = nil
        status = "Starting server…"
        canRetry = false
        publish()

        do {
            try process.run()
            scheduleStartupTimeout(for: process)
        } catch {
            output.fileHandleForReading.readabilityHandler = nil
            self.process = nil
            inputPipe = nil
            outputPipe = nil
            scheduleRestart(reason: "The server helper could not start.")
        }
    }

    private func consume(_ data: Data, from source: Process) {
        guard process === source, connection == nil else { return }
        readinessBuffer.append(data)
        guard readinessBuffer.count <= 16 * 1024 else {
            failReadiness(source)
            return
        }
        guard let newline = readinessBuffer.firstIndex(of: 0x0A) else { return }

        do {
            switch try ReadinessValidator.parse(readinessBuffer[..<newline]) {
            case let .ready(ready):
                connection = ready
                startupWorkItem?.cancel()
                startupWorkItem = nil
                status = "Server running (\(ready.helperVersion))"
                canRetry = false
                publish()
                scheduleStableReset(for: source)
            case let .startupFailure(message):
                terminalStartupFailure = message
                shouldRun = false
                startupWorkItem?.cancel()
                startupWorkItem = nil
                try? inputPipe?.fileHandleForWriting.close()
                if source.isRunning { source.terminate() }
            }
        } catch {
            failReadiness(source)
        }
        readinessBuffer.removeAll(keepingCapacity: false)
    }

    private func failReadiness(_ source: Process) {
        startupFailure = "The server helper returned an invalid startup response."
        try? inputPipe?.fileHandleForWriting.close()
        if source.isRunning { source.terminate() }
    }

    private func didExit(_ source: Process) {
        guard process === source else { return }
        let wasReady = connection != nil
        outputPipe?.fileHandleForReading.readabilityHandler = nil
        stableWorkItem?.cancel()
        startupWorkItem?.cancel()
        stableWorkItem = nil
        startupWorkItem = nil
        process = nil
        inputPipe = nil
        outputPipe = nil
        connection = nil

        if let message = terminalStartupFailure {
            terminalStartupFailure = nil
            status = message
            canRetry = true
            publish()
            return
        }

        guard shouldRun else {
            status = "Server stopped"
            canRetry = false
            publish()
            return
        }
        let reason = startupFailure ?? (wasReady
            ? "The server helper exited unexpectedly (status \(source.terminationStatus))."
            : "The server helper exited before it was ready (status \(source.terminationStatus)).")
        startupFailure = nil
        scheduleRestart(reason: reason)
    }

    private func scheduleRestart(reason: String) {
        guard shouldRun else { return }
        guard restartAttempt < restartDelays.count else {
            status = "\(reason) Automatic restart stopped."
            canRetry = true
            publish()
            return
        }
        let delay = restartDelays[restartAttempt]
        restartAttempt += 1
        status = "\(reason) Restarting in \(Int(delay)) second\(delay == 1 ? "" : "s")…"
        canRetry = false
        publish()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.restartWorkItem = nil
            self.launch()
        }
        restartWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func scheduleStableReset(for source: Process) {
        stableWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self, weak source] in
            guard let self, let source, self.process === source, self.connection != nil else { return }
            self.restartAttempt = 0
        }
        stableWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 60, execute: work)
    }

    private func scheduleStartupTimeout(for source: Process) {
        startupWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self, weak source] in
            guard let self, let source, self.process === source, self.connection == nil else { return }
            self.startupFailure = "The server helper did not become ready in time."
            try? self.inputPipe?.fileHandleForWriting.close()
            if source.isRunning { source.terminate() }
        }
        startupWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 10, execute: work)
    }

    private func publish() {
        onChange?(CompanionHostSnapshot(connection: connection, status: status, canRetry: canRetry))
    }
}

@MainActor
final class CompanionModel: ObservableObject {
    static let shared = CompanionModel()

    @Published private(set) var state: CompanionState?
    @Published private(set) var hostStatus = "Server stopped"
    @Published private(set) var canRetry = false
    @Published private(set) var pollError: String?
    @Published private(set) var isMutating = false
    @Published private(set) var feedback = ""
    @Published private(set) var pairingInvite: PairingInvite?
    @Published private(set) var pairingQRCode: NSImage?
    @Published var enrollmentRequest = ""
    @Published private(set) var enrollmentResponse = ""
    @Published var errorMessage: String?
    @Published private(set) var launchAtLogin = SMAppService.mainApp.status == .enabled

    private let host = CompanionHost()
    private var started = false
    private var connection: CompanionConnection?
    private var api: CompanionAPI?
    private var pollTask: Task<Void, Never>?
    private var attemptedAutomaticPairing = false

    private init() {
        host.onChange = { [weak self] snapshot in
            self?.apply(snapshot)
        }
    }

    var statusText: String {
        state?.connectionSummary ?? pollError ?? hostStatus
    }

    var statusSymbol: String {
        if state?.secure == true { return "checkmark.shield.fill" }
        if state?.connected == true { return "network" }
        if connection != nil { return "exclamationmark.triangle" }
        return canRetry ? "exclamationmark.triangle" : "hourglass"
    }

    var manualEnrollmentResponse: String {
        if !enrollmentResponse.isEmpty { return enrollmentResponse }
        guard let response = state?.enrollmentResponse else { return "" }
        return (try? response.formattedJSON()) ?? ""
    }

    func start() {
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil else { return }
        guard !started else { return }
        started = true
        host.start()
    }

    func stop() {
        started = false
        pollTask?.cancel()
        pollTask = nil
        clearPairingInvite()
        host.stop()
    }

    func retryServer() {
        host.retry()
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            launchAtLogin = SMAppService.mainApp.status == .enabled
        } catch {
            launchAtLogin = SMAppService.mainApp.status == .enabled
            errorMessage = "Launch at Login could not be changed: \(error.localizedDescription)"
        }
    }

    func enroll() {
        let rawRequest = enrollmentRequest
        mutate { [weak self] api in
            let reply = try await api.enroll(rawRequest)
            guard let self else { return }
            self.enrollmentResponse = try reply.formattedJSON()
            self.feedback = reply.warning ?? "Link created. Import the response on iPhone or iPad."
        }
    }

    func startPairing() {
        mutate { [weak self] api in
            let reply = try await api.startPairing()
            guard let self,
                  let image = try Self.pairingImage(
                    for: reply,
                    responseConnection: api.connection,
                    currentConnection: self.connection
                  )
            else { return }
            pairingInvite = reply.invite
            pairingQRCode = image
            feedback = "Scan this code with Remote DaVinci on iPhone or iPad."
        }
    }

    static func pairingImage(
        for reply: PairingStartReply,
        responseConnection: CompanionConnection,
        currentConnection: CompanionConnection?
    ) throws -> NSImage? {
        guard currentConnection == responseConnection else { return nil }
        let payload = try reply.invite.qrPayload()
        guard let image = QRCodeRenderer.image(for: payload) else {
            throw CompanionFailure.invalidResponse
        }
        return image
    }

    func approvePairing() {
        guard let pairID = state?.pairing?.approvalDetails?.pairID else { return }
        mutate { [weak self] api in
            try await api.approvePairing(pairID: pairID)
            self?.clearPairingInvite()
            self?.feedback = "Finishing secure pairing…"
        }
    }

    func rejectPairing() {
        guard let pairID = state?.pairing?.validPairID else { return }
        mutate { [weak self] api in
            try await api.rejectPairing(pairID: pairID)
            self?.clearPairingInvite()
            self?.feedback = "Pairing request rejected."
        }
    }

    func cancelPairing() {
        guard let pairID = pairingCancellationID else { return }
        mutate { [weak self] api in
            try await api.cancelPairing(pairID: pairID)
            self?.clearPairingInvite()
            self?.feedback = "Pairing cancelled."
        }
    }

    var canCancelPairing: Bool { pairingCancellationID != nil }

    private var pairingCancellationID: String? {
        if let pairID = state?.pairing?.validPairID { return pairID }
        guard let pairID = pairingInvite?.pairID, canonicalUUID(pairID) else { return nil }
        return pairID
    }

    func copyEnrollmentResponse() {
        let response = manualEnrollmentResponse
        guard !response.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        if pasteboard.setString(response, forType: .string) {
            feedback = "Enrollment response copied."
        } else {
            errorMessage = "The enrollment response could not be copied."
        }
    }

    func perform(_ operation: String) {
        mutate { [weak self] api in
            let result = try await api.perform(operation)
            self?.feedback = result
        }
    }

    func reset() {
        guard let linkID = state?.linkID else { return }
        mutate { [weak self] api in
            try await api.reset(linkID: linkID)
            self?.clearEnrollment(message: "Enrollment revoked and removed.")
        }
    }

    func forget() {
        guard let linkID = state?.linkID else { return }
        mutate { [weak self] api in
            let warning = try await api.forget(linkID: linkID)
            self?.clearEnrollment(message: warning)
        }
    }

    private func clearEnrollment(message: String) {
        enrollmentRequest = ""
        enrollmentResponse = ""
        feedback = message
        clearPairingInvite()
    }

    private func clearPairingInvite() {
        pairingInvite = nil
        pairingQRCode = nil
    }

    private func mutate(_ operation: @MainActor @escaping (CompanionAPI) async throws -> Void) {
        guard !isMutating else { return }
        guard let api else {
            errorMessage = "The local server is not available."
            return
        }
        isMutating = true
        errorMessage = nil
        Task { [weak self] in
            guard let self else { return }
            defer { self.isMutating = false }
            do {
                try await operation(api)
                await self.refresh(using: api)
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }

    private func apply(_ snapshot: CompanionHostSnapshot) {
        hostStatus = snapshot.status
        canRetry = snapshot.canRetry
        guard snapshot.connection != connection else { return }
        connection = snapshot.connection
        pollTask?.cancel()
        pollTask = nil
        state = nil
        pollError = nil
        guard let connection else {
            api = nil
            clearPairingInvite()
            return
        }
        let api = CompanionAPI(connection: connection)
        self.api = api
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh(using: api)
                do {
                    try await Task.sleep(for: .seconds(2))
                } catch {
                    return
                }
            }
        }
    }

    private func refresh(using api: CompanionAPI) async {
        do {
            let state = try await api.state()
            guard connection == api.connection else { return }
            self.state = state
            if state.secure {
                enrollmentRequest = ""
                enrollmentResponse = ""
            }
            if state.configured || state.pairing.map({ !$0.isShowingInvite }) == true {
                clearPairingInvite()
            }
            pollError = nil
            if !state.configured, state.pairing == nil, !attemptedAutomaticPairing {
                attemptedAutomaticPairing = true
                startPairing()
            }
        } catch {
            guard connection == api.connection else { return }
            state = nil
            pollError = "Server unavailable: \(error.localizedDescription)"
        }
    }
}
