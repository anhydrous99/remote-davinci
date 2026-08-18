import Combine
import CryptoKit
import Foundation
import Security
import UIKit

struct EnrollmentRequest: Codable, Equatable {
    let v: Int
    let controllerEndpointId: String
    let controllerCredentialHash: String
    let controllerNoiseKey: String
    let deviceLabel: String
}

struct EnrollmentResponse: Codable, Equatable {
    let v: Int
    let relayUrl: String
    let linkId: String
    let controllerEndpointId: String
    let companionEndpointId: String
    let companionNoiseKey: String
}

struct StoredEnrollment: Codable, Equatable {
    let controllerEndpointId: String
    let controllerSecret: String
    let controllerNoisePrivateKey: String
    let deviceLabel: String
    var expectedRelayUrl: String? = nil
    var response: EnrollmentResponse?
    var linkRevocationConfirmed: Bool? = nil
    var activationPending: Bool? = nil
    var grantedPermissions: [String]? = nil
    var companionNoiseFingerprint: String? = nil
    var pairingProtocol: String? = nil
    var pairingExpiresAt: Int64? = nil
}

struct ActiveEnrollment {
    let relayURL: URL
    let linkID: String
    let controllerEndpointID: String
    let companionEndpointID: String
    let controllerSecret: String
    let controllerNoisePrivateKey: Data
    let companionNoisePublicKey: Data
}

enum EnrollmentError: LocalizedError, Equatable {
    case invalidDeviceLabel
    case invalidRelay
    case invalidJSON
    case invalidResponse
    case mismatchedController
    case mismatchedRelay
    case missingRequest
    case randomFailure

    var errorDescription: String? {
        switch self {
        case .invalidDeviceLabel: "Enter a device label between 1 and 80 characters."
        case .invalidRelay: "The configured relay must be a canonical credential-free wss URL."
        case .invalidJSON: "The enrollment response is not valid JSON."
        case .invalidResponse: "The enrollment response is invalid."
        case .mismatchedController: "The response belongs to another controller."
        case .mismatchedRelay: "The response selected a different relay than the request."
        case .missingRequest: "Create an enrollment request first."
        case .randomFailure: "Secure random generation failed."
        }
    }
}

enum Enrollment {
    static let defaultRelayURL = "wss://t25ft375dj.execute-api.us-east-1.amazonaws.com/v1"

    static func deploymentRelayURL(_ override: String?) throws -> String {
        try validatedRelayURL(override ?? defaultRelayURL)
    }

    static func replacementRelayURL(
        stored: StoredEnrollment?,
        deploymentRelayURL: String
    ) throws -> String {
        try validatedRelayURL(stored?.expectedRelayUrl ?? deploymentRelayURL)
    }

    static func create(
        deviceLabel: String,
        relayURL: String = defaultRelayURL
    ) throws -> (EnrollmentRequest, StoredEnrollment) {
        let relayURL = try validatedRelayURL(relayURL)
        let label = deviceLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...80).contains(label.unicodeScalars.count) else {
            throw EnrollmentError.invalidDeviceLabel
        }

        let endpointID = UUID().uuidString.lowercased()
        let secret = try secureRandom(count: 32)
        let noisePrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let stored = StoredEnrollment(
            controllerEndpointId: endpointID,
            controllerSecret: Base64URL.encode(secret),
            controllerNoisePrivateKey: Base64URL.encode(noisePrivateKey.rawRepresentation),
            deviceLabel: label,
            expectedRelayUrl: relayURL,
            response: nil
        )
        return (try request(for: stored), stored)
    }

    static func request(for stored: StoredEnrollment) throws -> EnrollmentRequest {
        guard let expectedRelayURL = stored.expectedRelayUrl else {
            throw EnrollmentError.invalidRelay
        }
        _ = try validatedRelayURL(expectedRelayURL)
        guard isCanonicalUUID(stored.controllerEndpointId),
              let secret = Base64URL.decode32(stored.controllerSecret),
              let privateKeyData = Base64URL.decode32(stored.controllerNoisePrivateKey),
              let privateKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData),
              (1...80).contains(stored.deviceLabel.unicodeScalars.count)
        else {
            throw EnrollmentError.invalidResponse
        }
        return EnrollmentRequest(
            v: 1,
            controllerEndpointId: stored.controllerEndpointId,
            controllerCredentialHash: Base64URL.encode(Data(SHA256.hash(data: secret))),
            controllerNoiseKey: Base64URL.encode(privateKey.publicKey.rawRepresentation),
            deviceLabel: stored.deviceLabel
        )
    }

    static func migrateLegacy(
        _ stored: StoredEnrollment,
        deploymentRelayURL: String
    ) throws -> StoredEnrollment {
        _ = try validatedRelayURL(deploymentRelayURL)
        if let expectedRelayURL = stored.expectedRelayUrl {
            _ = try validatedRelayURL(expectedRelayURL)
            return stored
        }

        var migrated = stored
        if let response = stored.response {
            try validate(response: response, for: stored)
            migrated.expectedRelayUrl = response.relayUrl
        } else {
            migrated.expectedRelayUrl = deploymentRelayURL
            _ = try request(for: migrated)
        }
        return migrated
    }

    static func importResponse(_ json: String, into stored: StoredEnrollment) throws -> StoredEnrollment {
        guard let data = json.data(using: .utf8),
              let response = try? JSONDecoder().decode(EnrollmentResponse.self, from: data)
        else {
            throw EnrollmentError.invalidJSON
        }
        try validate(response: response, for: stored)
        guard let expectedRelayURL = stored.expectedRelayUrl else {
            throw EnrollmentError.invalidRelay
        }
        _ = try validatedRelayURL(expectedRelayURL)
        guard response.relayUrl == expectedRelayURL else {
            throw EnrollmentError.mismatchedRelay
        }

        var active = stored
        active.response = response
        return active
    }

    static func validatedRelayURL(_ value: String) throws -> String {
        guard let components = URLComponents(string: value),
              components.scheme == "wss",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              let relayURL = components.url,
              relayURL.absoluteString == value
        else {
            throw EnrollmentError.invalidRelay
        }
        return value
    }

    private static func validate(
        response: EnrollmentResponse,
        for stored: StoredEnrollment
    ) throws {
        guard response.v == 1,
              isCanonicalUUID(response.linkId),
              isCanonicalUUID(response.controllerEndpointId),
              isCanonicalUUID(response.companionEndpointId),
              response.controllerEndpointId != response.companionEndpointId,
              let companionNoiseKey = Base64URL.decode32(response.companionNoiseKey),
              isContributoryX25519PublicKey(companionNoiseKey),
              Base64URL.decode32(stored.controllerSecret) != nil,
              Base64URL.decode32(stored.controllerNoisePrivateKey) != nil,
              isCanonicalUUID(stored.controllerEndpointId)
        else {
            throw EnrollmentError.invalidResponse
        }
        do {
            _ = try validatedRelayURL(response.relayUrl)
        } catch {
            throw EnrollmentError.invalidResponse
        }
        guard response.controllerEndpointId == stored.controllerEndpointId else {
            throw EnrollmentError.mismatchedController
        }
    }

    static func isContributoryX25519PublicKey(_ data: Data) -> Bool {
        guard let publicKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: data) else {
            return false
        }
        return (try? Curve25519.KeyAgreement.PrivateKey()
            .sharedSecretFromKeyAgreement(with: publicKey)) != nil
    }

    static func active(from stored: StoredEnrollment) throws -> ActiveEnrollment {
        guard let response = stored.response else { throw EnrollmentError.missingRequest }
        let validated = try importResponse(try response.jsonString(), into: stored)
        guard let finalResponse = validated.response,
              let relayURL = URL(string: finalResponse.relayUrl),
              let privateKey = Base64URL.decode32(stored.controllerNoisePrivateKey),
              let peerKey = Base64URL.decode32(finalResponse.companionNoiseKey),
              Base64URL.decode32(stored.controllerSecret) != nil
        else {
            throw EnrollmentError.invalidResponse
        }
        return ActiveEnrollment(
            relayURL: relayURL,
            linkID: finalResponse.linkId,
            controllerEndpointID: stored.controllerEndpointId,
            companionEndpointID: finalResponse.companionEndpointId,
            controllerSecret: stored.controllerSecret,
            controllerNoisePrivateKey: privateKey,
            companionNoisePublicKey: peerKey
        )
    }

    private static func secureRandom(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw EnrollmentError.randomFailure }
        return data
    }
}

enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode32(_ value: String) -> Data? {
        guard !value.contains("="), value.count == 43 else { return nil }
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let decoded = Data(base64Encoded: base64),
              decoded.count == 32,
              encode(decoded) == value
        else {
            return nil
        }
        return decoded
    }
}

enum KeychainStore {
    private static let service = "dev.remote-davinci.controller"
    private static let account = "enrollment-v1"

    static func save(_ enrollment: StoredEnrollment) throws {
        let data = try JSONEncoder().encode(enrollment)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
        ]
        var attributes = query
        attributes[kSecValueData] = data
        attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly

        let addStatus = SecItemAdd(attributes as CFDictionary, nil)
        if addStatus == errSecDuplicateItem {
            let updateStatus = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData: data] as CFDictionary
            )
            guard updateStatus == errSecSuccess else { throw KeychainError.status(updateStatus) }
        } else if addStatus != errSecSuccess {
            throw KeychainError.status(addStatus)
        }
    }

    static func load() throws -> StoredEnrollment? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw KeychainError.status(status)
        }
        return try JSONDecoder().decode(StoredEnrollment.self, from: data)
    }

    static func delete() throws {
        let status = SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.status(status)
        }
    }
}

enum KeychainError: LocalizedError {
    case status(OSStatus)

    var errorDescription: String? {
        switch self {
        case let .status(status): "Keychain operation failed (\(status))."
        }
    }
}

enum ControllerProtocolError: LocalizedError, Equatable {
    case invalidMessage
    case invalidSequence
    case unexpectedMessage

    var errorDescription: String? {
        switch self {
        case .invalidMessage: "The companion sent an invalid message."
        case .invalidSequence: "The relay frame sequence is invalid or outside the receive window."
        case .unexpectedMessage: "The companion sent a message out of order."
        }
    }
}

struct RelayFrameBuffer {
    static let maximumGap: Int64 = 8
    static let maximumFrames = 8
    static let maximumBytes = 128 * 1_024

    private(set) var nextSequence: Int64 = 1
    private var frames = [Int64: Data]()
    private var byteCount = 0

    mutating func insert(sequence: Int64, frame: Data) throws -> [Data] {
        guard sequence >= nextSequence,
              sequence - nextSequence <= Self.maximumGap,
              frames[sequence] == nil
        else {
            throw ControllerProtocolError.invalidSequence
        }

        if sequence != nextSequence {
            guard frames.count < Self.maximumFrames,
                  byteCount + frame.count <= Self.maximumBytes
            else {
                throw ControllerProtocolError.invalidSequence
            }
            frames[sequence] = frame
            byteCount += frame.count
            return []
        }

        var contiguous = [frame]
        nextSequence += 1
        while let pending = frames.removeValue(forKey: nextSequence) {
            byteCount -= pending.count
            contiguous.append(pending)
            nextSequence += 1
        }
        return contiguous
    }
}

enum RelayLifecycleError: LocalizedError, Equatable {
    case server(code: String)

    var errorDescription: String? {
        switch self {
        case let .server(code): "Relay error: \(code)"
        }
    }
}

enum RelayConnectionError: LocalizedError, Equatable {
    case server(code: String, retryable: Bool)
    case linkRevoked
    case linkRevocationCheckpointFailed(String)
    case sessionClosed

    var errorDescription: String? {
        switch self {
        case let .server(code, _): "Relay error: \(code)"
        case .linkRevoked: "The remote link was revoked."
        case let .linkRevocationCheckpointFailed(message):
            "The link was revoked, but its recovery checkpoint could not be saved: \(message)"
        case .sessionClosed: "The relay session was closed."
        }
    }
}

enum RelayLifecycleResponse: Equatable {
    case success
    case failure(code: String, retryable: Bool)
    case event
}

enum RelayLifecycle {
    private static let errorCodes = Set([
        "INVALID_MESSAGE", "UNSUPPORTED_VERSION", "UNAUTHENTICATED", "FORBIDDEN",
        "PAIR_UNAVAILABLE", "PAIR_FULL", "PAIR_EXPIRED", "PEER_OFFLINE", "PEER_BUSY",
        "SESSION_NOT_FOUND", "PAYLOAD_TOO_LARGE", "RATE_LIMITED", "CONFLICT", "INTERNAL",
    ])

    static func reconnectDelaySeconds(attempt: Int, randomUnit: Double) -> Double {
        let ceiling = min(900, pow(2, Double(min(max(attempt, 0), 10))))
        return ceiling * min(max(randomUnit, 0), 1)
    }

    static func rotationDelaySeconds(randomUnit: Double) -> Double {
        5_400 + 1_200 * min(max(randomUnit, 0), 1)
    }

    static func shouldReconnect(code: String, retryable: Bool) -> Bool {
        retryable && code != "UNAUTHENTICATED" && code != "FORBIDDEN"
    }

    static func terminalHandshakeAuthorizationStatus(
        error: Error,
        response: URLResponse?
    ) -> Int? {
        if let status = (response as? HTTPURLResponse)?.statusCode,
           status == 401 || status == 403
        {
            return status
        }
        for value in (error as NSError).userInfo.values {
            if let status = (value as? HTTPURLResponse)?.statusCode,
               status == 401 || status == 403
            {
                return status
            }
        }
        return nil
    }

    static func isCurrentSessionClose(
        envelope: [String: Any],
        body: [String: Any],
        currentSessionID: String?
    ) throws -> Bool {
        guard envelope["replyTo"] == nil,
              let eventID = envelope["id"] as? String,
              isCanonicalUUID(eventID),
              let closedSessionID = body["sessionId"] as? String,
              isCanonicalUUID(closedSessionID),
              let reason = body["reason"] as? String,
              !reason.isEmpty,
              reason.count <= 64
        else {
            throw ControllerProtocolError.invalidMessage
        }
        return closedSessionID == currentSessionID
    }

    static func parseResponse(
        _ data: Data,
        requestID: String,
        requestType: String
    ) throws -> RelayLifecycleResponse {
        guard let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              envelope["protocol"] as? String == "remote-davinci.rendezvous",
              jsonInt64(envelope["v"]) == 1,
              let type = envelope["type"] as? String,
              let id = envelope["id"] as? String,
              isCanonicalUUID(id),
              let body = envelope["body"] as? [String: Any]
        else {
            throw ControllerProtocolError.invalidMessage
        }

        switch type {
        case "session.closed":
            _ = try isCurrentSessionClose(
                envelope: envelope,
                body: body,
                currentSessionID: nil
            )
            return .event
        case "link.revoked":
            guard envelope["replyTo"] == nil,
                  let linkID = body["linkId"] as? String,
                  isCanonicalUUID(linkID)
            else {
                throw ControllerProtocolError.invalidMessage
            }
            return .event
        case "ok", "error":
            guard let replyTo = envelope["replyTo"] as? String,
                  isCanonicalUUID(replyTo),
                  replyTo == requestID
            else {
                throw ControllerProtocolError.unexpectedMessage
            }
        default:
            throw ControllerProtocolError.unexpectedMessage
        }

        if type == "ok" {
            guard body["requestType"] as? String == requestType,
                  let result = body["result"] as? [String: Any],
                  jsonBool(result["revoked"]) == true
            else {
                throw ControllerProtocolError.invalidMessage
            }
            return .success
        }

        guard let code = body["code"] as? String,
              errorCodes.contains(code),
              let retryable = jsonBool(body["retryable"])
        else {
            throw ControllerProtocolError.invalidMessage
        }
        if body.keys.contains("retryAfterMs") {
            guard let retryAfter = jsonInt64(body["retryAfterMs"]),
                  (0...3_600_000).contains(retryAfter)
            else {
                throw ControllerProtocolError.invalidMessage
            }
        }
        return .failure(code: code, retryable: retryable)
    }
}

struct LateResponseWindow {
    static let maximumCount = 8
    private var ids = [String]()

    mutating func remember(_ id: String) {
        guard !ids.contains(id) else { return }
        if ids.count == Self.maximumCount {
            ids.removeFirst()
        }
        ids.append(id)
    }

    func contains(_ id: String) -> Bool {
        ids.contains(id)
    }
}

public enum ResolvePage: String, CaseIterable, Sendable {
    case cut
    case edit
    case fusion
    case color

    public var operation: String { "resolve.page.\(rawValue)" }

    init?(operation: String) {
        guard operation.hasPrefix("resolve.page.") else { return nil }
        self.init(rawValue: String(operation.dropFirst("resolve.page.".count)))
    }
}

enum ResolvePageControl {
    static func responsePage(operation: String, result: Any) throws -> ResolvePage? {
        guard let expected = ResolvePage(operation: operation) else { return nil }
        guard let result = result as? [String: Any],
              let rawPage = result["page"] as? String,
              let page = ResolvePage(rawValue: rawPage),
              page == expected
        else {
            throw ControllerProtocolError.invalidMessage
        }
        return page
    }

    static func eventPage(body: [String: Any]) throws -> ResolvePage? {
        guard let name = body["name"] as? String else {
            throw ControllerProtocolError.invalidMessage
        }
        guard name == "resolve.page.changed" else { return nil }
        guard let data = body["data"] as? [String: Any],
              let rawPage = data["page"] as? String,
              let page = ResolvePage(rawValue: rawPage)
        else {
            throw ControllerProtocolError.invalidMessage
        }
        return page
    }
}

@MainActor
public final class ControllerModel: ObservableObject {
    public static let operations = ResolvePage.allCases.map(\.operation) + ["host.volume.toggle-mute"]

    @Published public var deviceLabel = UIDevice.current.name
    @Published public var enrollmentResponseJSON = ""
    @Published public private(set) var enrollmentRequestJSON = ""
    @Published public private(set) var enrollmentStatus = "Not enrolled"
    @Published public private(set) var connectionStatus = "Disconnected"
    @Published public private(set) var feedback = ""
    @Published public private(set) var isEnrolled = false
    @Published public private(set) var hasLocalEnrollment = false
    @Published public private(set) var isConnected = false
    @Published public private(set) var isConnectionDesired = false
    @Published public private(set) var isReady = false
    @Published public private(set) var isResetting = false
    @Published public private(set) var isPairing = false
    @Published public private(set) var pairingStatus = ""
    @Published public private(set) var companionCapabilities = Set<String>()
    @Published public private(set) var grantedPermissions = Set<String>()
    @Published public private(set) var selectedPage: ResolvePage = .edit

    private struct PendingCommand {
        let id: String
        let operation: String
        let expiresAt: Int64
    }

    private var enrollmentRelayURL: String?
    private var storedEnrollment: StoredEnrollment?
    private let urlSession = URLSession(configuration: .ephemeral)
    private var socket: URLSessionWebSocketTask?
    private var receiveTask: Task<Void, Never>?
    private var pingTask: Task<Void, Never>?
    private var reconnectTask: Task<Void, Never>?
    private var rotationTask: Task<Void, Never>?
    private var expiryTask: Task<Void, Never>?
    private var pairingTask: Task<Void, Never>?
    private var pairingAttemptID: UUID?
    private var activeEnrollment: ActiveEnrollment?
    private var sessionID: String?
    private var nextSendSequence: Int64 = 1
    private var receivedFrames = RelayFrameBuffer()
    private var noise: NoiseIKInitiator?
    private var noiseReady = false
    private var receivedHello = false
    private var pendingCommand: PendingCommand?
    private var lateResponses = LateResponseWindow()
    private var reconnectAttempt = 0
    private var credentialStoreUnavailable = false
    private let keychainLoad: () throws -> StoredEnrollment?

    public convenience init(relayURL: String? = nil) {
        self.init(relayURL: relayURL, keychainLoad: KeychainStore.load)
    }

    init(relayURL: String?, keychainLoad: @escaping () throws -> StoredEnrollment?) {
        self.keychainLoad = keychainLoad
        do {
            enrollmentRelayURL = try Enrollment.deploymentRelayURL(relayURL)
        } catch {
            enrollmentRelayURL = nil
            enrollmentStatus = error.localizedDescription
            return
        }

        do {
            guard let loaded = try keychainLoad() else { return }
            _ = try restoreStoredEnrollment(loaded)
            if shouldAutomaticallyReconcilePendingActivation {
                Task { [weak self] in self?.connect() }
            }
        } catch {
            hasLocalEnrollment = true
            credentialStoreUnavailable = true
            enrollmentStatus = error.localizedDescription
        }
    }

    public func createEnrollmentRequest() {
        guard !hasLocalEnrollment, storedEnrollment == nil, !isResetting, !isPairing else {
            enrollmentStatus = "A local enrollment or request already exists."
            return
        }
        stopMaintainingConnection(status: "Disconnected", feedback: "")
        do {
            guard let enrollmentRelayURL else { throw EnrollmentError.invalidRelay }
            let (request, stored) = try Enrollment.create(
                deviceLabel: deviceLabel,
                relayURL: enrollmentRelayURL
            )
            let requestJSON = try request.jsonString()
            try KeychainStore.save(stored)
            storedEnrollment = stored
            hasLocalEnrollment = true
            enrollmentRequestJSON = requestJSON
            enrollmentResponseJSON = ""
            enrollmentStatus = "Request ready"
            isEnrolled = false
            grantedPermissions = Set(Self.operations)
        } catch {
            enrollmentStatus = error.localizedDescription
        }
    }

    public func importEnrollmentResponse() {
        guard let storedEnrollment else {
            enrollmentStatus = EnrollmentError.missingRequest.localizedDescription
            return
        }
        guard storedEnrollment.activationPending != true else {
            enrollmentStatus = "Pairing activation is unconfirmed; forget local credentials and pair again"
            return
        }
        do {
            let active = try Enrollment.importResponse(enrollmentResponseJSON, into: storedEnrollment)
            try KeychainStore.save(active)
            self.storedEnrollment = active
            isEnrolled = true
            grantedPermissions = Set(Self.operations)
            enrollmentStatus = "Enrolled"
            enrollmentResponseJSON = ""
        } catch {
            enrollmentStatus = error.localizedDescription
        }
    }

    public func canSend(_ operation: String) -> Bool {
        isReady && pendingCommand == nil && companionCapabilities.contains(operation) &&
            grantedPermissions.contains(operation)
    }

    public var canConnect: Bool {
        (isEnrolled || hasPendingPairingActivation) && storedEnrollment?.response != nil &&
            storedEnrollment?.linkRevocationConfirmed != true && !isResetting && !isPairing
    }

    public var canStartPairing: Bool {
        !isEnrolled && storedEnrollment?.activationPending != true && !credentialStoreUnavailable &&
            !isResetting && !isPairing
    }

    public var hasPendingPairingActivation: Bool {
        storedEnrollment?.activationPending == true
    }

    public var shouldAutomaticallyReconcilePendingActivation: Bool {
        hasPendingPairingActivation && Self.pendingActivationReconnectDelay(
            proposedDelay: 0,
            expiresAt: storedEnrollment?.pairingExpiresAt,
            now: Date().timeIntervalSince1970
        ) != nil
    }

    public func refreshCredentialStoreIfNeeded() {
        guard credentialStoreUnavailable else { return }
        _ = adoptPairingCheckpointIfPresent(fallbackStatus: "Not enrolled", load: keychainLoad)
    }

    public func pair(inviteJSON: String) {
        guard !isEnrolled, storedEnrollment?.activationPending != true, !credentialStoreUnavailable,
              !isResetting, !isPairing
        else {
            enrollmentStatus = "Resolve the current enrollment or pairing attempt first."
            return
        }
        guard let enrollmentRelayURL else {
            enrollmentStatus = EnrollmentError.invalidRelay.localizedDescription
            return
        }

        let invite: PairingInvite
        do {
            invite = try PairingInvite.parse(inviteJSON, expectedRelayURL: enrollmentRelayURL)
        } catch {
            enrollmentStatus = error.localizedDescription
            pairingStatus = error.localizedDescription
            return
        }

        if hasLocalEnrollment || storedEnrollment != nil {
            do {
                try KeychainStore.delete()
                clearLocalEnrollment()
            } catch {
                enrollmentStatus = "Could not replace the unfinished manual request: \(error.localizedDescription)"
                pairingStatus = enrollmentStatus
                return
            }
        }

        stopMaintainingConnection(status: "Disconnected", feedback: "")
        let attemptID = UUID()
        pairingAttemptID = attemptID
        isPairing = true
        pairingStatus = PairingProgress.joining.rawValue
        enrollmentStatus = "Pairing"
        pairingTask = Task { [weak self] in
            guard let self else { return }
            do {
                let enrolled = try await PairingClient.enroll(
                    invite: invite,
                    deviceLabel: deviceLabel
                ) { [weak self] progress in
                    guard self?.pairingAttemptID == attemptID else { return }
                    self?.pairingStatus = progress.rawValue
                }
                try Task.checkCancellation()
                guard pairingAttemptID == attemptID else { return }
                let request = try Enrollment.request(for: enrolled)
                storedEnrollment = enrolled
                hasLocalEnrollment = true
                isEnrolled = true
                grantedPermissions = Set(enrolled.grantedPermissions ?? Self.operations)
                enrollmentRequestJSON = try request.jsonString()
                enrollmentResponseJSON = ""
                enrollmentStatus = "Enrolled"
                pairingStatus = "Paired"
                pairingAttemptID = nil
                pairingTask = nil
                isPairing = false
                connect()
            } catch {
                guard pairingAttemptID == attemptID else { return }
                let status = Task.isCancelled || error is CancellationError
                    ? "Pairing cancelled"
                    : error.localizedDescription
                let activeWasSaved = adoptPairingCheckpointIfPresent(fallbackStatus: status)
                pairingStatus = activeWasSaved ? "Paired" : enrollmentStatus
                pairingAttemptID = nil
                pairingTask = nil
                isPairing = false
                if (activeWasSaved || hasPendingPairingActivation), !Task.isCancelled {
                    connect()
                }
            }
        }
    }

    public func cancelPairing() {
        guard isPairing else { return }
        pairingTask?.cancel()
        pairingStatus = "Cancelling pairing"
        enrollmentStatus = "Cancelling pairing"
    }

    public func connect() {
        guard canConnect, !isConnectionDesired else { return }
        isConnectionDesired = true
        reconnectAttempt = 0
        Task { await connectNow() }
    }

    public func disconnect() {
        stopMaintainingConnection(status: "Disconnected", feedback: "Disconnected")
    }

    public func requestPage(_ page: ResolvePage) {
        Task { await sendCommand(page.operation) }
    }

    public func toggleHostMute() {
        Task { await sendCommand("host.volume.toggle-mute") }
    }

    public func revokeAndReenroll() {
        guard isEnrolled, !isResetting, let storedEnrollment else { return }
        isResetting = true
        stopMaintainingConnection(status: "Revoking enrollment", feedback: "")
        Task { await revokeAndCreateRequest(from: storedEnrollment) }
    }

    public func forgetLocalEnrollmentAndReenroll() {
        guard hasLocalEnrollment, !isResetting else { return }
        isResetting = true
        stopMaintainingConnection(status: "Forgetting local credentials", feedback: "")

        do {
            try KeychainStore.delete()
            clearLocalEnrollment()
            try createReplacementRequest(status:
                "Local credentials forgotten; new request ready. The prior remote identity may remain."
            )
        } catch {
            enrollmentStatus = hasLocalEnrollment
                ? "Local forget failed: \(error.localizedDescription)"
                : "Local credentials deleted; re-enrollment failed: \(error.localizedDescription)"
            connectionStatus = "Disconnected"
        }
        isResetting = false
    }

    private func connectNow() async {
        guard isConnectionDesired, !isConnected, !isResetting else { return }
        guard let storedEnrollment else {
            isConnectionDesired = false
            connectionStatus = EnrollmentError.missingRequest.localizedDescription
            return
        }

        let active: ActiveEnrollment
        do {
            active = try Enrollment.active(from: storedEnrollment)
        } catch {
            isConnectionDesired = false
            teardownConnection(status: "Connection failed", feedback: error.localizedDescription)
            return
        }

        var request = URLRequest(url: active.relayURL)
        request.setValue(
            "Bearer rd1.\(active.controllerEndpointID).\(active.controllerSecret)",
            forHTTPHeaderField: "Authorization"
        )
        let task = urlSession.webSocketTask(with: request)
        socket = task
        activeEnrollment = active
        isConnected = true
        connectionStatus = "Connecting"
        task.resume()
        receiveTask = Task { [weak self] in
            await self?.receiveLoop(task)
        }
        pingTask = Task { [weak self] in
            await self?.pingLoop(task)
        }
        startRotation(for: task)

        do {
            try await sendOuter(type: "session.open", body: ["linkId": active.linkID], on: task)
            connectionStatus = "Waiting for companion"
        } catch {
            connectionFailed(task, error: error)
        }
    }

    private func receiveLoop(_ task: URLSessionWebSocketTask) async {
        do {
            while !Task.isCancelled, socket === task {
                let message = try await task.receive()
                guard socket === task else { return }
                switch message {
                case let .string(text):
                    guard let data = text.data(using: .utf8), data.count <= 32 * 1024 else {
                        throw ControllerProtocolError.invalidMessage
                    }
                    try await handleOuter(data, on: task)
                case .data:
                    throw ControllerProtocolError.invalidMessage
                @unknown default:
                    throw ControllerProtocolError.invalidMessage
                }
            }
        } catch {
            guard socket === task else { return }
            connectionFailed(task, error: error)
        }
    }

    private func pingLoop(_ task: URLSessionWebSocketTask) async {
        do {
            while !Task.isCancelled, socket === task {
                try await Task.sleep(for: .seconds(300))
                guard !Task.isCancelled, socket === task else { return }
                try await sendPing(task)
            }
        } catch {
            guard socket === task else { return }
            connectionFailed(task, error: error)
        }
    }

    private func handleOuter(_ data: Data, on task: URLSessionWebSocketTask) async throws {
        guard let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              envelope["protocol"] as? String == "remote-davinci.rendezvous",
              jsonInt64(envelope["v"]) == 1,
              let type = envelope["type"] as? String,
              let body = envelope["body"] as? [String: Any]
        else {
            throw ControllerProtocolError.invalidMessage
        }

        switch type {
        case "ok":
            return
        case "error":
            guard let code = body["code"] as? String,
                  let retryable = jsonBool(body["retryable"])
            else {
                throw ControllerProtocolError.invalidMessage
            }
            throw RelayConnectionError.server(code: code, retryable: retryable)
        case "session.opened":
            try await handleSessionOpened(body, on: task)
        case "session.frame":
            try await handleSessionFrame(body, on: task)
        case "session.closed":
            guard try RelayLifecycle.isCurrentSessionClose(
                envelope: envelope,
                body: body,
                currentSessionID: sessionID
            ) else {
                return
            }
            throw RelayConnectionError.sessionClosed
        case "link.revoked":
            guard envelope["replyTo"] == nil,
                  let eventID = envelope["id"] as? String,
                  isCanonicalUUID(eventID),
                  let activeEnrollment,
                  body["linkId"] as? String == activeEnrollment.linkID
            else {
                throw ControllerProtocolError.invalidMessage
            }
            do {
                try persistLinkRevocationCheckpoint(linkID: activeEnrollment.linkID)
            } catch {
                throw RelayConnectionError.linkRevocationCheckpointFailed(
                    error.localizedDescription
                )
            }
            throw RelayConnectionError.linkRevoked
        default:
            return
        }
    }

    private func handleSessionOpened(
        _ body: [String: Any],
        on task: URLSessionWebSocketTask
    ) async throws {
        guard let activeEnrollment,
              let receivedSessionID = body["sessionId"] as? String,
              let linkID = body["linkId"] as? String,
              let peerEndpointID = body["peerEndpointId"] as? String,
              isCanonicalUUID(receivedSessionID),
              linkID == activeEnrollment.linkID,
              peerEndpointID == activeEnrollment.companionEndpointID
        else {
            throw ControllerProtocolError.invalidMessage
        }
        if let sessionID {
            guard sessionID == receivedSessionID else {
                throw ControllerProtocolError.unexpectedMessage
            }
            return
        }

        sessionID = receivedSessionID
        nextSendSequence = 1
        receivedFrames = RelayFrameBuffer()
        let prologue = Data(
            "remote-davinci/session/v1\n\(activeEnrollment.linkID)\n\(receivedSessionID)".utf8
        )
        let initiator = try NoiseIKInitiator(
            staticPrivateKey: activeEnrollment.controllerNoisePrivateKey,
            remoteStaticKey: activeEnrollment.companionNoisePublicKey,
            prologue: prologue
        )
        noise = initiator
        try await sendFrame(try initiator.writeMessage1(), on: task)
        connectionStatus = "Securing session"
    }

    private func handleSessionFrame(
        _ body: [String: Any],
        on task: URLSessionWebSocketTask
    ) async throws {
        guard let sessionID,
              body["sessionId"] as? String == sessionID,
              let sequence = jsonInt64(body["seq"]),
              sequence >= 1,
              let payload = body["payload"] as? String,
              let frame = Base64URL.decode(payload),
              !frame.isEmpty,
              frame.count <= 16 * 1024
        else {
            throw ControllerProtocolError.invalidMessage
        }

        for orderedFrame in try receivedFrames.insert(sequence: sequence, frame: frame) {
            try await handleOrderedFrame(orderedFrame, on: task)
        }
    }

    private func handleOrderedFrame(
        _ frame: Data,
        on task: URLSessionWebSocketTask
    ) async throws {
        guard let noise else { throw ControllerProtocolError.unexpectedMessage }
        if !noiseReady {
            try noise.readMessage2(frame)
            noiseReady = true
            try await sendControl(
                type: "hello",
                body: [
                    "role": "controller",
                    "capabilities": Self.operations,
                    "appVersion": "0.1.0",
                ],
                on: task
            )
            connectionStatus = "Authenticating companion"
            return
        }

        let plaintext = try noise.decryptTransport(frame)
        try handleControl(plaintext)
    }

    private func handleControl(_ data: Data) throws {
        guard data.count <= NoiseIKInitiator.maxPlaintextBytes,
              let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              envelope["protocol"] as? String == "remote-davinci.control",
              jsonInt64(envelope["v"]) == 1,
              let type = envelope["type"] as? String,
              let id = envelope["id"] as? String,
              isCanonicalUUID(id),
              let body = envelope["body"] as? [String: Any]
        else {
            throw ControllerProtocolError.invalidMessage
        }

        if !receivedHello {
            guard type == "hello",
                  body["role"] as? String == "companion",
                  let capabilities = body["capabilities"] as? [String],
                  capabilities.count <= 64,
                  Set(capabilities).count == capabilities.count,
                  let appVersion = body["appVersion"] as? String,
                  !appVersion.isEmpty,
                  appVersion.count <= 64
            else {
                throw ControllerProtocolError.unexpectedMessage
            }
            receivedHello = true
            try finalizePendingActivation()
            reconnectAttempt = 0
            companionCapabilities = Set(capabilities)
            isReady = true
            connectionStatus = "Connected"
            feedback = Self.operations.contains(where: companionCapabilities.contains)
                ? "Ready"
                : "Companion offers no supported controls"
            return
        }

        if type == "event" {
            if let page = try ResolvePageControl.eventPage(body: body) {
                selectedPage = page
            }
            return
        }
        guard type == "response",
              let replyTo = envelope["replyTo"] as? String,
              isCanonicalUUID(replyTo)
        else {
            throw ControllerProtocolError.unexpectedMessage
        }
        guard let pendingCommand, pendingCommand.id == replyTo else {
            if lateResponses.contains(replyTo) { return }
            throw ControllerProtocolError.unexpectedMessage
        }

        expiryTask?.cancel()
        expiryTask = nil
        self.pendingCommand = nil
        guard nowMilliseconds() <= pendingCommand.expiresAt else {
            feedback = "\(pendingCommand.operation) expired"
            return
        }

        if jsonBool(body["ok"]) == true, let result = body["result"] {
            if let page = try ResolvePageControl.responsePage(
                operation: pendingCommand.operation,
                result: result
            ) {
                selectedPage = page
            }
            feedback = "\(pendingCommand.operation) succeeded"
        } else if jsonBool(body["ok"]) == false,
                  let error = body["error"] as? [String: Any],
                  let code = error["code"] as? String
        {
            feedback = "\(pendingCommand.operation) failed: \(code)"
        } else {
            throw ControllerProtocolError.invalidMessage
        }
    }

    private func sendCommand(_ operation: String) async {
        guard Self.operations.contains(operation), canSend(operation), let task = socket else { return }
        let sentAt = nowMilliseconds()
        let expiresAt = sentAt + 5_000
        let id = UUID().uuidString.lowercased()
        pendingCommand = PendingCommand(id: id, operation: operation, expiresAt: expiresAt)
        feedback = "Sending \(operation)"

        do {
            try await sendControl(
                type: "request",
                id: id,
                body: [
                    "operation": operation,
                    "args": [String: Any](),
                    "sentAt": sentAt,
                    "expiresAt": expiresAt,
                ],
                on: task
            )
            guard socket === task, pendingCommand?.id == id else { return }
            feedback = "Waiting for \(operation)"
            expiryTask = Task { [weak self] in
                try? await Task.sleep(for: .seconds(5))
                guard !Task.isCancelled else { return }
                self?.expireCommand(id)
            }
        } catch {
            connectionFailed(task, error: error)
        }
    }

    private func expireCommand(_ id: String) {
        guard let pendingCommand, pendingCommand.id == id else { return }
        lateResponses.remember(id)
        self.pendingCommand = nil
        expiryTask = nil
        feedback = "\(pendingCommand.operation) expired"
    }

    private func revokeAndCreateRequest(from stored: StoredEnrollment) async {
        defer { isResetting = false }

        do {
            let active = try Enrollment.active(from: stored)
            let endpointCleanupError = try await revokeRemoteEnrollment(active, stored: stored)
            try KeychainStore.delete()
            clearLocalEnrollment()
            try createReplacementRequest(status: endpointCleanupError == nil
                ? "Old endpoint revoked; new request ready"
                : "Link revoked; endpoint cleanup unconfirmed; new request ready"
            )
        } catch {
            enrollmentStatus = !hasLocalEnrollment
                ? "Endpoint revoked; re-enrollment failed: \(error.localizedDescription)"
                : "Reset failed: \(error.localizedDescription)"
            connectionStatus = "Disconnected"
        }
    }

    private func revokeRemoteEnrollment(
        _ active: ActiveEnrollment,
        stored: StoredEnrollment
    ) async throws -> Error? {
        var request = URLRequest(url: active.relayURL)
        request.setValue(
            "Bearer rd1.\(active.controllerEndpointID).\(active.controllerSecret)",
            forHTTPHeaderField: "Authorization"
        )
        let task = urlSession.webSocketTask(with: request)
        task.resume()
        defer { task.cancel(with: .normalClosure, reason: nil) }

        if stored.linkRevocationConfirmed != true {
            try await sendLifecycleRequest(
                type: "link.revoke",
                body: ["linkId": active.linkID],
                on: task
            )
            var checkpoint = stored
            checkpoint.linkRevocationConfirmed = true
            try KeychainStore.save(checkpoint)
            storedEnrollment = checkpoint
            enrollmentStatus = "Link revocation confirmed; cleaning up endpoint"
        }

        do {
            try await sendLifecycleRequest(type: "endpoint.revoke", body: [:], on: task)
            return nil
        } catch {
            return error
        }
    }

    private func clearLocalEnrollment() {
        storedEnrollment = nil
        hasLocalEnrollment = false
        credentialStoreUnavailable = false
        isEnrolled = false
        enrollmentRequestJSON = ""
        enrollmentResponseJSON = ""
        grantedPermissions = []
    }

    @discardableResult
    private func restoreStoredEnrollment(_ loaded: StoredEnrollment) throws -> Bool {
        guard let deploymentRelayURL = enrollmentRelayURL else {
            throw EnrollmentError.invalidRelay
        }
        let stored = try Enrollment.migrateLegacy(
            loaded,
            deploymentRelayURL: deploymentRelayURL
        )
        let requestJSON = try Enrollment.request(for: stored).jsonString()
        let replacementRelayURL = try Enrollment.replacementRelayURL(
            stored: stored,
            deploymentRelayURL: deploymentRelayURL
        )
        let active = stored.response != nil && stored.activationPending != true
        let status: String
        if active {
            _ = try Enrollment.active(from: stored)
            status = stored.linkRevocationConfirmed == true
                ? "Link revoked; finish re-enrollment"
                : "Enrolled"
        } else if stored.activationPending == true {
            _ = try Enrollment.active(from: stored)
            status = Self.pendingActivationReconnectDelay(
                proposedDelay: 0,
                expiresAt: stored.pairingExpiresAt,
                now: Date().timeIntervalSince1970
            ) == nil
                ? "Pairing activation deadline passed; recovery required"
                : "Pairing activation is unconfirmed; reconnecting securely"
        } else {
            status = "Request ready"
        }
        if stored != loaded {
            try KeychainStore.save(stored)
        }
        storedEnrollment = stored
        enrollmentRelayURL = replacementRelayURL
        hasLocalEnrollment = true
        credentialStoreUnavailable = false
        enrollmentRequestJSON = requestJSON
        isEnrolled = active
        grantedPermissions = Set(stored.grantedPermissions ?? Self.operations)
        enrollmentStatus = status
        return active
    }

    @discardableResult
    func adoptPairingCheckpointIfPresent(
        fallbackStatus: String,
        load: () throws -> StoredEnrollment? = KeychainStore.load
    ) -> Bool {
        let loaded: StoredEnrollment
        do {
            guard let checkpoint = try load() else {
                credentialStoreUnavailable = false
                if storedEnrollment == nil {
                    hasLocalEnrollment = false
                }
                enrollmentStatus = fallbackStatus
                return false
            }
            loaded = checkpoint
        } catch {
            hasLocalEnrollment = true
            credentialStoreUnavailable = true
            enrollmentStatus = "Saved pairing credentials could not be read: \(error.localizedDescription)"
            return false
        }
        do {
            return try restoreStoredEnrollment(loaded)
        } catch {
            hasLocalEnrollment = true
            credentialStoreUnavailable = true
            enrollmentStatus = "Saved pairing credentials could not be restored: \(error.localizedDescription)"
            return false
        }
    }

    private func createReplacementRequest(status: String) throws {
        guard let enrollmentRelayURL else { throw EnrollmentError.invalidRelay }
        let (request, replacement) = try Self.replacementEnrollment(
            deviceLabel: deviceLabel,
            relayURL: enrollmentRelayURL
        )
        let requestJSON = try request.jsonString()
        try KeychainStore.save(replacement)
        storedEnrollment = replacement
        hasLocalEnrollment = true
        enrollmentRequestJSON = requestJSON
        enrollmentStatus = status
        connectionStatus = "Disconnected"
        feedback = ""
    }

    nonisolated static func replacementEnrollment(
        deviceLabel: String,
        relayURL: String
    ) throws -> (EnrollmentRequest, StoredEnrollment) {
        try Enrollment.create(deviceLabel: deviceLabel, relayURL: relayURL)
    }

    private func persistLinkRevocationCheckpoint(linkID: String) throws {
        guard var stored = storedEnrollment,
              stored.response?.linkId == linkID
        else {
            throw EnrollmentError.invalidResponse
        }
        if stored.linkRevocationConfirmed != true {
            stored.linkRevocationConfirmed = true
            try KeychainStore.save(stored)
            storedEnrollment = stored
        }
        enrollmentStatus = "Link revoked; finish re-enrollment"
    }

    private func finalizePendingActivation() throws {
        guard var stored = storedEnrollment, stored.activationPending == true else { return }
        _ = try Enrollment.active(from: stored)
        stored.activationPending = false
        stored.pairingExpiresAt = nil
        try KeychainStore.save(stored)
        storedEnrollment = stored
        isEnrolled = true
        enrollmentStatus = "Enrolled"
    }

    private func sendLifecycleRequest(
        type: String,
        body: [String: Any],
        on task: URLSessionWebSocketTask
    ) async throws {
        let requestID = UUID().uuidString.lowercased()
        let envelope: [String: Any] = [
            "protocol": "remote-davinci.rendezvous",
            "v": 1,
            "type": type,
            "id": requestID,
            "body": body,
        ]
        let data = try JSONSerialization.data(
            withJSONObject: envelope,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard data.count <= 32 * 1024, let text = String(data: data, encoding: .utf8) else {
            throw ControllerProtocolError.invalidMessage
        }
        try await task.send(.string(text))

        let timeout = Task {
            do {
                try await Task.sleep(for: .seconds(15))
            } catch {
                return
            }
            task.cancel(with: .goingAway, reason: nil)
        }
        defer { timeout.cancel() }

        while true {
            let message = try await task.receive()
            guard case let .string(responseText) = message,
                  let responseData = responseText.data(using: .utf8),
                  responseData.count <= 32 * 1024
            else {
                throw ControllerProtocolError.invalidMessage
            }
            switch try RelayLifecycle.parseResponse(
                responseData,
                requestID: requestID,
                requestType: type
            ) {
            case .success:
                return
            case let .failure(code, _):
                throw RelayLifecycleError.server(code: code)
            case .event:
                continue
            }
        }
    }

    private func connectionFailed(_ task: URLSessionWebSocketTask, error: Error) {
        guard socket === task else { return }
        if let status = RelayLifecycle.terminalHandshakeAuthorizationStatus(
            error: error,
            response: task.response
        ) {
            if hasPendingPairingActivation {
                enrollmentStatus = "Pairing activation is unconfirmed; retrying securely"
                teardownConnection(
                    status: "Activation unconfirmed",
                    feedback: "The relay has not accepted the pending enrollment yet (HTTP \(status))."
                )
                scheduleReconnect()
                return
            }
            stopMaintainingConnection(
                status: "Recovery required",
                feedback: "Relay rejected the enrollment (HTTP \(status)). Forget local credentials and re-enroll."
            )
            return
        }
        if case let .linkRevocationCheckpointFailed(message) = error as? RelayConnectionError {
            enrollmentStatus = "Link revoked; local recovery checkpoint failed"
            stopMaintainingConnection(
                status: "Recovery required",
                feedback: "The link was revoked, but its checkpoint could not be saved: \(message). Forget local credentials and re-enroll."
            )
            return
        }
        if case .linkRevoked = error as? RelayConnectionError {
            stopMaintainingConnection(
                status: "Recovery required",
                feedback: "The link was revoked. Revoke and re-enroll, or forget local credentials."
            )
            return
        }
        if case let .server(code, retryable) = error as? RelayConnectionError,
           !RelayLifecycle.shouldReconnect(code: code, retryable: retryable)
        {
            if hasPendingPairingActivation, ["UNAUTHENTICATED", "FORBIDDEN"].contains(code) {
                enrollmentStatus = "Pairing activation is unconfirmed; retrying securely"
                teardownConnection(
                    status: "Activation unconfirmed",
                    feedback: "The relay has not accepted the pending enrollment yet (\(code))."
                )
                scheduleReconnect()
                return
            }
            stopMaintainingConnection(
                status: "Recovery required",
                feedback: "Relay rejected the enrollment (\(code)). Forget local credentials and re-enroll."
            )
            return
        }
        if error is ControllerProtocolError || error is NoiseError {
            stopMaintainingConnection(
                status: "Recovery required",
                feedback: "Secure session validation failed. Forget local credentials and re-enroll."
            )
            return
        }
        teardownConnection(status: "Disconnected", feedback: error.localizedDescription)
        scheduleReconnect()
    }

    private func scheduleReconnect(immediately: Bool = false) {
        guard isConnectionDesired, !isResetting, reconnectTask == nil else { return }
        var delay: Double
        if immediately {
            delay = 0
        } else {
            delay = RelayLifecycle.reconnectDelaySeconds(
                attempt: reconnectAttempt,
                randomUnit: Double.random(in: 0...1)
            )
            reconnectAttempt += 1
        }
        if hasPendingPairingActivation {
            guard let boundedDelay = Self.pendingActivationReconnectDelay(
                proposedDelay: delay,
                expiresAt: storedEnrollment?.pairingExpiresAt,
                now: Date().timeIntervalSince1970
            ) else {
                enrollmentStatus = "Pairing activation could not be confirmed before the pairing code expired"
                stopMaintainingConnection(
                    status: "Recovery required",
                    feedback: "Credentials were kept in case activation completed. Retry Connect, or forget local credentials and pair again."
                )
                return
            }
            delay = boundedDelay
        }
        connectionStatus = "Reconnecting in \(Int(ceil(delay)))s"
        reconnectTask = Task { [weak self] in
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch {
                return
            }
            await self?.resumeReconnect()
        }
    }

    private func resumeReconnect() async {
        reconnectTask = nil
        await connectNow()
    }

    nonisolated static func pendingActivationReconnectDelay(
        proposedDelay: Double,
        expiresAt: Int64?,
        now: TimeInterval
    ) -> Double? {
        guard let expiresAt else { return nil }
        let remaining = TimeInterval(expiresAt) - now
        guard remaining > 0 else { return nil }
        return min(proposedDelay, remaining)
    }

    private func startRotation(for task: URLSessionWebSocketTask) {
        let delay = RelayLifecycle.rotationDelaySeconds(randomUnit: Double.random(in: 0...1))
        rotationTask = Task { [weak self] in
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch {
                return
            }
            self?.rotateConnection(task)
        }
    }

    private func rotateConnection(_ task: URLSessionWebSocketTask) {
        guard socket === task, isConnectionDesired else { return }
        // ponytail: commands are never queued; reconnect restores a live session without replay.
        let rotationFeedback = pendingCommand == nil
            ? "Refreshing secure connection"
            : "Connection refreshed; the pending command was not replayed"
        teardownConnection(status: "Refreshing connection", feedback: rotationFeedback)
        scheduleReconnect(immediately: true)
    }

    private func sendControl(
        type: String,
        id: String = UUID().uuidString.lowercased(),
        body: [String: Any],
        on task: URLSessionWebSocketTask
    ) async throws {
        guard let noise else { throw ControllerProtocolError.unexpectedMessage }
        let envelope: [String: Any] = [
            "protocol": "remote-davinci.control",
            "v": 1,
            "type": type,
            "id": id,
            "body": body,
        ]
        let plaintext = try JSONSerialization.data(
            withJSONObject: envelope,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        try await sendFrame(try noise.encryptTransport(plaintext), on: task)
    }

    private func sendFrame(_ frame: Data, on task: URLSessionWebSocketTask) async throws {
        guard socket === task, let sessionID else {
            throw ControllerProtocolError.unexpectedMessage
        }
        let sequence = nextSendSequence
        nextSendSequence += 1
        try await sendOuter(
            type: "session.frame",
            body: [
                "sessionId": sessionID,
                "seq": sequence,
                "payload": Base64URL.encode(frame),
            ],
            on: task
        )
    }

    private func sendOuter(
        type: String,
        body: [String: Any],
        on task: URLSessionWebSocketTask
    ) async throws {
        let envelope: [String: Any] = [
            "protocol": "remote-davinci.rendezvous",
            "v": 1,
            "type": type,
            "id": UUID().uuidString.lowercased(),
            "body": body,
        ]
        let data = try JSONSerialization.data(
            withJSONObject: envelope,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard data.count <= 32 * 1024, let text = String(data: data, encoding: .utf8) else {
            throw ControllerProtocolError.invalidMessage
        }
        try await task.send(.string(text))
    }

    private func stopMaintainingConnection(status: String, feedback: String) {
        isConnectionDesired = false
        reconnectTask?.cancel()
        reconnectTask = nil
        teardownConnection(status: status, feedback: feedback)
    }

    private func teardownConnection(status: String, feedback: String) {
        receiveTask?.cancel()
        receiveTask = nil
        pingTask?.cancel()
        pingTask = nil
        rotationTask?.cancel()
        rotationTask = nil
        expiryTask?.cancel()
        expiryTask = nil
        let currentSocket = socket
        socket = nil
        currentSocket?.cancel(with: .goingAway, reason: nil)
        activeEnrollment = nil
        sessionID = nil
        nextSendSequence = 1
        receivedFrames = RelayFrameBuffer()
        noise = nil
        noiseReady = false
        receivedHello = false
        pendingCommand = nil
        lateResponses = LateResponseWindow()
        companionCapabilities = []
        isConnected = false
        isReady = false
        connectionStatus = status
        self.feedback = feedback
    }
}

private func sendPing(_ task: URLSessionWebSocketTask) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        task.sendPing { error in
            if let error {
                continuation.resume(throwing: error)
            } else {
                continuation.resume()
            }
        }
    }
}

private extension Encodable {
    func jsonString() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        guard let string = String(data: data, encoding: .utf8) else {
            throw EnrollmentError.invalidJSON
        }
        return string
    }
}

private func isCanonicalUUID(_ value: String) -> Bool {
    UUID(uuidString: value)?.uuidString.lowercased() == value
}

private func jsonInt64(_ value: Any?) -> Int64? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          number.doubleValue.rounded(.towardZero) == number.doubleValue,
          abs(number.doubleValue) <= 9_007_199_254_740_991
    else {
        return nil
    }
    return number.int64Value
}

private func jsonBool(_ value: Any?) -> Bool? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) == CFBooleanGetTypeID()
    else {
        return nil
    }
    return number.boolValue
}

private func nowMilliseconds() -> Int64 {
    Int64(Date().timeIntervalSince1970 * 1_000)
}

extension Base64URL {
    static func decode(_ value: String) -> Data? {
        guard !value.isEmpty, !value.contains("="), value.allSatisfy({
            $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_")
        }) else {
            return nil
        }
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let decoded = Data(base64Encoded: base64), encode(decoded) == value else {
            return nil
        }
        return decoded
    }
}
