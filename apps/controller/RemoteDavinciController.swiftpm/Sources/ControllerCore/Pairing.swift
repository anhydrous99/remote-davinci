import CryptoKit
import Foundation

struct PairingInvite: Codable, Equatable, Sendable {
    static let protocolName = "remote-davinci.pairing-invite"
    static let maximumBytes = 2 * 1_024
    static let maximumLifetimeSeconds: Int64 = 5 * 60
    static let clockSkewToleranceSeconds: Int64 = 60

    let protocolName: String
    let v: Int
    let relayUrl: String
    let pairId: String
    let creatorSideId: String
    let linkId: String
    let joinToken: String
    let psk: String
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case v, relayUrl, pairId, creatorSideId, linkId, joinToken, psk, expiresAt
    }

    static func parse(
        _ value: String,
        expectedRelayURL: String,
        now: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> PairingInvite {
        let data = Data(value.utf8)
        guard !data.isEmpty, data.count <= maximumBytes,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(CodingKeys.allCases.map(\.rawValue)),
              let invite = try? JSONDecoder().decode(Self.self, from: data),
              invite.protocolName == protocolName,
              invite.v == 1,
              pairingCanonicalUUID(invite.pairId),
              pairingCanonicalUUID(invite.creatorSideId),
              pairingCanonicalUUID(invite.linkId),
              Base64URL.decode32(invite.joinToken) != nil,
              Base64URL.decode32(invite.psk) != nil,
              invite.joinToken != invite.psk
        else {
            throw PairingError.invalidInvite
        }

        do {
            guard try Enrollment.validatedRelayURL(invite.relayUrl) == invite.relayUrl,
                  try Enrollment.validatedRelayURL(expectedRelayURL) == expectedRelayURL
            else {
                throw PairingError.invalidInvite
            }
        } catch {
            throw PairingError.invalidInvite
        }
        guard invite.relayUrl == expectedRelayURL else {
            throw PairingError.mismatchedRelay
        }
        guard now >= 0,
              invite.expiresAt > now,
              invite.expiresAt - now <= maximumLifetimeSeconds + clockSkewToleranceSeconds
        else {
            throw PairingError.expiredInvite
        }
        return invite
    }
}

extension PairingInvite.CodingKeys: CaseIterable {}

enum PairingProgress: String, Sendable {
    case joining = "Joining Mac pairing session"
    case securing = "Securing pairing session"
    case waitingForApproval = "Waiting for approval on Mac"
    case activating = "Activating enrollment"
}

enum PairingError: LocalizedError, Equatable {
    case invalidInvite
    case expiredInvite
    case mismatchedRelay
    case invalidMessage
    case pairClosed(String)
    case relay(code: String, retryable: Bool)
    case storage(String)

    var errorDescription: String? {
        switch self {
        case .invalidInvite:
            "This is not a valid Remote DaVinci pairing code."
        case .expiredInvite:
            "This pairing code expired. Generate a new code on the Mac."
        case .mismatchedRelay:
            "The Mac uses a different relay server."
        case .invalidMessage:
            "The Mac sent an invalid pairing message. Generate a new code and try again."
        case let .pairClosed(reason):
            "Pairing ended on the Mac (\(reason))."
        case let .relay(code, _):
            "Pairing server error: \(code)"
        case let .storage(message):
            "Could not save enrollment credentials: \(message)"
        }
    }
}

enum PairingCheckpointDisposition: Equatable {
    case delete
    case retain
}

func pairingCheckpointDisposition(
    commitStarted: Bool,
    error: Error
) -> PairingCheckpointDisposition {
    guard commitStarted else { return .delete }
    guard let pairingError = error as? PairingError else { return .retain }
    switch pairingError {
    case .pairClosed:
        return .delete
    case let .relay(_, retryable) where !retryable:
        return .delete
    default:
        return .retain
    }
}

private struct PairingIdentityEnvelope: Codable {
    let `protocol`: String
    let v: Int
    let type: String
    let id: String
    let body: PairingIdentityBody
}

private struct PairingIdentityBody: Codable {
    let linkId: String
    let endpointId: String
    let role: String
    let noiseKey: String
    let noiseFingerprint: String
    let deviceLabel: String
    let permissions: [String]
    let capabilities: [String]
}

private struct PairingRelayEnvelope {
    let type: String
    let id: String
    let replyTo: String?
    let body: [String: Any]

    static func parse(_ data: Data) throws -> PairingRelayEnvelope {
        guard data.count <= 32 * 1_024,
              let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              envelope["protocol"] as? String == "remote-davinci.rendezvous",
              pairingJSONInt64(envelope["v"]) == 1,
              let type = envelope["type"] as? String,
              let id = envelope["id"] as? String,
              pairingCanonicalUUID(id),
              let body = envelope["body"] as? [String: Any]
        else {
            throw PairingError.invalidMessage
        }
        let replyTo: String?
        if let rawReplyTo = envelope["replyTo"] {
            guard let value = rawReplyTo as? String, pairingCanonicalUUID(value) else {
                throw PairingError.invalidMessage
            }
            replyTo = value
        } else {
            replyTo = nil
        }
        return PairingRelayEnvelope(type: type, id: id, replyTo: replyTo, body: body)
    }
}

@MainActor
enum PairingClient {
    private static let allowedErrorCodes = Set([
        "INVALID_MESSAGE", "UNSUPPORTED_VERSION", "UNAUTHENTICATED", "FORBIDDEN",
        "PAIR_UNAVAILABLE", "PAIR_FULL", "PAIR_EXPIRED", "PEER_OFFLINE", "PEER_BUSY",
        "SESSION_NOT_FOUND", "PAYLOAD_TOO_LARGE", "RATE_LIMITED", "CONFLICT", "INTERNAL",
    ])

    static func enroll(
        invite: PairingInvite,
        deviceLabel: String,
        progress: (PairingProgress) -> Void
    ) async throws -> StoredEnrollment {
        let (request, baseEnrollment) = try Enrollment.create(
            deviceLabel: deviceLabel,
            relayURL: invite.relayUrl
        )
        guard let relayURL = URL(string: invite.relayUrl),
              let psk = Base64URL.decode32(invite.psk)
        else {
            throw PairingError.invalidInvite
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.urlCache = nil
        let session = URLSession(configuration: configuration)
        var upgrade = URLRequest(url: relayURL)
        upgrade.setValue("Pairing rd1", forHTTPHeaderField: "Authorization")
        let socket = session.webSocketTask(with: upgrade)
        socket.resume()

        let expiry = Task {
            let seconds = max(0, invite.expiresAt - Int64(Date().timeIntervalSince1970))
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled else { return }
            socket.cancel(with: .goingAway, reason: nil)
        }
        defer {
            expiry.cancel()
            socket.cancel(with: .normalClosure, reason: nil)
            session.invalidateAndCancel()
        }

        return try await withTaskCancellationHandler {
            var pendingSaved = false
            var commitSent = false
            do {
                progress(.joining)
                let joined = try await join(invite: invite, socket: socket)
                try Task.checkCancellation()

                progress(.securing)
                let prologue = pairingNoisePrologue(
                    relayURL: invite.relayUrl,
                    pairID: invite.pairId,
                    creatorSideID: invite.creatorSideId,
                    joinerSideID: joined.sideID,
                    linkID: invite.linkId,
                    expiresAt: invite.expiresAt
                )
                let noise = try NoiseNNpsk0Initiator(psk: psk, prologue: prologue)
                try await sendPairFrame(
                    try noise.writeMessage1(),
                    sequence: 1,
                    pairID: invite.pairId,
                    socket: socket
                )

                var frameBuffer = RelayFrameBuffer()
                var queuedFrames = [Data]()
                let response = try await receivePairFrame(
                    pairID: invite.pairId,
                    socket: socket,
                    buffer: &frameBuffer,
                    queued: &queuedFrames
                )
                try noise.readMessage2(response)

                let controllerIdentity = PairingIdentityEnvelope(
                    protocol: "remote-davinci.pairing",
                    v: 1,
                    type: "identity",
                    id: UUID().uuidString.lowercased(),
                    body: PairingIdentityBody(
                        linkId: invite.linkId,
                        endpointId: request.controllerEndpointId,
                        role: "controller",
                        noiseKey: request.controllerNoiseKey,
                        noiseFingerprint: try noiseFingerprint(request.controllerNoiseKey),
                        deviceLabel: baseEnrollment.deviceLabel,
                        permissions: ControllerModel.operations,
                        capabilities: ControllerModel.operations
                    )
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try await sendPairFrame(
                    try noise.encryptTransport(encoder.encode(controllerIdentity)),
                    sequence: 2,
                    pairID: invite.pairId,
                    socket: socket
                )

                progress(.waitingForApproval)
                let companionCiphertext = try await receivePairFrame(
                    pairID: invite.pairId,
                    socket: socket,
                    buffer: &frameBuffer,
                    queued: &queuedFrames
                )
                let companion = try validateCompanionIdentity(
                    noise.decryptTransport(companionCiphertext),
                    invite: invite,
                    controllerEndpointID: request.controllerEndpointId
                )

                let responseEnrollment = EnrollmentResponse(
                    v: 1,
                    relayUrl: invite.relayUrl,
                    linkId: invite.linkId,
                    controllerEndpointId: request.controllerEndpointId,
                    companionEndpointId: companion.endpointId,
                    companionNoiseKey: companion.noiseKey
                )
                var pending = baseEnrollment
                pending.response = responseEnrollment
                pending.activationPending = true
                pending.grantedPermissions = companion.permissions
                pending.companionNoiseFingerprint = companion.noiseFingerprint
                pending.pairingProtocol = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
                pending.pairingExpiresAt = invite.expiresAt
                do {
                    try KeychainStore.save(pending)
                    pendingSaved = true
                } catch {
                    throw PairingError.storage(error.localizedDescription)
                }

                progress(.activating)
                let commitID = UUID().uuidString.lowercased()
                // Once a commit send begins, activation may have happened even if the reply is lost.
                commitSent = true
                try await sendOuter(
                    type: "pair.commit",
                    id: commitID,
                    body: [
                        "pairId": invite.pairId,
                        "sideId": joined.sideID,
                        "linkId": invite.linkId,
                        "self": [
                            "endpointId": request.controllerEndpointId,
                            "role": "controller",
                            "credentialHash": request.controllerCredentialHash,
                        ],
                        "peer": [
                            "endpointId": companion.endpointId,
                            "role": "companion",
                        ],
                    ],
                    socket: socket
                )
                try await waitForActivation(
                    invite: invite,
                    companionEndpointID: companion.endpointId,
                    requestID: commitID,
                    socket: socket
                )

                pending.activationPending = false
                pending.pairingExpiresAt = nil
                do {
                    try KeychainStore.save(pending)
                } catch {
                    throw PairingError.storage(error.localizedDescription)
                }
                return pending
            } catch {
                if pendingSaved,
                   pairingCheckpointDisposition(commitStarted: commitSent, error: error) == .delete
                {
                    do {
                        try KeychainStore.delete()
                    } catch {
                        throw PairingError.storage(error.localizedDescription)
                    }
                }
                if Int64(Date().timeIntervalSince1970) >= invite.expiresAt {
                    throw PairingError.expiredInvite
                }
                throw error
            }
        } onCancel: {
            socket.cancel(with: .goingAway, reason: nil)
        }
    }

    private static func join(
        invite: PairingInvite,
        socket: URLSessionWebSocketTask
    ) async throws -> (sideID: String, expiresAt: Int64) {
        let requestID = UUID().uuidString.lowercased()
        try await sendOuter(
            type: "pair.join",
            id: requestID,
            body: ["joinToken": invite.joinToken],
            socket: socket
        )

        var sideID: String?
        var ready = false
        while sideID == nil || !ready {
            let envelope = try await receiveOuter(socket)
            switch envelope.type {
            case "ok" where envelope.replyTo == requestID:
                guard envelope.body["requestType"] as? String == "pair.join",
                      let result = envelope.body["result"] as? [String: Any],
                      result["pairId"] as? String == invite.pairId,
                      let receivedSideID = result["sideId"] as? String,
                      pairingCanonicalUUID(receivedSideID),
                      receivedSideID != invite.creatorSideId,
                      let receivedExpiry = pairingJSONInt64(result["expiresAt"]),
                      receivedExpiry == invite.expiresAt
                else {
                    throw PairingError.invalidMessage
                }
                sideID = receivedSideID
            case "pair.ready":
                guard envelope.replyTo == nil,
                      envelope.body["pairId"] as? String == invite.pairId,
                      envelope.body["peerSideId"] as? String == invite.creatorSideId,
                      pairingJSONInt64(envelope.body["expiresAt"]) == invite.expiresAt
                else {
                    throw PairingError.invalidMessage
                }
                ready = true
            case "error":
                guard envelope.replyTo == requestID else {
                    throw PairingError.invalidMessage
                }
                throw try relayError(envelope)
            case "pair.closed":
                throw try closedError(envelope, pairID: invite.pairId)
            default:
                throw PairingError.invalidMessage
            }
        }
        return (sideID!, invite.expiresAt)
    }

    private static func receivePairFrame(
        pairID: String,
        socket: URLSessionWebSocketTask,
        buffer: inout RelayFrameBuffer,
        queued: inout [Data]
    ) async throws -> Data {
        if !queued.isEmpty { return queued.removeFirst() }
        while true {
            let envelope = try await receiveOuter(socket)
            switch envelope.type {
            case "pair.frame":
                guard envelope.replyTo == nil,
                      envelope.body["pairId"] as? String == pairID,
                      let sequence = pairingJSONInt64(envelope.body["seq"]),
                      sequence >= 1,
                      let payload = envelope.body["payload"] as? String,
                      let frame = Base64URL.decode(payload),
                      !frame.isEmpty,
                      frame.count <= 16 * 1_024
                else {
                    throw PairingError.invalidMessage
                }
                queued.append(contentsOf: try buffer.insert(sequence: sequence, frame: frame))
                if !queued.isEmpty { return queued.removeFirst() }
            case "error":
                throw try relayError(envelope)
            case "pair.closed":
                throw try closedError(envelope, pairID: pairID)
            default:
                throw PairingError.invalidMessage
            }
        }
    }

    private static func waitForActivation(
        invite: PairingInvite,
        companionEndpointID: String,
        requestID: String,
        socket: URLSessionWebSocketTask
    ) async throws {
        while true {
            let envelope = try await receiveOuter(socket)
            switch envelope.type {
            case "ok" where envelope.replyTo == requestID:
                guard envelope.body["requestType"] as? String == "pair.commit",
                      let result = envelope.body["result"] as? [String: Any]
                else {
                    throw PairingError.invalidMessage
                }
                if pairingJSONBool(result["active"]) == true,
                   result["linkId"] as? String == invite.linkId
                {
                    return
                }
                guard pairingJSONBool(result["pending"]) == true else {
                    throw PairingError.invalidMessage
                }
            case "pair.completed":
                guard envelope.replyTo == nil,
                      envelope.body["pairId"] as? String == invite.pairId,
                      envelope.body["linkId"] as? String == invite.linkId,
                      envelope.body["peerEndpointId"] as? String == companionEndpointID,
                      envelope.body["peerRole"] as? String == "companion"
                else {
                    throw PairingError.invalidMessage
                }
                return
            case "error":
                guard envelope.replyTo == requestID else {
                    throw PairingError.invalidMessage
                }
                throw try relayError(envelope)
            case "pair.closed":
                throw try closedError(envelope, pairID: invite.pairId)
            default:
                throw PairingError.invalidMessage
            }
        }
    }

    private static func validateCompanionIdentity(
        _ data: Data,
        invite: PairingInvite,
        controllerEndpointID: String
    ) throws -> PairingIdentityBody {
        guard data.count <= 8_140,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["protocol", "v", "type", "id", "body"]),
              let rawBody = object["body"] as? [String: Any],
              Set(rawBody.keys) == Set([
                  "linkId", "endpointId", "role", "noiseKey", "noiseFingerprint",
                  "deviceLabel", "permissions", "capabilities",
              ]),
              let identity = try? JSONDecoder().decode(PairingIdentityEnvelope.self, from: data),
              identity.protocol == "remote-davinci.pairing",
              identity.v == 1,
              identity.type == "identity",
              pairingCanonicalUUID(identity.id),
              identity.body.linkId == invite.linkId,
              pairingCanonicalUUID(identity.body.endpointId),
              identity.body.endpointId != controllerEndpointID,
              identity.body.role == "companion",
              let peerKey = Base64URL.decode32(identity.body.noiseKey),
              Enrollment.isContributoryX25519PublicKey(peerKey),
              identity.body.noiseFingerprint == (try? noiseFingerprint(identity.body.noiseKey)),
              (1...80).contains(identity.body.deviceLabel.unicodeScalars.count),
              validNames(identity.body.permissions),
              validNames(identity.body.capabilities),
              !identity.body.permissions.isEmpty,
              Set(identity.body.permissions).isSubset(of: Set(ControllerModel.operations)),
              Set(identity.body.permissions).isSubset(of: Set(identity.body.capabilities))
        else {
            throw PairingError.invalidMessage
        }
        return identity.body
    }

    private static func receiveOuter(_ socket: URLSessionWebSocketTask) async throws -> PairingRelayEnvelope {
        try Task.checkCancellation()
        switch try await socket.receive() {
        case let .string(text):
            guard let data = text.data(using: .utf8) else { throw PairingError.invalidMessage }
            return try PairingRelayEnvelope.parse(data)
        case .data:
            throw PairingError.invalidMessage
        @unknown default:
            throw PairingError.invalidMessage
        }
    }

    private static func sendPairFrame(
        _ frame: Data,
        sequence: Int64,
        pairID: String,
        socket: URLSessionWebSocketTask
    ) async throws {
        guard !frame.isEmpty, frame.count <= 16 * 1_024 else {
            throw PairingError.invalidMessage
        }
        try await sendOuter(
            type: "pair.frame",
            id: UUID().uuidString.lowercased(),
            body: [
                "pairId": pairID,
                "seq": sequence,
                "payload": Base64URL.encode(frame),
            ],
            socket: socket
        )
    }

    private static func sendOuter(
        type: String,
        id: String,
        body: [String: Any],
        socket: URLSessionWebSocketTask
    ) async throws {
        let envelope: [String: Any] = [
            "protocol": "remote-davinci.rendezvous",
            "v": 1,
            "type": type,
            "id": id,
            "body": body,
        ]
        let data = try JSONSerialization.data(
            withJSONObject: envelope,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard data.count <= 32 * 1_024,
              let text = String(data: data, encoding: .utf8)
        else {
            throw PairingError.invalidMessage
        }
        try await socket.send(.string(text))
    }

    private static func relayError(_ envelope: PairingRelayEnvelope) throws -> PairingError {
        guard let code = envelope.body["code"] as? String,
              allowedErrorCodes.contains(code),
              let retryable = pairingJSONBool(envelope.body["retryable"])
        else {
            throw PairingError.invalidMessage
        }
        return .relay(code: code, retryable: retryable)
    }

    private static func closedError(
        _ envelope: PairingRelayEnvelope,
        pairID: String
    ) throws -> PairingError {
        guard envelope.replyTo == nil,
              envelope.body["pairId"] as? String == pairID,
              let reason = envelope.body["reason"] as? String,
              ["cancelled", "expired", "peer-disconnected", "failed"].contains(reason)
        else {
            throw PairingError.invalidMessage
        }
        return .pairClosed(reason)
    }
}

func pairingNoisePrologue(
    relayURL: String,
    pairID: String,
    creatorSideID: String,
    joinerSideID: String,
    linkID: String,
    expiresAt: Int64
) -> Data {
    let value = "remote-davinci/pair-qr/v1\n\(relayURL)\n\(pairID)\n\(creatorSideID)\n" +
        "\(joinerSideID)\n\(linkID)\n\(expiresAt)"
    return Data(value.utf8)
}

private func noiseFingerprint(_ encodedKey: String) throws -> String {
    guard let key = Base64URL.decode32(encodedKey) else { throw PairingError.invalidMessage }
    return "sha256:" + Base64URL.encode(Data(SHA256.hash(data: key)))
}

private func validNames(_ values: [String]) -> Bool {
    values.count <= 64 && Set(values).count == values.count && values.allSatisfy { value in
        !value.isEmpty && value.count <= 128 && value.range(
            of: #"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"#,
            options: .regularExpression
        ) != nil
    }
}

private func pairingCanonicalUUID(_ value: String) -> Bool {
    UUID(uuidString: value)?.uuidString.lowercased() == value
}

private func pairingJSONInt64(_ value: Any?) -> Int64? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          number.doubleValue.rounded(.towardZero) == number.doubleValue,
          abs(number.doubleValue) <= 9_007_199_254_740_991
    else {
        return nil
    }
    return number.int64Value
}

private func pairingJSONBool(_ value: Any?) -> Bool? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) == CFBooleanGetTypeID()
    else {
        return nil
    }
    return number.boolValue
}
