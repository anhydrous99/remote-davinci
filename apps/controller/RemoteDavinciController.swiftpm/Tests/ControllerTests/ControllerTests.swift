import CryptoKit
import XCTest
@testable import ControllerCore

final class ControllerTests: XCTestCase {
    // flynn/noise vectors.txt: Noise_IK_25519_ChaChaPoly_SHA256, empty prologue/payloads.
    func testOfficialFlynnNoiseIKVector() throws {
        let initiatorStatic = try XCTUnwrap(Data(hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
        let responderStatic = try XCTUnwrap(Data(hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
        let initiatorEphemeral = try XCTUnwrap(Data(hex: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
        let responderPublic = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: responderStatic
        ).publicKey.rawRepresentation
        let initiator = try NoiseIKInitiator(
            staticPrivateKey: initiatorStatic,
            remoteStaticKey: responderPublic,
            prologue: Data(),
            ephemeralPrivateKey: initiatorEphemeral
        )

        XCTAssertEqual(
            try initiator.writeMessage1(),
            Data(hex:
                "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254" +
                "4f8445e5dc2467b1e32653192d05dee85c4781bf0dd8d33ceebb5905a7a069f0" +
                "9e0d3f2cad1c842930a762eb75e52827f01d2c85189d527644b3221b4c3fc5cc"
            )
        )

        try initiator.readMessage2(try XCTUnwrap(Data(hex:
            "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466" +
            "aabfe2e5b1650bbaa88e33679893fc77"
        )))
        XCTAssertEqual(
            try initiator.encryptTransport(Data("yellowsubmarine".utf8)),
            Data(hex: "226ca869f2777611f37350a7ab446f650c0cfe2855b7f020ce658bcf100f2d")
        )
        XCTAssertEqual(
            try initiator.decryptTransport(try XCTUnwrap(Data(hex:
                "90d84d69cd44829283b05d684879b53b8d714e51619b601438a1ae67caacd9"
            ))),
            Data("submarineyellow".utf8)
        )
    }

    func testOfficialFlynnNoiseNNpsk0Vector() throws {
        let initiator = try NoiseNNpsk0Initiator(
            psk: try XCTUnwrap(Data(hex:
                "2176657279736563726574766572797365637265747665727973656372657421"
            )),
            prologue: Data(),
            ephemeralPrivateKey: try XCTUnwrap(Data(hex:
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ))
        )

        XCTAssertEqual(
            try initiator.writeMessage1(),
            Data(hex:
                "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254" +
                    "e7136508cb8178281204abd62e9f2a3e"
            )
        )
        try initiator.readMessage2(try XCTUnwrap(Data(hex:
            "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466" +
                "922f3b7824001193c077abd8b7a73030"
        )))
        XCTAssertEqual(
            try initiator.encryptTransport(Data("yellowsubmarine".utf8)),
            Data(hex: "b349a522c145762c7c737ac1d1425ce1fb25c7cca626177ee4ceed3cd6fb3d")
        )
        XCTAssertEqual(
            try initiator.decryptTransport(try XCTUnwrap(Data(hex:
                "b41e24399dc3f1ad2faf82868700e4bf31bb89f6616e1d6a92802bb8ad80d6"
            ))),
            Data("submarineyellow".utf8)
        )
    }

    func testPairingInviteMatchesGoContractAndPrologue() throws {
        let relay = "wss://relay.example/v1"
        let object = pairingInviteObject(expiresAt: 301)
        let json = String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
        let invite = try PairingInvite.parse(json, expectedRelayURL: relay, now: 1)

        XCTAssertEqual(invite.protocolName, "remote-davinci.pairing-invite")
        XCTAssertEqual(invite.joinToken, Base64URL.encode(Data(repeating: 1, count: 32)))
        XCTAssertEqual(
            String(decoding: pairingNoisePrologue(
                relayURL: invite.relayUrl,
                pairID: invite.pairId,
                creatorSideID: invite.creatorSideId,
                joinerSideID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                linkID: invite.linkId,
                expiresAt: invite.expiresAt
            ), as: UTF8.self),
            "remote-davinci/pair-qr/v1\nwss://relay.example/v1\n" +
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n" +
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\n" +
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd\n" +
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc\n301"
        )
    }

    func testPairingInviteRejectsMalformedAndUnknownFields() throws {
        let relay = "wss://relay.example/v1"

        var unknown = pairingInviteObject(expiresAt: 300)
        unknown["future"] = true
        XCTAssertThrowsError(try parsePairingInvite(unknown, relay: relay)) { error in
            XCTAssertEqual(error as? PairingError, .invalidInvite)
        }

        var missing = pairingInviteObject(expiresAt: 300)
        missing.removeValue(forKey: "linkId")
        XCTAssertThrowsError(try parsePairingInvite(missing, relay: relay)) { error in
            XCTAssertEqual(error as? PairingError, .invalidInvite)
        }

        var unsupported = pairingInviteObject(expiresAt: 300)
        unsupported["v"] = 2
        XCTAssertThrowsError(try parsePairingInvite(unsupported, relay: relay)) { error in
            XCTAssertEqual(error as? PairingError, .invalidInvite)
        }

        var noncanonicalUUID = pairingInviteObject(expiresAt: 300)
        noncanonicalUUID["pairId"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
        XCTAssertThrowsError(try parsePairingInvite(noncanonicalUUID, relay: relay)) { error in
            XCTAssertEqual(error as? PairingError, .invalidInvite)
        }

        var noncanonicalSecret = pairingInviteObject(expiresAt: 300)
        noncanonicalSecret["psk"] = Base64URL.encode(Data(repeating: 2, count: 32)) + "="
        XCTAssertThrowsError(try parsePairingInvite(noncanonicalSecret, relay: relay)) { error in
            XCTAssertEqual(error as? PairingError, .invalidInvite)
        }

        var reusedSecret = pairingInviteObject(expiresAt: 300)
        reusedSecret["psk"] = reusedSecret["joinToken"]
        XCTAssertThrowsError(try parsePairingInvite(reusedSecret, relay: relay)) { error in
            XCTAssertEqual(error as? PairingError, .invalidInvite)
        }
    }

    func testPairingInvitePinsRelayAndAllowsBoundedClockLag() throws {
        let relay = "wss://relay.example/v1"
        XCTAssertNoThrow(try parsePairingInvite(
            pairingInviteObject(expiresAt: 301),
            relay: relay,
            now: 1
        ))

        XCTAssertThrowsError(try parsePairingInvite(
            pairingInviteObject(expiresAt: 1),
            relay: relay,
            now: 1
        )) { error in
            XCTAssertEqual(error as? PairingError, .expiredInvite)
        }
        XCTAssertNoThrow(try parsePairingInvite(
            pairingInviteObject(expiresAt: 361),
            relay: relay,
            now: 1
        ))
        XCTAssertThrowsError(try parsePairingInvite(
            pairingInviteObject(expiresAt: 362),
            relay: relay,
            now: 1
        )) { error in
            XCTAssertEqual(error as? PairingError, .expiredInvite)
        }

        XCTAssertThrowsError(try parsePairingInvite(
            pairingInviteObject(expiresAt: 300),
            relay: "wss://other.example/v1"
        )) { error in
            XCTAssertEqual(error as? PairingError, .mismatchedRelay)
        }

        var insecure = pairingInviteObject(expiresAt: 300)
        insecure["relayUrl"] = "https://relay.example/v1"
        XCTAssertThrowsError(try parsePairingInvite(insecure, relay: relay)) { error in
            XCTAssertEqual(error as? PairingError, .invalidInvite)
        }
    }

    func testPairingCheckpointDeletesOnlyDefinitiveCommitFailures() {
        XCTAssertEqual(
            pairingCheckpointDisposition(commitStarted: false, error: PairingError.invalidMessage),
            .delete,
            "A locally staged identity is disposable before commit begins"
        )
        XCTAssertEqual(
            pairingCheckpointDisposition(
                commitStarted: true,
                error: PairingError.pairClosed("failed")
            ),
            .delete
        )
        XCTAssertEqual(
            pairingCheckpointDisposition(
                commitStarted: true,
                error: PairingError.relay(code: "FORBIDDEN", retryable: false)
            ),
            .delete
        )
        XCTAssertEqual(
            pairingCheckpointDisposition(
                commitStarted: true,
                error: PairingError.relay(code: "INTERNAL", retryable: true)
            ),
            .retain
        )
        XCTAssertEqual(
            pairingCheckpointDisposition(commitStarted: true, error: PairingError.invalidMessage),
            .retain,
            "Malformed or uncorrelated replies cannot prove that activation lost"
        )
        XCTAssertEqual(
            pairingCheckpointDisposition(
                commitStarted: true,
                error: URLError(.networkConnectionLost)
            ),
            .retain
        )
    }

    func testEnrollmentRequestUsesExactFiveFieldV1WireAndPinsDeploymentRelay() throws {
        let customRelay = "wss://relay.example/v1"
        let (request, stored) = try Enrollment.create(
            deviceLabel: "Test iPad",
            relayURL: customRelay
        )
        XCTAssertEqual(stored.expectedRelayUrl, customRelay)
        XCTAssertEqual(try Enrollment.request(for: stored), request)

        let object = try XCTUnwrap(JSONSerialization.jsonObject(
            with: JSONEncoder().encode(request)
        ) as? [String: Any])
        XCTAssertEqual(
            object.keys.sorted(),
            [
                "controllerCredentialHash",
                "controllerEndpointId",
                "controllerNoiseKey",
                "deviceLabel",
                "v",
            ]
        )
    }

    func testDeploymentRelayValidationAndReplacementPreserveOverride() throws {
        let customRelay = "wss://relay.example/custom"
        XCTAssertEqual(try Enrollment.deploymentRelayURL(nil), Enrollment.defaultRelayURL)
        XCTAssertEqual(try Enrollment.deploymentRelayURL(customRelay), customRelay)
        for invalid in [
            "https://relay.example/v1",
            "wss://user@relay.example/v1",
            "wss://relay.example/v1?token=secret",
            "wss://relay.example/v1#fragment",
            "wss:///v1",
        ] {
            XCTAssertThrowsError(try Enrollment.deploymentRelayURL(invalid)) { error in
                XCTAssertEqual(error as? EnrollmentError, .invalidRelay)
            }
            XCTAssertThrowsError(try Enrollment.create(deviceLabel: "Test iPad", relayURL: invalid))
        }

        let (request, stored) = try ControllerModel.replacementEnrollment(
            deviceLabel: "Replacement iPad",
            relayURL: customRelay
        )
        XCTAssertEqual(stored.expectedRelayUrl, customRelay)
        XCTAssertEqual(try Enrollment.request(for: stored), request)
    }

    @MainActor
    func testInvalidDeploymentOverrideFailsClosedWithoutClaimingLocalEnrollment() {
        let model = ControllerModel(relayURL: "https://relay.example/v1")
        XCTAssertFalse(model.hasLocalEnrollment)
        XCTAssertFalse(model.isEnrolled)
        XCTAssertTrue(model.enrollmentRequestJSON.isEmpty)
        XCTAssertEqual(model.enrollmentStatus, EnrollmentError.invalidRelay.localizedDescription)
    }

    @MainActor
    func testCheckpointReadFailureBlocksUntilSavedEnrollmentIsReadable() throws {
        let (_, savedRequest) = try Enrollment.create(
            deviceLabel: "Saved iPad",
            relayURL: "wss://saved-relay.example/v1"
        )
        var readableCheckpoint: StoredEnrollment?
        let model = ControllerModel(
            relayURL: "wss://relay.example/v1",
            keychainLoad: { readableCheckpoint }
        )
        XCTAssertTrue(model.canStartPairing)

        XCTAssertFalse(model.adoptPairingCheckpointIfPresent(
            fallbackStatus: "Pairing failed",
            load: { throw KeychainError.status(-25_308) }
        ))

        XCTAssertTrue(model.hasLocalEnrollment)
        XCTAssertFalse(model.canStartPairing)
        XCTAssertTrue(model.enrollmentStatus.contains("could not be read"))

        model.pair(inviteJSON: "{}")
        XCTAssertFalse(model.isPairing)
        XCTAssertEqual(
            model.enrollmentStatus,
            "Resolve the current enrollment or pairing attempt first."
        )

        readableCheckpoint = savedRequest
        model.refreshCredentialStoreIfNeeded()
        XCTAssertTrue(model.hasLocalEnrollment)
        XCTAssertEqual(model.enrollmentStatus, "Request ready")
        XCTAssertEqual(
            try JSONDecoder().decode(
                EnrollmentRequest.self,
                from: Data(model.enrollmentRequestJSON.utf8)
            ),
            try Enrollment.request(for: savedRequest)
        )
        XCTAssertTrue(model.canStartPairing, "A readable unfinished request may be replaced")
    }

    func testPendingActivationReconnectIsBoundedByPersistedExpiry() {
        XCTAssertEqual(
            ControllerModel.pendingActivationReconnectDelay(
                proposedDelay: 30,
                expiresAt: 120,
                now: 100
            ),
            20
        )
        XCTAssertNil(ControllerModel.pendingActivationReconnectDelay(
            proposedDelay: 1,
            expiresAt: 100,
            now: 100
        ))
        XCTAssertNil(ControllerModel.pendingActivationReconnectDelay(
            proposedDelay: 1,
            expiresAt: nil,
            now: 100
        ))
    }

    func testEnrollmentResponseValidation() throws {
        let controllerID = "11111111-1111-4111-8111-111111111111"
        let controllerPrivate = Data(0..<32)
        let companionPrivate = Data(1...32)
        let companionPublic = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: companionPrivate
        ).publicKey.rawRepresentation
        let pending = StoredEnrollment(
            controllerEndpointId: controllerID,
            controllerSecret: Base64URL.encode(Data(repeating: 7, count: 32)),
            controllerNoisePrivateKey: Base64URL.encode(controllerPrivate),
            deviceLabel: "Test iPad",
            expectedRelayUrl: "wss://example.execute-api.us-east-1.amazonaws.com/v1",
            response: nil
        )
        let response = EnrollmentResponse(
            v: 1,
            relayUrl: "wss://example.execute-api.us-east-1.amazonaws.com/v1",
            linkId: "22222222-2222-4222-8222-222222222222",
            controllerEndpointId: controllerID,
            companionEndpointId: "33333333-3333-4333-8333-333333333333",
            companionNoiseKey: Base64URL.encode(companionPublic)
        )
        let responseJSON = String(
            decoding: try JSONEncoder().encode(response),
            as: UTF8.self
        )

        XCTAssertEqual(try Enrollment.importResponse(responseJSON, into: pending).response, response)

        var legacy = pending
        legacy.expectedRelayUrl = nil
        legacy.response = response
        let migrated = try Enrollment.migrateLegacy(
            legacy,
            deploymentRelayURL: Enrollment.defaultRelayURL
        )
        XCTAssertEqual(migrated.expectedRelayUrl, response.relayUrl)
        XCTAssertEqual(try Enrollment.active(from: migrated).relayURL.absoluteString, response.relayUrl)
        var activationPending = migrated
        activationPending.activationPending = true
        activationPending.grantedPermissions = ["resolve.page.edit"]
        activationPending.pairingExpiresAt = 300
        XCTAssertEqual(
            try Enrollment.active(from: activationPending).linkID,
            response.linkId,
            "Pending credentials remain usable only to reconcile an uncertain commit"
        )
        XCTAssertEqual(
            try JSONDecoder().decode(
                StoredEnrollment.self,
                from: JSONEncoder().encode(activationPending)
            ),
            activationPending
        )
        let effectiveRelay = try Enrollment.replacementRelayURL(
            stored: migrated,
            deploymentRelayURL: Enrollment.defaultRelayURL
        )
        XCTAssertEqual(effectiveRelay, response.relayUrl)
        XCTAssertEqual(
            try ControllerModel.replacementEnrollment(
                deviceLabel: "Replacement iPad",
                relayURL: effectiveRelay
            ).1.expectedRelayUrl,
            response.relayUrl
        )

        XCTAssertEqual(
            try Enrollment.migrateLegacy(
                pending,
                deploymentRelayURL: "wss://ignored.example/v1"
            ),
            pending
        )
        XCTAssertEqual(
            try Enrollment.replacementRelayURL(
                stored: pending,
                deploymentRelayURL: Enrollment.defaultRelayURL
            ),
            pending.expectedRelayUrl
        )

        let wrongController = EnrollmentResponse(
            v: response.v,
            relayUrl: response.relayUrl,
            linkId: response.linkId,
            controllerEndpointId: "44444444-4444-4444-8444-444444444444",
            companionEndpointId: response.companionEndpointId,
            companionNoiseKey: response.companionNoiseKey
        )
        let wrongJSON = String(
            decoding: try JSONEncoder().encode(wrongController),
            as: UTF8.self
        )
        XCTAssertThrowsError(try Enrollment.importResponse(wrongJSON, into: pending)) { error in
            XCTAssertEqual(error as? EnrollmentError, .mismatchedController)
        }
        let wrongRelay = EnrollmentResponse(
            v: response.v,
            relayUrl: "wss://different.example/v1",
            linkId: response.linkId,
            controllerEndpointId: response.controllerEndpointId,
            companionEndpointId: response.companionEndpointId,
            companionNoiseKey: response.companionNoiseKey
        )
        XCTAssertThrowsError(try Enrollment.importResponse(
            String(decoding: try JSONEncoder().encode(wrongRelay), as: UTF8.self),
            into: pending
        )) { error in
            XCTAssertEqual(error as? EnrollmentError, .mismatchedRelay)
        }
        let insecureResponse = EnrollmentResponse(
            v: response.v,
            relayUrl: "https://example.execute-api.us-east-1.amazonaws.com/v1",
            linkId: response.linkId,
            controllerEndpointId: response.controllerEndpointId,
            companionEndpointId: response.companionEndpointId,
            companionNoiseKey: response.companionNoiseKey
        )
        XCTAssertThrowsError(try Enrollment.importResponse(
            String(decoding: try JSONEncoder().encode(insecureResponse), as: UTF8.self),
            into: pending
        ))

        let lowOrderResponse = EnrollmentResponse(
            v: response.v,
            relayUrl: response.relayUrl,
            linkId: response.linkId,
            controllerEndpointId: response.controllerEndpointId,
            companionEndpointId: response.companionEndpointId,
            companionNoiseKey: Base64URL.encode(Data(repeating: 0, count: 32))
        )
        XCTAssertThrowsError(try Enrollment.importResponse(
            String(decoding: try JSONEncoder().encode(lowOrderResponse), as: UTF8.self),
            into: pending
        ))
        var orderOne = Data(repeating: 0, count: 32)
        orderOne[0] = 1
        XCTAssertFalse(Enrollment.isContributoryX25519PublicKey(orderOne))
    }

    func testLifecycleTimingBounds() {
        XCTAssertEqual(RelayLifecycle.reconnectDelaySeconds(attempt: 0, randomUnit: 0), 0)
        XCTAssertEqual(RelayLifecycle.reconnectDelaySeconds(attempt: 0, randomUnit: 1), 1)
        XCTAssertEqual(RelayLifecycle.reconnectDelaySeconds(attempt: 10, randomUnit: 1), 900)
        XCTAssertEqual(RelayLifecycle.reconnectDelaySeconds(attempt: 100, randomUnit: 1), 900)
        XCTAssertEqual(RelayLifecycle.rotationDelaySeconds(randomUnit: 0), 5_400)
        XCTAssertEqual(RelayLifecycle.rotationDelaySeconds(randomUnit: 1), 6_600)
        XCTAssertEqual(RelayLifecycle.sessionSetupTimeoutSeconds, 15)
        XCTAssertEqual(RelayLifecycle.remainingMilliseconds(expiresAt: 6_000, now: 1_000), 5_000)
        XCTAssertEqual(RelayLifecycle.remainingMilliseconds(expiresAt: 1_000, now: 6_000), 0)
        XCTAssertEqual(
            RelayLifecycle.recoveryDisposition(code: "PEER_OFFLINE", retryable: true),
            .reconnect
        )
        XCTAssertEqual(
            RelayLifecycle.recoveryDisposition(code: "PEER_OFFLINE", retryable: false),
            .stop
        )
        XCTAssertEqual(
            RelayLifecycle.recoveryDisposition(code: "SESSION_NOT_FOUND", retryable: false),
            .reconnect
        )
    }

    func testOnlyAuthorizationHandshakeResponsesAreTerminal() throws {
        let url = try XCTUnwrap(URL(string: "wss://relay.example/v1"))
        let generic = NSError(domain: NSURLErrorDomain, code: NSURLErrorCannotConnectToHost)
        let unauthorized = try XCTUnwrap(HTTPURLResponse(
            url: url,
            statusCode: 401,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        ))
        let forbidden = try XCTUnwrap(HTTPURLResponse(
            url: url,
            statusCode: 403,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        ))
        let serverError = try XCTUnwrap(HTTPURLResponse(
            url: url,
            statusCode: 500,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        ))

        XCTAssertEqual(
            RelayLifecycle.terminalHandshakeAuthorizationStatus(
                error: generic,
                response: unauthorized
            ),
            401
        )
        XCTAssertEqual(
            RelayLifecycle.terminalHandshakeAuthorizationStatus(
                error: NSError(
                    domain: NSURLErrorDomain,
                    code: NSURLErrorBadServerResponse,
                    userInfo: ["failingResponse": forbidden]
                ),
                response: nil
            ),
            403
        )
        XCTAssertNil(RelayLifecycle.terminalHandshakeAuthorizationStatus(
            error: generic,
            response: serverError
        ))
        XCTAssertNil(RelayLifecycle.terminalHandshakeAuthorizationStatus(
            error: generic,
            response: nil
        ))
    }

    func testSessionCloseCorrelationIgnoresStaleSession() throws {
        let oldSessionID = "11111111-1111-4111-8111-111111111111"
        let currentSessionID = "22222222-2222-4222-8222-222222222222"
        let data = Data("""
        {"protocol":"remote-davinci.rendezvous","v":1,"type":"session.closed",
        "id":"33333333-3333-4333-8333-333333333333",
        "body":{"sessionId":"\(oldSessionID)","reason":"peer-disconnected"}}
        """.utf8)
        let envelope = try XCTUnwrap(RendezvousEnvelope(data, allowedTypes: ["session.closed"]))

        XCTAssertFalse(try RelayLifecycle.isCurrentSessionClose(
            envelope,
            currentSessionID: currentSessionID
        ))
        XCTAssertTrue(try RelayLifecycle.isCurrentSessionClose(
            envelope,
            currentSessionID: oldSessionID
        ))
        XCTAssertFalse(RelayLifecycle.isCurrentSessionFrame(
            receivedSessionID: oldSessionID,
            currentSessionID: nil
        ))
        XCTAssertFalse(RelayLifecycle.isCurrentSessionFrame(
            receivedSessionID: oldSessionID,
            currentSessionID: currentSessionID
        ))
        XCTAssertTrue(RelayLifecycle.isCurrentSessionFrame(
            receivedSessionID: oldSessionID,
            currentSessionID: oldSessionID
        ))
    }

    func testLateResponseWindowIsBounded() {
        var window = LateResponseWindow()
        for id in 0...LateResponseWindow.maximumCount {
            window.remember(String(id))
        }
        XCTAssertFalse(window.contains("0"))
        XCTAssertTrue(window.contains(String(LateResponseWindow.maximumCount)))
    }

    func testResolvePageOperationsAreFixed() {
        XCTAssertEqual(
            ResolvePage.allCases.map(\.operation),
            [
                "resolve.page.media",
                "resolve.page.cut",
                "resolve.page.edit",
                "resolve.page.fusion",
                "resolve.page.color",
                "resolve.page.fairlight",
                "resolve.page.deliver",
            ]
        )
        XCTAssertEqual(ResolvePage(operation: "resolve.page.media"), .media)
        XCTAssertEqual(ResolvePage(operation: "resolve.page.deliver"), .deliver)
        XCTAssertNil(ResolvePage(operation: "resolve.page.photo"))
        XCTAssertNil(ResolvePage(operation: "host.volume.toggle-mute"))
    }

    func testPendingPageOverridesConfirmedPageUntilCleared() {
        XCTAssertEqual(
            ResolvePageControl.displayedPage(selected: .edit, pending: .color),
            .color
        )
        XCTAssertEqual(
            ResolvePageControl.displayedPage(selected: .fusion, pending: nil),
            .fusion
        )
    }

    func testResolvePageResponseRequiresMatchingReadback() throws {
        XCTAssertEqual(
            try ResolvePageControl.response(
                operation: "resolve.page.color",
                result: ["page": "color"]
            ),
            .page(.color)
        )
        XCTAssertEqual(
            try ResolvePageControl.response(
                operation: "host.volume.toggle-mute",
                result: ["muted": true]
            ),
            .muted(true)
        )
        XCTAssertThrowsError(try ResolvePageControl.response(
            operation: "resolve.page.color",
            result: ["page": "edit"]
        )) { error in
            XCTAssertEqual(error as? ControllerProtocolError, .invalidMessage)
        }
        XCTAssertThrowsError(try ResolvePageControl.response(
            operation: "resolve.page.color",
            result: [:]
        ))
        XCTAssertThrowsError(try ResolvePageControl.response(
            operation: "host.volume.toggle-mute",
            result: [:]
        ))
        XCTAssertThrowsError(try ResolvePageControl.response(
            operation: "host.volume.toggle-mute",
            result: ["muted": "yes"]
        ))
    }

    func testResolvePageEventParsesKnownAndIgnoresUnknown() throws {
        XCTAssertEqual(
            try ResolvePageControl.eventPage(body: [
                "name": "resolve.page.changed",
                "data": ["page": "fairlight"],
            ]),
            .fairlight
        )
        XCTAssertNil(try ResolvePageControl.eventPage(body: [
            "name": "resolve.transport.changed",
            "data": ["playing": true],
        ]))
        XCTAssertThrowsError(try ResolvePageControl.eventPage(body: [
            "name": "resolve.page.changed",
            "data": ["page": "photo"],
        ])) { error in
            XCTAssertEqual(error as? ControllerProtocolError, .invalidMessage)
        }
        XCTAssertThrowsError(try ResolvePageControl.eventPage(body: [
            "name": "resolve.page.changed",
            "data": [:],
        ]))
    }

    func testStoredEnrollmentDecodesWithoutRevocationCheckpoint() throws {
        let json = """
        {
          "controllerEndpointId":"11111111-1111-4111-8111-111111111111",
          "controllerSecret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "controllerNoisePrivateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "deviceLabel":"Old \\u202einstall",
          "companionNoiseFingerprint":"obsolete",
          "pairingProtocol":"obsolete",
          "response":null
        }
        """
        var stored = try JSONDecoder().decode(
            StoredEnrollment.self,
            from: Data(json.utf8)
        )
        XCTAssertNil(stored.linkRevocationConfirmed)
        XCTAssertNil(stored.expectedRelayUrl)
        XCTAssertNil(stored.activationPending)
        XCTAssertNil(stored.grantedPermissions)
        stored = try Enrollment.migrateLegacy(
            stored,
            deploymentRelayURL: "wss://self-hosted.example/v1"
        )
        XCTAssertEqual(stored.expectedRelayUrl, "wss://self-hosted.example/v1")
        XCTAssertEqual(try Enrollment.request(for: stored).deviceLabel, "Legacy device")
        stored.linkRevocationConfirmed = true
        XCTAssertEqual(
            try JSONDecoder().decode(
                StoredEnrollment.self,
                from: JSONEncoder().encode(stored)
            ).linkRevocationConfirmed,
            true
        )
    }

    func testInvalidActiveLegacyMigrationDoesNotProduceMutatedRecord() throws {
        let (_, pending) = try Enrollment.create(
            deviceLabel: "Legacy iPad",
            relayURL: "wss://old.example/v1"
        )
        let companionPrivate = Curve25519.KeyAgreement.PrivateKey()
        let invalidResponse = EnrollmentResponse(
            v: 1,
            relayUrl: "https://attacker.example/v1",
            linkId: "22222222-2222-4222-8222-222222222222",
            controllerEndpointId: pending.controllerEndpointId,
            companionEndpointId: "33333333-3333-4333-8333-333333333333",
            companionNoiseKey: Base64URL.encode(companionPrivate.publicKey.rawRepresentation)
        )
        var legacy = pending
        legacy.expectedRelayUrl = nil
        legacy.response = invalidResponse
        let original = legacy

        XCTAssertThrowsError(try Enrollment.migrateLegacy(
            legacy,
            deploymentRelayURL: Enrollment.defaultRelayURL
        )) { error in
            XCTAssertEqual(error as? EnrollmentError, .invalidResponse)
        }
        XCTAssertEqual(legacy, original)
    }

    func testRelayFramesBufferBoundedReorderingAndRejectDuplicates() throws {
        var buffer = RelayFrameBuffer()
        let first = Data([1])
        let second = Data([2])

        XCTAssertEqual(try buffer.insert(sequence: 2, frame: second), [])
        XCTAssertEqual(try buffer.insert(sequence: 1, frame: first), [first, second])
        XCTAssertEqual(buffer.nextSequence, 3)
        XCTAssertThrowsError(try buffer.insert(sequence: 2, frame: second)) { error in
            XCTAssertEqual(error as? ControllerProtocolError, .invalidSequence)
        }
        XCTAssertThrowsError(try buffer.insert(
            sequence: buffer.nextSequence + RelayFrameBuffer.maximumGap + 1,
            frame: Data([3])
        )) { error in
            XCTAssertEqual(error as? ControllerProtocolError, .invalidSequence)
        }

        var memoryBounded = RelayFrameBuffer()
        for sequence in 2...9 {
            XCTAssertEqual(
                try memoryBounded.insert(sequence: Int64(sequence), frame: Data(count: 16 * 1_024)),
                []
            )
        }
        XCTAssertThrowsError(try memoryBounded.insert(
            sequence: 10,
            frame: Data(count: 16 * 1_024)
        ))
    }

    func testLifecycleRequiresCorrelatedRevocationConfirmation() throws {
        let requestID = "11111111-1111-4111-8111-111111111111"
        let responseID = "22222222-2222-4222-8222-222222222222"
        let success: [String: Any] = [
            "protocol": "remote-davinci.rendezvous",
            "v": 1,
            "type": "ok",
            "id": responseID,
            "replyTo": requestID,
            "body": [
                "requestType": "link.revoke",
                "result": ["revoked": true],
            ],
        ]
        XCTAssertEqual(
            try RelayLifecycle.parseResponse(
                JSONSerialization.data(withJSONObject: success),
                requestID: requestID,
                requestType: "link.revoke"
            ),
            .success
        )

        var uncorrelated = success
        uncorrelated["replyTo"] = "33333333-3333-4333-8333-333333333333"
        XCTAssertThrowsError(try RelayLifecycle.parseResponse(
            JSONSerialization.data(withJSONObject: uncorrelated),
            requestID: requestID,
            requestType: "link.revoke"
        ))

        var unconfirmed = success
        unconfirmed["body"] = [
            "requestType": "link.revoke",
            "result": ["revoked": false],
        ]
        XCTAssertThrowsError(try RelayLifecycle.parseResponse(
            JSONSerialization.data(withJSONObject: unconfirmed),
            requestID: requestID,
            requestType: "link.revoke"
        ))

        let failure: [String: Any] = [
            "protocol": "remote-davinci.rendezvous",
            "v": 1,
            "type": "error",
            "id": responseID,
            "replyTo": requestID,
            "body": ["code": "CONFLICT", "retryable": true, "retryAfterMs": 100],
        ]
        XCTAssertEqual(
            try RelayLifecycle.parseResponse(
                JSONSerialization.data(withJSONObject: failure),
                requestID: requestID,
                requestType: "link.revoke"
            ),
            .failure(code: "CONFLICT", retryable: true)
        )
    }

    func testProtocolJSONRequiresExactSafeIntegers() throws {
        let validIntegers: [(String, Int64)] = [
            ("1", 1), ("1.0", 1), ("1e0", 1), ("1.2e1", 12), ("100e-2", 1),
            ("1.0000000000000000000000000000000000000000", 1),
            ("900719925474099100e-2", 9_007_199_254_740_991),
        ]
        for (spelling, expected) in validIntegers {
            let object = try XCTUnwrap(ProtocolJSON.object(Data("{\"n\":\(spelling)}".utf8)))
            XCTAssertEqual(jsonInt64(object["n"]), expected, spelling)
        }
        for spelling in [
            "1.0000000000000001", "1.0000000000000000000000000000000000000001",
            "9007199254740990.0000000000000000000000001", "9007199254740990.5",
            "9007199254740992", "true",
        ] {
            let object = try XCTUnwrap(ProtocolJSON.object(Data("{\"n\":\(spelling)}".utf8)))
            XCTAssertNil(jsonInt64(object["n"]), spelling)
        }
        XCTAssertNil(ProtocolJSON.object(Data("{\"n\":1} trailing".utf8)))

        func additiveEnvelope(_ number: String) -> Data {
            Data("""
            {"protocol":"remote-davinci.rendezvous","v":1,"type":"session.closed",
            "id":"11111111-1111-4111-8111-111111111111",
            "body":{"sessionId":"22222222-2222-4222-8222-222222222222","reason":"expired",
            "futureNumber":\(number)}}
            """.utf8)
        }
        for boundary in [String(repeating: "9", count: 128), "1e4096", "1e-4096"] {
            XCTAssertNotNil(
                RendezvousEnvelope(additiveEnvelope(boundary), allowedTypes: ["session.closed"]),
                boundary
            )
        }
        for excessive in [String(repeating: "9", count: 129), "1e4097", "1e-4097"] {
            XCTAssertNil(
                RendezvousEnvelope(additiveEnvelope(excessive), allowedTypes: ["session.closed"]),
                excessive
            )
        }
        for malformed in ["1e", "1e+", "1.", "01", "--1", "+1"] {
            XCTAssertNil(ProtocolJSON.object(Data("{\"n\":\(malformed)}".utf8)), malformed)
        }
    }

    func testPairingInviteRejectsFractionalWireIntegersThatFoundationRounds() throws {
        let data = try JSONSerialization.data(withJSONObject: pairingInviteObject(expiresAt: 300))
        let json = String(decoding: data, as: UTF8.self)
        XCTAssertThrowsError(try PairingInvite.parse(
            json.replacingOccurrences(of: "\"v\":1", with: "\"v\":1.0000000000000001"),
            expectedRelayURL: "wss://relay.example/v1",
            now: 1
        ))
        XCTAssertThrowsError(try PairingInvite.parse(
            json.replacingOccurrences(of: "\"expiresAt\":300", with: "\"expiresAt\":300.5"),
            expectedRelayURL: "wss://relay.example/v1",
            now: 1
        ))
    }

    func testRendezvousEnvelopeFailsClosed() throws {
        let valid = """
        {"protocol":"remote-davinci.rendezvous","v":1,"type":"session.closed",
        "id":"11111111-1111-4111-8111-111111111111",
        "body":{"sessionId":"22222222-2222-4222-8222-222222222222","reason":"expired"}}
        """
        XCTAssertNotNil(RendezvousEnvelope(Data(valid.utf8), allowedTypes: ["session.closed"]))
        XCTAssertNil(RendezvousEnvelope(
            Data(valid.replacingOccurrences(of: "\"v\":1", with: "\"v\":1.0000000000000001").utf8),
            allowedTypes: ["session.closed"]
        ))
        XCTAssertNil(RendezvousEnvelope(
            Data(valid.replacingOccurrences(of: "\"session.closed\"", with: "\"future.event\"").utf8),
            allowedTypes: ["session.closed"]
        ))
        XCTAssertNil(RendezvousEnvelope(
            Data(valid.replacingOccurrences(
                of: "\"body\":",
                with: "\"replyTo\":\"33333333-3333-4333-8333-333333333333\",\"body\":"
            ).utf8),
            allowedTypes: ["session.closed"]
        ))
    }

    func testDeviceLabelsRejectInvisibleAndControlCharacters() throws {
        XCTAssertNoThrow(try Enrollment.create(deviceLabel: "Jules’s iPad 🚀", relayURL: "wss://relay.example/v1"))
        for label in ["line\nbreak", "right\u{202E}to-left", "zero\u{200B}width"] {
            XCTAssertThrowsError(try Enrollment.create(
                deviceLabel: label,
                relayURL: "wss://relay.example/v1"
            )) { error in
                XCTAssertEqual(error as? EnrollmentError, .invalidDeviceLabel)
            }
        }
    }

    func testPairingFingerprintProgressAndBundleVersionFallback() {
        let fingerprint = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        XCTAssertEqual(PairingProgress.waitingForApproval(fingerprint: fingerprint).fingerprint, fingerprint)
        XCTAssertEqual(
            PairingProgress.waitingForApproval(fingerprint: fingerprint).status,
            "Waiting for approval on Mac"
        )
        XCTAssertEqual(ControllerModel.appVersion("1.2.3"), "1.2.3")
        XCTAssertEqual(ControllerModel.appVersion(""), "unknown")
        XCTAssertEqual(ControllerModel.appVersion(nil), "unknown")
    }
}

private func pairingInviteObject(expiresAt: Int64) -> [String: Any] {
    [
        "protocol": "remote-davinci.pairing-invite",
        "v": 1,
        "relayUrl": "wss://relay.example/v1",
        "pairId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "creatorSideId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "linkId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "joinToken": Base64URL.encode(Data(repeating: 1, count: 32)),
        "psk": Base64URL.encode(Data(repeating: 2, count: 32)),
        "expiresAt": expiresAt,
    ]
}

private func parsePairingInvite(
    _ object: [String: Any],
    relay: String,
    now: Int64 = 1
) throws -> PairingInvite {
    let data = try JSONSerialization.data(withJSONObject: object)
    return try PairingInvite.parse(String(decoding: data, as: UTF8.self), expectedRelayURL: relay, now: now)
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
