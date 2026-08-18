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
        XCTAssertTrue(RelayLifecycle.shouldReconnect(code: "PEER_OFFLINE", retryable: true))
        XCTAssertFalse(RelayLifecycle.shouldReconnect(code: "PEER_OFFLINE", retryable: false))
        XCTAssertFalse(RelayLifecycle.shouldReconnect(code: "UNAUTHENTICATED", retryable: true))
        XCTAssertFalse(RelayLifecycle.shouldReconnect(code: "FORBIDDEN", retryable: true))
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
        let envelope: [String: Any] = [
            "id": "33333333-3333-4333-8333-333333333333",
        ]
        let body: [String: Any] = [
            "sessionId": oldSessionID,
            "reason": "peer-disconnected",
        ]

        XCTAssertFalse(try RelayLifecycle.isCurrentSessionClose(
            envelope: envelope,
            body: body,
            currentSessionID: currentSessionID
        ))
        XCTAssertTrue(try RelayLifecycle.isCurrentSessionClose(
            envelope: envelope,
            body: body,
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
                "resolve.page.cut",
                "resolve.page.edit",
                "resolve.page.fusion",
                "resolve.page.color",
            ]
        )
        XCTAssertEqual(ResolvePage(operation: "resolve.page.cut"), .cut)
        XCTAssertNil(ResolvePage(operation: "resolve.page.media"))
        XCTAssertNil(ResolvePage(operation: "host.volume.toggle-mute"))
    }

    func testResolvePageResponseRequiresMatchingReadback() throws {
        XCTAssertEqual(
            try ResolvePageControl.responsePage(
                operation: "resolve.page.color",
                result: ["page": "color"]
            ),
            .color
        )
        XCTAssertNil(try ResolvePageControl.responsePage(
            operation: "host.volume.toggle-mute",
            result: ["muted": true]
        ))
        XCTAssertThrowsError(try ResolvePageControl.responsePage(
            operation: "resolve.page.color",
            result: ["page": "edit"]
        )) { error in
            XCTAssertEqual(error as? ControllerProtocolError, .invalidMessage)
        }
        XCTAssertThrowsError(try ResolvePageControl.responsePage(
            operation: "resolve.page.color",
            result: [:]
        ))
    }

    func testResolvePageEventParsesKnownAndIgnoresUnknown() throws {
        XCTAssertEqual(
            try ResolvePageControl.eventPage(body: [
                "name": "resolve.page.changed",
                "data": ["page": "fusion"],
            ]),
            .fusion
        )
        XCTAssertNil(try ResolvePageControl.eventPage(body: [
            "name": "resolve.transport.changed",
            "data": ["playing": true],
        ]))
        XCTAssertThrowsError(try ResolvePageControl.eventPage(body: [
            "name": "resolve.page.changed",
            "data": ["page": "media"],
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
          "deviceLabel":"Old install",
          "response":null
        }
        """
        var stored = try JSONDecoder().decode(
            StoredEnrollment.self,
            from: Data(json.utf8)
        )
        XCTAssertNil(stored.linkRevocationConfirmed)
        stored.linkRevocationConfirmed = true
        XCTAssertEqual(
            try JSONDecoder().decode(
                StoredEnrollment.self,
                from: JSONEncoder().encode(stored)
            ).linkRevocationConfirmed,
            true
        )
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
