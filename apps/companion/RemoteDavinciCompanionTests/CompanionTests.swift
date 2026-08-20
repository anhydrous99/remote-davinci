import Foundation
import XCTest
@testable import RemoteDavinciCompanion

final class CompanionTests: XCTestCase {
    private let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    func testHelperLaunchArgumentsPassConfiguredRelayOverride() throws {
        let relayURL = "wss://relay.example/v1"

        XCTAssertEqual(
            try CompanionLaunchArguments.make(environment: [
                CompanionLaunchArguments.relayEnvironmentKey: relayURL,
            ]),
            ["-native", "-relay", relayURL]
        )
        XCTAssertEqual(try CompanionLaunchArguments.make(environment: [:]), ["-native"])
    }

    @MainActor
    func testInvalidRelayOverrideFailsBeforeHelperLaunch() {
        let invalidRelayURLs = [
            "https://relay.example/v1",
            "wss://user@relay.example/v1",
            "wss://relay.example/v1?token=secret",
            "wss://relay.example/v1#fragment",
            "wss:///v1",
        ]

        for relayURL in invalidRelayURLs {
            let environment = [CompanionLaunchArguments.relayEnvironmentKey: relayURL]
            XCTAssertThrowsError(try CompanionLaunchArguments.make(environment: environment))
        }

        let host = CompanionHost(environment: [
            CompanionLaunchArguments.relayEnvironmentKey: invalidRelayURLs[0],
        ])
        var snapshot: CompanionHostSnapshot?
        host.onChange = { snapshot = $0 }
        host.start()
        XCTAssertEqual(
            snapshot,
            CompanionHostSnapshot(
                connection: nil,
                status: "REMOTE_DAVINCI_RELAY_URL must be a credential-free wss URL.",
                canRetry: false
            )
        )
    }

    @MainActor
    func testHostedTestsNeverStartTheHelper() {
        CompanionModel.shared.start()
        XCTAssertEqual(CompanionModel.shared.hostStatus, "Server stopped")
    }

    func testReadinessAcceptsOnlyCanonicalNumericLoopbackURL() throws {
        let line = Data(#"{"v":1,"version":"0.1.0","url":"http://127.0.0.1:43123/?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.utf8)
        guard case let .ready(connection) = try ReadinessValidator.parse(line) else {
            return XCTFail("Expected a ready result")
        }

        XCTAssertEqual(connection.helperVersion, "0.1.0")
        XCTAssertEqual(connection.baseURL.absoluteString, "http://127.0.0.1:43123/")
        XCTAssertEqual(connection.token, token)

        let ipv6 = Data(#"{"v":1,"version":"0.1.0","url":"http://[::1]:43123/?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.utf8)
        guard case .ready = try ReadinessValidator.parse(ipv6) else {
            return XCTFail("Expected numeric IPv6 loopback to be accepted")
        }
    }

    func testReadinessRejectsNonNumericHostAndInvalidToken() {
        let localhost = Data(#"{"v":1,"version":"0.1.0","url":"http://localhost:43123/?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.utf8)
        let padded = Data(#"{"v":1,"version":"0.1.0","url":"http://127.0.0.1:43123/?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#.utf8)
        let duplicate = Data(#"{"v":1,"version":"0.1.0","url":"http://127.0.0.1:43123/?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.utf8)

        XCTAssertThrowsError(try ReadinessValidator.parse(localhost))
        XCTAssertThrowsError(try ReadinessValidator.parse(padded))
        XCTAssertThrowsError(try ReadinessValidator.parse(duplicate))
    }

    func testStartupErrorRecordsAreSafeTerminalResults() throws {
        let expectations = [
            "CONFIG_MISMATCH": "Stored companion credentials do not match. No connection was started.",
            "KEYCHAIN_UNAVAILABLE": "The macOS Keychain is unavailable. Unlock it or allow access, then retry.",
            "STARTUP_FAILED": "The server helper could not start.",
        ]

        for (code, expectedMessage) in expectations {
            let line = Data(#"{"v":1,"error":{"code":"\#(code)"}}"#.utf8)
            guard case let .startupFailure(message) = try ReadinessValidator.parse(line) else {
                return XCTFail("Expected a startup failure for \(code)")
            }
            XCTAssertEqual(message, expectedMessage)
        }
    }

    func testStateAndEnrollmentModelsMatchHelperJSON() throws {
        let reply = EnrollmentReply(
            v: 1,
            relayURL: "wss://relay.example/v1",
            linkID: "link",
            controllerEndpointID: "controller",
            companionEndpointID: "companion",
            companionNoiseKey: token,
            warning: nil
        )
        let state = try JSONDecoder().decode(CompanionState.self, from: Data(#"{"configured":true,"relayUrl":"wss://relay.example/v1","endpointId":"endpoint","linkId":"link","controllerLabel":"iPad","connected":true,"secure":false,"status":"Waiting for controller","pairing":null,"enrollmentResponse":{"v":1,"relayUrl":"wss://relay.example/v1","linkId":"link","controllerEndpointId":"controller","companionEndpointId":"companion","companionNoiseKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#.utf8))
        XCTAssertEqual(state.connectionSummary, "Connected to relay")
        XCTAssertEqual(state.controllerLabel, "iPad")
        XCTAssertEqual(state.enrollmentResponse, reply)

        let roundTrip = try JSONDecoder().decode(
            EnrollmentReply.self,
            from: Data(try reply.formattedJSON().utf8)
        )
        XCTAssertEqual(roundTrip, reply)
    }

    func testPairingInviteRoundTripsToRenderableQRCode() throws {
        let invite = PairingInvite(
            protocolName: "remote-davinci.pairing-invite",
            v: 1,
            relayURL: "wss://relay.example/v1",
            pairID: "11111111-1111-4111-8111-111111111111",
            creatorSideID: "22222222-2222-4222-8222-222222222222",
            linkID: "33333333-3333-4333-8333-333333333333",
            joinToken: token,
            psk: token,
            expiresAt: 1_800_000_000
        )

        let payload = try invite.qrPayload()
        XCTAssertEqual(try JSONDecoder().decode(PairingInvite.self, from: Data(payload.utf8)), invite)
        XCTAssertNotNil(QRCodeRenderer.image(for: payload))
    }

    func testPairingStateMatchesHelperJSON() throws {
        let data = Data(#"{"configured":false,"relayUrl":"wss://relay.example/v1","connected":false,"secure":false,"status":"Awaiting approval","pairing":{"phase":"awaitingApproval","pairId":"11111111-1111-4111-8111-111111111111","expiresAt":1800000000,"controllerLabel":"My iPhone","controllerFingerprint":"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requestedPermissions":["resolve.page.edit"]}}"#.utf8)
        let state = try JSONDecoder().decode(CompanionState.self, from: data)

        XCTAssertTrue(state.pairing?.isAwaitingApproval == true)
        XCTAssertTrue(state.pairing?.isApprovable == true)
        XCTAssertEqual(state.pairing?.controllerLabel, "My iPhone")
        XCTAssertEqual(state.pairing?.requestedPermissions, ["resolve.page.edit"])
    }

    func testPairingApprovalFailsClosedForInvalidDetails() {
        let valid = pairingSnapshot()
        XCTAssertEqual(valid.approvalDetails?.pairID, "11111111-1111-4111-8111-111111111111")
        XCTAssertTrue(valid.isApprovable)
        XCTAssertTrue(pairingSnapshot(requestedPermissions: ["resolve.page.edit", "future.action"]).isApprovable)

        let invalid = [
            pairingSnapshot(pairID: nil),
            pairingSnapshot(pairID: "not-a-pair-id"),
            pairingSnapshot(controllerLabel: nil),
            pairingSnapshot(controllerLabel: "spoof\u{202E}"),
            pairingSnapshot(controllerFingerprint: nil),
            pairingSnapshot(controllerFingerprint: "sha256:not-canonical"),
            pairingSnapshot(requestedPermissions: nil),
            pairingSnapshot(requestedPermissions: []),
            pairingSnapshot(requestedPermissions: ["resolve.page.edit", "resolve.page.edit"]),
            pairingSnapshot(requestedPermissions: ["resolve.page.unknown"]),
            pairingSnapshot(requestedPermissions: ["resolve.page.edit", "future action"]),
        ]
        for snapshot in invalid {
            XCTAssertNil(snapshot.approvalDetails)
            XCTAssertFalse(snapshot.isApprovable)
        }
    }

    func testLegacyUnsafeControllerLabelIsNotRendered() {
        let state = CompanionState(
            configured: true,
            relayURL: "wss://relay.example/v1",
            endpointID: "endpoint",
            linkID: "link",
            controllerLabel: "Trusted\u{202E}spoof",
            connected: false,
            secure: false,
            status: "Waiting",
            pairing: nil,
            enrollmentResponse: nil
        )
        XCTAssertEqual(state.controllerDisplayLabel, "Unknown controller")
    }

    @MainActor
    func testPairingReplyFromReplacedHelperIsIgnored() throws {
        let original = CompanionConnection(
            helperVersion: "0.1.0",
            baseURL: URL(string: "http://127.0.0.1:43123/")!,
            token: token
        )
        let replacement = CompanionConnection(
            helperVersion: "0.1.0",
            baseURL: URL(string: "http://127.0.0.1:43124/")!,
            token: token
        )
        let reply = PairingStartReply(invite: PairingInvite(
            protocolName: "remote-davinci.pairing-invite",
            v: 1,
            relayURL: "wss://relay.example/v1",
            pairID: "11111111-1111-4111-8111-111111111111",
            creatorSideID: "22222222-2222-4222-8222-222222222222",
            linkID: "33333333-3333-4333-8333-333333333333",
            joinToken: token,
            psk: token,
            expiresAt: 1_800_000_000
        ))

        XCTAssertNil(try CompanionModel.pairingImage(
            for: reply,
            responseConnection: original,
            currentConnection: replacement
        ))
    }

    private func pairingSnapshot(
        pairID: String? = "11111111-1111-4111-8111-111111111111",
        controllerLabel: String? = "My iPhone",
        controllerFingerprint: String? = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        requestedPermissions: [String]? = ["resolve.page.edit"]
    ) -> PairingSnapshot {
        PairingSnapshot(
            phase: "awaitingApproval",
            pairID: pairID,
            expiresAt: 1_800_000_000,
            controllerLabel: controllerLabel,
            controllerFingerprint: controllerFingerprint,
            requestedPermissions: requestedPermissions
        )
    }
}
