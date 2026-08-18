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
        let state = try JSONDecoder().decode(CompanionState.self, from: Data(#"{"configured":true,"relayUrl":"wss://relay.example/v1","endpointId":"endpoint","linkId":"link","controllerLabel":"iPad","connected":true,"secure":true,"status":"Secure session"}"#.utf8))
        XCTAssertEqual(state.connectionSummary, "Secure controller session")
        XCTAssertEqual(state.controllerLabel, "iPad")

        let reply = EnrollmentReply(
            v: 1,
            relayURL: "wss://relay.example/v1",
            linkID: "link",
            controllerEndpointID: "controller",
            companionEndpointID: "companion",
            companionNoiseKey: token,
            warning: nil
        )
        let roundTrip = try JSONDecoder().decode(
            EnrollmentReply.self,
            from: Data(try reply.formattedJSON().utf8)
        )
        XCTAssertEqual(roundTrip, reply)
    }
}
