import Foundation
import XPC
import XCTest
@testable import FaceIDAuthIPC

final class FaceIDAuthXPCClientTests: XCTestCase {
    private func reply(
        version: Int64 = FaceIDAuthXPCProtocol.version,
        status: String = FaceIDAuthXPCProtocol.unavailableStatus,
        reason: String = FaceIDAuthXPCProtocol.notReadyReason
    ) -> xpc_object_t {
        let dictionary = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(dictionary, FaceIDAuthXPCProtocol.versionKey, version)
        status.withCString {
            xpc_dictionary_set_string(dictionary, FaceIDAuthXPCProtocol.responseStatusKey, $0)
        }
        reason.withCString {
            xpc_dictionary_set_string(dictionary, FaceIDAuthXPCProtocol.responseReasonKey, $0)
        }
        return dictionary
    }

    func testDaemonRequirementPinsIdentifierAndTeam() throws {
        XCTAssertEqual(
            try FaceIDAuthXPCProtocol.makeDaemonCodeSigningRequirement(teamIdentifier: "ABCDE12345"),
            "anchor apple generic and identifier \"com.joeqiao.faceid.authd\" and certificate leaf[subject.OU] = \"ABCDE12345\""
        )
    }

    func testDaemonRequirementRejectsInvalidTeam() {
        XCTAssertThrowsError(
            try FaceIDAuthXPCProtocol.makeDaemonCodeSigningRequirement(teamIdentifier: "adhoc")
        ) { error in
            XCTAssertEqual(error as? ClientTrustPolicyError, .invalidTeamIdentifier)
        }
    }

    func testAcceptsOnlyRootDaemonAndUnavailableStatus() throws {
        let response = try FaceIDAuthXPCClient.decodeStatusReply(reply(), peerEUID: 0)
        XCTAssertEqual(
            response,
            FaceIDAuthXPCStatusResponse(
                status: FaceIDAuthXPCProtocol.unavailableStatus,
                reason: FaceIDAuthXPCProtocol.notReadyReason
            )
        )
    }

    func testRejectsNonRootPeer() {
        XCTAssertThrowsError(
            try FaceIDAuthXPCClient.decodeStatusReply(reply(), peerEUID: 501)
        ) { error in
            XCTAssertEqual(error as? FaceIDAuthXPCClientError, .daemonNotRoot)
        }
    }

    func testRejectsUnsupportedProtocolVersion() {
        XCTAssertThrowsError(
            try FaceIDAuthXPCClient.decodeStatusReply(reply(version: 2), peerEUID: 0)
        ) { error in
            XCTAssertEqual(error as? FaceIDAuthXPCClientError, .unsupportedVersion)
        }
    }

    func testRejectsAnyApprovalLikeStatus() {
        XCTAssertThrowsError(
            try FaceIDAuthXPCClient.decodeStatusReply(reply(status: "approved"), peerEUID: 0)
        ) { error in
            XCTAssertEqual(error as? FaceIDAuthXPCClientError, .unexpectedStatus)
        }
    }

    func testRejectsUnknownReason() {
        XCTAssertThrowsError(
            try FaceIDAuthXPCClient.decodeStatusReply(reply(reason: "arbitrary"), peerEUID: 0)
        ) { error in
            XCTAssertEqual(error as? FaceIDAuthXPCClientError, .unknownReason)
        }
    }

    func testRejectsMissingResponseFields() {
        let dictionary = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(dictionary, FaceIDAuthXPCProtocol.versionKey, FaceIDAuthXPCProtocol.version)
        XCTAssertThrowsError(
            try FaceIDAuthXPCClient.decodeStatusReply(dictionary, peerEUID: 0)
        ) { error in
            XCTAssertEqual(error as? FaceIDAuthXPCClientError, .malformedReply)
        }
    }
}
