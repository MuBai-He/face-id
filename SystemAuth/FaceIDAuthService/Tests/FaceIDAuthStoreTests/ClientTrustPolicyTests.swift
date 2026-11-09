import XCTest
@testable import FaceIDAuthIPC

final class ClientTrustPolicyTests: XCTestCase {
    func testBuildsPinnedDeveloperIDRequirement() throws {
        let policy = try ClientTrustPolicy(
            daemonSigningIdentifier: ClientTrustPolicy.expectedDaemonSigningIdentifier,
            teamIdentifier: "ABCDE12345"
        )
        XCTAssertEqual(
            policy.codeSigningRequirement,
            "anchor apple generic and identifier \"com.mubai.faceid\" and certificate leaf[subject.OU] = \"ABCDE12345\""
        )
    }

    func testRejectsInvalidTeamIdentifiers() {
        for teamID in ["", "ABCDE1234", "ABCDE123456", "abcde12345", "ABCDE-2345", "ABCDEFGHIJ "] {
            XCTAssertThrowsError(
                try ClientTrustPolicy(
                    daemonSigningIdentifier: ClientTrustPolicy.expectedDaemonSigningIdentifier,
                    teamIdentifier: teamID
                )
            ) { error in
                XCTAssertEqual(error as? ClientTrustPolicyError, .invalidTeamIdentifier)
            }
        }
    }

    func testRejectsUnexpectedDaemonSigningIdentifier() {
        XCTAssertThrowsError(
            try ClientTrustPolicy(
                daemonSigningIdentifier: "com.attacker.helper",
                teamIdentifier: "ABCDE12345"
            )
        ) { error in
            XCTAssertEqual(error as? ClientTrustPolicyError, .invalidDaemonSigningIdentifier)
        }
    }

    func testTeamIdentifierMustBeTenUppercaseASCIICharacters() {
        XCTAssertTrue(ClientTrustPolicy.isValidTeamIdentifier("ABCDE12345"))
        XCTAssertTrue(ClientTrustPolicy.isValidTeamIdentifier("1234567890"))
        XCTAssertFalse(ClientTrustPolicy.isValidTeamIdentifier("abcdefghij"))
        XCTAssertFalse(ClientTrustPolicy.isValidTeamIdentifier("ABCDE1234"))
    }

    func testDaemonRequirementPinsTheFaceIDBundleIdentifier() throws {
        let requirement = try ClientTrustPolicy.makeCodeSigningRequirement(
            teamIdentifier: "ABCDE12345"
        )
        XCTAssertTrue(requirement.contains("identifier \"com.mubai.faceid\""))
        XCTAssertTrue(requirement.contains("certificate leaf[subject.OU] = \"ABCDE12345\""))
    }
}
