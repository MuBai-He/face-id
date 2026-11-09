import Foundation
import Darwin
import XCTest
@testable import FaceIDAuthIPC

final class ClientTrustPolicyTests: XCTestCase {
    private func makeDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("faceid-xpc-trust-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(directory.path, 0o700), 0)
        return directory
    }

    private func validRequirement() throws -> String {
        try ClientTrustPolicy.makeCodeSigningRequirement(teamIdentifier: "ABCDE12345")
    }

    private func writeRequirement(_ requirement: String, to directory: URL) throws -> URL {
        let file = directory.appendingPathComponent(ClientTrustPolicy.policyFileName)
        try Data(requirement.utf8).write(to: file)
        XCTAssertEqual(chmod(file.path, 0o600), 0)
        return file
    }

    func testBuildsPinnedDeveloperIDRequirement() throws {
        XCTAssertEqual(
            try validRequirement(),
            "anchor apple generic and identifier \"com.joeqiao.faceid\" and certificate leaf[subject.OU] = \"ABCDE12345\""
        )
    }

    func testRejectsInvalidTeamIdentifiers() {
        for teamID in ["", "ABCDE1234", "ABCDE123456", "abcde12345", "ABCDE-2345", "ABCDEFGHIJ "] {
            XCTAssertThrowsError(try ClientTrustPolicy.makeCodeSigningRequirement(teamIdentifier: teamID))
        }
    }

    func testLoadsRootOwnedPolicyInIsolatedDirectory() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let requirement = try validRequirement()
        try writeRequirement(requirement, to: directory)

        let policy = try ClientTrustPolicy(directoryURL: directory, expectedOwnerUID: getuid())
        XCTAssertEqual(policy.codeSigningRequirement, requirement)
    }

    func testMissingPolicyIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        XCTAssertThrowsError(
            try ClientTrustPolicy(directoryURL: directory, expectedOwnerUID: getuid())
        ) { error in
            XCTAssertEqual(error as? ClientTrustPolicyError, .missingPolicy)
        }
    }

    func testSymlinkedPolicyIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target")
        try Data(try validRequirement().utf8).write(to: target)
        let policy = directory.appendingPathComponent(ClientTrustPolicy.policyFileName)
        try FileManager.default.createSymbolicLink(at: policy, withDestinationURL: target)

        XCTAssertThrowsError(
            try ClientTrustPolicy(directoryURL: directory, expectedOwnerUID: getuid())
        )
    }

    func testGroupReadablePolicyIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = try writeRequirement(validRequirement(), to: directory)
        XCTAssertEqual(chmod(file.path, 0o640), 0)

        XCTAssertThrowsError(
            try ClientTrustPolicy(directoryURL: directory, expectedOwnerUID: getuid())
        ) { error in
            XCTAssertEqual(error as? ClientTrustPolicyError, .unsafePolicyFile)
        }
    }

    func testMalformedOrAdHocRequirementIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try writeRequirement("identifier \"com.joeqiao.faceid\"", to: directory)

        XCTAssertThrowsError(
            try ClientTrustPolicy(directoryURL: directory, expectedOwnerUID: getuid())
        ) { error in
            XCTAssertEqual(error as? ClientTrustPolicyError, .malformedRequirement)
        }
    }

    func testSymlinkedTrustDirectoryIsRejected() throws {
        let parent = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let target = parent.appendingPathComponent("target", isDirectory: true)
        let link = parent.appendingPathComponent("link", isDirectory: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(target.path, 0o700), 0)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        XCTAssertThrowsError(
            try ClientTrustPolicy(directoryURL: link, expectedOwnerUID: getuid())
        ) { error in
            XCTAssertEqual(error as? ClientTrustPolicyError, .unsafeDirectory)
        }
    }
}
