import Foundation
import Darwin
import Security

public enum ClientTrustPolicyError: Error, Equatable {
    case notPrivileged
    case signingInformationUnavailable(Int32)
    case invalidDaemonSigningIdentifier
    case missingTeamIdentifier
    case invalidTeamIdentifier
}

/// Derives the GUI client's trust requirement from the running daemon's own
/// verified code signature. Both executables must be signed by the same Apple
/// Developer Team; the GUI bundle identifier is pinned as well.
///
/// This removes mutable on-disk trust configuration from the installation
/// path. An ad-hoc or unsigned daemon has no Team ID and refuses to start.
public struct ClientTrustPolicy: Sendable {
    public static let expectedSigningIdentifier = "com.mubai.faceid"
    public static let expectedDaemonSigningIdentifier = "faceid-authd"

    public let codeSigningRequirement: String

    public init() throws {
        guard geteuid() == 0 else {
            throw ClientTrustPolicyError.notPrivileged
        }
        self.codeSigningRequirement = try Self.requirementForRunningDaemon()
    }

    /// Test seam for deterministic policy construction without a signed daemon.
    init(daemonSigningIdentifier: String, teamIdentifier: String) throws {
        guard daemonSigningIdentifier == Self.expectedDaemonSigningIdentifier else {
            throw ClientTrustPolicyError.invalidDaemonSigningIdentifier
        }
        self.codeSigningRequirement = try Self.makeCodeSigningRequirement(
            teamIdentifier: teamIdentifier
        )
    }

    public static func makeCodeSigningRequirement(teamIdentifier: String) throws -> String {
        guard isValidTeamIdentifier(teamIdentifier) else {
            throw ClientTrustPolicyError.invalidTeamIdentifier
        }
        return "anchor apple generic and identifier \"\(expectedSigningIdentifier)\" and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }

    public static func isValidTeamIdentifier(_ value: String) -> Bool {
        guard value.utf8.count == 10 else { return false }
        return value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
        }
    }

    private static func requirementForRunningDaemon() throws -> String {
        var code: SecCode?
        let codeStatus = SecCodeCopySelf(SecCSFlags(rawValue: 0), &code)
        guard codeStatus == errSecSuccess, let code else {
            throw ClientTrustPolicyError.signingInformationUnavailable(codeStatus)
        }

        var staticCode: SecStaticCode?
        let staticCodeStatus = SecCodeCopyStaticCode(
            code,
            SecCSFlags(rawValue: 0),
            &staticCode
        )
        guard staticCodeStatus == errSecSuccess, let staticCode else {
            throw ClientTrustPolicyError.signingInformationUnavailable(staticCodeStatus)
        }

        let validityStatus = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: 0),
            nil
        )
        guard validityStatus == errSecSuccess else {
            throw ClientTrustPolicyError.signingInformationUnavailable(validityStatus)
        }

        var signingInformation: CFDictionary?
        let informationStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInformation
        )
        guard informationStatus == errSecSuccess,
              let dictionary = signingInformation as? [String: Any] else {
            throw ClientTrustPolicyError.signingInformationUnavailable(informationStatus)
        }

        guard let identifier = dictionary[kSecCodeInfoIdentifier as String] as? String,
              identifier == expectedDaemonSigningIdentifier else {
            throw ClientTrustPolicyError.invalidDaemonSigningIdentifier
        }

        guard let teamIdentifier = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
              !teamIdentifier.isEmpty else {
            throw ClientTrustPolicyError.missingTeamIdentifier
        }

        return try makeCodeSigningRequirement(teamIdentifier: teamIdentifier)
    }
}
