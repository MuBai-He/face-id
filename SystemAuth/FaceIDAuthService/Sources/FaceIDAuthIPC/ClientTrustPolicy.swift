import Foundation
import Darwin

public enum ClientTrustPolicyError: Error, Equatable {
    case notPrivileged
    case unsafeDirectory
    case missingPolicy
    case unsafePolicyFile
    case invalidTeamIdentifier
    case malformedRequirement
    case readFailure
}

/// Root-owned trust anchor for the GUI application's XPC connection.
///
/// The installer must derive the Team ID from the signed application it is
/// installing, validate that signature, and write this requirement as root.
/// The daemon never accepts a Team ID or requirement supplied by an XPC client.
public struct ClientTrustPolicy: Sendable {
    public static let productionDirectory = URL(
        fileURLWithPath: "/Library/Application Support/com.joeqiao.faceid",
        isDirectory: true
    )
    public static let policyFileName = "client-requirement.txt"
    public static let expectedSigningIdentifier = "com.joeqiao.faceid"
    public static let maximumPolicyBytes = 512

    public let codeSigningRequirement: String

    public init() throws {
        guard geteuid() == 0 else {
            throw ClientTrustPolicyError.notPrivileged
        }
        self.codeSigningRequirement = try Self.load(
            from: Self.productionDirectory,
            expectedOwnerUID: 0
        )
    }

    /// Test-only injection point. Production code must use the parameterless
    /// initializer so callers cannot select a user-owned trust directory.
    init(directoryURL: URL, expectedOwnerUID: uid_t) throws {
        self.codeSigningRequirement = try Self.load(
            from: directoryURL,
            expectedOwnerUID: expectedOwnerUID
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

    private static func validateRequirement(_ value: String) throws {
        let prefix = "anchor apple generic and identifier \"\(expectedSigningIdentifier)\" and certificate leaf[subject.OU] = \""
        guard value.hasPrefix(prefix), value.hasSuffix("\"") else {
            throw ClientTrustPolicyError.malformedRequirement
        }
        let teamIdentifier = String(value.dropFirst(prefix.count).dropLast())
        guard isValidTeamIdentifier(teamIdentifier),
              try makeCodeSigningRequirement(teamIdentifier: teamIdentifier) == value else {
            throw ClientTrustPolicyError.malformedRequirement
        }
    }

    private static func load(from directoryURL: URL, expectedOwnerUID: uid_t) throws -> String {
        var directoryInfo = stat()
        guard lstat(directoryURL.path, &directoryInfo) == 0,
              (directoryInfo.st_mode & S_IFMT) == S_IFDIR,
              directoryInfo.st_uid == expectedOwnerUID,
              (directoryInfo.st_mode & 0o077) == 0 else {
            throw ClientTrustPolicyError.unsafeDirectory
        }

        let policyURL = directoryURL.appendingPathComponent(policyFileName)
        let descriptor = Darwin.open(policyURL.path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            if errno == ENOENT {
                throw ClientTrustPolicyError.missingPolicy
            }
            throw ClientTrustPolicyError.unsafePolicyFile
        }
        defer { _ = close(descriptor) }

        var fileInfo = stat()
        guard fstat(descriptor, &fileInfo) == 0,
              (fileInfo.st_mode & S_IFMT) == S_IFREG,
              fileInfo.st_uid == expectedOwnerUID,
              (fileInfo.st_mode & 0o077) == 0,
              fileInfo.st_nlink == 1,
              fileInfo.st_size > 0,
              fileInfo.st_size <= Int64(maximumPolicyBytes) else {
            throw ClientTrustPolicyError.unsafePolicyFile
        }

        var bytes = [UInt8](repeating: 0, count: Int(fileInfo.st_size))
        var offset = 0
        while offset < bytes.count {
            let remaining = bytes.count - offset
            let count = bytes.withUnsafeMutableBytes { raw in
                Darwin.read(descriptor, raw.baseAddress!.advanced(by: offset), remaining)
            }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw ClientTrustPolicyError.readFailure }
            offset += count
        }

        var trailingByte: UInt8 = 0
        let trailingCount = withUnsafeMutablePointer(to: &trailingByte) {
            Darwin.read(descriptor, $0, 1)
        }
        guard trailingCount == 0,
              let requirement = String(bytes: bytes, encoding: .utf8) else {
            throw ClientTrustPolicyError.unsafePolicyFile
        }
        try validateRequirement(requirement)
        return requirement
    }
}
