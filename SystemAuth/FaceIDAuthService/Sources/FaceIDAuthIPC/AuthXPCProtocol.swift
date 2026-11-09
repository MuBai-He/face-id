import Foundation

public enum FaceIDAuthXPCProtocol {
    public static let serviceName = "com.mubai.faceid.authd"
    public static let version: Int64 = 1

    public static let operationKey = "operation"
    public static let versionKey = "version"
    public static let statusOperation = "status"

    public static let responseStatusKey = "status"
    public static let responseReasonKey = "reason"

    /// This bootstrap endpoint is intentionally non-authorizing.
    public static let unavailableStatus = "unavailable"
    public static let notReadyReason = "authentication_pipeline_not_ready"
    public static let unsupportedVersionReason = "unsupported_protocol_version"
    public static let unsupportedOperationReason = "unsupported_operation"
}


extension FaceIDAuthXPCProtocol {
    public static let daemonSigningIdentifier = "faceid-authd"

    /// Builds the exact daemon requirement from the signed app's own Team ID.
    /// The client must never accept a daemon Team ID supplied by the daemon.
    public static func makeDaemonCodeSigningRequirement(teamIdentifier: String) throws -> String {
        guard ClientTrustPolicy.isValidTeamIdentifier(teamIdentifier) else {
            throw ClientTrustPolicyError.invalidTeamIdentifier
        }
        return "anchor apple generic and identifier \"\(daemonSigningIdentifier)\" and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }
}
