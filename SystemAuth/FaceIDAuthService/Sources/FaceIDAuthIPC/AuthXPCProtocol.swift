import Foundation

public enum FaceIDAuthXPCProtocol {
    public static let serviceName = "com.joeqiao.faceid.authd"
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
