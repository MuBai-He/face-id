import Foundation
import Darwin
import Security
import XPC

public enum FaceIDAuthXPCClientError: Error, Equatable, Sendable {
    case invalidTimeout
    case signingInformationUnavailable(Int32)
    case missingTeamIdentifier
    case invalidTeamIdentifier
    case connectionSetupFailed(Int32)
    case timedOut
    case connectionFailed
    case daemonNotRoot
    case malformedReply
    case unsupportedVersion
    case unexpectedStatus
    case unknownReason
}

public struct FaceIDAuthXPCStatusResponse: Equatable, Sendable {
    public let status: String
    public let reason: String
}

private final class XPCConnectionBox: @unchecked Sendable {
    let raw: xpc_connection_t

    init(_ raw: xpc_connection_t) {
        self.raw = raw
    }

    func cancel() {
        xpc_connection_cancel(raw)
    }

    func peerEUID() -> uid_t {
        xpc_connection_get_euid(raw)
    }
}

private final class XPCCompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else { return false }
        completed = true
        return true
    }
}

/// One-shot client for the non-authorizing daemon status endpoint.
///
/// The client derives the expected Team ID from its own code signature and
/// pins the daemon's signing identifier + Team ID before sending any message.
/// It accepts only an unavailable response; no reply can authorize PAM.
public enum FaceIDAuthXPCClient {
    public static func requestStatus(
        timeout: TimeInterval = 3,
        completion: @escaping @Sendable (Result<FaceIDAuthXPCStatusResponse, FaceIDAuthXPCClientError>) -> Void
    ) throws {
        guard timeout.isFinite, timeout > 0, timeout <= 30 else {
            throw FaceIDAuthXPCClientError.invalidTimeout
        }

        let teamIdentifier = try currentTeamIdentifier()
        guard ClientTrustPolicy.isValidTeamIdentifier(teamIdentifier) else {
            throw FaceIDAuthXPCClientError.invalidTeamIdentifier
        }
        let requirement = try FaceIDAuthXPCProtocol.makeDaemonCodeSigningRequirement(
            teamIdentifier: teamIdentifier
        )

        let connection = FaceIDAuthXPCProtocol.serviceName.withCString {
            xpc_connection_create_mach_service($0, nil, 0)
        }

        let connectionBox = XPCConnectionBox(connection)
        xpc_connection_set_event_handler(connection) { _ in }
        let requirementStatus = requirement.withCString {
            xpc_connection_set_peer_code_signing_requirement(connection, $0)
        }
        guard requirementStatus == 0 else {
            connectionBox.cancel()
            throw FaceIDAuthXPCClientError.connectionSetupFailed(requirementStatus)
        }

        xpc_connection_activate(connection)

        let request = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(
            request,
            FaceIDAuthXPCProtocol.versionKey,
            FaceIDAuthXPCProtocol.version
        )
        FaceIDAuthXPCProtocol.statusOperation.withCString {
            xpc_dictionary_set_string(request, FaceIDAuthXPCProtocol.operationKey, $0)
        }

        let gate = XPCCompletionGate()
        let replyQueue = DispatchQueue(label: "com.mubai.faceid.xpc-client.reply")
        let timeoutWork = DispatchWorkItem {
            guard gate.claim() else { return }
            connectionBox.cancel()
            completion(.failure(.timedOut))
        }
        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + timeout,
            execute: timeoutWork
        )

        xpc_connection_send_message_with_reply(connection, request, replyQueue) { reply in
            guard gate.claim() else { return }
            defer { connectionBox.cancel() }

            do {
                let response = try decodeStatusReply(
                    reply,
                    peerEUID: connectionBox.peerEUID()
                )
                completion(.success(response))
            } catch let error as FaceIDAuthXPCClientError {
                completion(.failure(error))
            } catch {
                completion(.failure(.malformedReply))
            }
        }
    }

    /// Internal so tests can validate replies without installing a LaunchDaemon.
    static func decodeStatusReply(
        _ reply: xpc_object_t,
        peerEUID: uid_t
    ) throws -> FaceIDAuthXPCStatusResponse {
        // A missing service or transport error is not evidence of a
        // non-root daemon. Classify the XPC reply before inspecting peer credentials.
        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
            throw FaceIDAuthXPCClientError.connectionFailed
        }
        guard peerEUID == 0 else {
            throw FaceIDAuthXPCClientError.daemonNotRoot
        }
        guard xpc_dictionary_get_int64(reply, FaceIDAuthXPCProtocol.versionKey)
                == FaceIDAuthXPCProtocol.version else {
            throw FaceIDAuthXPCClientError.unsupportedVersion
        }

        guard let statusPointer = xpc_dictionary_get_string(
            reply,
            FaceIDAuthXPCProtocol.responseStatusKey
        ),
        let reasonPointer = xpc_dictionary_get_string(
            reply,
            FaceIDAuthXPCProtocol.responseReasonKey
        ) else {
            throw FaceIDAuthXPCClientError.malformedReply
        }

        let status = String(cString: statusPointer)
        let reason = String(cString: reasonPointer)

        // The bootstrap client deliberately has no approved state.
        guard status == FaceIDAuthXPCProtocol.unavailableStatus else {
            throw FaceIDAuthXPCClientError.unexpectedStatus
        }
        let knownReasons = [
            FaceIDAuthXPCProtocol.notReadyReason,
            FaceIDAuthXPCProtocol.unsupportedVersionReason,
            FaceIDAuthXPCProtocol.unsupportedOperationReason
        ]
        guard knownReasons.contains(reason) else {
            throw FaceIDAuthXPCClientError.unknownReason
        }

        return FaceIDAuthXPCStatusResponse(status: status, reason: reason)
    }

    private static func currentTeamIdentifier() throws -> String {
        var runningCode: SecCode?
        let runningCodeStatus = SecCodeCopySelf(SecCSFlags(rawValue: 0), &runningCode)
        guard runningCodeStatus == errSecSuccess, let runningCode else {
            throw FaceIDAuthXPCClientError.signingInformationUnavailable(runningCodeStatus)
        }

        var staticCode: SecStaticCode?
        let staticCodeStatus = SecCodeCopyStaticCode(
            runningCode,
            SecCSFlags(rawValue: 0),
            &staticCode
        )
        guard staticCodeStatus == errSecSuccess, let staticCode else {
            throw FaceIDAuthXPCClientError.signingInformationUnavailable(staticCodeStatus)
        }

        let validityStatus = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: 0),
            nil
        )
        guard validityStatus == errSecSuccess else {
            throw FaceIDAuthXPCClientError.signingInformationUnavailable(validityStatus)
        }

        var signingInformation: CFDictionary?
        let informationStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInformation
        )
        guard informationStatus == errSecSuccess,
              let dictionary = signingInformation as? [String: Any] else {
            throw FaceIDAuthXPCClientError.signingInformationUnavailable(informationStatus)
        }
        guard let teamIdentifier = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
              !teamIdentifier.isEmpty else {
            throw FaceIDAuthXPCClientError.missingTeamIdentifier
        }
        return teamIdentifier
    }
}
