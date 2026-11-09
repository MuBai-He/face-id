import Foundation
import Darwin
import FaceIDAuthIPC

private func log(_ message: String) {
    fputs("faceid-authd: \(message)\n", stderr)
}

private func sendUnavailableReply(
    for message: xpc_object_t,
    over connection: xpc_connection_t,
    reason: String
) {
    guard let reply = xpc_dictionary_create_reply(message) else {
        return
    }
    xpc_dictionary_set_int64(reply, FaceIDAuthXPCProtocol.versionKey, FaceIDAuthXPCProtocol.version)
    xpc_dictionary_set_string(reply, FaceIDAuthXPCProtocol.responseStatusKey, FaceIDAuthXPCProtocol.unavailableStatus)
    xpc_dictionary_set_string(reply, FaceIDAuthXPCProtocol.responseReasonKey, reason)
    xpc_connection_send_message(connection, reply)
}

private func handleMessage(_ message: xpc_object_t, over connection: xpc_connection_t) {
    guard xpc_get_type(message) == XPC_TYPE_DICTIONARY else {
        xpc_connection_cancel(connection)
        return
    }

    // This is only a diagnostic endpoint. Even a trusted client can never
    // submit a face vector, liveness Boolean, UID override, or approval result.
    let peerUID = xpc_connection_get_euid(connection)
    let peerAuditSession = xpc_connection_get_asid(connection)
    guard peerUID != 0, peerAuditSession != 0 else {
        xpc_connection_cancel(connection)
        return
    }

    let requestVersion = xpc_dictionary_get_int64(message, FaceIDAuthXPCProtocol.versionKey)
    guard requestVersion == FaceIDAuthXPCProtocol.version else {
        sendUnavailableReply(
            for: message,
            over: connection,
            reason: FaceIDAuthXPCProtocol.unsupportedVersionReason
        )
        return
    }

    guard let operationPointer = xpc_dictionary_get_string(message, FaceIDAuthXPCProtocol.operationKey),
          String(cString: operationPointer) == FaceIDAuthXPCProtocol.statusOperation else {
        sendUnavailableReply(
            for: message,
            over: connection,
            reason: FaceIDAuthXPCProtocol.unsupportedOperationReason
        )
        return
    }

    sendUnavailableReply(
        for: message,
        over: connection,
        reason: FaceIDAuthXPCProtocol.notReadyReason
    )
}

guard geteuid() == 0 else {
    log("must run as root")
    exit(77)
}

let trustPolicy: ClientTrustPolicy
do {
    trustPolicy = try ClientTrustPolicy()
} catch {
    log("refusing to start without a valid signed daemon identity: \(error)")
    exit(78)
}

let listener = FaceIDAuthXPCProtocol.serviceName.withCString {
    xpc_connection_create_mach_service(
        $0,
        nil,
        UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
    )
}

xpc_connection_set_event_handler(listener) { event in
    switch xpc_get_type(event) {
    case XPC_TYPE_CONNECTION:
        let peer: xpc_connection_t = event
        // This public XPC API makes the kernel enforce the exact code-signing
        // requirement on every message. No PID lookup or private audit-token API.
        let requirementStatus = trustPolicy.codeSigningRequirement.withCString {
            xpc_connection_set_peer_code_signing_requirement(peer, $0)
        }
        guard requirementStatus == 0 else {
            log("could not apply peer code-signing requirement")
            xpc_connection_cancel(peer)
            return
        }

        nonisolated(unsafe) let peerForHandler = peer
        xpc_connection_set_event_handler(peer) { message in
            switch xpc_get_type(message) {
            case XPC_TYPE_DICTIONARY:
                handleMessage(message, over: peerForHandler)
            case XPC_TYPE_ERROR:
                break
            default:
                xpc_connection_cancel(peerForHandler)
            }
        }
        xpc_connection_activate(peer)

    case XPC_TYPE_ERROR:
        log("Mach service listener reported an XPC error")

    default:
        log("Mach service listener received an unexpected event")
    }
}

xpc_connection_activate(listener)
dispatchMain()
