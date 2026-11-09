import Foundation
import Observation
import ServiceManagement
import FaceIDAuthIPC

/// Manages the user-approved LaunchDaemon lifecycle and read-only XPC diagnostics.
///
/// Registering this service never enables PAM authentication. The daemon currently
/// exposes only an "unavailable" status response.
@Observable
@MainActor
final class SystemAuthServiceStatus {
    enum ConnectionState: Equatable {
        case notChecked
        case checking
        case connected(reason: String)
        case failed(message: String)
    }

    enum RegistrationState: Equatable {
        case notRegistered
        case enabled
        case requiresApproval
        case notFound
        case failed(message: String)
    }

    private let service = SMAppService.daemon(plistName: "com.joeqiao.faceid.authd.plist")

    private(set) var connectionState: ConnectionState = .notChecked
    private(set) var registrationState: RegistrationState = .notFound

    init() {
        refreshRegistrationStatus()
    }

    var registrationDescription: String {
        switch registrationState {
        case .notRegistered:
            return "尚未安装系统服务。安装后需要在系统设置中允许后台服务运行。"
        case .enabled:
            return "系统服务已注册并获准运行。人脸认证仍未启用。"
        case .requiresApproval:
            return "系统服务已注册，但需要在系统设置中手动允许。"
        case .notFound:
            return "未找到 App 内嵌的 LaunchDaemon。请重新构建完整 App。"
        case .failed(let message):
            return "系统服务管理失败：\\(message)"
        }
    }

    var connectionDescription: String {
        switch connectionState {
        case .notChecked:
            return "尚未检查 XPC 连接。"
        case .checking:
            return "正在验证系统服务的签名与连接…"
        case .connected(let reason):
            if reason == FaceIDAuthXPCProtocol.notReadyReason {
                return "XPC 已连接。服务端明确报告认证流程尚未启用。"
            }
            return "XPC 已连接，但认证暂不可用（\\(reason)）。"
        case .failed(let message):
            return "\\(message)。现有密码和 Touch ID 认证不受影响。"
        }
    }

    var canRegister: Bool {
        registrationState == .notRegistered
    }

    var canUnregister: Bool {
        registrationState == .enabled || registrationState == .requiresApproval
    }

    var canOpenLoginItems: Bool {
        registrationState == .requiresApproval
    }

    var isCheckingConnection: Bool {
        connectionState == .checking
    }

    func refreshRegistrationStatus() {
        switch service.status {
        case .notRegistered:
            registrationState = .notRegistered
        case .enabled:
            registrationState = .enabled
        case .requiresApproval:
            registrationState = .requiresApproval
        case .notFound:
            registrationState = .notFound
        @unknown default:
            registrationState = .notFound
        }
    }

    func registerService() {
        guard canRegister else { return }
        do {
            try service.register()
            refreshRegistrationStatus()
        } catch {
            registrationState = .failed(message: error.localizedDescription)
        }
    }

    func unregisterService() {
        guard canUnregister else { return }
        do {
            try service.unregister()
            refreshRegistrationStatus()
            connectionState = .notChecked
        } catch {
            registrationState = .failed(message: error.localizedDescription)
        }
    }

    func openLoginItemsSettings() {
        guard canOpenLoginItems else { return }
        SMAppService.openSystemSettingsLoginItems()
    }

    func checkConnection() {
        guard !isCheckingConnection else { return }
        connectionState = .checking

        do {
            try FaceIDAuthXPCClient.requestStatus { [weak self] result in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    switch result {
                    case .success(let response):
                        self.connectionState = .connected(reason: response.reason)
                    case .failure(let error):
                        self.connectionState = .failed(message: Self.message(for: error))
                    }
                }
            }
        } catch let error as FaceIDAuthXPCClientError {
            connectionState = .failed(message: Self.message(for: error))
        } catch {
            connectionState = .failed(message: "无法启动系统服务检查")
        }
    }

    private static func message(for error: FaceIDAuthXPCClientError) -> String {
        switch error {
        case .invalidTimeout:
            return "检查超时时间无效"
        case .signingInformationUnavailable:
            return "无法验证当前 Face ID 应用的代码签名"
        case .missingTeamIdentifier:
            return "当前应用没有可用的 Developer Team ID"
        case .invalidTeamIdentifier:
            return "当前应用的 Team ID 格式无效"
        case .connectionSetupFailed(let status):
            return "无法配置系统服务签名校验（\\(status)）"
        case .timedOut:
            return "系统服务响应超时"
        case .connectionFailed:
            return "系统服务未安装、未运行或无法连接"
        case .daemonNotRoot:
            return "系统服务没有以 root 身份运行"
        case .malformedReply:
            return "系统服务返回了无效响应"
        case .unsupportedVersion:
            return "系统服务协议版本不兼容"
        case .unexpectedStatus:
            return "系统服务返回了不允许的认证状态"
        case .unknownReason:
            return "系统服务返回了未知状态"
        }
    }
}
