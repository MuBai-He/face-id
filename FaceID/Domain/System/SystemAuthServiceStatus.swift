import Foundation
import Observation
import FaceIDAuthIPC

/// Read-only diagnostics for the privileged authentication service.
///
/// This type can report whether the signed app can reach the signed daemon.
/// It deliberately exposes no authentication, enrollment, or authorization API.
@Observable
@MainActor
final class SystemAuthServiceStatus {
    enum State: Equatable {
        case notChecked
        case checking
        case connected(reason: String)
        case failed(message: String)
    }

    private(set) var state: State = .notChecked

    var statusDescription: String {
        switch state {
        case .notChecked:
            return "尚未检查。此功能目前不会影响 sudo、登录或锁屏认证。"
        case .checking:
            return "正在验证系统服务的签名与连接…"
        case .connected(let reason):
            if reason == FaceIDAuthXPCProtocol.notReadyReason {
                return "服务已连接，但系统人脸认证尚未启用。"
            }
            return "服务已连接，但认证功能暂不可用（\(reason)）。"
        case .failed(let message):
            return "\(message)。现有密码和 Touch ID 认证不受影响。"
        }
    }

    var buttonTitle: String {
        state == .checking ? "检查中" : "检查"
    }

    var canCheck: Bool {
        state != .checking
    }

    func check() {
        guard canCheck else { return }
        state = .checking

        do {
            try FaceIDAuthXPCClient.requestStatus { [weak self] result in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    switch result {
                    case .success(let response):
                        self.state = .connected(reason: response.reason)
                    case .failure(let error):
                        self.state = .failed(message: Self.message(for: error))
                    }
                }
            }
        } catch let error as FaceIDAuthXPCClientError {
            state = .failed(message: Self.message(for: error))
        } catch {
            state = .failed(message: "无法启动系统服务检查")
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
            return "无法配置系统服务签名校验（\(status)）"
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
