# macOS PAM 第一阶段：代码状态

这是系统认证的通信与策略基础，不是“安装后即可刷脸 sudo”的成品。
现有 GUI、人脸录入、应用锁和密码注入路径没有改动。

## 已实现

- 新增严格 ArcFace 初始化入口。模型加载失败直接抛错，不降级到 Vision
  Feature Print；旧的 App 初始化逻辑保持不变。
- 新增仅处理 `sudo` 的 PAM 适配器、固定长度协议和共享的有界 I/O。
- 校验 socket 类型、root 所有权、权限以及连接对端身份；每次生成随机挑战，
  校验响应版本和 nonce，通信使用一个四秒单调时钟截止时间。
- 核对发起者与 `PAM_USER`，不会用当前用户的人脸代替 root 或其他账户认证。
- 对静默认证、显式远程主机、未知配置参数、非 sudo 服务等情况回退。
  注意：`PAM_RHOST` 为空不能证明是本地操作，真实服务仍须验证 GUI/audit 会话。
- 诊断探针永远返回 `UNAVAILABLE`，不会批准任何认证。

## 验证范围

本次在 Linux 隔离容器里通过了 33 项回归测试；测试使用假的 PAM ABI 和临时
socket，不会改 `/etc/pam.d`。覆盖超时、分片、旧响应重放、错误账户、权限过宽、
符号链接、root 所有但非 root 进程提供的 socket，以及探针不批准认证。

已附 Linux/macOS CI 配置。macOS 作业会另外用真实 SDK 编译 C 模块；是否实际运行
及通过，以 GitHub Actions 的结果为准。没有宣称 Swift App、真实 PAM 栈、TCC、
摄像头、人脸匹配或系统登录已验收。

## Mac 上仅编译

```sh
make -C SystemAuth/PAM
make -C SystemAuth/Daemon
```

测试仅在可恢复的专用测试机或容器执行：

```sh
sudo python3 SystemAuth/tests/test_pam_transport.py
```

不要安装 `examples/sudo_local.example`，不要把探针注册成常驻服务。

## 尚未实现

真实的人脸推理服务、CameraAgent、受保护模板库、授权录入、安全安装与卸载，
以及 `su`、原生锁屏和登录窗口。下一阶段的具体安全门槛在英文 README 中列出。
本分支没有修改 AuthorizationDB、FileVault 或 SIP，也没有关闭密码认证。
