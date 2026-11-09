# LaunchDaemon packaging scaffold

The plist in this directory is a packaging template only. It is not installed,
bootstrapped, or loaded by the test suite.

Expected installed layout:

- Executable: /Library/PrivilegedHelperTools/com.joeqiao.faceid.authd
- LaunchDaemon: /Library/LaunchDaemons/com.joeqiao.faceid.authd.plist
- Trust policy: /Library/Application Support/com.joeqiao.faceid/client-requirement.txt

The installer must create the application-support directory as root:wheel
mode 0700, verify the signed Face ID application, derive its 10-character
Developer ID Team ID, and write the exact requirement below as root:wheel
mode 0600:

    anchor apple generic and identifier "com.joeqiao.faceid" and certificate leaf[subject.OU] = "TEAMID"

Replace TEAMID only after verifying the actual signed app. Do not use an
ad-hoc signature, a PID-only check, or a client-supplied requirement. The daemon
uses Apple's public xpc_connection_set_peer_code_signing_requirement API,
which enforces the requirement on every message.

The daemon is intentionally non-authorizing: its only supported operation is
a status probe and it always returns unavailable. It does not accept biometric
vectors, liveness flags, enrollment data, or approval decisions. The existing
PAM module is not connected to this XPC service.

Do not manually install this plist yet. A later installer must include
signature pinning, code-signing of the helper, ownership/mode verification,
rollback, and uninstall support.
