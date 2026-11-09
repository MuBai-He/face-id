# FaceIDAuthService foundation

This Swift package is the first service-side building block. It currently ships
only an encrypted, permission-checked template store. It is **not a LaunchDaemon,
does not open a socket or XPC listener, does not capture camera frames, and is
not connected to PAM**.

## Current contract

- Production initialization is parameterless and requires effective UID 0.
- The store lives at
  `/Library/Application Support/com.joeqiao.faceid`, owned by root with no
  group/other access.
- The AES-GCM key and ciphertext are separate files in that root-only directory,
  each with mode 0600. FileVault should remain enabled. Because the key is stored
  beside the ciphertext, this is protection against unprivileged logged-in users,
  not against root compromise or offline disk access without FileVault.
- Only the current ArcFace model identifier (`arcface-w600k_mbf-v1`) and
  512-dimensional finite, L2-normalized embeddings are accepted. Vision Feature
  Print templates are rejected.
- Input size, identity count, sample count, owner UID, symlinks, hard links,
  permissions, and ciphertext authentication are checked.
- The test-only directory/owner injection initializer is internal to the module
  and is not part of the production API.

## Important security boundary

The store does not grant authorization. Before a daemon calls `save`, it must
validate a fresh administrator authorization right, bind the operation to the
authenticated console user, and verify the caller's code identity. Never expose
a generic write operation to the unprivileged app or accept a face vector as
proof that enrollment was authorized.

The current app stores its face database and device key in the user's
Application Support directory. This package intentionally does not read those
files as a privileged authority. A later migration flow must explicitly authorize
enrollment and re-capture samples; blindly importing a user-writable file would
allow the user to replace the identity template.

## Build and test

On macOS 15 or later with Xcode Command Line Tools:

```sh
swift test --package-path SystemAuth/FaceIDAuthService
```

The tests use a temporary directory owned by the current test user. They do not
touch the production path, install a LaunchDaemon, or modify PAM.

## Not implemented yet

- LaunchDaemon lifecycle, XPC listener, caller audit-token/code-signature checks.
- CameraAgent and a trusted capture/session handshake.
- ArcFace inference in the privileged service.
- Administrator-authorized enrollment and migration.
- PAM-to-service approval path, installer, rollback, and uninstall.
- `su`, loginwindow, screensaver, or FileVault integration.

Until those pieces are implemented and reviewed, the PAM diagnostic responder
continues to return `UNAVAILABLE`; do not install the example PAM rule.
