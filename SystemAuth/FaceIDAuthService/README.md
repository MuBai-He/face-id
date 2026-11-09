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


## Recognition and liveness extension

The `FaceIDAuthRecognition` target now contains:

- `ArcFaceModelRunner`: loads the checked-in Core ML model from an explicit path, verifies the 112x112 image input and 512-value output, rejects unsafe model bundle paths, and returns finite L2-normalized vectors.
- `FaceIDRecognitionEngine`: runs Vision detection and the app's canonical 5-point/2-point alignment. System-auth recognition rejects zero/multiple faces, small faces, low or unavailable capture quality, and the padded-crop alignment fallback. It has no Vision Feature Print fallback.
- The app's landmark geometry and current passive liveness cues: specular glare, device-bezel detection, planar-vs-3D geometry, yaw/nose-depth consistency, and blink dynamics.
- `FaceIDLivenessEngine`: uses the heavy-mode evaluator, keeps deny cues active, requires at least 8 frames, rejects non-monotonic timestamps and gaps over one second, and returns denial if a scan is finished without a positive cue.

The macOS CI loads the real checked-in `ArcFace.mlmodelc` and runs inference on a synthetic aligned image. Tests also verify that a blank frame cannot produce a recognition embedding, that heavy mode does not auto-confirm without a positive cue, and that a deny cue overrides an earlier confirmation.

**Security limitation:** this is still passive RGB-camera liveness, not a random action challenge. It has not been calibrated against real users, replay videos, high-quality displays, or generated video. A blink or head-turn in a replay may satisfy some passive cues. It must not be treated as equivalent to Touch ID or used to approve PAM yet.

The recognition sources are currently mirrored from the app into the new package so the service can be developed independently. A later refactor should move the shared implementation into a single reusable target to prevent drift.


## UID-scoped template matching

The recognition target also exposes `FaceIDTemplateMatcher`:

- Requires the requested UID explicitly and never matches another account's template.
- Ignores disabled identities and non-ArcFace model identifiers.
- Requires at least three valid 512-dimensional normalized samples.
- Uses the mean of the three best sample similarities plus a lower centroid sanity gate; one unusually good frame cannot carry an otherwise poor match.
- Requires the caller to pass an explicit similarity threshold (minimum 0.30). There is no silent default inherited from the app's UI settings.

The threshold is only a parameterized policy hook. It is not calibrated for system authentication and must not be enabled in PAM until evaluated on representative genuine/impostor data.


## Phase 3 bootstrap: privileged XPC daemon

The package now defines an executable product named faceid-authd, a small
FaceIDAuthIPC policy module, and a LaunchDaemon packaging template.

- The daemon refuses to run unless its effective UID is root.
- It uses a launchd Mach service and Apple's public
  xpc_connection_set_peer_code_signing_requirement API. The kernel checks the
  peer's code signature for every message; the implementation does not use a
  PID-only lookup, private auditToken properties, or private XPC audit-token APIs.
- The signing requirement is loaded only from a root-owned, mode-0700 directory
  and a root-owned, mode-0600 regular file. The requirement pins the app bundle
  identifier and the 10-character Developer ID Team ID.
- If the trust policy is absent or malformed, every incoming connection is
  rejected. There is no development-mode bypass.
- The only XPC operation is a status probe. It always replies unavailable.
  There is no method that can approve PAM, enroll a user, or accept a client-
  supplied embedding or liveness result.
- The daemon checks that a peer is non-root and has a nonzero audit-session ID
  before replying. Full console-session/PAM-session binding is still outstanding.

The LaunchDaemon plist is a packaging template, not an install instruction.
The installer must derive the actual Team ID from the signed application,
write the trust requirement as root, sign and install the daemon, and support
rollback/uninstall. No PAM stack, AuthorizationDB, SIP, or FileVault setting
is changed by this phase.
