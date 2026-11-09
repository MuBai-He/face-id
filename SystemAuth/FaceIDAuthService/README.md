# FaceIDAuthService foundation

This Swift package contains encrypted template storage, ArcFace recognition,
XPC IPC, and the status-only faceid-authd LaunchDaemon executable. It is
**not yet a working face-authentication feature**: the daemon's only XPC
operation returns unavailable, and no camera capture or PAM approval path
is connected.

## Current contract

- Production initialization is parameterless and requires effective UID 0.
- The store lives at
  `/Library/Application Support/com.mubai.faceid`, owned by root with no
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

- CameraAgent and a trusted capture/session handshake.
- Administrator-authorized enrollment and migration into the root-owned store.
- Binding the PAM request to the active console/audit session.
- A production PAM-to-service approval path and end-to-end security review.
- Signed release packaging, rollback, and uninstall verification on real Macs.
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
- The signing requirement is derived from the daemon's own verified code
  signature. It pins the GUI app bundle identifier and the daemon's 10-character
  Apple Developer Team ID; no mutable trust-policy file is read.
- If the daemon is unsigned, ad-hoc signed, or has an unexpected signing
  identifier, it refuses to start. There is no development-mode bypass.
- The only XPC operation is a status probe. It always replies unavailable.
  There is no method that can approve PAM, enroll a user, or accept a client-
  supplied embedding or liveness result.
- The daemon checks that a peer is non-root and has a nonzero audit-session ID
  before replying. Full console-session/PAM-session binding is still outstanding.

The LaunchDaemon plist is now embedded in the app bundle for SMAppService.
The daemon binary is built as a separate Xcode tool target and copied into
Contents/Library/PrivilegedHelperTools. Registration and unregistration are
handled by SMAppService with explicit user approval. No PAM stack,
AuthorizationDB, SIP, or FileVault setting is changed by this phase.


## Phase 3 extension: app-side XPC client

The IPC library now includes a one-shot status client:

- Reads the Team ID from the current process's code signature using Security.framework.
- Builds a daemon requirement pinning both com.mubai.faceid.authd and the same Team ID.
- Applies the peer code-signing requirement before activating the XPC connection.
- Sends only protocol version 1 and the status operation.
- Verifies that the reply peer has EUID 0, checks protocol version and known response reasons, and rejects any status other than unavailable.
- Uses a bounded timeout and cancels the one-shot connection after the reply.

This client intentionally cannot return an authorization success. It is linked into the Face ID app's Xcode project, but has not yet been integration-tested against an installed, correctly signed LaunchDaemon. The app and daemon must be signed by the same Apple Developer Team.


## Phase 3 extension: Face ID app integration

The Face ID Xcode project now references this package locally and links the
FaceIDAuthIPC product into the app target. The About page exposes an explicit
"系统认证服务" connectivity check backed by SystemAuthServiceStatus.

This is diagnostic-only. The check asks the daemon for its status and can
report that the daemon is reachable but authentication is not ready. It does
not start camera capture, enroll a face, approve an authentication request, or
change any PAM configuration. If the app is ad-hoc signed or has no Developer
Team ID, the client refuses to connect.


## Phase 4: bundled LaunchDaemon registration

The Face ID Xcode project now builds the \`faceid-authd\` command-line target,
embeds it at \`Contents/Library/PrivilegedHelperTools/faceid-authd\`, and embeds
its launchd property list at \`Contents/Library/LaunchDaemons/\`. The plist uses
\`BundleProgram\` and is registered through Apple's \`SMAppService.daemon\`
API (macOS 13+), not by writing directly to \`/Library/LaunchDaemons\`.

The daemon derives its client code-signing requirement from its own verified
code signature. It requires the daemon identifier \`com.mubai.faceid.authd\`
and a valid Apple Developer Team ID, then pins the GUI app identifier
\`com.mubai.faceid\` to that same Team ID. An ad-hoc/unsigned daemon refuses
to start. This removes the previous root-owned trust-policy file from the
installation flow.

The About page provides explicit Register, open Login Items for approval,
Unregister, refresh, and XPC diagnostic actions. Registration is opt-in and
requires macOS user approval. Unregister stops the helper through Service
Management. No PAM configuration is changed.

**Still not an authentication feature:** the XPC endpoint only returns
\`unavailable\`; no camera capture, enrollment, template migration, PAM socket
bridge, or approval path exists. Do not add the PAM rule or use this service
to authenticate privileged operations.


## Fork identity and Keychain migration

This fork uses the `com.mubai.faceid` namespace for the GUI app, Keychain
service/access group, privileged daemon, and Mach service. The Xcode test bundle
uses `com.mubai.faceid.tests`. The PAM transport socket is
`/var/run/com.mubai.faceid.authd.sock`.

Changing the signing Team and Keychain access group creates a new Keychain
namespace. Existing Keychain items from the original developer's Team are not
deleted, but this fork cannot automatically read them under the new Team ID.
Do not delete the old app or Keychain items as part of this code migration.
A deliberate migration/re-enrollment flow is still required.
