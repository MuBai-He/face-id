# macOS PAM authentication bootstrap

Based on `joe0515/face-id` at `287babef7a4ac9e2b05a3e38501b16c631bf4bb7`.
Chinese status: [README.zh-CN.md](README.zh-CN.md).

**Not a working face-authentication feature. Do not install the example PAM
rule.** The supplied diagnostic responder always returns `UNAVAILABLE`; no
camera frames or face templates are connected to the privileged service.
Nothing here installs a daemon or modifies PAM, AuthorizationDB, loginwindow,
FileVault or SIP. Existing app behavior is unchanged.

## Implemented

- `FaceRecognitionPipeline.forSystemAuthentication()` constructs ArcFace or
  throws. It cannot silently fall back to Vision Feature Print. The existing
  app initializer is unchanged; the new factory is not wired to system auth yet.
- `PAM/pam_faceid.c` is a thin, sudo-only adapter. It verifies the socket's
  type, ownership and permissions, then the connected peer's root UID.
- Every request has a new 128-bit random nonce. Replies must have the correct
  magic, version, nonce and explicit `APPROVED` status. Partial I/O shares a
  single four-second monotonic transport deadline, checked again before success.
- The invoking UID must equal the account selected by `PAM_USER`. Policies
  requiring a different account (`rootpw`, `targetpw`, `runaspw`) fall through;
  recognizing the invoker must not satisfy another user's authentication.
- Non-sudo services, silent auth, nonempty `PAM_RHOST`, unknown module options,
  missing identities and root invokers are declined. **An empty RHOST is not
  proof of a local console session**, and does not reliably detect sudo over SSH.
- The root-only probe never approves anyone, bounds partial I/O, and refuses to
  replace an existing path. Its timeout is not renewed by trickled bytes.
- 33 isolated regression tests cover approval/rejection, malformed replies,
  replay, deadlines, account selection, socket permissions, symlinks, a root-owned
  socket served by a non-root process, and the probe's non-approving behavior.

## Build and test

macOS 15+ with Command Line Tools, compile only:

```sh
make -C SystemAuth/PAM
make -C SystemAuth/Daemon
```

In a disposable macOS test machine or Linux container, with Python 3.9+:

```sh
sudo python3 SystemAuth/tests/test_pam_transport.py
```

The tests compile with fake PAM declarations and an isolated root-owned socket
under a temporary directory. Their return-code numbers are fixtures, not a claim
about macOS's PAM ABI. They do not load a module into sudo or modify system files.
Do not run the probe as a persistent service. The test process drops a child to
`nobody` to verify peer credentials; it needs a POSIX environment supporting that.

The workflow separately compiles the C module against real macOS SDK headers and
libpam, then runs the shim-based tests on Linux/macOS. It does **not** build the
Swift app or validate TCC, the model, camera access, actual PAM stack control flags,
code-signature loading or native login. A workflow definition is not evidence that
those checks ran; consult its run results.

The C components are outside `FaceID/` deliberately, so Xcode's synchronized app
source group does not accidentally compile a PAM module into the GUI app.

## Local protocol, version 1

The fixed path `/var/run/com.mubai.faceid.authd.sock` must be a UID-0-owned
socket with no group/other access (normally `0600`). Its parent must remain
root-controlled. No socket path or identity comes from environment variables.

`PAM/faceid_auth_protocol.h` defines fixed-size network-order messages:

- Request, 112 bytes: magic, version, invoking UID, PID, 16-byte nonce, username,
  service (`sudo`).
- Response, 28 bytes: magic, version, status, echoed nonce.
- Status: `APPROVED=1`, `REJECTED=0`, `UNAVAILABLE=2`. Unknown values fall through.

A nonce echo and UID-0 peer do not prove recognition. Request PID/UID are claims,
not verified audit credentials. Before any real daemon may issue `APPROVED`, it
must independently validate caller identity, account policy, current GUI/audit
session and freshness, then perform its own matching against protected templates.
Do not accept a GUI process's boolean verdict. User-supplied frames also are not
cryptographically trusted camera input.

A supported `auth sufficient` placement lets non-success continue to existing
methods. **Placement matters**: retain the password/Touch ID chain and account
checks, and do not claim that fall-through creates MFA. This code is not suitable
as a `required` factor or a replacement for a complete PAM policy.

## Remaining before enabling sudo

1. Extract a standalone recognition core; add the real, independently verifying
   service, stable signing, bounded concurrency and audit/session validation.
2. Implement administrator-authorized enrollment and root-protected templates.
   Do not adopt user-writable templates as an authentication authority.
3. Implement the camera agent, validate AVFoundation/TCC on each supported macOS
   version, and test liveness. RGB recognition is not Apple Face ID / Secure Enclave.
4. Add an opt-in signed installer with backup, conditional edits and uninstall of
   only its own `sudo_local` rule. Verify the entire stack on a recovery-capable
   test machine before use. Do not change unknown local policies automatically.
5. Treat `su`, passwordless native lock-screen/login and FileVault as separate
   work. This bootstrap implements none of them and does not disable protections.

## References

- Apple Touch ID PAM module reads the account selected for authentication:
  https://github.com/apple-oss-distributions/pam_modules/blob/main/modules/pam_tid/pam_tid.c
- Sudo authentication account policies:
  https://www.sudo.ws/docs/man/sudoers.man/
