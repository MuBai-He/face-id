# Face ID LaunchDaemon packaging

The Face ID app embeds this property list at:

- `Contents/Library/LaunchDaemons/com.mubai.faceid.authd.plist`

The signed helper is embedded at:

- `Contents/Library/PrivilegedHelperTools/faceid-authd`

The app registers and unregisters the daemon through Apple's
`SMAppService.daemon(plistName:)` API. Do not copy this plist manually into
`/Library/LaunchDaemons` and do not bootstrap it with launchctl by hand.

## Code-signing identity

- GUI app identifier: `com.mubai.faceid`
- Daemon identifier: `com.mubai.faceid.authd`
- Mach service: `com.mubai.faceid.authd`

The app and daemon must be signed by the same Apple Developer Team. The daemon
validates its own code signature and derives the Team ID used to pin the GUI
client. The app independently pins the daemon's identifier and Team ID.

The current daemon implements only a status endpoint and always returns
`unavailable`. It is not connected to camera capture, enrollment, template
matching, or PAM approval. Do not enable the example PAM rule.

## Installation safety

Registration is opt-in from the app's About page. Install the signed app in
`/Applications` or `~/Applications` before registering it; the app blocks
registration from transient Xcode DerivedData paths. macOS may require the user
to approve the background service in System Settings > General > Login Items.

Unregister through the app's Service Management action. No PAM configuration,
AuthorizationDB, SIP, or FileVault settings are changed.
