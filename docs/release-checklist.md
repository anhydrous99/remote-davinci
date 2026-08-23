# Release checklist

This is the release gate for the macOS companion and iOS/iPadOS controller.
Source builds, simulator tests, and ad-hoc signatures are not customer release
evidence.

## 1. Prepare the candidate

- Work from a clean, reviewed commit on `main`.
- Confirm the companion and controller use the intended display version and
  monotonically increasing build number.
- Confirm the production relay account, region, alarms, and operator
  subscription before producing customer artifacts.
- Run:

  ```sh
  make bootstrap
  make check
  go test -race -count=1 ./...
  make companion-app-check
  make controller-check
  make controller-ios-build
  make companion-release-check
  go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
  npm --prefix infra/cdk audit --audit-level=high
  ```

- Complete the physical-device, live AWS, real Resolve, rotation, and soak
  phases in [`e2e-test-plan.md`](e2e-test-plan.md).

## 2. Archive the Mac companion

Use a Developer ID Application certificate. Xcode signs the embedded Go helper
before it signs the outer app; do not use `codesign --deep` to create the
signature.

```sh
RELEASE_ARCHIVE_PATH="$PWD/.build/release/RemoteDavinciCompanion.xcarchive"
xcodebuild archive \
  -project apps/companion/RemoteDavinciCompanion.xcodeproj \
  -scheme RemoteDavinciCompanion \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -archivePath "$RELEASE_ARCHIVE_PATH" \
  DEVELOPMENT_TEAM="YOUR_TEAM_ID" \
  CODE_SIGN_STYLE=Automatic
```

Export the Developer ID application from Xcode Organizer for the first beta.
Automate export only after the manual signing path has succeeded repeatedly.

Before notarization, inspect both signatures:

```sh
RELEASE_APP_PATH="/absolute/path/to/Remote DaVinci Companion.app"
codesign -d --verbose=4 "$RELEASE_APP_PATH"
codesign -d --verbose=4 \
  "$RELEASE_APP_PATH/Contents/MacOS/remote-davinci-companion"
codesign --verify --deep --strict --verbose=2 "$RELEASE_APP_PATH"
```

Both executables must have the intended TeamIdentifier, hardened runtime, and
secure timestamp.

## 3. Notarize and staple

Store App Store Connect credentials in a Keychain profile; never place them in
the repository or shell history.

```sh
RELEASE_APP_PATH="/absolute/path/to/Remote DaVinci Companion.app"
RELEASE_ZIP_PATH="$PWD/.build/release/Remote-DaVinci-Companion.zip"
ditto -c -k --keepParent "$RELEASE_APP_PATH" "$RELEASE_ZIP_PATH"
xcrun notarytool submit "$RELEASE_ZIP_PATH" \
  --keychain-profile remote-davinci-notary \
  --wait
xcrun stapler staple "$RELEASE_APP_PATH"
xcrun stapler validate "$RELEASE_APP_PATH"
spctl --assess --type execute --verbose=4 "$RELEASE_APP_PATH"
```

Recreate the distribution ZIP after stapling and publish its SHA-256 checksum
with the artifact.

## 4. Archive the controller

- Open `apps/controller/RemoteDavinciController.swiftpm` in Xcode.
- Select a generic iOS device and the Release configuration.
- Confirm the production bundle identifier, team, version, build number, icon,
  and privacy metadata.
- Archive and run Xcode validation.
- Upload to TestFlight and distribute first to the internal group.
- Install from TestFlight on an iPhone and iPad that have never received a
  development build.

## 5. Clean-machine acceptance

On a supported Mac without Xcode, Go, or a repository checkout:

- Gatekeeper accepts the stapled companion.
- The helper launches from the application bundle.
- Login-Keychain storage works after first launch and after upgrade.
- A legacy mode-0600 file enrollment migrates only after successful Keychain readback.
- The companion survives quit/relaunch and Mac sleep/wake.
- QR and pasted-code enrollment work with the TestFlight controller.
- All granted controls work against a supported Resolve Studio installation.
- Diagnostics contain no bearer credentials, pairing secrets, Noise material,
  message bodies, or plaintext control payloads.

## 6. Release evidence and rollback

Record the commit, artifact hashes, notarization submission ID, TestFlight build,
relay stack version, test devices, Resolve version, performance report, open
exceptions, and approver in the release record. Retain the previous signed Mac
artifact and relay commit until the new candidate completes the staged rollout.
