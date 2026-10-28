#!/bin/bash
set -euo pipefail

APP="${1:?Usage: IP_GUARD_TEAM_ID=... IP_GUARD_SIGN_IDENTITY=... IP_GUARD_APP_PROFILE=... IP_GUARD_FILTER_PROFILE=... bash sign-local.sh /Applications/IP\ Guard.app}"
TEAM="${IP_GUARD_TEAM_ID:?Set the Apple Team ID locally}"
IDENTITY="${IP_GUARD_SIGN_IDENTITY:?Set the Developer ID Application identity from your Mac keychain}"
APP_PROFILE="${IP_GUARD_APP_PROFILE:?Set the host provisioning profile path}"
FILTER_PROFILE="${IP_GUARD_FILTER_PROFILE:?Set the network extension provisioning profile path}"
[[ "$TEAM" =~ ^[A-Z0-9]{10}$ ]] || { echo 'Invalid Team ID' >&2; exit 1; }
[[ "$APP" = /Applications/*.app && -d "$APP/Contents" && ! -L "$APP" ]] || { echo 'Move the test app into /Applications first; symlink destinations are not accepted' >&2; exit 1; }
[[ "$IDENTITY" == "Developer ID Application:"*"($TEAM)" ]] || { echo 'The signing identity must be a Developer ID Application certificate for this Team ID' >&2; exit 1; }
PLIST=/usr/libexec/PlistBuddy
[[ "$($PLIST -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist")" = com.ip-guard.desktop ]] || { echo 'Unexpected application identifier' >&2; exit 1; }
TMP_BASE="${TMPDIR:-/tmp}/ipguard-sign."
SIGN_TMP="$(mktemp -d "${TMP_BASE}XXXXXX")"
cleanup() { case "$SIGN_TMP" in "$TMP_BASE"*) rm -rf -- "$SIGN_TMP" ;; *) echo 'Refusing unexpected cleanup path' >&2 ;; esac; }
trap cleanup EXIT
for kind in APP FILTER; do
  if [[ "$kind" = APP ]]; then profile="$APP_PROFILE"; bundle=com.ip-guard.desktop; else profile="$FILTER_PROFILE"; bundle=com.ip-guard.desktop.filter; fi
  security cms -D -i "$profile" > "$SIGN_TMP/$kind.plist"
  [[ "$($PLIST -c 'Print :TeamIdentifier:0' "$SIGN_TMP/$kind.plist")" = "$TEAM" ]] || { echo "Wrong profile team: $kind" >&2; exit 1; }
  [[ "$($PLIST -c 'Print :Entitlements:com.apple.application-identifier' "$SIGN_TMP/$kind.plist")" = "$TEAM.$bundle" ]] || { echo "Wrong profile application identifier: $kind" >&2; exit 1; }
done

BUILD="$APP/Contents/Resources/mac-build"
EXTENSION="$APP/Contents/Library/SystemExtensions/com.ip-guard.desktop.filter.systemextension"
CONTROL="$APP/Contents/MacOS/IpGuardMacControl"
if [[ -d "$BUILD/com.ip-guard.desktop.filter.systemextension" ]]; then
  [[ ! -e "$EXTENSION" && ! -e "$CONTROL" ]] || { echo 'Destination already exists; use a fresh extracted preview before signing again' >&2; exit 1; }
  mkdir -p "$APP/Contents/Library/SystemExtensions"
  mv "$BUILD/com.ip-guard.desktop.filter.systemextension" "$EXTENSION"
  mv "$BUILD/IpGuardMacControl" "$CONTROL"
  rm -f -- "$BUILD/PolicyTests" "$BUILD/ProcessMonitorTests"
  rmdir "$BUILD"
fi
[[ -f "$CONTROL" && -d "$EXTENSION" ]] || { echo 'Missing compiled macOS components' >&2; exit 1; }
$PLIST -c "Set :NetworkExtension:NEMachServiceName $TEAM.com.ip-guard.desktop.policy" "$EXTENSION/Contents/Info.plist"
$PLIST -c 'Add :NSSystemExtensionUsageDescription string IP Guard validates the independently locked IP before allowing selected applications to use the network.' "$APP/Contents/Info.plist" 2>/dev/null || true
cp "$APP_PROFILE" "$APP/Contents/embedded.provisionprofile"
cp "$FILTER_PROFILE" "$EXTENSION/Contents/embedded.provisionprofile"
cat > "$SIGN_TMP/base.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>com.apple.security.cs.allow-jit</key><true/>
<key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>
PLIST
cat > "$SIGN_TMP/host.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>com.apple.security.cs.allow-jit</key><true/>
<key>com.apple.security.cs.disable-library-validation</key><true/>
<key>com.apple.developer.system-extension.install</key><true/>
<key>com.apple.developer.networking.networkextension</key><array><string>content-filter-provider-systemextension</string></array>
<key>com.apple.security.application-groups</key><array><string>$TEAM.com.ip-guard.desktop</string></array>
<key>com.apple.application-identifier</key><string>$TEAM.com.ip-guard.desktop</string>
<key>com.apple.developer.team-identifier</key><string>$TEAM</string>
</dict></plist>
PLIST
cat > "$SIGN_TMP/filter.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.developer.networking.networkextension</key><array><string>content-filter-provider-systemextension</string></array>
<key>com.apple.security.application-groups</key><array><string>$TEAM.com.ip-guard.desktop</string></array>
<key>com.apple.application-identifier</key><string>$TEAM.com.ip-guard.desktop.filter</string>
<key>com.apple.developer.team-identifier</key><string>$TEAM</string>
</dict></plist>
PLIST

# Sign nested code before its enclosing bundle; restricted network entitlements apply
# only to the host/controller and filter, never to Chromium's renderer helpers.
while IFS= read -r -d '' binary; do
  if file -b "$binary" | grep -q 'Mach-O'; then codesign --force --timestamp --options runtime --entitlements "$SIGN_TMP/base.plist" --sign "$IDENTITY" "$binary"; fi
done < <(find "$APP/Contents/Frameworks" -type f -print0)
while IFS= read -r -d '' bundle; do
  codesign --force --timestamp --options runtime --entitlements "$SIGN_TMP/base.plist" --sign "$IDENTITY" "$bundle"
done < <(find "$APP/Contents/Frameworks" -depth -type d \( -name '*.framework' -o -name '*.app' \) -print0)
codesign --force --timestamp --options runtime --entitlements "$SIGN_TMP/filter.plist" --sign "$IDENTITY" "$EXTENSION"
codesign --force --timestamp --options runtime --identifier com.ip-guard.desktop --entitlements "$SIGN_TMP/host.plist" --sign "$IDENTITY" "$CONTROL"
codesign --force --timestamp --options runtime --entitlements "$SIGN_TMP/host.plist" --sign "$IDENTITY" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
if [[ -n "${IP_GUARD_NOTARY_PROFILE:-}" ]]; then
  ditto -c -k --keepParent "$APP" "$SIGN_TMP/IP-Guard-signed.zip"
  xcrun notarytool submit "$SIGN_TMP/IP-Guard-signed.zip" --keychain-profile "$IP_GUARD_NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP"
  spctl --assess --type execute --verbose=2 "$APP"
  echo 'Signed and notarized. Open IP Guard and enable the macOS filter from protection settings.'
else
  echo 'Signed locally. Complete notarization before activating the system extension; set IP_GUARD_NOTARY_PROFILE to a credentials profile in your Mac keychain and rerun this script.'
fi
