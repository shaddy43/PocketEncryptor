#!/usr/bin/env bash
# Builds the release files that are made on the Mac:
#   - the Mac app (zip, Apple Silicon + Intel) and the Mac CLI (Apple Silicon and Intel zips)
# into artifacts/release/v<version>/, and appends their SHA-256 checksums to SHA256SUMS.txt.
#
# Run from the repo folder:   bash scripts/release-mac.sh
# The Windows and Android files are made on the Windows PC with scripts/release-windows.ps1;
# copy that folder's SHA256SUMS.txt here first if you want one combined list.
#
# Signing: without an Apple Developer account the app is signed only ad hoc, so other Macs
# ask the user to allow it once (README, "Download"). For Developer ID signing and
# notarization, see RELEASING.md.
#
# DOTNET overrides the dotnet used (e.g. DOTNET=/usr/local/share/dotnet/dotnet).

set -euo pipefail
cd "$(dirname "$0")/.."
DOTNET="${DOTNET:-dotnet}"
# Neutral source paths (/_/...) in the dlls instead of this Mac's folders, and no .pdb files.
clean=(-p:ContinuousIntegrationBuild=true -p:DebugType=none)

version=$(sed -n 's:.*<ApplicationDisplayVersion>\(.*\)</ApplicationDisplayVersion>.*:\1:p' PocketEncryptor.App/PocketEncryptor.App.csproj | head -n1)
out="artifacts/release/v$version"
mkdir -p "$out"
echo "PocketEncryptor $version -> $out"

# Start from empty Release folders so no older build (with this Mac's paths) is reused.
for p in PocketEncryptor.App PocketEncryptor.Core PocketEncryptor.Cli PocketEncryptor.Tests; do
  rm -rf "$p/bin/Release" "$p/obj/Release"
done

echo "== Tests"
"$DOTNET" test PocketEncryptor.Tests -c Release "${clean[@]}" --nologo

echo "== Mac app"
"$DOTNET" build PocketEncryptor.App -f net10.0-maccatalyst -c Release -p:ValidateXcodeVersion=false "${clean[@]}" --nologo
# The finished universal app is this one; the per-architecture copies lack the sandbox.
app="PocketEncryptor.App/bin/Release/net10.0-maccatalyst/PocketEncryptor.app"
rm -f "$out/PocketEncryptor-$version-macos.zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$out/PocketEncryptor-$version-macos.zip"

for rid in osx-arm64 osx-x64; do
  echo "== Mac CLI ($rid)"
  tmp=$(mktemp -d)
  "$DOTNET" publish PocketEncryptor.Cli -c Release -r "$rid" --self-contained \
    -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true "${clean[@]}" -o "$tmp" --nologo
  name="PocketEncryptor-CLI-$version-macos-${rid#osx-}.zip"
  rm -f "$out/$name"
  ditto -c -k "$tmp/PocketEncryptor" "$out/$name"
  rm -rf "$tmp"
done

# Guard: the release must not contain this Mac's home folder. The CLI compresses its dlls,
# so check the uncompressed build outputs.
if leaks=$(grep -rlF "$HOME" --include='PocketEncryptor*.dll' PocketEncryptor.*/bin/Release PocketEncryptor.*/obj/Release); then
  rm -f "$out"/*-macos*.zip
  echo "Mac files removed: these contain your home folder path:" >&2
  echo "$leaks" >&2
  exit 1
fi

# Append (or refresh) this script's files in the checksum list.
sums="$out/SHA256SUMS.txt"
touch "$sums"
grep -v -e '-macos' "$sums" > "$sums.tmp" || true
(cd "$out" && shasum -a 256 *-macos*.zip) >> "$sums.tmp"
sort -k2 "$sums.tmp" > "$sums" && rm "$sums.tmp"

echo
echo "Done:"
ls -lh "$out"
