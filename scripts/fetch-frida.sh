#!/usr/bin/env bash
# Download the frida-inject binaries the APK bundles, into app/src/main/jniLibs/<abi>/libfridainject.so.
# They are NOT committed (large, in .gitignore); run this once before building, and CI runs it too.
set -euo pipefail
VERSION="${FRIDA_VERSION:-17.26.2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
declare -A ABIS=( [arm64-v8a]=android-arm64 [x86_64]=android-x86_64 )
for abi in "${!ABIS[@]}"; do
  asset="frida-inject-${VERSION}-${ABIS[$abi]}.xz"
  dest="$ROOT/app/src/main/jniLibs/$abi"
  mkdir -p "$dest"
  echo "==> $asset -> $dest/libfridainject.so"
  curl -fL --retry 4 -o "/tmp/$asset" \
    "https://github.com/frida/frida/releases/download/${VERSION}/${asset}"
  xz -dc "/tmp/$asset" > "$dest/libfridainject.so"
  rm -f "/tmp/$asset"
done
echo "frida-inject $VERSION staged."
