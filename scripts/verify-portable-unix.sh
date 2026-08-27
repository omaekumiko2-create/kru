#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <archive> <macos|linux-gui|linux-headless>" >&2
  exit 1
fi

archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
kind="$2"
project_root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

case "$kind" in
  macos) /usr/bin/ditto -x -k "$archive" "$work" ;;
  linux-gui|linux-headless) tar -xzf "$archive" -C "$work" ;;
  *) echo "Unknown package kind: $kind" >&2; exit 1 ;;
esac

mapfile_command=(find "$work" -mindepth 1 -maxdepth 1 -type d ! -name __MACOSX -print)
if [[ "$(uname -s)" == "Darwin" ]]; then
  package_roots=()
  while IFS= read -r entry; do package_roots+=("$entry"); done < <("${mapfile_command[@]}")
else
  mapfile -t package_roots < <("${mapfile_command[@]}")
fi
[[ ${#package_roots[@]} -eq 1 ]] || { echo "Archive must contain exactly one top-level directory." >&2; exit 1; }
root="${package_roots[0]}"

test -f "$root/README.md"
test -f "$root/LICENSE"
test -f "$root/browser-extension/manifest.json"
test -f "$root/SHA256SUMS.txt"
(
  cd "$root"
  if [[ "$kind" == "macos" ]]; then shasum -a 256 -c SHA256SUMS.txt; else sha256sum -c SHA256SUMS.txt; fi
)

case "$kind" in
  macos)
    executable="$root/KRU.app/Contents/MacOS/kru"
    test -x "$executable"
    /usr/bin/codesign --verify --deep --strict --verbose=2 "$root/KRU.app"
    if [[ "${KRU_REQUIRE_NOTARIZED:-0}" == "1" ]]; then
      signature_details="$(/usr/bin/codesign --display --verbose=4 "$root/KRU.app" 2>&1)"
      grep -Fq "Authority=Developer ID Application:" <<<"$signature_details"
      grep -Fq "runtime" <<<"$signature_details"
      grep -Fq "Timestamp=" <<<"$signature_details"
      /usr/bin/xcrun stapler validate "$root/KRU.app"
      /usr/sbin/spctl --assess --type execute --verbose=4 "$root/KRU.app"
    fi
    ;;
  linux-gui)
    executable="$root/kru"
    test -x "$executable"
    test -x "$root/KRU.AppImage"
    ;;
  linux-headless)
    executable="$root/kru"
    test -x "$executable"
    ;;
esac

node "$project_root/scripts/smoke-cli.mjs" "$executable"
