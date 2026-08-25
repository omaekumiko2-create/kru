#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -d "$1" ]]; then
  echo "usage: $0 <KRU.app>" >&2
  exit 1
fi

app_path="$1"
signature_details="$(/usr/bin/codesign --display --verbose=4 "$app_path" 2>&1)"

grep -Fq "Authority=Developer ID Application:" <<<"$signature_details"
grep -Fq "runtime" <<<"$signature_details"
grep -Fq "Timestamp=" <<<"$signature_details"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$app_path"
/usr/bin/xcrun stapler validate "$app_path"
/usr/sbin/spctl --assess --type execute --verbose=4 "$app_path"
