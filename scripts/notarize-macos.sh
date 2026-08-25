#!/bin/bash

set -euo pipefail

app_path="${1:-}"
if [[ -z "$app_path" || ! -d "$app_path" ]]; then
  echo "Usage: $0 /path/to/App.app" >&2
  exit 2
fi

for variable_name in APPLE_API_KEY_PATH APPLE_API_KEY APPLE_API_ISSUER; do
  if [[ -z "${!variable_name:-}" ]]; then
    echo "Missing required environment variable: $variable_name" >&2
    exit 2
  fi
done

poll_interval="${NOTARY_POLL_INTERVAL_SECONDS:-60}"
max_wait="${NOTARY_MAX_WAIT_SECONDS:-19800}"
case "$poll_interval:$max_wait" in
  *[!0-9:]*|:*)
    echo "Polling interval and maximum wait must be non-negative integers." >&2
    exit 2
    ;;
esac
if (( poll_interval < 1 || max_wait < 1 )); then
  echo "Polling interval and maximum wait must be greater than zero." >&2
  exit 2
fi

temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
work_dir="$(mktemp -d "$temp_root/kru-notary.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

notary_zip="$work_dir/KRU.zip"
submission_json="$work_dir/submission.json"
info_json="$work_dir/info.json"

echo "Verifying Developer ID signature before notarization..."
codesign --verify --deep --strict --verbose=2 "$app_path"

echo "Creating notarization archive..."
ditto -c -k --sequesterRsrc --keepParent "$app_path" "$notary_zip"

auth_arguments=(
  --key "$APPLE_API_KEY_PATH"
  --key-id "$APPLE_API_KEY"
  --issuer "$APPLE_API_ISSUER"
)

echo "Submitting application to Apple notary service..."
xcrun notarytool submit \
  "$notary_zip" \
  "${auth_arguments[@]}" \
  --output-format json >"$submission_json"

submission_id="$(plutil -extract id raw -o - "$submission_json")"
if [[ -z "$submission_id" ]]; then
  echo "Apple did not return a notarization submission ID." >&2
  cat "$submission_json" >&2
  exit 1
fi
echo "Apple notarization submission: $submission_id"

started_at="$(date +%s)"
deadline=$(( started_at + max_wait ))
attempt=0

while (( $(date +%s) < deadline )); do
  attempt=$(( attempt + 1 ))
  if xcrun notarytool info \
    "$submission_id" \
    "${auth_arguments[@]}" \
    --output-format json >"$info_json"; then
    notary_status="$(plutil -extract status raw -o - "$info_json")"
    echo "Notarization status (attempt $attempt): $notary_status"
    case "$notary_status" in
      Accepted)
        for staple_attempt in 1 2 3 4 5; do
          if xcrun stapler staple "$app_path"; then
            xcrun stapler validate "$app_path"
            echo "Apple notarization accepted and ticket stapled."
            exit 0
          fi
          echo "Stapling attempt $staple_attempt failed; retrying in 30 seconds..." >&2
          sleep 30
        done
        echo "Apple accepted the submission, but the ticket could not be stapled." >&2
        exit 1
        ;;
      Invalid|Rejected)
        echo "Apple rejected notarization submission $submission_id." >&2
        xcrun notarytool log \
          "$submission_id" \
          "${auth_arguments[@]}" || true
        exit 1
        ;;
      "In Progress")
        ;;
      *)
        echo "Unexpected Apple notarization status: $notary_status" >&2
        cat "$info_json" >&2
        exit 1
        ;;
    esac
  else
    echo "Notarization status check $attempt failed; treating it as a transient network error." >&2
  fi
  sleep "$poll_interval"
done

echo "Apple submission $submission_id is still processing after $max_wait seconds." >&2
echo "The submission remains active on Apple's servers and can be checked later." >&2
exit 1
