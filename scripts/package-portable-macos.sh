#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This packaging script must run on macOS." >&2
  exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_root="$(cd "$script_dir/.." && pwd)"
version="$(node -p "require('$project_root/package.json').version")"

case "$(uname -m)" in
  arm64) package_arch="arm64" ;;
  x86_64) package_arch="x64" ;;
  *) echo "Unsupported macOS architecture: $(uname -m)" >&2; exit 1 ;;
esac

package_name="KRU_${version}_macos-${package_arch}"
app_source="$project_root/src-tauri/target/release/bundle/macos/KRU.app"
dist_root="$project_root/dist"
stage_root="$dist_root/.portable-macos-stage"
package_root="$stage_root/$package_name"
archive_path="$dist_root/${package_name}-portable.zip"
checksum_path="$archive_path.sha256"

if [[ ! -d "$app_source" ]]; then
  echo "KRU.app is missing. Run npm run build:mac first." >&2
  exit 1
fi

case "$stage_root" in
  "$dist_root"/*) ;;
  *) echo "Portable staging path escaped the dist directory." >&2; exit 1 ;;
esac

rm -rf "$stage_root"
mkdir -p "$package_root"
/usr/bin/ditto "$app_source" "$package_root/KRU.app"
cp "$project_root/README.md" "$project_root/README.zh-CN.md" "$project_root/SECURITY.md" "$project_root/LICENSE" "$package_root/"
mkdir -p "$package_root/.github/assets"
cp "$project_root/.github/assets/kru-hero.svg" "$project_root/.github/assets/kru-flow.svg" "$package_root/.github/assets/"
cp -R "$project_root/browser-extension" "$package_root/browser-extension"

# Ad-hoc signing keeps the local bundle internally consistent. Public releases
# can replace this with Developer ID signing and notarization later.
/usr/bin/codesign --force --deep --sign - "$package_root/KRU.app"

(
  cd "$package_root"
  find . -type f ! -name SHA256SUMS.txt -print0 \
    | sort -z \
    | xargs -0 shasum -a 256 \
    > SHA256SUMS.txt
)

rm -f "$archive_path" "$checksum_path"
(
  cd "$stage_root"
  /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$package_name" "$archive_path"
)
archive_hash="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
printf '%s  %s\n' "$archive_hash" "$(basename "$archive_path")" > "$checksum_path"
rm -rf "$stage_root"

ls -lh "$archive_path" "$checksum_path"
