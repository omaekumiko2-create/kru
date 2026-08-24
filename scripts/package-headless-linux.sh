#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This packaging script must run on Linux." >&2
  exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_root="$(cd "$script_dir/.." && pwd)"
version="$(node -p "require('$project_root/package.json').version")"

case "$(uname -m)" in
  x86_64) package_arch="x64" ;;
  aarch64|arm64) package_arch="arm64" ;;
  *) echo "Unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac

binary_source="$project_root/src-tauri/target/release/kru"
if [[ ! -f "$binary_source" ]]; then
  echo "Headless KRU binary is missing. Run npm run build:headless first." >&2
  exit 1
fi

package_name="KRU_${version}_linux-headless-${package_arch}"
dist_root="$project_root/dist"
stage_root="$dist_root/.headless-linux-stage"
package_root="$stage_root/$package_name"
archive_path="$dist_root/${package_name}.tar.gz"
checksum_path="$archive_path.sha256"

case "$stage_root" in
  "$dist_root"/*) ;;
  *) echo "Headless staging path escaped the dist directory." >&2; exit 1 ;;
esac

rm -rf "$stage_root"
mkdir -p "$package_root"
cp "$binary_source" "$package_root/kru"
chmod +x "$package_root/kru"
cp "$project_root/README.md" "$project_root/README.zh-CN.md" "$project_root/SECURITY.md" "$project_root/LICENSE" "$package_root/"
mkdir -p "$package_root/.github/assets"
cp "$project_root/.github/assets/kru-hero.svg" "$project_root/.github/assets/kru-flow.svg" "$package_root/.github/assets/"
cp -R "$project_root/browser-extension" "$package_root/browser-extension"

(
  cd "$package_root"
  find . -type f ! -name SHA256SUMS.txt -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    > SHA256SUMS.txt
)

rm -f "$archive_path" "$checksum_path"
tar -C "$stage_root" -czf "$archive_path" "$package_name"
sha256sum "$archive_path" | sed "s#  .*#  $(basename "$archive_path")#" > "$checksum_path"
rm -rf "$stage_root"

ls -lh "$archive_path" "$checksum_path"
