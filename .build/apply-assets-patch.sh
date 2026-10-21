#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
patch_file="$repo_dir/.build/assets-features.patch"
assets_dir="$repo_dir/assets"

if [[ ! -f "$assets_dir/package.json" ]]; then
  echo "Initialize the frontend first: git submodule update --init assets" >&2
  exit 1
fi

if git -C "$assets_dir" apply --check "$patch_file" 2>/dev/null; then
  git -C "$assets_dir" apply "$patch_file"
elif git -C "$assets_dir" apply --reverse --check "$patch_file" 2>/dev/null; then
  # Already applied; builds can safely invoke this repeatedly.
  exit 0
else
  echo "The frontend feature patch conflicts with the current assets checkout." >&2
  echo "Review the assets changes before building." >&2
  exit 1
fi
