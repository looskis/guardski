#!/usr/bin/env bash
# Copy the published formula into looskis/homebrew-tap. The release workflow does this
# itself when TAP_GITHUB_TOKEN is configured; run this locally otherwise.
set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')}"
tag="v$version"
tap_repo="looskis/homebrew-tap"
branch="guardski-$version"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

gh release download "$tag" --pattern guardski.rb --dir "$work"
gh repo clone "$tap_repo" "$work/tap" -- --depth 1
cp "$work/guardski.rb" "$work/tap/Formula/guardski.rb"

cd "$work/tap"
if git diff --quiet -- Formula/guardski.rb; then
  echo "tap already has guardski $version"
  exit 0
fi

git checkout -b "$branch"
git add Formula/guardski.rb
git commit -m "guardski $version"
git push -u origin "$branch"
gh pr create --repo "$tap_repo" --head "$branch" \
  --title "guardski $version" \
  --body "Formula for Guardski $version, published from $tag."
gh pr merge --repo "$tap_repo" "$branch" --squash --delete-branch
