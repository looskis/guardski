#!/usr/bin/env bash
# Tag a release. The tag push triggers .github/workflows/release.yml, which builds the
# distributions, publishes the GitHub release, and updates the Homebrew tap.
set -euo pipefail

cd "$(dirname "$0")/.."

version="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
tag="v$version"

if [ -n "$(git status --porcelain)" ]; then
  echo "working tree is not clean" >&2
  exit 1
fi

if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
  echo "release from main" >&2
  exit 1
fi

grep -q "## \[$version\]" CHANGELOG.md || {
  echo "CHANGELOG.md has no section for $version" >&2
  exit 1
}

git tag -s "$tag" -m "Guardski $version"
git push origin main
git push origin "$tag"
echo "released $tag"
