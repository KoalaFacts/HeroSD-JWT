#!/usr/bin/env bash
# Verify exactly the core and symbol packages produced by the pinned Create Release run.
# Usage: verify_release_asset_hashes.sh VERSION PACKAGE_DIRECTORY NUPKG_SHA256 SNUPKG_SHA256
set -euo pipefail
version="${1:?Provide the release version}"
package_dir="${2:?Provide the package directory}"
nupkg_sha256="${3:?Provide the main package SHA-256}"
snupkg_sha256="${4:?Provide the symbol package SHA-256}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]] ||
   [[ ! "$nupkg_sha256" =~ ^[0-9a-f]{64}$ ]] ||
   [[ ! "$snupkg_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Invalid release version or SHA-256 digest" >&2
  exit 1
fi

# sha256sum exits non-zero for a missing or altered artifact; never proceed to attestation/publish.
printf '%s  %s\n' "$nupkg_sha256" "$package_dir/HeroSD-JWT.$version.nupkg" \
  "$snupkg_sha256" "$package_dir/HeroSD-JWT.$version.snupkg" | sha256sum --check --status -
echo "Both release packages match the exact Create Release artifact hashes."
