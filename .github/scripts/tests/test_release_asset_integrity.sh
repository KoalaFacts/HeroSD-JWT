#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
verify="$root/.github/scripts/verify_release_asset_hashes.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
version=2.0.0
nupkg="$tmp/HeroSD-JWT.$version.nupkg"
snupkg="$tmp/HeroSD-JWT.$version.snupkg"
printf 'packed-core' > "$nupkg"
printf 'packed-symbols' > "$snupkg"
nupkg_sha="$(sha256sum "$nupkg" | cut -d' ' -f1)"
snupkg_sha="$(sha256sum "$snupkg" | cut -d' ' -f1)"

bash "$verify" "$version" "$tmp" "$nupkg_sha" "$snupkg_sha" >/dev/null
printf 'tampered' >> "$nupkg"
if bash "$verify" "$version" "$tmp" "$nupkg_sha" "$snupkg_sha" >/dev/null 2>&1; then
  echo 'Altered core artifact accepted' >&2; exit 1
fi
printf 'packed-core' > "$nupkg"
printf 'tampered' >> "$snupkg"
if bash "$verify" "$version" "$tmp" "$nupkg_sha" "$snupkg_sha" >/dev/null 2>&1; then
  echo 'Altered symbol artifact accepted' >&2; exit 1
fi
printf 'packed-symbols' > "$snupkg"
if bash "$verify" "$version" "$tmp" "${nupkg_sha%?}x" "$snupkg_sha" >/dev/null 2>&1; then
  echo 'Malformed hash accepted' >&2; exit 1
fi
rm "$snupkg"
if bash "$verify" "$version" "$tmp" "$nupkg_sha" "$snupkg_sha" >/dev/null 2>&1; then
  echo 'Missing symbol artifact accepted' >&2; exit 1
fi
echo 'Release artifact integrity regression: valid pair accepted, modified/missing assets rejected.'
