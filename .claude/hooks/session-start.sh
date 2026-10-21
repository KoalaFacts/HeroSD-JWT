#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# Installs the .NET SDKs this repo targets (net8.0 / net9.0 / net10.0) so `dotnet
# build`, `dotnet test`, and `dotnet format` use the same pinned baseline as CI.
# Keep normal locked restore, vulnerability auditing, and analyzer checks enabled.
#
# Runs in async mode: the SDK download happens in the background while the session
# starts, so you are not blocked waiting on ~600 MB of SDKs.
set -euo pipefail

echo '{"async": true, "asyncTimeout": 600000}'

# Only needed in the remote (Claude Code on the web) environment; locally you use your
# own SDK install.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

DOTNET_DIR="$HOME/.dotnet"
INSTALLER="/tmp/dotnet-install.sh"
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}"

# 1. Install the exact SDK versions used by CI and global.json.
SDK_VERSIONS=$(sed -n 's/.*<SupportedSdkVersions>\([^<]*\)<\/SupportedSdkVersions>.*/\1/p' "$PROJECT_DIR/Directory.Build.props")
if [ -z "$SDK_VERSIONS" ]; then
  echo "Could not read SupportedSdkVersions from Directory.Build.props" >&2
  exit 1
fi
if [ ! -x "$INSTALLER" ]; then
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o "$INSTALLER"
  chmod +x "$INSTALLER"
fi
IFS=';' read -ra VERSIONS <<< "$SDK_VERSIONS"
for version in "${VERSIONS[@]}"; do
  "$INSTALLER" --version "$version" --install-dir "$DOTNET_DIR" --no-path --skip-non-versioned-files
done

# 2. Remove only the validation overrides created by older versions of this hook.
for sdkdir in "$DOTNET_DIR"/sdk/*/; do
  importdir="${sdkdir}Current/Imports/Microsoft.Common.props/ImportAfter"
  rm -f -- "${importdir}/ZZZ.ClaudeWebSession.Overrides.props"
done

# 3. Restore visibility of lock files hidden by older versions of this hook.
if command -v git >/dev/null 2>&1; then
  git -C "$PROJECT_DIR" ls-files -z '*packages.lock.json' 2>/dev/null \
    | xargs -0 -r git -C "$PROJECT_DIR" update-index --no-skip-worktree
fi

# 4. Persist the SDK on PATH (and quiet first-run/telemetry) for the rest of the session.
{
  echo "export DOTNET_ROOT=\"$DOTNET_DIR\""
  echo "export PATH=\"$DOTNET_DIR:\$PATH\""
  echo "export DOTNET_CLI_TELEMETRY_OPTOUT=1"
  echo "export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1"
  echo "export DOTNET_NOLOGO=1"
} >> "$CLAUDE_ENV_FILE"
