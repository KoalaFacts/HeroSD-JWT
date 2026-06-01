#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# Installs the .NET SDKs this repo targets (net8.0 / net9.0 / net10.0) so `dotnet
# build`, `dotnet test`, and `dotnet format` work out of the box, and relaxes a few
# CI-only build settings *for the ephemeral web session only* (never in the repo) so
# those commands succeed without per-command flags.
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

# 1. Install one SDK per target framework. dotnet-install skips channels that are
#    already present, so re-running the hook is cheap and idempotent.
if [ ! -x "$INSTALLER" ]; then
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o "$INSTALLER"
  chmod +x "$INSTALLER"
fi
for channel in 8.0 9.0 10.0; do
  "$INSTALLER" --channel "$channel" --install-dir "$DOTNET_DIR" --no-path
done

# 2. Drop an MSBuild override into each installed SDK (NOT into the repo). It is
#    auto-imported right after Directory.Build.props during the props phase, so it
#    applies to both restore and build. This lets a freshly installed SDK patch work
#    against the repo's pinned lock files and strict analyzer settings:
#      - RestoreLockedMode=false          : tolerate SDK-patch drift vs packages.lock.json
#      - NuGetAudit=false                 : don't fail restore on known transitive advisories
#      - TreatWarningsAsErrors=false      : don't fail build on newer-analyzer style rules
#      - ContinuousIntegrationBuild=false : this is an interactive dev session, not CI
#    The repo keeps its strict settings; CI is unaffected because this file lives only
#    in the web container's SDK install.
for sdkdir in "$DOTNET_DIR"/sdk/*/; do
  importdir="${sdkdir}Current/Imports/Microsoft.Common.props/ImportAfter"
  mkdir -p "$importdir"
  cat > "${importdir}/ZZZ.ClaudeWebSession.Overrides.props" << 'XML'
<Project>
  <PropertyGroup>
    <RestoreLockedMode>false</RestoreLockedMode>
    <NuGetAudit>false</NuGetAudit>
    <TreatWarningsAsErrors>false</TreatWarningsAsErrors>
    <ContinuousIntegrationBuild>false</ContinuousIntegrationBuild>
  </PropertyGroup>
</Project>
XML
done

# 3. With RestoreLockedMode off, the first restore rewrites the drifted lock files.
#    Mark them skip-worktree so that rewrite never shows up as uncommitted changes
#    (keeps `git status` clean and prevents accidental commits of patch drift).
if command -v git >/dev/null 2>&1 && [ -n "${CLAUDE_PROJECT_DIR:-}" ]; then
  git -C "$CLAUDE_PROJECT_DIR" ls-files '*packages.lock.json' 2>/dev/null \
    | xargs -r git -C "$CLAUDE_PROJECT_DIR" update-index --skip-worktree || true
fi

# 4. Persist the SDK on PATH (and quiet first-run/telemetry) for the rest of the session.
{
  echo "export DOTNET_ROOT=\"$DOTNET_DIR\""
  echo "export PATH=\"$DOTNET_DIR:\$PATH\""
  echo "export DOTNET_CLI_TELEMETRY_OPTOUT=1"
  echo "export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1"
  echo "export DOTNET_NOLOGO=1"
} >> "$CLAUDE_ENV_FILE"
