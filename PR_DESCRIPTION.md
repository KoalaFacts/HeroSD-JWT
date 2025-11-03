# Improve NuGet Publishing Workflow and Add Setup Guide

## Summary

This PR enhances the NuGet publishing workflow with better reliability, testing, and documentation for the Trusted Publishing setup.

## Changes

### 🔧 Workflow Improvements (`publish-nuget.yml`)

**Added build and test validation:**
- ✅ `.NET setup` step for consistent environment
- ✅ `Restore dependencies` before building
- ✅ `Build` step to ensure code compiles
- ✅ `Run tests` to validate functionality before publishing
- ✅ `Pack NuGet packages` directly in the workflow

**Enhanced reliability:**
- Better error messages and validation
- Package content validation before publishing
- Improved version detection (supports workflow_run, manual trigger, and csproj fallback)
- More detailed output with `✅` success indicators

**Better output:**
- Enhanced release summary with clear next steps
- Package availability timeline (5-10 minutes)
- Direct links to NuGet.org package page

### 📚 Documentation (`NUGET_PUBLISH_GUIDE.md`)

Created comprehensive setup guide with:
- Step-by-step Trusted Publishing setup instructions
- Screenshots-ready format for NuGet.org and GitHub configuration
- Troubleshooting section for common issues
- Comparison of Trusted Publishing vs API Key approaches
- Security benefits explanation

### 🔐 Alternative Workflow (`publish-nuget-apikey.yml`)

Added simpler alternative workflow for users who prefer API keys:
- Easier initial setup (single secret vs OIDC configuration)
- Includes security note recommending migration to Trusted Publishing
- Useful for local testing and emergency publishing

## Why These Changes?

1. **Reliability**: The workflow now builds and tests packages before publishing, catching issues early
2. **Documentation**: Clear setup instructions make it easier for contributors to configure Trusted Publishing
3. **Flexibility**: Manual trigger now has a fallback to read version from .csproj
4. **Better DX**: Improved error messages and output make debugging easier

## Testing

- ✅ Workflow syntax validated
- ✅ Conflict resolution tested with main branch
- ✅ All steps are idiomatic GitHub Actions patterns

## Security

- ✅ Maintains Trusted Publishing with OIDC (NuGet/login@v1)
- ✅ No long-lived API keys in primary workflow
- ✅ Package provenance attestation included
- ✅ Environment protection rules support

## Next Steps After Merge

Once this is merged, to publish the next version:

1. Complete Trusted Publishing setup (see NUGET_PUBLISH_GUIDE.md)
2. Bump version in `src/HeroSdJwt.csproj`
3. Create release with tag (e.g., `v1.0.6`)
4. Workflow automatically publishes to NuGet.org

---

**Note:** Package has already been published up to v1.0.5. Next release should be v1.0.6 or higher.
