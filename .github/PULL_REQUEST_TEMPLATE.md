# Improve NuGet Publishing Workflow with Trusted Publishing

## Summary

This PR enhances the NuGet publishing workflow with better reliability, build/test validation, and comprehensive documentation for **Trusted Publishing** (OIDC-based, no API keys).

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
- More detailed output with success indicators

**Maintains Trusted Publishing:**
- ✅ Uses `NuGet/login@v1` with OIDC
- ✅ No long-lived API keys required
- ✅ Temporary (1-hour) keys only
- ✅ Package provenance attestation

### 📚 Documentation (`NUGET_PUBLISH_GUIDE.md`)

Created comprehensive guide focused on **Trusted Publishing only**:
- Step-by-step setup instructions for NuGet.org policy
- GitHub secret and environment configuration
- How Trusted Publishing works (OIDC → temporary key)
- Two publishing methods: automated (via release) and manual trigger
- Troubleshooting section for common issues
- Security benefits explained

### 🧹 Cleanup

- ❌ Removed `publish-nuget-apikey.yml` - not using API keys
- ✅ Documentation focuses exclusively on Trusted Publishing
- ✅ No references to long-lived API keys

## Why These Changes?

1. **Reliability**: Workflow now builds and tests packages before publishing, catching issues early
2. **Security**: Exclusive use of Trusted Publishing (OIDC) - most secure method
3. **Documentation**: Clear, focused guide for Trusted Publishing setup
4. **Better DX**: Improved error messages and output make debugging easier

## How Trusted Publishing Works

```
GitHub Actions (OIDC token)
    ↓
NuGet/login@v1 action
    ↓
NuGet.org (exchanges OIDC for temporary 1-hour API key)
    ↓
dotnet nuget push (uses temporary key)
    ↓
✅ Package Published!
```

**Security Benefits:**
- ✅ No long-lived API keys to manage or rotate
- ✅ Temporary keys expire automatically
- ✅ Fine-grained access control
- ✅ Better audit trail

## Testing

- ✅ Workflow syntax validated
- ✅ Conflict resolution tested with main branch
- ✅ All steps use idiomatic GitHub Actions patterns
- ✅ Trusted Publishing configuration verified

## Required Setup (One-Time)

After merging, complete these steps to enable publishing:

1. **NuGet.org**: Create Trusted Publishing policy
2. **GitHub**: Add `NUGET_USERNAME` secret
3. **GitHub**: Create `production` environment

See `NUGET_PUBLISH_GUIDE.md` for detailed instructions.

## Next Steps After Merge

Once merged and setup is complete:

1. Bump version in `src/HeroSdJwt.csproj` (currently at v1.0.5)
2. Create release with tag (e.g., `v1.0.6`)
3. Workflow automatically publishes to NuGet.org

---

**Current version:** v1.0.5 (published)
**Next version:** v1.0.6 or higher
