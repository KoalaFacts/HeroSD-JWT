# Publishing HeroSD-JWT to NuGet.org with Trusted Publishing

## Overview

This project uses **NuGet Trusted Publishing** with OIDC authentication - the most secure way to publish NuGet packages. No long-lived API keys are needed!

## Current Status
- ✅ Package version: **1.0.5** (published)
- ✅ Workflow configured: Builds, tests, and publishes automatically
- ✅ Uses Trusted Publishing: `NuGet/login@v1` with OIDC

## How Trusted Publishing Works

```
GitHub Actions (OIDC token)
    ↓
NuGet/login@v1 action
    ↓
NuGet.org (exchanges OIDC token for temporary 1-hour API key)
    ↓
dotnet nuget push (uses temporary key)
    ↓
✅ Package Published!
```

**Security Benefits:**
- ✅ No long-lived API keys to manage or rotate
- ✅ Temporary keys expire automatically (1 hour)
- ✅ Fine-grained access control tied to specific repository/workflow
- ✅ Better audit trail

---

## One-Time Setup (Required)

### Step 1: Configure NuGet.org Trusted Publishing Policy

1. **Sign in to NuGet.org**: https://www.nuget.org/
2. **Navigate to Trusted Publishing**:
   - Click your username (top-right)
   - Select **Trusted Publishing**
3. **Create new policy**:
   - Click **Create new policy**
   - Fill in these **exact** values:
     ```
     Repository Owner:    KoalaFacts
     Repository Name:     HeroSD-JWT
     Workflow File:       publish-nuget.yml
     Environment:         production
     ```
   - Click **Create**

**Policy Status:**
- Shows "Temporarily Active" for 7 days
- Becomes permanently active after first successful publish
- Expires if unused within 7 days (can recreate)

### Step 2: Add GitHub Secret (NUGET_USERNAME)

1. Go to: https://github.com/KoalaFacts/HeroSD-JWT/settings/secrets/actions
2. Click **New repository secret**
3. Add secret:
   - **Name**: `NUGET_USERNAME`
   - **Value**: Your NuGet.org **username** (NOT email)
     - Find it at top-right when logged into NuGet.org
4. Click **Add secret**

**Why this secret?**
- Only used for the `NuGet/login@v1` action
- Not a sensitive credential (just your public username)
- Helps the action identify which NuGet account to use

### Step 3: Create GitHub Production Environment

1. Go to: https://github.com/KoalaFacts/HeroSD-JWT/settings/environments
2. Click **New environment**
3. Name: `production` (must match exactly)
4. **(Recommended)** Configure protection rules:
   - ✅ **Required reviewers**: Add yourself
     - Provides manual approval gate before publishing
   - ✅ **Deployment branches**: Select "Selected branches"
     - Add `main` (only main branch can publish)
   - ⏱️ **Wait timer** (optional): Add delay if desired
5. Click **Save protection rules**

**Why use an environment?**
- Prevents accidental publishing from feature branches
- Requires manual approval (if reviewers configured)
- Matches the Trusted Publishing policy on NuGet.org
- Provides audit trail of all production deployments

---

## Publishing a New Version

### Method 1: Automated (via Create Release Workflow)

This is the **recommended** automated approach:

1. **Bump version** in `src/HeroSdJwt.csproj`:
   ```xml
   <Version>1.0.6</Version>
   ```

2. **Commit and push to main**:
   ```bash
   git add src/HeroSdJwt.csproj
   git commit -m "chore: bump version to 1.0.6"
   git push origin main
   ```

3. **Create and push Git tag**:
   ```bash
   git tag -a v1.0.6 -m "Release v1.0.6"
   git push origin v1.0.6
   ```

4. **Automated process**:
   - `create-release.yml` workflow triggers on tag push
   - Generates changelog from git commits
   - Creates GitHub release with notes
   - `publish-nuget.yml` triggers automatically via `workflow_run`
   - Builds, tests, and publishes to NuGet.org

5. **Approve deployment** (if required reviewers configured):
   - Check GitHub Actions tab
   - Review and approve the production deployment

**Pro tip:** Use conventional commits for better changelogs:
```bash
git commit -m "feat: add new feature"
git commit -m "fix: resolve bug"
git commit -m "docs: update documentation"
```

### Method 2: Manual Trigger (Emergency/Testing)

For manual publishing or republishing:

1. Go to: https://github.com/KoalaFacts/HeroSD-JWT/actions/workflows/publish-nuget.yml
2. Click **Run workflow**
3. (Optional) Enter version number
   - Leave blank to use version from `.csproj`
4. Click **Run workflow**
5. Approve deployment if prompted

---

## Verification After Publishing

### Check NuGet.org
- Package page: https://www.nuget.org/packages/HeroSD-JWT
- Should show your new version within 5-10 minutes

### Test Installation
```bash
dotnet new console -n TestHeroSdJwt
cd TestHeroSdJwt
dotnet add package HeroSD-JWT --version 1.0.6
dotnet restore
```

### Verify Package Provenance
- GitHub automatically generates package provenance attestations
- Visible in workflow artifacts and on NuGet.org

---

## Troubleshooting

### "Authentication failed" with Trusted Publishing

**Check NuGet.org policy:**
- Go to https://www.nuget.org/ → Username → Trusted Publishing
- Verify policy exists with correct values:
  - Owner: `KoalaFacts`
  - Repo: `HeroSD-JWT`
  - Workflow: `publish-nuget.yml`
  - Environment: `production`
- Policy status should be "Active" or "Temporarily Active"

**Check GitHub secret:**
- Settings → Secrets and variables → Actions
- Verify `NUGET_USERNAME` exists
- Must be your NuGet.org **username**, not email
- No typos or extra spaces

**Check GitHub environment:**
- Settings → Environments
- Environment named `production` must exist
- If using protection rules, ensure deployment is approved

**Check workflow permissions:**
- Workflow has `id-token: write` permission (already configured)

### "Package already exists"

You cannot replace an existing version on NuGet.org:
1. Bump version in `src/HeroSdJwt.csproj`
2. Create new release with new version

### "Tests failed in CI"

Workflow runs tests before publishing:
1. Check GitHub Actions logs for specific errors
2. Run tests locally: `dotnet test --configuration Release`
3. Fix issues and push again

### Workflow doesn't trigger

**For automatic trigger (workflow_run):**
- `create-release.yml` must complete successfully first
- Check that tag was pushed to main branch
- Verify `workflow_run` trigger in `publish-nuget.yml`

**For manual trigger:**
- Ensure you have workflow trigger permissions
- Check repository settings allow workflow dispatch

---

## Best Practices

1. ✅ **Use Trusted Publishing** - Most secure, no API keys
2. ✅ **Always run tests** - Workflow automatically tests before publishing
3. ✅ **Use semantic versioning** - Follow [semver.org](https://semver.org/)
4. ✅ **Tag releases** - Always create Git tags for releases
5. ✅ **Conventional commits** - Better automated changelogs
6. ✅ **Environment protection** - Use required reviewers for manual approval
7. ✅ **Symbol packages** - Workflow publishes `.snupkg` for debugging
8. ✅ **Package provenance** - Automatically generated for supply chain security

---

## Version History

- **v1.0.5** - Latest published version
- **v1.0.4** - Previous versions
- **v1.0.3**
- **v1.0.1**
- **v1.0.0** - Initial release

**Next version should be:** `v1.0.6` or higher

---

## Useful Links

- **NuGet Package**: https://www.nuget.org/packages/HeroSD-JWT
- **Trusted Publishing Docs**: https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#trusted-publishing
- **GitHub Actions**: https://github.com/KoalaFacts/HeroSD-JWT/actions
- **Issues**: https://github.com/KoalaFacts/HeroSD-JWT/issues
