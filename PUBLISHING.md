# Publishing HeroSD-JWT to NuGet.org

This guide explains how to publish the HeroSD-JWT package to NuGet.org using **GitHub Actions Trusted Publishing** with OIDC authentication - **no API keys required!**

## Quick Start Checklist

For first-time publishing with Trusted Publishing:

- [ ] Have a NuGet.org account
- [ ] Set up Trusted Publishing policy on NuGet.org with environment `production` (see Setup Steps below)
- [ ] Add `NUGET_USERNAME` secret to GitHub repository (Settings → Secrets)
- [ ] Create GitHub environment named `production` with protection rules
- [ ] Push code to `https://github.com/KoalaFacts/HeroSD-JWT`
- [ ] Create and publish a GitHub release with tag `v1.0.0`
- [ ] GitHub Actions automatically authenticates via OIDC and publishes

**No long-lived API keys needed!** Only your NuGet.org username. 🎉

## Prerequisites

1. **NuGet.org Account**: You need an account on [NuGet.org](https://www.nuget.org/)
2. **GitHub Repository**: Code must be in `https://github.com/KoalaFacts/HeroSD-JWT`
3. **Package Ownership**: You must own the `HeroSD-JWT` package on NuGet.org (or be publishing for the first time)

## Setup Steps

### 1. Configure Trusted Publishing on NuGet.org

NuGet.org now supports **Trusted Publishing** using GitHub Actions OIDC - this is the **recommended and most secure method** (no long-lived API keys!).

**IMPORTANT**: You **must** set up a Trusted Publishing policy on NuGet.org **before** your first publish:

1. **Log into NuGet.org**:
   - Go to https://www.nuget.org/
   - Sign in with your account

2. **Navigate to Trusted Publishing**:
   - Click your username (top-right)
   - Select **Trusted Publishing**

3. **Create a New Policy**:
   - Click **Create new policy**
   - Fill in the details:
     - **Repository Owner**: `KoalaFacts`
     - **Repository Name**: `HeroSD-JWT`
     - **Workflow File**: `publish-nuget.yml` (just the filename, not the full path)
     - **Environment**: `production` (**required** - matches the workflow environment)
   - Click **Create**

4. **Policy Status**:
   - New policies show as "Temporarily Active" for 7 days
   - After a successful publish, the policy becomes permanently active
   - If no publish occurs within 7 days, the policy expires

**How it works**: When GitHub Actions runs, it gets a short-lived OIDC token, exchanges it for a temporary (1-hour) NuGet API key, then uses that key to publish. The temporary key expires automatically.

### 2. Add NuGet Username to GitHub Secrets

The workflow needs your NuGet.org username (not email!) to authenticate:

1. Go to your repository: https://github.com/KoalaFacts/HeroSD-JWT
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add:
   - **Name**: `NUGET_USERNAME`
   - **Value**: Your NuGet.org username (visible at https://www.nuget.org/ when logged in)
5. Click **Add secret**

**Why use secrets?**
- Keeps your username private in workflow logs (better privacy)
- Consistent with how credentials are typically handled
- Prevents accidental exposure in public repos or forks

### 3. Create GitHub Production Environment (Required)

The workflow uses a `production` environment for additional security and control:

1. Go to **Settings** → **Environments**
2. Click **New environment**
3. Name it: `production` (**must match exactly - required by workflow**)
4. Configure **Environment protection rules** (highly recommended for production):
   - ✅ **Required reviewers**: Add yourself or team members for manual approval before publishing
   - ✅ **Deployment branches**: Select "Selected branches" → Add `main` (only main branch can publish to production)
   - ⚠️ **Wait timer** (optional): Add a delay before deployment if desired
5. **Environment secrets** (optional but recommended):
   - You can optionally move `NUGET_USERNAME` from repository secrets to environment secrets for better isolation
   - This restricts the username to only the production environment
   - Go to the `production` environment → Environment secrets → Add secret

**Why use a production environment?**
- Prevents accidental publishing from feature branches
- Requires manual approval before publishing (if reviewers are configured)
- Provides audit trail of all production deployments
- Matches the Trusted Publishing policy on NuGet.org

## Publishing Methods

### Method 1: Publish on GitHub Release (Recommended)

This is automated and triggered when you create a GitHub release:

1. **Create a Git Tag**:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0: Initial production release"
   git push origin v1.0.0
   ```

2. **Create GitHub Release**:
   - Go to https://github.com/KoalaFacts/HeroSD-JWT/releases
   - Click **Draft a new release**
   - Choose the tag you just created (`v1.0.0`)
   - Set release title: `v1.0.0 - Initial Release`
   - Add release notes (can copy from `RELEASE_NOTES.md`)
   - Click **Publish release**

3. **Automatic Publishing**:
   - GitHub Actions will automatically:
     - Build the project
     - Run all tests
     - Create the NuGet package
     - Publish to NuGet.org

4. **Monitor Progress**:
   - Go to **Actions** tab
   - Watch the "Publish to NuGet" workflow

### Method 2: Manual Publish via Workflow Dispatch

For testing or manual releases:

1. Go to **Actions** tab
2. Select "Publish to NuGet" workflow
3. Click **Run workflow**
4. Enter the version (e.g., `1.0.0`)
5. Click **Run workflow**

### Method 3: Local Manual Publish (Requires API Key)

For emergency or local testing, you'll need a temporary API key:

```bash
# Build the package
dotnet pack src/HeroSdJwt.csproj --configuration Release --output ./nupkg

# Publish to NuGet.org (requires API key from https://www.nuget.org/account/apikeys)
dotnet nuget push ./nupkg/HeroSD-JWT.1.0.0.nupkg \
  --source https://api.nuget.org/v3/index.json \
  --api-key YOUR_API_KEY
```

**Note**: Local publishing requires an API key. For security, use Trusted Publishing via GitHub Actions instead (Methods 1 or 2).

## Verification

After publishing, verify the package:

1. **Check NuGet.org**: https://www.nuget.org/packages/HeroSD-JWT
2. **Test Installation**:
   ```bash
   dotnet new console -n TestHeroSdJwt
   cd TestHeroSdJwt
   dotnet add package HeroSD-JWT --version 1.0.0
   dotnet restore
   ```

## Version Bump Checklist

Before each release, update:

1. **Version in `.csproj`**: Update `<Version>1.0.0</Version>` in `src/HeroSdJwt.csproj`
2. **Release Notes**: Update `<PackageReleaseNotes>` in `src/HeroSdJwt.csproj`
3. **CHANGELOG.md**: Add entry for the new version
4. **README.md**: Update version badges if applicable

## Troubleshooting

### Package Already Exists

If you get "Package already exists" error:
- You cannot replace an existing version on NuGet.org
- Bump the version number in `src/HeroSdJwt.csproj`
- Rebuild and republish

### Authentication Fails (Trusted Publishing)

With Trusted Publishing, authentication happens via OIDC token → temporary API key. If you get authentication errors:

- **Verify Trusted Publishing Policy on NuGet.org**:
  - Check https://www.nuget.org/ → your username → Trusted Publishing
  - Ensure policy exists with correct repository owner (`KoalaFacts`), repository name (`HeroSD-JWT`), and workflow file (`publish-nuget.yml`)
  - Policy must be "Active" or "Temporarily Active"

- **Check `NUGET_USERNAME` Secret**:
  - Verify the secret exists in GitHub (Settings → Secrets and variables → Actions → Secrets tab)
  - **Must be your NuGet.org username, NOT your email address**
  - Check for typos or extra spaces
  - Secrets are masked in logs for privacy

- **Verify Workflow Permissions**:
  - Workflow must have `id-token: write` permission (already configured)

- **Check GitHub Environment**:
  - Environment name must match exactly: `production` (not `nuget-org`)
  - If using environment protection rules, ensure the workflow is approved by reviewers
  - Check that deployment is allowed from the `main` branch

### Tests Fail in CI

- Run tests locally first: `dotnet test --configuration Release`
- Check GitHub Actions logs for specific errors
- Ensure all dependencies are restored correctly

### Trusted Publishing Not Working

If Trusted Publishing fails:

1. **Check NuGet.org Trusted Publishing Policy**:
   - Repository owner: `KoalaFacts`
   - Repository name: `HeroSD-JWT`
   - Workflow file: `publish-nuget.yml` (just filename)
   - Environment: `production` (must match exactly)
2. **Verify GitHub Configuration**:
   - `NUGET_USERNAME` secret exists and is correct (username, not email)
   - `production` environment exists with correct name
   - Workflow has `id-token: write` permission
3. **Check Workflow Logs**:
   - Look for "Determine version" step output
   - Verify version number is correct (e.g., `1.0.0` not `v1.0.0`)
4. **Fallback to API Key**: As a temporary workaround, you can use an API key (see Method 3)

## Best Practices

1. **Use Trusted Publishing**: Always use GitHub Actions with OIDC for maximum security (no API keys!)
2. **Always Run Tests**: GitHub Actions runs tests before publishing
3. **Use Semantic Versioning**: Follow [semver.org](https://semver.org/)
4. **Tag Releases**: Always create Git tags for releases
5. **Document Changes**: Keep CHANGELOG.md up to date
6. **Review Before Publishing**: Use GitHub environment protection for manual approval workflows
7. **Symbol Packages**: Always publish `.snupkg` for better debugging experience
8. **Avoid API Keys**: Only use API keys for local emergency publishing - prefer Trusted Publishing

## How Trusted Publishing Works

```
┌─────────────────────┐
│  GitHub Actions     │
│  (your workflow)    │
└──────────┬──────────┘
           │
           │ 1. Request OIDC token
           │    (id-token: write permission)
           ▼
┌─────────────────────┐
│  GitHub OIDC        │
│  Token Issuer       │
└──────────┬──────────┘
           │
           │ 2. Short-lived token
           │    (expires in minutes)
           ▼
┌─────────────────────┐
│  NuGet/login@v1     │
│  Action             │
└──────────┬──────────┘
           │
           │ 3. Exchange OIDC token for
           │    temporary NuGet API key
           │    (valid for 1 hour)
           ▼
┌─────────────────────┐
│  NuGet.org          │
│  API                │
└──────────┬──────────┘
           │
           │ 4. Publish package using
           │    temporary API key
           ▼
      ✅ Published!
```

## Security Benefits of Trusted Publishing

✅ **No Long-Lived API Keys**: Only temporary (1-hour) keys exist, eliminating leak risks
✅ **Automatic Rotation**: OIDC tokens are short-lived and automatically rotated
✅ **Fine-grained Access**: Tied to specific repository and workflow
✅ **Audit Trail**: Better visibility into who published what and when
✅ **Recommended by NuGet.org**: Official best practice for publishing packages
✅ **No Secrets Management**: Only need username, not sensitive credentials

## Useful Links

- **Trusted Publishing Docs**: https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#trusted-publishing
- **Issues**: https://github.com/KoalaFacts/HeroSD-JWT/issues
- **NuGet Package**: https://www.nuget.org/packages/HeroSD-JWT
- **GitHub Actions**: https://docs.github.com/en/actions
