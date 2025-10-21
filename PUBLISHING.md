# Publishing HeroSD-JWT to NuGet.org

This guide explains how to publish the HeroSD-JWT package to NuGet.org using **GitHub Actions Trusted Publishing** with OIDC authentication - **no API keys required!**

## Quick Start Checklist

For first-time publishing with Trusted Publishing:

- [ ] Have a NuGet.org account
- [ ] Push code to `https://github.com/KoalaFacts/HeroSD-JWT`
- [ ] Create GitHub environment named `nuget-org` (optional but recommended)
- [ ] Create and publish a GitHub release with tag `v1.0.0`
- [ ] GitHub Actions automatically publishes to NuGet.org via OIDC
- [ ] After first publish, optionally configure Trusted Publishers on NuGet.org for additional security

That's it! No API keys needed. 🎉

## Prerequisites

1. **NuGet.org Account**: You need an account on [NuGet.org](https://www.nuget.org/)
2. **GitHub Repository**: Code must be in `https://github.com/KoalaFacts/HeroSD-JWT`
3. **Package Ownership**: You must own the `HeroSD-JWT` package on NuGet.org (or be publishing for the first time)

## Setup Steps

### 1. Configure Trusted Publishing on NuGet.org

NuGet.org now supports **Trusted Publishing** using GitHub Actions OIDC - this is the **recommended and most secure method** (no API keys to manage!).

1. **First-time package registration**:
   - If this is your first time publishing `HeroSD-JWT`, NuGet.org will automatically accept the package from your GitHub Actions workflow
   - The package will be associated with your NuGet.org account

2. **For existing packages** (if you've published before):
   - Go to https://www.nuget.org/packages/HeroSD-JWT/manage
   - Navigate to the **Trusted Publishers** section
   - Add GitHub Actions as a trusted publisher:
     - **Repository Owner**: `KoalaFacts`
     - **Repository Name**: `HeroSD-JWT`
     - **Workflow file**: `.github/workflows/publish-nuget.yml`
     - **Environment** (optional): `nuget-org`

That's it! **No API keys needed** - authentication happens automatically via GitHub's OIDC token.

### 2. Create GitHub Environment (Optional but Recommended)

For better security and approval workflows:

1. Go to **Settings** → **Environments**
2. Click **New environment**
3. Name it: `nuget-org`
4. Configure:
   - **Environment protection rules** (recommended):
     - Add required reviewers (yourself or team members) for manual approval before publishing
     - Add branch protection (only `main` branch can publish)
     - Set deployment delay if desired
   - **No secrets needed** - Trusted Publishing uses OIDC!

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

With Trusted Publishing, authentication happens automatically via OIDC. If you get authentication errors:

- **Verify GitHub Environment**: Ensure the workflow is running in the `nuget-org` environment
- **Check NuGet.org Trusted Publishers**: Verify the repository and workflow are correctly configured
- **Verify Permissions**: Ensure the workflow has `id-token: write` and `contents: read` permissions
- **First-time Package**: Make sure you're logged into NuGet.org with the account that will own the package

### Tests Fail in CI

- Run tests locally first: `dotnet test --configuration Release`
- Check GitHub Actions logs for specific errors
- Ensure all dependencies are restored correctly

### Trusted Publishing Not Working

If Trusted Publishing fails:

1. **Check NuGet.org Support**: Ensure your NuGet.org account has Trusted Publishing enabled
2. **Verify Workflow Configuration**:
   - Repository owner: `KoalaFacts`
   - Repository name: `HeroSD-JWT`
   - Workflow path: `.github/workflows/publish-nuget.yml`
3. **Fallback to API Key**: As a temporary workaround, you can use an API key (see Method 3)

## Best Practices

1. **Use Trusted Publishing**: Always use GitHub Actions with OIDC for maximum security (no API keys!)
2. **Always Run Tests**: GitHub Actions runs tests before publishing
3. **Use Semantic Versioning**: Follow [semver.org](https://semver.org/)
4. **Tag Releases**: Always create Git tags for releases
5. **Document Changes**: Keep CHANGELOG.md up to date
6. **Review Before Publishing**: Use GitHub environment protection for manual approval workflows
7. **Symbol Packages**: Always publish `.snupkg` for better debugging experience
8. **Avoid API Keys**: Only use API keys for local emergency publishing - prefer Trusted Publishing

## Security Benefits of Trusted Publishing

✅ **No API Keys to Manage**: Eliminates the risk of leaked or stolen API keys
✅ **Automatic Rotation**: OIDC tokens are short-lived and automatically rotated
✅ **Fine-grained Access**: Tied to specific repository and workflow
✅ **Audit Trail**: Better visibility into who published what and when
✅ **Recommended by NuGet.org**: Official best practice for publishing packages

## Useful Links

- **Trusted Publishing Docs**: https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package#trusted-publishing
- **Issues**: https://github.com/KoalaFacts/HeroSD-JWT/issues
- **NuGet Package**: https://www.nuget.org/packages/HeroSD-JWT
- **GitHub Actions**: https://docs.github.com/en/actions
