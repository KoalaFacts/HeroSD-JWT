# Quick Guide: Publishing HeroSD-JWT to NuGet.org

## Current Status
- ✅ Package version: **1.0.0** (ready in src/HeroSdJwt.csproj)
- ✅ Workflow improved: Builds packages directly (more reliable)
- ⚠️ Setup required: NuGet.org Trusted Publishing + GitHub configuration

## Option 1: Trusted Publishing (Recommended - Most Secure)

### Prerequisites Setup (One-time, ~10 minutes)

#### Step 1: Configure NuGet.org Trusted Publishing
1. Go to https://www.nuget.org/ and sign in
2. Click your username (top-right) → **Trusted Publishing**
3. Click **Create new policy** and fill in:
   - **Repository Owner**: `KoalaFacts`
   - **Repository Name**: `HeroSD-JWT`
   - **Workflow File**: `publish-nuget.yml`
   - **Environment**: `production`
4. Click **Create**
   - Status will show "Temporarily Active" for 7 days
   - Becomes permanent after first successful publish

#### Step 2: Add GitHub Secret
1. Go to https://github.com/KoalaFacts/HeroSD-JWT/settings/secrets/actions
2. Click **New repository secret**
3. Add:
   - **Name**: `NUGET_USERNAME`
   - **Value**: Your NuGet.org username (NOT email!)
4. Click **Add secret**

#### Step 3: Create GitHub Environment
1. Go to https://github.com/KoalaFacts/HeroSD-JWT/settings/environments
2. Click **New environment**
3. Name: `production` (must match exactly)
4. Configure protection rules (recommended):
   - ✅ **Required reviewers**: Add yourself for manual approval
   - ✅ **Deployment branches**: Select "Selected branches" → Add `main`
5. Click **Save protection rules**

### Publishing

Once setup is complete, you can publish in two ways:

#### Method A: Automated (via Git Tag)
```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```
The workflow will automatically trigger and publish to NuGet.org.

#### Method B: Manual Trigger
1. Go to https://github.com/KoalaFacts/HeroSD-JWT/actions/workflows/publish-nuget.yml
2. Click **Run workflow**
3. Optionally enter version (or leave blank to use version from .csproj)
4. Click **Run workflow**
5. If required reviewers are configured, approve the deployment

---

## Option 2: API Key Method (Quick Start - Less Secure)

If you want to publish quickly without Trusted Publishing setup:

### Step 1: Get NuGet API Key
1. Go to https://www.nuget.org/account/apikeys
2. Click **Create**
3. Settings:
   - **Key Name**: HeroSD-JWT Publishing
   - **Package Owner**: Select your account
   - **Glob Pattern**: HeroSD-JWT
   - **Scopes**: Check "Push new packages and package versions"
   - **Expiration**: Set an expiration date (e.g., 365 days)
4. Click **Create**
5. **Copy the API key** (shown only once!)

### Step 2: Add GitHub Secret
1. Go to https://github.com/KoalaFacts/HeroSD-JWT/settings/secrets/actions
2. Click **New repository secret**
3. Add:
   - **Name**: `NUGET_API_KEY`
   - **Value**: Paste the API key from Step 1
4. Click **Add secret**

### Step 3: Create Simple Workflow
I can create a simpler workflow file that uses the API key instead of Trusted Publishing.

Would you like me to create this alternative workflow?

---

## Verification After Publishing

1. Check NuGet.org: https://www.nuget.org/packages/HeroSD-JWT
2. Test installation:
   ```bash
   dotnet new console -n TestHeroSdJwt
   cd TestHeroSdJwt
   dotnet add package HeroSD-JWT --version 1.0.0
   dotnet restore
   ```

---

## Troubleshooting

### "Authentication failed" with Trusted Publishing
- Verify the Trusted Publishing policy exists on NuGet.org
- Check that `NUGET_USERNAME` is your NuGet username (not email)
- Ensure the `production` environment exists in GitHub

### "Package already exists"
- You cannot replace versions on NuGet.org
- Bump the version in `src/HeroSdJwt.csproj`
- Rebuild and republish

### Workflow doesn't trigger
- Ensure you're pushing to the correct repository: https://github.com/KoalaFacts/HeroSD-JWT
- Check you have permissions to trigger workflows

---

## What Changed in the Workflow

I improved the publish workflow to:
- ✅ Build packages directly (instead of downloading from releases)
- ✅ Run tests before publishing
- ✅ Better error handling and package validation
- ✅ Works with manual trigger (no version tag required)
- ✅ More detailed output and summaries

The old workflow had a complex dependency chain (CI → Release → Publish) that could fail. The new workflow is simpler and more reliable.
