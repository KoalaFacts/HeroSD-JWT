# Security Features Setup Guide

This guide walks you through enabling GitHub's built-in security features for the HeroSD-JWT repository.

---

## 🔒 GitHub Secret Scanning

**What it does:** Automatically detects accidentally committed secrets (API keys, tokens, passwords) in your code.

### Enable Secret Scanning

1. **Navigate to Security Settings**
   - Go to: https://github.com/KoalaFacts/HeroSD-JWT/settings/security_analysis
   - Or: Repository → Settings → Code security and analysis

2. **Enable Secret Scanning**
   - Find the "Secret scanning" section
   - Click **Enable** button
   - Status should change to "Enabled"

3. **Enable Push Protection (Recommended)**
   - In the same section, enable "Push protection"
   - This **blocks** commits containing secrets before they're pushed
   - Prevents secrets from ever entering git history

### What Gets Scanned

GitHub automatically detects 200+ secret patterns including:

| Provider | Secret Types |
|----------|--------------|
| **AWS** | Access keys, secret keys, session tokens |
| **Azure** | Storage account keys, SAS tokens, service principal credentials |
| **GitHub** | Personal access tokens, OAuth tokens, SSH keys |
| **Google** | API keys, OAuth client secrets, service account keys |
| **Stripe** | API keys, webhook secrets |
| **NuGet** | API keys |
| **Slack** | Bot tokens, webhook URLs |
| **MongoDB** | Connection strings |
| **And 190+ more...** | See [full list](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-patterns) |

### Verify It's Working

After enabling, check the Security tab:
```
https://github.com/KoalaFacts/HeroSD-JWT/security
```

You should see:
- ✅ "Secret scanning" listed under Security overview
- Initial scan completes within minutes
- Historical scan covers entire git history

---

## 🔍 CodeQL Analysis

**What it does:** Static code analysis to detect security vulnerabilities in C# code.

### Enable CodeQL (Recommended Method)

GitHub has a **default setup** that's easier than custom workflows:

1. **Navigate to Code Security**
   - Go to: https://github.com/KoalaFacts/HeroSD-JWT/settings/security_analysis

2. **Enable CodeQL Analysis**
   - Find "Code scanning" section
   - Click **Set up** → **Default**
   - GitHub will automatically configure:
     - Languages to scan (C#)
     - Scan frequency (on push, PR, weekly)
     - Query suite (security-extended)

3. **Verify Setup**
   - First scan runs immediately
   - Results appear in Security → Code scanning alerts
   - Badge shows up in Security tab

### What CodeQL Detects

| Category | Examples |
|----------|----------|
| **Injection** | SQL injection, command injection, XSS |
| **Authentication** | Weak authentication, session fixation |
| **Cryptography** | Weak algorithms, insecure random, hardcoded keys |
| **Path Traversal** | Directory traversal, zip slip |
| **Memory Safety** | Buffer overflows, use-after-free |
| **Concurrency** | Race conditions, deadlocks |

---

## 🛡️ Dependabot Security Updates

**What it does:** Automatically creates PRs to update vulnerable dependencies.

### Enable Dependabot

1. **Navigate to Security Settings**
   - Go to: https://github.com/KoalaFacts/HeroSD-JWT/settings/security_analysis

2. **Enable Dependabot Alerts**
   - Find "Dependabot alerts" section
   - Click **Enable**

3. **Enable Dependabot Security Updates**
   - Find "Dependabot security updates" section
   - Click **Enable**
   - Dependabot will automatically create PRs for vulnerable dependencies

### Configure Dependabot (Optional)

Create `.github/dependabot.yml` to customize update schedule:

```yaml
version: 2
updates:
  # NuGet dependencies
  - package-ecosystem: "nuget"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
      - "security"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "ci"
```

---

## 🔐 Branch Protection Rules

**What it does:** Prevents direct commits to main, requires PR reviews and status checks.

### Recommended Settings for Main Branch

1. **Navigate to Branch Settings**
   - Go to: https://github.com/KoalaFacts/HeroSD-JWT/settings/branches

2. **Add Branch Protection Rule**
   - Branch name pattern: `main`
   - Enable the following:

**Protect matching branches:**
- ✅ Require a pull request before merging
  - ✅ Require approvals (1+)
  - ✅ Dismiss stale pull request approvals
  - ✅ Require review from Code Owners (if you have CODEOWNERS file)

**Require status checks before merging:**
- ✅ Require status checks to pass
- ✅ Require branches to be up to date
- Add required checks:
  - `build-and-test (ubuntu-latest, 8.0.x)`
  - `build-and-test (ubuntu-latest, 9.0.x)`
  - `code-quality`
  - `nuget-audit`

**Other settings:**
- ✅ Require conversation resolution before merging
- ✅ Do not allow bypassing the above settings
- ✅ Restrict who can push to matching branches (Maintainers only)

---

## 📊 Security Overview

After enabling all features, your Security tab should show:

```
┌─────────────────────────────────────────────┐
│ Security Overview                           │
├─────────────────────────────────────────────┤
│ ✅ Code scanning         │ 0 alerts         │
│ ✅ Secret scanning       │ 0 alerts         │
│ ✅ Dependabot alerts     │ 0 vulnerabilities│
│ ✅ Security policy       │ SECURITY.md      │
└─────────────────────────────────────────────┘
```

---

## 🚨 Responding to Security Alerts

### Secret Scanning Alert

If a secret is detected:

1. **Revoke the secret immediately**
   - Generate new key/token
   - Update all services using it

2. **Remove from git history**
   ```bash
   # Use git-filter-repo or BFG Repo-Cleaner
   git filter-repo --path-glob '**/*secret*' --invert-paths
   ```

3. **Close the alert**
   - Go to Security → Secret scanning
   - Mark as "Revoked" or "False positive"

### CodeQL Alert

If a vulnerability is found:

1. **Review the alert** in Security → Code scanning
2. **Click "Show more"** for detailed explanation
3. **Follow the remediation** guidance
4. **Create PR** with fix
5. **Verify** alert closes after merge

### Dependabot Alert

If a vulnerable dependency is found:

1. **Review the alert** in Security → Dependabot
2. **Check if Dependabot created PR** automatically
3. **If yes:** Review and merge the PR
4. **If no:** Manually update the dependency
   ```bash
   dotnet add package PackageName --version X.Y.Z
   ```

---

## ✅ Verification Checklist

Use this checklist to ensure all security features are enabled:

- [ ] Secret scanning enabled
- [ ] Secret scanning push protection enabled
- [ ] CodeQL analysis enabled (default setup)
- [ ] Dependabot alerts enabled
- [ ] Dependabot security updates enabled
- [ ] Branch protection rules configured for `main`
- [ ] Required status checks configured
- [ ] Security policy (SECURITY.md) exists
- [ ] All security alerts reviewed and resolved

---

## 🎯 Best Practices

1. **Review security alerts weekly**
   - Check Security tab every Monday
   - Triage and fix high/critical alerts first

2. **Keep dependencies updated**
   - Merge Dependabot PRs promptly
   - Run `dotnet list package --outdated` monthly

3. **Test security fixes**
   - All security PRs must pass CI
   - Review changes carefully

4. **Document security decisions**
   - If dismissing alerts, document why
   - Keep SECURITY.md updated

5. **Educate contributors**
   - Share this guide with team
   - Discuss security in code reviews

---

## 📚 Resources

- [GitHub Security Features](https://docs.github.com/en/code-security)
- [Secret Scanning Patterns](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-patterns)
- [CodeQL for C#](https://codeql.github.com/docs/codeql-language-guides/codeql-for-csharp/)
- [Dependabot Configuration](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)

---

## 🆘 Troubleshooting

### Problem: Secret scanning not finding secrets in history

**Solution:**
- GitHub scans incrementally
- Wait 15-30 minutes for full historical scan
- Check Security → Secret scanning for results

### Problem: CodeQL scan failing

**Solution:**
- Check Actions → CodeQL workflow logs
- Ensure .NET SDK version matches project
- Verify no breaking changes in codebase

### Problem: Dependabot PRs not appearing

**Solution:**
- Check Dependabot alerts are enabled
- Verify Dependabot security updates are enabled
- Check Insights → Dependency graph → Dependabot

---

**Questions?** Open an issue or discussion on GitHub.
