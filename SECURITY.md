# Security Policy

## Supported Versions

We actively support the following versions of HeroSD-JWT with security updates:

| Version | Supported          | .NET Targets       |
| ------- | ------------------ | ------------------ |
| 1.0.x   | :white_check_mark: | .NET 8.0 & 9.0     |
| < 1.0   | :x:                | Not supported      |

**Note:** As a library with zero dependencies relying solely on .NET BCL, security updates are primarily driven by .NET runtime updates and library-specific vulnerability fixes.

---

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in HeroSD-JWT, please report it responsibly.

### 🔒 How to Report

**GitHub Issues:**
1. **For sensitive vulnerabilities:** Create a GitHub issue with `[SECURITY]` prefix in the title
2. **Mark as private** if possible, or contact maintainers first before creating public issue
3. Go to: https://github.com/KoalaFacts/HeroSD-JWT/issues/new
4. Include the information listed below

**Note:** For critical vulnerabilities that should not be publicly disclosed, please reach out to repository maintainers via GitHub discussion or issue to coordinate private reporting.

### 📝 What to Include

Please include the following information in your report:

1. **Description** - Clear description of the vulnerability
2. **Impact** - What could an attacker accomplish?
3. **Reproduction** - Step-by-step instructions to reproduce the issue
4. **Proof of Concept** - Code, screenshots, or examples demonstrating the vulnerability
5. **Suggested Fix** - If you have recommendations (optional)
6. **CVE ID** - If you have obtained a CVE identifier (optional)

### ⏱️ Response Timeline

- **Initial Response:** Within 48 hours of report receipt
- **Triage & Assessment:** Within 5 business days
- **Status Updates:** Every 7 days until resolution
- **Public Disclosure:** 90 days after fix is released (coordinated disclosure)

---

## Security Update Process

### 1. Vulnerability Assessment

Once a vulnerability is reported, we will:

1. Acknowledge receipt within 48 hours
2. Assign a severity level (Critical, High, Medium, Low)
3. Determine affected versions
4. Develop a remediation plan

### 2. Fix Development

- **Critical/High Severity:** Fix developed immediately, release within 7-14 days
- **Medium Severity:** Fix developed within 30 days
- **Low Severity:** Fix included in next scheduled release

### 3. Release & Disclosure

1. **Patched Version Released** - Security fix deployed to NuGet
2. **Security Advisory Published** - GitHub Security Advisory created
3. **CVE Assignment** - CVE identifier assigned (if applicable)
4. **Public Announcement** - Security update announced via:
   - GitHub Releases
   - NuGet package release notes
   - GitHub Security Advisory
   - Repository README (if critical)

### 4. Coordinated Disclosure

We follow a **90-day coordinated disclosure policy:**

- **Day 0:** Vulnerability reported and acknowledged
- **Day 0-90:** Private development of fix, coordination with reporter
- **Day 90:** Public disclosure, even if fix is not complete (with mitigation guidance)
- **Preferred:** Public disclosure occurs when fix is released (before Day 90)

Reporters are credited in the security advisory unless anonymity is requested.

---

## Security Best Practices

When using HeroSD-JWT in production, please follow these security best practices documented in our [Security Guide](docs/users/security.md):

### ⚡ Critical Security Considerations

1. **Key Management**
   - Use hardware security modules (HSMs) or cloud key vaults for production keys
   - Never hardcode signing keys in source code
   - Rotate signing keys regularly (recommended: every 90 days)
   - Use unique `kid` (key ID) for each key

2. **Algorithm Selection**
   - **Recommended:** ES256 (ECDSA with P-256), RS256 (RSA-PSS), EdDSA (Ed25519)
   - **Avoid:** HS256 in distributed systems (shared secret vulnerability)
   - **Never:** "none" algorithm (automatically rejected by HeroSD-JWT)

3. **Temporal Claim Validation**
   - Always validate `exp` (expiration time)
   - Use `nbf` (not before) for future-dated credentials
   - Configure appropriate clock skew (default: 5 minutes)

4. **Key Binding**
   - Require key binding (`RequireKeyBinding = true`) for high-security scenarios
   - Validate holder's proof-of-possession before accepting disclosures

5. **Disclosure Limits**
   - Be aware of DoS protection limits:
     - Maximum JWT size: 64 KB
     - Maximum disclosures: 100
     - Maximum nesting depth: 10 levels
   - These limits prevent resource exhaustion attacks

6. **Critical Claims Protection**
   - The following claims are **never** selectively disclosable:
     - `iss`, `iat`, `exp`, `nbf`, `aud`, `cnf`, `_sd_alg`, `_sd`
   - This prevents algorithm confusion and cryptographic attacks

### 🔐 Cryptographic Guarantees

HeroSD-JWT implements the following security measures:

- ✅ **Constant-time comparison** for digest validation (prevents timing attacks)
- ✅ **Cryptographically secure RNG** for salt generation (128-bit minimum)
- ✅ **Algorithm confusion prevention** (rejects "none" algorithm)
- ✅ **DoS protection** (size and count limits)
- ✅ **Reserved claim protection** (prevents selective disclosure of security-critical claims)

For detailed security guidance, see [docs/users/security.md](docs/users/security.md).

---

## Known Security Limitations

### Out of Scope

The following are **explicitly out of scope** for HeroSD-JWT security:

1. **Key Storage** - HeroSD-JWT does not provide key storage mechanisms. Implementers must use:
   - Azure Key Vault
   - AWS KMS
   - HashiCorp Vault
   - Hardware Security Modules (HSMs)

2. **Network Security** - TLS/HTTPS transport encryption is the application's responsibility

3. **Authentication** - SD-JWT is for **authorization** and **credential presentation**, not authentication

4. **Revocation** - Token revocation requires external infrastructure (status lists, certificate revocation)

5. **Zero-Knowledge Proofs** - HeroSD-JWT implements selective disclosure, not zero-knowledge cryptography

### Dependency Security

**Zero Third-Party Dependencies:**
HeroSD-JWT has **zero external dependencies** and relies only on .NET Base Class Library (BCL) cryptographic primitives. This:

- ✅ Eliminates supply chain attack vectors
- ✅ Reduces attack surface
- ✅ Simplifies security audits
- ✅ Ensures compatibility with .NET security updates

The library is automatically covered by:
- .NET Runtime security patches
- Microsoft Security Response Center (MSRC) advisories
- CodeQL security scanning (CI/CD)
- Dependency review (CI/CD)
- NuGet audit (CI/CD)

---

## Security Audits

### Internal Security Measures

- ✅ **Static Analysis:** TreatWarningsAsErrors enforced in all projects
- ✅ **Code Scanning:** CodeQL integrated in CI/CD
- ✅ **Dependency Scanning:** GitHub Dependency Review and NuGet audit
- ✅ **Secret Scanning:** GitHub secret scanning enabled
- ✅ **Test Coverage:** 95%+ test coverage including security-specific tests
- ✅ **Security Test Suite:** Dedicated `tests/Security/` directory with:
  - Algorithm confusion tests
  - Timing attack resistance tests
  - Salt security tests
  - Key ID security tests

### External Security Audits

**Status:** No external security audits have been conducted yet.

We welcome security researchers to audit the library and report findings responsibly.

---

## Security-Related Configuration

### Recommended Production Configuration

```csharp
var options = new SdJwtVerificationOptions
{
    // Require key binding for high-security scenarios
    RequireKeyBinding = true,

    // Validate temporal claims
    ValidateExpirationTime = true,
    ValidateNotBeforeTime = true,

    // Validate issuer (prevent token misuse)
    ExpectedIssuer = "https://trusted-issuer.example.com",

    // Validate audience (prevent token replay)
    ExpectedAudience = "https://your-api.example.com",

    // Configure clock skew (default: 5 minutes)
    ClockSkewSeconds = 300,

    // Use secure key resolution
    KeyResolver = async (kid) =>
    {
        // Fetch from Azure Key Vault, AWS KMS, etc.
        return await keyVault.GetKeyAsync(kid);
    }
};
```

### ASP.NET Core Configuration

```csharp
services.AddAuthentication()
    .AddSdJwt(options =>
    {
        options.RequireKeyBinding = true;
        options.ExpectedIssuer = "https://trusted-issuer.example.com";
        options.ExpectedAudience = "https://api.example.com";

        options.KeyResolver = async (kid, ct) =>
        {
            // Secure key resolution from key vault
            return await keyVault.GetKeyAsync(kid, ct);
        };
    });
```

---

## Security Changelog

Security-related changes are documented in [CHANGELOG.md](CHANGELOG.md) with `[SECURITY]` prefix.

### Security Fixes by Version

| Version | Date       | CVE ID | Severity | Description |
|---------|------------|--------|----------|-------------|
| 1.0.x   | N/A        | N/A    | N/A      | No known vulnerabilities |

---

## Recognition

We gratefully acknowledge security researchers who have responsibly disclosed vulnerabilities:

_(No security researchers listed yet)_

---

## Additional Resources

- **Security Best Practices:** [docs/users/security.md](docs/users/security.md)
- **IETF Specification:** [draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- **.NET Cryptography:** [Microsoft Cryptography Documentation](https://learn.microsoft.com/en-us/dotnet/standard/security/cryptography-model)
- **OWASP JWT Security:** [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

## Questions?

For security-related questions (non-vulnerabilities):
- **GitHub Discussions:** https://github.com/KoalaFacts/HeroSD-JWT/discussions
- **GitHub Issues:** https://github.com/KoalaFacts/HeroSD-JWT/issues (for non-security bugs)

**For security vulnerabilities:** Create a GitHub issue with `[SECURITY]` prefix at https://github.com/KoalaFacts/HeroSD-JWT/issues/new

---

**Last Updated:** 2025-01-07
**Version:** 1.0
