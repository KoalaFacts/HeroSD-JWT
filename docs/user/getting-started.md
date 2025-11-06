# Getting Started with HeroSD-JWT

This guide will help you get started with HeroSD-JWT, a .NET library for creating and verifying SD-JWT (Selective Disclosure for JSON Web Tokens).

## Prerequisites

- .NET 8.0 or .NET 9.0 SDK installed
- Basic understanding of JWT (JSON Web Tokens)
- Familiarity with C# and .NET

## Installation

Add the HeroSD-JWT package to your project:

### Using .NET CLI

```bash
dotnet add package HeroSD-JWT
```

### Using Package Manager Console

```powershell
Install-Package HeroSD-JWT
```

### Using PackageReference

Add this to your `.csproj` file:

```xml
<PackageReference Include="HeroSD-JWT" Version="1.0.7" />
```

## Your First SD-JWT

Let's create a simple SD-JWT with selectively disclosable claims:

```csharp
using HeroSdJwt.Issuance;
using HeroSdJwt.Common;
using HeroSdJwt.Verification;

// 1. Generate a signing key
var keyGen = KeyGenerator.Instance;
var key = keyGen.GenerateHmacKey();

// 2. Create SD-JWT with the fluent builder
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("name", "Alice Smith")
    .WithClaim("email", "alice@example.com")
    .WithClaim("age", 30)
    .WithClaim("country", "USA")
    .MakeSelective("email", "age")  // Only email and age are selectively disclosable
    .SignWithHmac(key)
    .Build();

// 3. Holder creates a presentation revealing only email
var presentation = sdJwt.ToPresentation("email");

// 4. Verifier receives and verifies the presentation
var verifier = new SdJwtVerifier();
var result = verifier.VerifyPresentation(presentation, key);

// 5. Access the disclosed claims
Console.WriteLine($"Subject: {result.DisclosedClaims["sub"]}");
Console.WriteLine($"Name: {result.DisclosedClaims["name"]}");
Console.WriteLine($"Email: {result.DisclosedClaims["email"]}");
// Note: "age" was not disclosed, so it won't be in DisclosedClaims
```

## Understanding the Three-Party Model

SD-JWT follows a three-party model:

### 1. Issuer
The issuer creates the SD-JWT and decides which claims can be selectively disclosed.

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.com")
    .MakeSelective("email")  // Email can be selectively disclosed
    .SignWithHmac(key)
    .Build();
```

### 2. Holder
The holder receives the SD-JWT from the issuer and decides which claims to disclose to the verifier.

```csharp
// Disclose only the email claim
var presentation = sdJwt.ToPresentation("email");

// Or disclose all available claims
var fullPresentation = sdJwt.ToPresentationWithAllClaims();
```

### 3. Verifier
The verifier receives the presentation and verifies the signature and disclosed claims.

```csharp
var verifier = new SdJwtVerifier();
var result = verifier.VerifyPresentation(presentation, verificationKey);

if (result.IsValid)
{
    // Access disclosed claims
    var email = result.DisclosedClaims["email"];
}
```

## Signature Algorithms

HeroSD-JWT supports three signature algorithms:

### HMAC-SHA256 (HS256) - Symmetric

```csharp
var key = keyGen.GenerateHmacKey();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithHmac(key)
    .Build();
```

### RSA-SHA256 (RS256) - Asymmetric

```csharp
var (rsaPrivate, rsaPublic) = keyGen.GenerateRsaKeyPair();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithRsa(rsaPrivate)
    .Build();

// Verify with public key
var result = verifier.VerifyPresentation(presentation, rsaPublic);
```

### ECDSA-P256-SHA256 (ES256) - Asymmetric

```csharp
var (ecPrivate, ecPublic) = keyGen.GenerateEcdsaKeyPair();
var sdJwt = SdJwtBuilder.Create()
    .WithClaims(claims)
    .MakeSelective("email")
    .SignWithEcdsa(ecPrivate)
    .Build();

// Verify with public key
var result = verifier.VerifyPresentation(presentation, ecPublic);
```

## Next Steps

- [Examples](examples.md) - More detailed examples
- [Security Best Practices](security.md) - Security considerations
- [API Reference](api-reference.md) - Complete API documentation
- [README](../../README.md) - Full feature list and overview

## Need Help?

- [GitHub Issues](https://github.com/KoalaFacts/HeroSD-JWT/issues) - Report bugs or request features
- [Discussions](https://github.com/KoalaFacts/HeroSD-JWT/discussions) - Community support
