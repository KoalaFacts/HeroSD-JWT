# HeroSD-JWT Examples

This document provides detailed examples of using HeroSD-JWT for various scenarios.

## Table of Contents

- [Live Examples](#live-examples)
- [Basic Examples](#basic-examples)
- [Nested Objects](#nested-objects)
- [Array Elements](#array-elements)
- [Key Binding](#key-binding)
- [Different Signature Algorithms](#different-signature-algorithms)
- [Error Handling](#error-handling)
- [Real-World Scenarios](#real-world-scenarios)
- [Array & Object Reconstruction](#array--object-reconstruction)
- [JWT Key Rotation](#jwt-key-rotation)

## Live Examples

The repository includes complete, runnable example projects that demonstrate real-world integrations:

### 🌐 ASP.NET Core Integration Example

**Location:** [examples/AspNetCoreIntegrationExample/](../../examples/AspNetCoreIntegrationExample/)

A production-ready REST API demonstrating SD-JWT authentication and authorization with ASP.NET Core.

**Features:**
- ✅ SD-JWT token issuance endpoint
- ✅ Automatic authentication middleware
- ✅ Protected endpoints with claims-based authorization
- ✅ OpenAPI documentation with Scalar UI
- ✅ Configuration-based setup
- ✅ Full request/response examples

**Quick Start:**
```bash
cd examples/AspNetCoreIntegrationExample
dotnet run
# Visit https://localhost:5001/openapi/v1
```

**Learn More:** [ASP.NET Core Integration README](../../examples/AspNetCoreIntegrationExample/README.md)

### 📊 Observability with Serilog Example

**Location:** [examples/SerilogExample/](../../examples/SerilogExample/)

Comprehensive observability demonstration using Serilog for structured logging, metrics, and distributed tracing.

**Features:**
- ✅ Structured logging with Serilog (console + file)
- ✅ Real-time metrics collection and reporting
- ✅ Distributed tracing with Activity/Span tracking
- ✅ Custom log enrichers (correlation IDs, environment info)
- ✅ Complete SD-JWT lifecycle demonstration
- ✅ Error logging and verification failure examples

**Quick Start:**
```bash
cd examples/SerilogExample
dotnet run
# Check console output and logs/sdjwt-*.log
```

**Learn More:** [Serilog Example README](../../examples/SerilogExample/README.md)

---

## Basic Examples

### Simple Credential with Selective Disclosure

```csharp
using HeroSdJwt.Issuance;
using HeroSdJwt.Common;
using HeroSdJwt.Verification;

// Issuer creates SD-JWT
var keyGen = KeyGenerator.Instance;
var key = keyGen.GenerateHmacKey();

var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("name", "Alice Smith")
    .WithClaim("email", "alice@example.com")
    .WithClaim("phone", "+1-555-0100")
    .WithClaim("birthdate", "1990-01-01")
    .MakeSelective("email", "phone", "birthdate")
    .SignWithHmac(key)
    .Build();

// Holder creates presentation with only email and birthdate
var presentation = sdJwt.ToPresentation("email", "birthdate");

// Verifier verifies and accesses claims
var verifier = new SdJwtVerifier();
var result = verifier.VerifyPresentation(presentation, key);

Console.WriteLine($"Name: {result.DisclosedClaims["name"]}");  // Always visible
Console.WriteLine($"Email: {result.DisclosedClaims["email"]}"); // Disclosed
Console.WriteLine($"Birthdate: {result.DisclosedClaims["birthdate"]}"); // Disclosed
// Phone was not disclosed, so it's not available
```

## Nested Objects

### Address with Selective Disclosure

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-456")
    .WithClaim("name", "Bob Johnson")
    .WithClaim("address", new
    {
        street = "123 Main Street",
        city = "Boston",
        state = "MA",
        zip = "02101",
        country = "USA",
        geo = new
        {
            lat = 42.3601,
            lon = -71.0589
        }
    })
    .MakeSelective(
        "address.street",
        "address.zip",
        "address.geo.lat",
        "address.geo.lon"
    )
    .SignWithHmac(key)
    .Build();

// Holder discloses only street and coordinates
var presentation = sdJwt.ToPresentation(
    "address.street",
    "address.geo.lat",
    "address.geo.lon"
);

// Verifier reconstructs the nested object
var result = verifier.VerifyPresentation(presentation, key);
var address = result.GetDisclosedObject("address");
// Result: { "street": "123 Main Street", "city": "Boston", "state": "MA",
//           "country": "USA", "geo": { "lat": 42.3601, "lon": -71.0589 } }
// Note: zip was not disclosed
```

### Multi-Level Nesting

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("profile", new
    {
        personal = new
        {
            name = "Alice",
            age = 30,
            contacts = new
            {
                email = "alice@example.com",
                phone = "+1-555-0100"
            }
        },
        employment = new
        {
            company = "Acme Corp",
            position = "Engineer"
        }
    })
    .MakeSelective(
        "profile.personal.age",
        "profile.personal.contacts.email",
        "profile.personal.contacts.phone",
        "profile.employment.position"
    )
    .SignWithHmac(key)
    .Build();

// Disclose only age and email
var presentation = sdJwt.ToPresentation(
    "profile.personal.age",
    "profile.personal.contacts.email"
);
```

## Array Elements

### Education Degrees

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-789")
    .WithClaim("name", "Carol White")
    .WithClaim("degrees", new[] { "BS", "MS", "PhD" })
    .WithClaim("certifications", new[] { "AWS", "Azure", "GCP" })
    .MakeSelective("degrees[1]", "degrees[2]")  // MS and PhD are selective
    .MakeSelective("certifications[0]", "certifications[1]", "certifications[2]")
    .SignWithHmac(key)
    .Build();

// Disclose only PhD and Azure certification
var presentation = sdJwt.ToPresentation("degrees[2]", "certifications[1]");

// Reconstruct arrays
var result = verifier.VerifyPresentation(presentation, key);
var degrees = result.GetDisclosedArray("degrees");
// Result: ["BS", null, "PhD"] - sparse array with only disclosed elements

var certs = result.GetDisclosedArray("certifications");
// Result: [null, "Azure", null]
```

### Array of Objects

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("experiences", new[]
    {
        new { company = "Acme Corp", years = 3 },
        new { company = "TechStart", years = 2 },
        new { company = "BigCo", years = 5 }
    })
    .MakeSelective("experiences[0]", "experiences[1]", "experiences[2]")
    .SignWithHmac(key)
    .Build();

// Disclose only most recent two experiences
var presentation = sdJwt.ToPresentation("experiences[1]", "experiences[2]");
```

## Key Binding

### Proof of Possession

Key binding proves that the presenter holds a specific key, preventing presentation theft.

```csharp
using System.Security.Cryptography;

// Issuer creates SD-JWT with holder's public key
var holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var holderPublicKey = holderEcdsa.ExportSubjectPublicKeyInfo();

var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.com")
    .WithHolderPublicKey(holderPublicKey, "ES256")  // Bind to holder's key
    .MakeSelective("email")
    .SignWithHmac(issuerKey)
    .Build();

// Holder creates presentation with key binding JWT
var holderPrivateKey = holderEcdsa.ExportPkcs8PrivateKey();
var audience = "https://verifier.example.com";
var nonce = "random-nonce-12345";

var presentation = sdJwt.ToPresentationWithKeyBinding(
    holderPrivateKey,
    SignatureAlgorithm.ES256,
    audience,
    nonce,
    new[] { "email" }
);

// Verifier checks key binding
var result = verifier.VerifyPresentation(
    presentation,
    issuerKey,
    expectedAudience: audience,
    expectedNonce: nonce
);

if (result.KeyBindingVerified)
{
    Console.WriteLine("✅ Key binding verified - presenter owns the credential");
}
```

## Different Signature Algorithms

### RSA (RS256)

```csharp
var keyGen = KeyGenerator.Instance;
var (rsaPrivate, rsaPublic) = keyGen.GenerateRsaKeyPair();

// Issuer signs with private key
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.com")
    .MakeSelective("email")
    .SignWithRsa(rsaPrivate)
    .Build();

// Verifier verifies with public key
var presentation = sdJwt.ToPresentation("email");
var result = verifier.VerifyPresentation(presentation, rsaPublic);
```

### ECDSA (ES256)

```csharp
var (ecPrivate, ecPublic) = keyGen.GenerateEcdsaKeyPair();

// Issuer signs with private key
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.com")
    .MakeSelective("email")
    .SignWithEcdsa(ecPrivate)
    .Build();

// Verifier verifies with public key
var presentation = sdJwt.ToPresentation("email");
var result = verifier.VerifyPresentation(presentation, ecPublic);
```

## Error Handling

### Using Try* Pattern

```csharp
var result = verifier.TryVerifyPresentation(presentation, key);

if (!result.IsValid)
{
    Console.WriteLine("❌ Verification failed:");
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"  - {error}");
    }
    return;
}

// Safe to access claims
var email = result.DisclosedClaims["email"];
```

### Using Exceptions

```csharp
try
{
    var result = verifier.VerifyPresentation(presentation, key);
    var email = result.DisclosedClaims["email"];
}
catch (InvalidOperationException ex)
{
    Console.WriteLine($"Verification failed: {ex.Message}");
}
```

## Real-World Scenarios

### Driver's License

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("iss", "state-dmv")
    .WithClaim("sub", "license-123456")
    .WithClaim("name", "Alice Smith")
    .WithClaim("birthdate", "1990-01-01")
    .WithClaim("address", new
    {
        street = "123 Main St",
        city = "Boston",
        state = "MA",
        zip = "02101"
    })
    .WithClaim("license_class", "D")
    .WithClaim("restrictions", new[] { "CORRECTIVE_LENSES" })
    .MakeSelective(
        "birthdate",
        "address.street",
        "address.zip",
        "restrictions[0]"
    )
    .SignWithRsa(dmvPrivateKey)
    .Build();

// Age verification - only disclose birthdate
var ageVerificationPresentation = sdJwt.ToPresentation("birthdate");

// Address verification - disclose only city and state (not street/zip)
var addressPresentation = sdJwt.ToPresentation(
    "address.city",
    "address.state"
);
```

### Medical Record

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("patient_id", "P123456")
    .WithClaim("name", "Bob Johnson")
    .WithClaim("medications", new[]
    {
        new { name = "Medication A", dosage = "10mg" },
        new { name = "Medication B", dosage = "20mg" }
    })
    .WithClaim("allergies", new[] { "penicillin", "peanuts" })
    .WithClaim("blood_type", "O+")
    .MakeSelective(
        "medications[0]",
        "medications[1]",
        "allergies[0]",
        "allergies[1]",
        "blood_type"
    )
    .SignWithEcdsa(hospitalPrivateKey)
    .Build();

// Emergency responder - disclose only critical info
var emergencyPresentation = sdJwt.ToPresentation(
    "allergies[0]",
    "allergies[1]",
    "blood_type"
);
```

### Employee Credential

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("employee_id", "E123456")
    .WithClaim("name", "Carol White")
    .WithClaim("department", "Engineering")
    .WithClaim("position", "Senior Engineer")
    .WithClaim("clearance_level", 3)
    .WithClaim("email", "carol@company.com")
    .WithClaim("phone", "+1-555-0100")
    .WithClaim("salary", 150000)
    .MakeSelective(
        "position",
        "clearance_level",
        "email",
        "phone",
        "salary"
    )
    .SignWithRsa(companyPrivateKey)
    .Build();

// Building access - only disclose clearance level
var accessPresentation = sdJwt.ToPresentation("clearance_level");

// External partner - disclose contact info only
var contactPresentation = sdJwt.ToPresentation("email", "phone");
```

## Array & Object Reconstruction

### Discovering Reconstructible Claims

When working with complex presentations, use `GetReconstructibleClaims()` to discover which claims can be reconstructed from the disclosed data:

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("user", new
    {
        name = "Alice",
        contact = new
        {
            email = "alice@example.com",
            phone = "+1-555-0100"
        },
        addresses = new[]
        {
            new { type = "home", street = "123 Main St" },
            new { type = "work", street = "456 Office Blvd" }
        }
    })
    .MakeSelective(
        "user.contact.email",
        "user.addresses[0]",
        "user.addresses[1].street"
    )
    .SignWithHmac(key)
    .Build();

// Holder creates presentation
var presentation = sdJwt.ToPresentation(
    "user.contact.email",
    "user.addresses[0]"
);

// Verifier discovers what can be reconstructed
var result = verifier.VerifyPresentation(presentation, key);
var reconstructible = result.GetReconstructibleClaims();
// Returns: ["user", "user.contact", "user.addresses"]

// Reconstruct discovered structures
var user = result.GetDisclosedObject("user");
// Result: {
//   "name": "Alice",
//   "contact": { "email": "alice@example.com" },
//   "addresses": [{ "type": "home", "street": "123 Main St" }, null]
// }

var addresses = result.GetDisclosedArray("user.addresses");
// Result: [{ "type": "home", "street": "123 Main St" }, null]
```

### Complex Nested Reconstruction

Combine arrays and objects in hierarchical structures:

```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("education", new[]
    {
        new
        {
            degree = "BS",
            university = "MIT",
            location = new { city = "Cambridge", state = "MA" },
            year = 2015
        },
        new
        {
            degree = "MS",
            university = "Stanford",
            location = new { city = "Stanford", state = "CA" },
            year = 2017
        },
        new
        {
            degree = "PhD",
            university = "Berkeley",
            location = new { city = "Berkeley", state = "CA" },
            year = 2021
        }
    })
    .MakeSelective(
        "education[0].degree",
        "education[0].university",
        "education[1]",
        "education[2].location.city",
        "education[2].location.state"
    )
    .SignWithHmac(key)
    .Build();

// Disclose graduate degrees with partial location info
var presentation = sdJwt.ToPresentation(
    "education[1]",
    "education[2].location.city",
    "education[2].location.state"
);

var result = verifier.VerifyPresentation(presentation, key);
var education = result.GetDisclosedArray("education");
// Result: [
//   null,
//   { "degree": "MS", "university": "Stanford",
//     "location": { "city": "Stanford", "state": "CA" }, "year": 2017 },
//   { "location": { "city": "Berkeley", "state": "CA" } }
// ]
```

## JWT Key Rotation

### Issuing with Key IDs

Use the `kid` (key ID) parameter to support key rotation scenarios:

```csharp
var keyGen = KeyGenerator.Instance;
var currentKey = keyGen.GenerateHmacKey();

// Issue SD-JWT with key identifier
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("email", "alice@example.com")
    .WithClaim("role", "admin")
    .MakeSelective("email", "role")
    .WithKeyId("key-2024-11")  // Specify key ID
    .SignWithHmac(currentKey)
    .Build();

// The JWT header will include: { "alg": "HS256", "kid": "key-2024-11" }
```

### Verifying with Key Resolver

Implement dynamic key resolution for multi-key deployments:

```csharp
using HeroSdJwt.Cryptography;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

// Set up key store with multiple active keys
var keyStore = new Dictionary<string, byte[]>
{
    ["key-2024-09"] = oldKey,      // Being phased out
    ["key-2024-10"] = previousKey, // Previous generation
    ["key-2024-11"] = currentKey,  // Current active key
    ["key-2024-12"] = nextKey      // Pre-deployed for rotation
};

// Create key resolver delegate
KeyResolver resolver = keyId =>
{
    if (keyStore.TryGetValue(keyId, out var key))
    {
        return key;
    }

    // Log missing key for monitoring
    Console.WriteLine($"Warning: Unknown key ID requested: {keyId}");
    return null;
};

// Verify presentation using resolver
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions(),
    new EcPublicKeyConverter(),
    new SignatureValidator(),
    new DigestValidator(),
    new KeyBindingValidator(),
    new ClaimValidator());

var result = verifier.TryVerifyPresentation(presentation, resolver);

if (result.IsValid)
{
    Console.WriteLine($"Verified successfully with key: {result.KeyId}");
    var role = result.DisclosedClaims["role"].GetString();
}
else
{
    Console.WriteLine($"Verification failed: {result.ErrorMessage}");
}
```

### Key Rotation Workflow

Complete example of rotating keys in production:

```csharp
public class KeyRotationService
{
    private readonly Dictionary<string, KeyMetadata> _keys = new();

    public class KeyMetadata
    {
        public byte[] Key { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? RotatedAt { get; set; }
        public bool IsActive { get; set; }
    }

    public string IssueToken(Dictionary<string, object> claims, string[] selectiveClaims)
    {
        // Get current active key
        var activeKey = _keys.First(k => k.Value.IsActive);

        var sdJwt = SdJwtBuilder.Create()
            .WithClaims(claims)
            .MakeSelective(selectiveClaims)
            .WithKeyId(activeKey.Key)  // Use active key ID
            .SignWithHmac(activeKey.Value.Key)
            .Build();

        return sdJwt.EncodedSdJwt;
    }

    public void RotateKey()
    {
        var keyGen = KeyGenerator.Instance;
        var newKeyId = $"key-{DateTime.UtcNow:yyyy-MM}";
        var newKey = keyGen.GenerateHmacKey();

        // Add new key (not active yet)
        _keys[newKeyId] = new KeyMetadata
        {
            Key = newKey,
            CreatedAt = DateTime.UtcNow,
            IsActive = false
        };

        Console.WriteLine($"New key deployed: {newKeyId}");
    }

    public void ActivateKey(string keyId)
    {
        // Deactivate current key
        foreach (var key in _keys.Where(k => k.Value.IsActive))
        {
            key.Value.IsActive = false;
            key.Value.RotatedAt = DateTime.UtcNow;
        }

        // Activate new key
        _keys[keyId].IsActive = true;
        Console.WriteLine($"Activated key: {keyId}");
    }

    public void RemoveOldKeys(TimeSpan retention)
    {
        var cutoff = DateTime.UtcNow - retention;
        var oldKeys = _keys
            .Where(k => k.Value.RotatedAt.HasValue && k.Value.RotatedAt < cutoff)
            .Select(k => k.Key)
            .ToList();

        foreach (var keyId in oldKeys)
        {
            _keys.Remove(keyId);
            Console.WriteLine($"Removed old key: {keyId}");
        }
    }

    public KeyResolver GetKeyResolver()
    {
        return keyId => _keys.GetValueOrDefault(keyId)?.Key;
    }
}

// Usage
var rotationService = new KeyRotationService();

// 1. Deploy new key (overlap period begins)
rotationService.RotateKey();
Thread.Sleep(TimeSpan.FromHours(1)); // Wait for propagation

// 2. Activate new key (new tokens use new key)
rotationService.ActivateKey("key-2024-11");

// 3. Keep old keys for validation during grace period
Thread.Sleep(TimeSpan.FromDays(7));

// 4. Remove old keys after retention period
rotationService.RemoveOldKeys(TimeSpan.FromDays(30));
```

## Next Steps

- [Security Best Practices](security.md) - Important security considerations
- [API Reference](api-reference.md) - Complete API documentation
- [Getting Started](getting-started.md) - Basic setup guide
