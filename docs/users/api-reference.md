# API Reference

Complete API reference for HeroSD-JWT.

## Table of Contents

- [Namespaces](#namespaces)
- [Issuance](#issuance)
  - [SdJwtBuilder](#sdjwtbuilder)
  - [SdJwtIssuer](#sdjwtissuer)
- [Verification](#verification)
  - [SdJwtVerifier](#sdjwtverifier)
  - [VerificationResult](#verificationresult)
- [Common](#common)
  - [KeyGenerator](#keygenerator)
  - [SignatureAlgorithm](#signaturealgorithm)
  - [HashAlgorithm](#hashalgorithm)
- [Core](#core)
  - [SdJwt](#sdjwt)
  - [Disclosure](#disclosure)
- [Extension Methods](#extension-methods)

## Namespaces

- `HeroSdJwt.Issuance` - SD-JWT creation and issuance
- `HeroSdJwt.Verification` - SD-JWT verification
- `HeroSdJwt.Common` - Shared utilities and helpers
- `HeroSdJwt.Core` - Core domain models
- `HeroSdJwt.Presentation` - Presentation creation

## Issuance

### SdJwtBuilder

Fluent builder for creating SD-JWTs.

#### Methods

##### `Create()`

Creates a new builder instance.

```csharp
public static SdJwtBuilder Create()
```

**Example:**
```csharp
var builder = SdJwtBuilder.Create();
```

##### `WithClaim(string claimName, object claimValue)`

Adds a claim to the SD-JWT.

```csharp
public SdJwtBuilder WithClaim(string claimName, object claimValue)
```

**Parameters:**
- `claimName` - The name of the claim
- `claimValue` - The value of the claim (must be JSON-serializable)

**Returns:** The builder instance for chaining

**Example:**
```csharp
builder.WithClaim("sub", "user-123")
       .WithClaim("email", "alice@example.com")
       .WithClaim("age", 30);
```

##### `WithClaims(Dictionary<string, object> claims)`

Adds multiple claims at once.

```csharp
public SdJwtBuilder WithClaims(Dictionary<string, object> claims)
```

**Parameters:**
- `claims` - Dictionary of claim names to values

**Returns:** The builder instance for chaining

**Example:**
```csharp
var claims = new Dictionary<string, object>
{
    ["sub"] = "user-123",
    ["email"] = "alice@example.com",
    ["age"] = 30
};
builder.WithClaims(claims);
```

##### `MakeSelective(params string[] claimPaths)`

Marks claims as selectively disclosable.

```csharp
public SdJwtBuilder MakeSelective(params string[] claimPaths)
```

**Parameters:**
- `claimPaths` - Claim paths to make selective. Supports:
  - Simple claims: `"email"`
  - Nested claims: `"address.street"`
  - Array elements: `"degrees[1]"`

**Returns:** The builder instance for chaining

**Example:**
```csharp
builder.MakeSelective("email", "address.street", "degrees[1]");
```

##### `WithDecoys(int count)`

Adds decoy digests for privacy protection.

```csharp
public SdJwtBuilder WithDecoys(int count)
```

**Parameters:**
- `count` - Number of decoy digests to add (recommended: 2-5)

**Returns:** The builder instance for chaining

**Example:**
```csharp
builder.WithDecoys(3);
```

##### `WithHolderPublicKey(byte[] publicKey, string algorithm)`

Binds the SD-JWT to a holder's public key.

```csharp
public SdJwtBuilder WithHolderPublicKey(byte[] publicKey, string algorithm)
```

**Parameters:**
- `publicKey` - Holder's public key (SubjectPublicKeyInfo format)
- `algorithm` - Algorithm identifier ("ES256", "RS256", "HS256")

**Returns:** The builder instance for chaining

**Example:**
```csharp
var holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var publicKey = holderKey.ExportSubjectPublicKeyInfo();
builder.WithHolderPublicKey(publicKey, "ES256");
```

##### `SignWithHmac(byte[] key)`

Signs the SD-JWT with HMAC-SHA256.

```csharp
public SdJwtBuilder SignWithHmac(byte[] key)
```

**Parameters:**
- `key` - HMAC key (minimum 256 bits)

**Returns:** The builder instance for chaining

**Example:**
```csharp
var key = KeyGenerator.Instance.GenerateHmacKey();
builder.SignWithHmac(key);
```

##### `SignWithRsa(byte[] privateKey)`

Signs the SD-JWT with RSA-SHA256.

```csharp
public SdJwtBuilder SignWithRsa(byte[] privateKey)
```

**Parameters:**
- `privateKey` - RSA private key in PKCS#8 format (minimum 2048 bits)

**Returns:** The builder instance for chaining

**Example:**
```csharp
var (privateKey, _) = KeyGenerator.Instance.GenerateRsaKeyPair();
builder.SignWithRsa(privateKey);
```

##### `SignWithEcdsa(byte[] privateKey)`

Signs the SD-JWT with ECDSA-P256-SHA256.

```csharp
public SdJwtBuilder SignWithEcdsa(byte[] privateKey)
```

**Parameters:**
- `privateKey` - ECDSA private key in PKCS#8 format (P-256 curve)

**Returns:** The builder instance for chaining

**Example:**
```csharp
var (privateKey, _) = KeyGenerator.Instance.GenerateEcdsaKeyPair();
builder.SignWithEcdsa(privateKey);
```

##### `Build()`

Builds the SD-JWT.

```csharp
public SdJwt Build()
```

**Returns:** The constructed `SdJwt` instance

**Throws:**
- `InvalidOperationException` - If required configuration is missing

**Example:**
```csharp
var sdJwt = builder.Build();
```

### SdJwtIssuer

Low-level API for creating SD-JWTs.

#### Methods

##### `CreateSdJwt(...)`

Creates an SD-JWT with specified parameters.

```csharp
public SdJwt CreateSdJwt(
    Dictionary<string, object> claims,
    IEnumerable<string> selectivelyDisclosableClaims,
    byte[] signingKey,
    HashAlgorithm hashAlgorithm = HashAlgorithm.Sha256,
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256,
    int numberOfDecoys = 0,
    byte[]? holderPublicKey = null,
    string? holderKeyAlgorithm = null)
```

**Parameters:**
- `claims` - All claims to include
- `selectivelyDisclosableClaims` - Claims that can be selectively disclosed
- `signingKey` - Key for signing the JWT
- `hashAlgorithm` - Hash algorithm for digests (default: SHA-256)
- `signatureAlgorithm` - Signature algorithm (default: HS256)
- `numberOfDecoys` - Number of decoy digests (default: 0)
- `holderPublicKey` - Optional holder public key for binding
- `holderKeyAlgorithm` - Algorithm for holder's key

**Returns:** The constructed `SdJwt` instance

## Verification

### SdJwtVerifier

Verifies SD-JWT presentations.

#### Methods

##### `VerifyPresentation(...)`

Verifies a presentation and returns the result.

```csharp
public VerificationResult VerifyPresentation(
    string presentationString,
    byte[] verificationKey,
    string? expectedAudience = null,
    string? expectedNonce = null)
```

**Parameters:**
- `presentationString` - The complete presentation string
- `verificationKey` - Key for signature verification
- `expectedAudience` - Expected audience for key binding (optional)
- `expectedNonce` - Expected nonce for key binding (optional)

**Returns:** `VerificationResult` containing disclosed claims

**Throws:**
- `InvalidOperationException` - If verification fails

**Example:**
```csharp
var result = verifier.VerifyPresentation(
    presentation,
    key,
    expectedAudience: "https://verifier.example.com",
    expectedNonce: "abc123"
);
```

##### `TryVerifyPresentation(...)`

Attempts to verify a presentation without throwing exceptions.

```csharp
public VerificationResult TryVerifyPresentation(
    string presentationString,
    byte[] verificationKey,
    string? expectedAudience = null,
    string? expectedNonce = null)
```

**Parameters:** Same as `VerifyPresentation`

**Returns:** `VerificationResult` with `IsValid` indicating success or failure

**Example:**
```csharp
var result = verifier.TryVerifyPresentation(presentation, key);
if (!result.IsValid)
{
    Console.WriteLine("Verification failed: " + string.Join(", ", result.Errors));
}
```

### VerificationResult

Result of presentation verification.

#### Properties

##### `IsValid`

Indicates whether verification succeeded.

```csharp
public bool IsValid { get; }
```

##### `DisclosedClaims`

Dictionary of disclosed claims.

```csharp
public IReadOnlyDictionary<string, object> DisclosedClaims { get; }
```

##### `KeyBindingVerified`

Indicates whether key binding was verified.

```csharp
public bool KeyBindingVerified { get; }
```

##### `Errors`

List of error messages if verification failed.

```csharp
public IReadOnlyList<string> Errors { get; }
```

#### Methods

##### `GetDisclosedObject(string claimName)`

Reconstructs a nested object from disclosed claims.

```csharp
public Dictionary<string, object> GetDisclosedObject(string claimName)
```

**Parameters:**
- `claimName` - Name of the claim containing the object

**Returns:** Reconstructed object with disclosed properties

**Example:**
```csharp
var address = result.GetDisclosedObject("address");
// { "street": "123 Main St", "city": "Boston" }
```

##### `GetDisclosedArray(string claimName)`

Reconstructs an array from disclosed elements.

```csharp
public object?[] GetDisclosedArray(string claimName)
```

**Parameters:**
- `claimName` - Name of the claim containing the array

**Returns:** Sparse array with disclosed elements (nulls for undisclosed)

**Example:**
```csharp
var degrees = result.GetDisclosedArray("degrees");
// ["BS", null, "PhD"]
```

## Common

### KeyGenerator

Generates cryptographic keys.

#### Properties

##### `Instance`

Singleton instance.

```csharp
public static IKeyGenerator Instance { get; }
```

#### Methods

##### `GenerateHmacKey()`

Generates a 256-bit HMAC key.

```csharp
public byte[] GenerateHmacKey()
```

**Returns:** 32-byte HMAC key

##### `GenerateRsaKeyPair()`

Generates a 2048-bit RSA key pair.

```csharp
public (byte[] privateKey, byte[] publicKey) GenerateRsaKeyPair()
```

**Returns:** Tuple of (PKCS#8 private key, SubjectPublicKeyInfo public key)

##### `GenerateEcdsaKeyPair()`

Generates a P-256 ECDSA key pair.

```csharp
public (byte[] privateKey, byte[] publicKey) GenerateEcdsaKeyPair()
```

**Returns:** Tuple of (PKCS#8 private key, SubjectPublicKeyInfo public key)

### SignatureAlgorithm

Enumeration of supported signature algorithms.

```csharp
public enum SignatureAlgorithm
{
    HS256,  // HMAC-SHA256
    RS256,  // RSA-SHA256
    ES256   // ECDSA-P256-SHA256
}
```

### HashAlgorithm

Enumeration of supported hash algorithms.

```csharp
public enum HashAlgorithm
{
    Sha256,  // SHA-256 (default)
    Sha384,  // SHA-384
    Sha512   // SHA-512
}
```

## Core

### SdJwt

Represents a Selective Disclosure JWT.

#### Properties

##### `Jwt`

The JWT portion of the SD-JWT.

```csharp
public string Jwt { get; }
```

##### `Disclosures`

List of disclosure objects.

```csharp
public IReadOnlyList<Disclosure> Disclosures { get; }
```

#### Methods

##### `ToCombinedFormat()`

Converts to the combined format string.

```csharp
public string ToCombinedFormat()
```

**Returns:** Format: `jwt~disclosure1~disclosure2~...~`

### Disclosure

Represents a single disclosure.

#### Properties

##### `Salt`

Random salt for the disclosure.

```csharp
public string Salt { get; }
```

##### `ClaimName`

Name of the disclosed claim.

```csharp
public string ClaimName { get; }
```

##### `ClaimValue`

Value of the disclosed claim.

```csharp
public object ClaimValue { get; }
```

## Extension Methods

### SdJwt Extensions

#### `ToPresentation(...)`

Creates a presentation with specified claims.

```csharp
public static string ToPresentation(
    this SdJwt sdJwt,
    params string[] claimsToDisclose)
```

**Example:**
```csharp
var presentation = sdJwt.ToPresentation("email", "address.street");
```

#### `ToPresentationWithAllClaims()`

Creates a presentation disclosing all claims.

```csharp
public static string ToPresentationWithAllClaims(this SdJwt sdJwt)
```

**Example:**
```csharp
var presentation = sdJwt.ToPresentationWithAllClaims();
```

#### `ToPresentationWithKeyBinding(...)`

Creates a presentation with key binding JWT.

```csharp
public static string ToPresentationWithKeyBinding(
    this SdJwt sdJwt,
    byte[] holderPrivateKey,
    SignatureAlgorithm algorithm,
    string audience,
    string nonce,
    params string[] claimsToDisclose)
```

**Example:**
```csharp
var presentation = sdJwt.ToPresentationWithKeyBinding(
    holderPrivateKey,
    SignatureAlgorithm.ES256,
    "https://verifier.example.com",
    "random-nonce",
    "email", "age"
);
```

## Type Support

### Supported Claim Value Types

- `string`
- `int`, `long`, `double`, `decimal`
- `bool`
- `DateTime`, `DateTimeOffset`
- Arrays and `List<T>`
- Dictionaries and objects
- `JsonElement` (for pre-parsed JSON)
- `null`

### AOT Compatibility

All types are AOT-compatible when using standard JSON-serializable types. For custom classes, ensure they have the appropriate JSON serialization attributes.

## Thread Safety

All public types are thread-safe for read operations. For write operations:
- `SdJwtBuilder` - Not thread-safe (single-threaded builder pattern)
- `SdJwtIssuer` - Thread-safe (reusable, stateless)
- `SdJwtVerifier` - Thread-safe (reusable, stateless)
- `KeyGenerator` - Thread-safe (singleton)
