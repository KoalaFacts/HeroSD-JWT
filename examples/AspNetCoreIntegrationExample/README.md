# ASP.NET Core Integration Example

This example demonstrates how to integrate HeroSD-JWT with ASP.NET Core for automatic SD-JWT authentication and authorization.

## Features Demonstrated

- ✅ **SD-JWT Token Issuance** - Creating SD-JWTs with selective disclosure
- ✅ **Automatic Authentication** - Using the `HeroSdJwt.AspNetCore` package for seamless integration
- ✅ **Claims Mapping** - Automatic mapping of disclosed claims to `HttpContext.User`
- ✅ **Protected Endpoints** - Using `[RequireAuthorization]` with SD-JWT authentication
- ✅ **Configuration** - Loading settings from `appsettings.json`
- ✅ **API Documentation** - Using Microsoft's built-in OpenAPI with Scalar UI

## Prerequisites

- .NET 8.0 SDK or later (supports .NET 8.0 LTS, 9.0, and 10.0)
- Basic understanding of ASP.NET Core Minimal APIs
- Basic understanding of JWT/SD-JWT concepts

## Running the Example

1. **Navigate to the example directory:**
   ```bash
   cd examples/AspNetCoreIntegrationExample
   ```

2. **Run the application:**
   ```bash
   dotnet run
   ```

3. **Access the API:**
   - **API Documentation (Scalar)**: https://localhost:5001/openapi/v1 (or http://localhost:5000/openapi/v1)
   - **OpenAPI Spec**: https://localhost:5001/openapi/v1.json
   - **Root**: https://localhost:5001/

## API Endpoints

### Public Endpoints (No Authentication Required)

#### GET /
Root endpoint with API information.

**Response:**
```json
{
  "message": "HeroSD-JWT Example API",
  "version": "1.0.0",
  "endpoints": {
    "token": "/token - Issue a new SD-JWT",
    "profile": "/api/profile - Get user profile (requires authentication)",
    "claims": "/api/claims - Get all disclosed claims (requires authentication)"
  }
}
```

#### POST /token
Issue a new SD-JWT token.

**Request Body:**
```json
{
  "username": "demo",
  "password": "password"
}
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJzZC1qd3QiLCJhbGci...~WyJzYWx0MSIsImVtYWlsIiwiam9obi5kb...~",
  "type": "SD-JWT",
  "expiresIn": 3600,
  "message": "Token issued successfully. Use this token in the Authorization header as 'Bearer {token}'",
  "selectiveDisclosure": {
    "enabled": true,
    "disclosableClaims": ["email", "phone", "department", "address"],
    "note": "In a real application, the holder would create selective presentations"
  }
}
```

### Protected Endpoints (Authentication Required)

#### GET /api/profile
Get the authenticated user's profile.

**Headers:**
```
Authorization: Bearer {your-sd-jwt-token}
```

**Response:**
```json
{
  "name": "John Doe",
  "email": "john.doe@example.com",
  "role": "admin",
  "department": "Engineering",
  "message": "Profile retrieved successfully from disclosed SD-JWT claims"
}
```

#### GET /api/claims
Get all disclosed claims from the SD-JWT presentation.

**Headers:**
```
Authorization: Bearer {your-sd-jwt-token}
```

**Response:**
```json
{
  "userId": "user-12345",
  "claims": [
    { "type": "sub", "value": "user-12345" },
    { "type": "name", "value": "John Doe" },
    { "type": "email", "value": "john.doe@example.com" },
    { "type": "role", "value": "admin" }
  ],
  "message": "All disclosed claims from the SD-JWT presentation"
}
```

#### GET /api/admin
Admin-only endpoint (requires "admin" role).

**Headers:**
```
Authorization: Bearer {your-sd-jwt-token}
```

**Response:**
```json
{
  "message": "Welcome admin! You have access to this protected resource.",
  "role": "admin",
  "timestamp": "2025-06-11T21:45:00Z"
}
```

## Testing with cURL

### 1. Get a Token

```bash
curl -X POST https://localhost:5001/token \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"password"}' \
  -k
```

### 2. Access Protected Endpoint

```bash
# Replace {token} with the token from step 1
curl https://localhost:5001/api/profile \
  -H "Authorization: Bearer {token}" \
  -k
```

## Testing with PowerShell

### 1. Get a Token

```powershell
$response = Invoke-RestMethod -Method Post `
  -Uri "https://localhost:5001/token" `
  -ContentType "application/json" `
  -Body '{"username":"demo","password":"password"}' `
  -SkipCertificateCheck

$token = $response.token
```

### 2. Access Protected Endpoint

```powershell
Invoke-RestMethod -Method Get `
  -Uri "https://localhost:5001/api/profile" `
  -Headers @{ Authorization = "Bearer $token" } `
  -SkipCertificateCheck
```

## Configuration

The example uses configuration from `appsettings.json`:

```json
{
  "SdJwt": {
    "SigningKey": "VGhpc0lzQVNlY3JldEtleUZvclNESldURGVtb05lZWRzVG9CZTMyQnl0ZXM=",
    "Issuer": "https://sdjwt-example.example.com",
    "Audience": "https://api.example.com"
  }
}
```

**⚠️ Security Note:** In production, never store signing keys in `appsettings.json`. Use:
- Azure Key Vault
- AWS Secrets Manager
- Environment variables
- Secure key management systems

## How It Works

### 1. Service Registration

```csharp
// Register SD-JWT services
builder.Services.AddSdJwtServices();

// Configure authentication
builder.Services.AddAuthentication()
    .AddSdJwt(options =>
    {
        options.FallbackKey = signingKey;
        options.VerificationOptions = new SdJwtVerificationOptions
        {
            ClockSkew = TimeSpan.FromMinutes(5),
            RequireKeyBinding = false,
            ExpectedIssuer = builder.Configuration["SdJwt:Issuer"],
            ExpectedAudience = builder.Configuration["SdJwt:Audience"]
        };
    });

builder.Services.AddAuthorization();
```

### 2. Middleware Configuration

```csharp
app.UseAuthentication();  // Verify SD-JWT tokens
app.UseAuthorization();    // Check authorization policies
```

### 3. Protected Endpoints

```csharp
app.MapGet("/api/profile", (HttpContext context) =>
{
    // Claims are automatically populated from the SD-JWT
    var name = context.User.FindFirst("name")?.Value;
    var email = context.User.FindFirst("email")?.Value;

    return Results.Ok(new { name, email });
})
.RequireAuthorization();  // Automatic SD-JWT verification
```

## Selective Disclosure Explained

In this example:

1. **Token Issuance**: Four claims are marked as selectively disclosable:
   - `email`
   - `phone`
   - `department`
   - `address`

2. **Holder's Choice**: In a real-world scenario, the token holder can create presentations that disclose only a subset of these claims.

3. **Verifier**: The ASP.NET Core API automatically verifies the presentation and extracts only the disclosed claims.

## Key Features Demonstrated

| Feature | Location | Description |
|---------|----------|-------------|
| DI Registration | `Program.cs:14` | `.AddSdJwtServices()` |
| Authentication Setup | `Program.cs:20-34` | `.AddSdJwt(options => {...})` |
| Token Issuance | `Program.cs:75-145` | Creating SD-JWTs |
| Protected Endpoints | `Program.cs:154-211` | `.RequireAuthorization()` |
| Claims Access | `Program.cs:157-160` | `context.User.FindFirst()` |
| Selective Disclosure | `Program.cs:106-112` | Marking claims as selective |

## Next Steps

- **Add Role-Based Authorization**: Implement `[Authorize(Roles = "admin")]`
- **Add Policy-Based Authorization**: Define custom authorization policies
- **Implement Key Rotation**: Use `KeyResolver` for multiple keys
- **Add Key Binding**: Require proof of possession
- **Integrate with Identity**: Connect to ASP.NET Core Identity
- **Add Refresh Tokens**: Implement token refresh flow

## Learn More

- [HeroSD-JWT Documentation](../../README.md)
- [SD-JWT Specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- [ASP.NET Core Authentication](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/)
