# Multi-Tenant SD-JWT Authentication Example

A comprehensive example demonstrating how to implement multi-tenant SD-JWT authentication with HeroSD-JWT, including tenant isolation, key rotation, and secure key management.

## Features

- ✅ **Multi-Tenant Architecture** - Support multiple tenants with isolated signing keys
- ✅ **JWT Key Rotation** - Per-tenant key rotation with `kid` parameter support
- ✅ **Tenant Isolation** - Strict separation of tenant data and cryptographic keys
- ✅ **Configuration-Based Setup** - Easy tenant management via appsettings.json
- ✅ **Key Resolver Pattern** - Tenant-aware key resolution for verification
- ✅ **Graceful Key Transitions** - Support for overlapping key validity periods
- ✅ **Tenant-Specific Policies** - Custom token lifetimes and default claims per tenant
- ✅ **OpenAPI Documentation** - Interactive API documentation with Scalar UI

## Quick Start

```bash
# Navigate to the example directory
cd examples/MultiTenantAuthExample

# Run the application
dotnet run

# Open the API documentation
# https://localhost:5001/scalar/v1
```

## Architecture Overview

```
┌─────────────┐
│   Tenant A  │──┐
│ (acme-corp) │  │
└─────────────┘  │         ┌────────────────────┐
                 │────────>│  TenantService     │
┌─────────────┐  │         │  - Key Management  │
│   Tenant B  │──┤         │  - Key Rotation    │
│  (contoso)  │  │         │  - Tenant Isolation│
└─────────────┘  │         └────────────────────┘
                 │                    │
┌─────────────┐  │                    ▼
│   Tenant C  │──┘         ┌────────────────────┐
│  (fabrikam) │            │  SD-JWT Operations │
└─────────────┘            │  - Issue Tokens    │
                           │  - Verify Tokens   │
                           └────────────────────┘
```

### Key Components

1. **TenantService** - Manages tenant configurations, signing keys, and key resolution
2. **TokensController** - REST API for token issuance and verification
3. **TenantConfiguration** - Per-tenant settings including keys, policies, and metadata

## Configuration

Tenants are configured in `appsettings.json`:

```json
{
  "MultiTenant": {
    "Tenants": [
      {
        "TenantId": "acme-corp",
        "TenantName": "ACME Corporation",
        "CurrentKeyId": "acme-2024-11",
        "SigningKeys": {
          "acme-2024-10": "oldKeyBase64==",
          "acme-2024-11": "currentKeyBase64=="
        },
        "DefaultClaims": {
          "org": "acme-corp",
          "org_name": "ACME Corporation"
        },
        "MaxTokenLifetimeSeconds": 7200,
        "IsActive": true
      }
    ]
  }
}
```

### Configuration Fields

- **TenantId**: Unique identifier for the tenant (e.g., "acme-corp")
- **TenantName**: Human-readable display name
- **CurrentKeyId**: ID of the active signing key for new tokens
- **SigningKeys**: Dictionary of key ID → Base64-encoded key bytes
  - Supports multiple keys for rotation (old + new keys during transition)
- **DefaultClaims**: Claims automatically added to all tokens for this tenant
- **MaxTokenLifetimeSeconds**: Maximum allowed token lifetime (optional)
- **IsActive**: Whether the tenant can issue/verify tokens

## API Endpoints

### 1. Issue Token

**POST** `/api/tokens/issue`

Issues a new SD-JWT for a specific tenant.

**Request Body:**
```json
{
  "tenantId": "acme-corp",
  "subject": "user-12345",
  "claims": {
    "email": "alice@example.com",
    "role": "admin",
    "department": "engineering"
  },
  "selectivelyDisclosableClaims": ["email", "department"],
  "tokenLifetimeSeconds": 3600
}
```

**Response:**
```json
{
  "sdJwt": "eyJhbGc...jwt~WyI2cU1R...disclosure~...",
  "tenantId": "acme-corp",
  "keyId": "acme-2024-11",
  "expiresAt": 1699564800,
  "selectivelyDisclosableClaims": ["email", "department"]
}
```

### 2. Verify Token

**POST** `/api/tokens/verify`

Verifies an SD-JWT presentation with tenant-aware key resolution.

**Request Body:**
```json
{
  "presentation": "eyJhbGc...jwt~WyI2cU1R...disclosure~...",
  "tenantId": "acme-corp"
}
```

**Response (Success):**
```json
{
  "isValid": true,
  "tenantId": "acme-corp",
  "keyId": "acme-2024-11",
  "disclosedClaims": {
    "sub": "user-12345",
    "email": "alice@example.com",
    "role": "admin",
    "iss": "https://example.com/tenants/acme-corp",
    "tenant_id": "acme-corp",
    "org": "acme-corp",
    "org_name": "ACME Corporation"
  },
  "errors": null
}
```

**Response (Failure):**
```json
{
  "isValid": false,
  "tenantId": "acme-corp",
  "keyId": null,
  "disclosedClaims": null,
  "errors": ["Signature validation failed"]
}
```

### 3. List Tenants

**GET** `/api/tokens/tenants`

Returns all active tenants and their configuration metadata.

**Response:**
```json
[
  {
    "tenantId": "acme-corp",
    "tenantName": "ACME Corporation",
    "currentKeyId": "acme-2024-11",
    "availableKeys": ["acme-2024-10", "acme-2024-11"],
    "isActive": true
  }
]
```

## Key Rotation Workflow

### 1. Initial State (Single Key)

```json
{
  "TenantId": "acme-corp",
  "CurrentKeyId": "key-v1",
  "SigningKeys": {
    "key-v1": "currentKeyBytes..."
  }
}
```

- All new tokens issued with `key-v1`
- All verifications use `key-v1`

### 2. Adding New Key (Transition Period)

```json
{
  "TenantId": "acme-corp",
  "CurrentKeyId": "key-v2",
  "SigningKeys": {
    "key-v1": "oldKeyBytes...",
    "key-v2": "newKeyBytes..."
  }
}
```

- New tokens issued with `key-v2`
- Verification accepts **both** `key-v1` and `key-v2`
- Existing tokens with `key-v1` still valid during grace period

### 3. Remove Old Key (After Grace Period)

```json
{
  "TenantId": "acme-corp",
  "CurrentKeyId": "key-v2",
  "SigningKeys": {
    "key-v2": "newKeyBytes..."
  }
}
```

- Only `key-v2` remains
- Old tokens with `key-v1` now fail verification

## Security Features

### Tenant Isolation

- **Separate Signing Keys**: Each tenant has its own cryptographic keys
- **Key Scoping**: Key resolver only searches within the tenant's key set
- **Tenant Identification**: Every token includes `tenant_id` claim for validation
- **Configuration Isolation**: Tenant configurations loaded independently

### Key Management

- **Key Rotation Support**: Multiple active keys per tenant for graceful transitions
- **Key Identifier (kid)**: RFC 7515 compliant `kid` parameter in JWT header
- **Key Resolver Pattern**: Dynamic key selection based on `kid` and tenant context
- **Fallback Key**: Supports tokens without `kid` (legacy compatibility)

### Validation

- **Tenant Activity Status**: Inactive tenants cannot issue or verify tokens
- **Signature Verification**: Cryptographic validation using correct tenant key
- **Temporal Claims**: Automatic validation of `iat`, `exp`, `nbf` claims
- **Digest Integrity**: SD-JWT disclosure digest verification

## Example Scenarios

### Scenario 1: Multi-Tenant SaaS Application

You have multiple customers (tenants) using your SaaS platform:

1. **Customer A** (acme-corp) - Large enterprise with 2-hour token lifetime
2. **Customer B** (contoso) - Standard customer with 1-hour token lifetime
3. **Customer C** (fabrikam) - Security-conscious customer with 30-minute tokens

Each customer gets isolated signing keys and can rotate keys independently without affecting other customers.

### Scenario 2: Key Rotation After Security Audit

**Day 1**: Security audit recommends key rotation for acme-corp

1. Generate new key `acme-2024-11`
2. Add to configuration alongside old key `acme-2024-10`
3. Update `CurrentKeyId` to `acme-2024-11`
4. Restart service

**Day 1-30**: Transition period
- New tokens use `acme-2024-11`
- Old tokens with `acme-2024-10` still verify successfully

**Day 30**: Remove old key
- Remove `acme-2024-10` from configuration
- Old tokens now fail verification

### Scenario 3: Emergency Key Revocation

Compromised key detected for contoso tenant:

1. Immediately remove compromised key from `SigningKeys`
2. Update configuration
3. Restart service
4. All tokens issued with compromised key immediately fail verification

## Testing with cURL

### Issue a Token

```bash
curl -X POST https://localhost:5001/api/tokens/issue \
  -H "Content-Type: application/json" \
  -d '{
    "tenantId": "acme-corp",
    "subject": "user-123",
    "claims": {
      "email": "alice@acme.com",
      "role": "admin"
    },
    "selectivelyDisclosableClaims": ["email"]
  }'
```

### Verify a Token

```bash
curl -X POST https://localhost:5001/api/tokens/verify \
  -H "Content-Type: application/json" \
  -d '{
    "presentation": "eyJhbGc...jwt~WyI2cU1R...disclosure~...",
    "tenantId": "acme-corp"
  }'
```

### List All Tenants

```bash
curl https://localhost:5001/api/tokens/tenants
```

## Project Structure

```
MultiTenantAuthExample/
├── Controllers/
│   └── TokensController.cs      # REST API endpoints
├── Models/
│   ├── TenantConfiguration.cs   # Tenant configuration model
│   ├── TokenIssueRequest.cs     # Request models
│   ├── TokenVerifyRequest.cs
│   ├── TokenIssueResponse.cs    # Response models
│   └── TokenVerifyResponse.cs
├── Services/
│   ├── ITenantService.cs        # Service interface
│   └── TenantService.cs         # Multi-tenant service implementation
├── Program.cs                    # Application startup
├── appsettings.json              # Tenant configuration
└── README.md                     # This file
```

## Best Practices

### Key Management

1. **Generate Strong Keys**: Use cryptographically secure random keys (256-bit for HMAC)
2. **Store Keys Securely**: Use Azure Key Vault, AWS Secrets Manager, or similar
3. **Rotate Regularly**: Plan key rotation every 90 days minimum
4. **Transition Period**: Keep old keys valid for at least 2× max token lifetime
5. **Audit Key Usage**: Log all key access and rotation events

### Tenant Isolation

1. **Validate Tenant ID**: Always verify tenant exists and is active
2. **Scope Key Resolution**: Never leak keys across tenant boundaries
3. **Separate Databases**: Consider separate data stores per tenant for complete isolation
4. **Rate Limiting**: Apply per-tenant rate limits to prevent abuse

### Configuration

1. **Environment-Specific**: Use different configurations for dev/staging/production
2. **Externalize Secrets**: Never commit real signing keys to source control
3. **Configuration Validation**: Validate tenant configuration at startup
4. **Hot Reload**: Support configuration updates without service restart (if needed)

## Production Considerations

### Before Deploying to Production

- [ ] Replace sample Base64 keys with securely generated keys
- [ ] Move signing keys to a secure key management service (Azure Key Vault, AWS KMS, etc.)
- [ ] Implement proper logging and monitoring
- [ ] Add rate limiting per tenant
- [ ] Configure HTTPS with valid certificates
- [ ] Add authentication/authorization for the API endpoints
- [ ] Implement audit logging for all token operations
- [ ] Set up alerts for failed verifications and suspicious activity
- [ ] Load test with expected tenant count and token volume
- [ ] Document tenant onboarding/offboarding procedures

### Scalability

- **Service Singleton**: `TenantService` is registered as singleton for performance
- **In-Memory Caching**: Tenant configurations and decoded keys cached in memory
- **Stateless Design**: Can be deployed across multiple instances
- **Horizontal Scaling**: Add more instances as tenant count grows

## Troubleshooting

### Token Verification Fails

1. Check tenant is active: `GET /api/tokens/tenants`
2. Verify `kid` in JWT header matches a key in tenant's `SigningKeys`
3. Ensure `tenant_id` claim matches the expected tenant
4. Check token hasn't expired (`exp` claim)
5. Verify key bytes are correctly Base64-encoded

### Key Rotation Issues

1. Ensure old key remains in `SigningKeys` during transition
2. Update `CurrentKeyId` to new key for issuing new tokens
3. Monitor logs for "Key resolver failed" warnings
4. Validate Base64 encoding of new key

### "Invalid Tenant" Errors

1. Check `TenantId` matches configuration exactly (case-sensitive)
2. Verify `IsActive` is `true` in configuration
3. Check application logs for configuration loading errors

## Related Documentation

- [HeroSD-JWT Main README](../../README.md)
- [Security Best Practices](../../docs/users/security.md)
- [Key Rotation Guide](../../README.md#-jwt-key-rotation-support)
- [IETF SD-JWT Specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)

## License

This example is part of the HeroSD-JWT project and is licensed under the MIT License.
