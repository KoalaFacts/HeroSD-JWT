using HeroSdJwt.AspNetCore.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using Microsoft.AspNetCore.OpenApi;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddOpenApi();

// Register SD-JWT services (verifier, issuer, presenter, etc.)
builder.Services.AddSdJwtServices();

// Configure SD-JWT authentication
var signingKeyBase64 = builder.Configuration["SdJwt:SigningKey"]!;
var signingKey = Convert.FromBase64String(signingKeyBase64);

builder.Services.AddAuthentication()
    .AddSdJwt(options =>
    {
        // Configure the signing key for verification
        options.FallbackKey = signingKey;

        // Configure verification options
        options.VerificationOptions = new SdJwtVerificationOptions
        {
            ClockSkew = TimeSpan.FromMinutes(5),
            RequireKeyBinding = false,
            ExpectedIssuer = builder.Configuration["SdJwt:Issuer"],
            ExpectedAudience = builder.Configuration["SdJwt:Audience"]
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi("/openapi/v1.json");
    app.MapScalarApiReference(options =>
    {
        options
            .WithEndpointPrefix("/openapi/{documentName}")
            .WithOpenApiRoutePattern("/openapi/v1.json");
    });
}

app.UseHttpsRedirection();

// Enable authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// =====================================================================
// Public Endpoints (No Authentication Required)
// =====================================================================

app.MapGet("/", () => new
{
    message = "HeroSD-JWT Example API",
    version = "1.0.0",
    endpoints = new
    {
        token = "/token - Issue a new SD-JWT",
        profile = "/api/profile - Get user profile (requires authentication)",
        claims = "/api/claims - Get all disclosed claims (requires authentication)"
    }
})
.WithName("GetRoot")
.WithOpenApi();

// =====================================================================
// Token Issuance Endpoint
// =====================================================================

app.MapPost("/token", (ISdJwtIssuer issuer, ISdJwtPresenter presenter, IConfiguration config, UserCredentials credentials) =>
{
    // In a real application, you would validate credentials against a database
    if (credentials.Username != "demo" || credentials.Password != "password")
    {
        return Results.Unauthorized();
    }

    // Create claims for the user
    var claims = new Dictionary<string, object>
    {
        ["sub"] = "user-12345",
        ["name"] = "John Doe",
        ["email"] = "john.doe@example.com",
        ["role"] = "admin",
        ["department"] = "Engineering",
        ["phone"] = "+1-555-0123",
        ["address"] = new Dictionary<string, object>
        {
            ["street"] = "123 Main St",
            ["city"] = "San Francisco",
            ["state"] = "CA",
            ["zip"] = "94105"
        },
        ["iss"] = config["SdJwt:Issuer"]!,
        ["aud"] = config["SdJwt:Audience"]!,
        ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
    };

    // Mark which claims should be selectively disclosable
    var selectiveClaims = new[]
    {
        "email",       // User can choose whether to disclose email
        "phone",       // User can choose whether to disclose phone
        "department",  // User can choose whether to disclose department
        "address"      // Entire address object can be selectively disclosed
    };

    var signingKeyBase64 = config["SdJwt:SigningKey"]!;
    var signingKey = Convert.FromBase64String(signingKeyBase64);

    // Create the SD-JWT
    var sdJwt = issuer.CreateSdJwt(
        claims,
        selectiveClaims,
        signingKey,
        HashAlgorithm.Sha256,
        SignatureAlgorithm.HS256,
        holderPublicKey: null,
        decoyDigestCount: 2  // Add 2 decoy digests for privacy
    );

    // Create a full presentation (holder can later choose to disclose only some claims)
    var presentation = presenter.FormatPresentation(
        presenter.CreatePresentationWithAllClaims(sdJwt));

    return Results.Ok(new
    {
        token = presentation,
        type = "SD-JWT",
        expiresIn = 3600,
        message = "Token issued successfully. Use this token in the Authorization header as 'Bearer {token}'",
        selectiveDisclosure = new
        {
            enabled = true,
            disclosableClaims = selectiveClaims,
            note = "In a real application, the holder would create selective presentations"
        }
    });
})
.WithName("IssueToken")
.WithOpenApi()
.Accepts<UserCredentials>("application/json");

// =====================================================================
// Protected Endpoints (Authentication Required)
// =====================================================================

app.MapGet("/api/profile", (HttpContext context) =>
{
    // Extract claims from the authenticated user
    var name = context.User.FindFirst("name")?.Value;
    var email = context.User.FindFirst("email")?.Value;
    var role = context.User.FindFirst("role")?.Value;
    var department = context.User.FindFirst("department")?.Value;

    return Results.Ok(new
    {
        name,
        email,
        role,
        department,
        message = "Profile retrieved successfully from disclosed SD-JWT claims"
    });
})
.WithName("GetProfile")
.WithOpenApi()
.RequireAuthorization();

app.MapGet("/api/claims", (HttpContext context) =>
{
    // Get all claims from the authenticated user
    var allClaims = context.User.Claims
        .Select(c => new { c.Type, c.Value })
        .ToList();

    return Results.Ok(new
    {
        userId = context.User.FindFirst("sub")?.Value,
        claims = allClaims,
        message = "All disclosed claims from the SD-JWT presentation"
    });
})
.WithName("GetClaims")
.WithOpenApi()
.RequireAuthorization();

app.MapGet("/api/admin", (HttpContext context) =>
{
    var role = context.User.FindFirst("role")?.Value;

    if (role != "admin")
    {
        return Results.Forbid();
    }

    return Results.Ok(new
    {
        message = "Welcome admin! You have access to this protected resource.",
        role,
        timestamp = DateTimeOffset.UtcNow
    });
})
.WithName("AdminOnly")
.WithOpenApi()
.RequireAuthorization();

app.Run();

// =====================================================================
// Request Models
// =====================================================================

record UserCredentials(string Username, string Password);
