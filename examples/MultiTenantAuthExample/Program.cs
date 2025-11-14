using HeroSdJwt.AspNetCore;
using MultiTenantAuthExample.Services;
using Scalar.AspNetCore;
#if NET9_0_OR_GREATER
using Microsoft.AspNetCore.OpenApi;
#endif

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
#if NET9_0_OR_GREATER
builder.Services.AddOpenApi();
#else
// .NET 8: Use Swashbuckle for OpenAPI generation (AddOpenApi requires .NET 9+)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
#endif

// Register HeroSdJwt services (includes all cryptographic and validation services)
builder.Services.AddSdJwtServices();

// Register multi-tenant service
builder.Services.AddSingleton<ITenantService, TenantService>();

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Information);

var app = builder.Build();

// Configure the HTTP request pipeline
app.UseHttpsRedirection();

#if NET9_0_OR_GREATER
app.MapOpenApi();
#endif
app.MapScalarApiReference(options =>
{
    options
        .WithTitle("Multi-Tenant SD-JWT API")
        .WithTheme(ScalarTheme.Purple)
        .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
});

app.MapControllers();

// Log configured tenants on startup
var tenantService = app.Services.GetRequiredService<ITenantService>();
var tenants = tenantService.GetAllTenants().ToList();
app.Logger.LogInformation("Multi-Tenant SD-JWT API started with {TenantCount} tenant(s)", tenants.Count);
foreach (var tenant in tenants)
{
    app.Logger.LogInformation("   Tenant {TenantId}: {TenantName} (Key: {KeyId})",
        tenant.TenantId, tenant.TenantName, tenant.CurrentKeyId);
}

app.Logger.LogInformation("OpenAPI documentation: https://localhost:{Port}/scalar/v1",
    app.Configuration["ASPNETCORE_HTTPS_PORT"] ?? "5001");

app.Run();
