using MultiTenantAuthExample.Services;
using HeroSdJwt.AspNetCore.Extensions;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

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

app.MapOpenApi();
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
