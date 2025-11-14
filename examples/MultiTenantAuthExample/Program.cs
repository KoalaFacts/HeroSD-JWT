using HeroSdJwt;
using HeroSdJwt.AspNetCore;
using HeroSdJwt.Issuance;
using HeroSdJwt.Verification;
using MultiTenantAuthExample.Services;
#if NET9_0_OR_GREATER
using Scalar.AspNetCore;
#endif

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
#if NET9_0_OR_GREATER
builder.Services.AddOpenApi();
#else
// .NET 8: Use Swashbuckle for OpenAPI
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new() { Title = "Multi-Tenant SD-JWT API", Version = "1.0.0" });
});
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
app.MapScalarApiReference(options =>
{
    options
        .WithTitle("Multi-Tenant SD-JWT API")
        .WithTheme(ScalarTheme.Purple)
        .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
});
#else
// .NET 8: Use Swashbuckle UI
app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "Multi-Tenant SD-JWT API v1");
});
#endif

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
