using HeroSdJwt.Verification.ReplayProtection;
using System.Text.Json;

namespace HeroSdJwt.Tests.Verification.ReplayProtection;

public class OptionalJtiAdmissionTests
{
    [Fact]
    public async Task Should_SkipReplayMetadata_WhenOptionalJtiIsAbsent()
    {
        // Without a JTI there is no replay marker to key by issuer or retain
        // until exp. An opt-out policy must not require either claim.
        var options = new ReplayProtectionOptions
        {
            Enabled = true,
            RequireJtiClaim = false
        };
        using var cache = new InMemoryJtiCache(options);
        var validator = new JtiValidator(cache, options);
        var claims = new Dictionary<string, JsonElement>();

        await validator.ValidateAsync(claims, TestContext.Current.CancellationToken);
    }
}
