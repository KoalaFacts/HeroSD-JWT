using HeroSdJwt.Verification;

namespace HeroSdJwt.AspNetCore.Authentication;

// Explicit application verifiers must not resolve unused default collaborators or lose their policy.
internal sealed class AuthenticationVerifierFactory
{
    private readonly Lazy<Func<SdJwtVerificationOptions, SdJwtVerifier>> _create;
    private readonly Lazy<SdJwtVerifier> _defaultVerifier;

    internal AuthenticationVerifierFactory(Func<Func<SdJwtVerificationOptions, SdJwtVerifier>> configure)
    {
        _create = new(configure);
        _defaultVerifier = new(() => _create.Value(new SdJwtVerificationOptions
        {
            ClockSkew = TimeSpan.FromMinutes(5)
        }));
    }

    internal SdJwtVerifier DefaultVerifier => _defaultVerifier.Value;

    internal bool Owns(ISdJwtVerifier verifier) =>
        _defaultVerifier.IsValueCreated && ReferenceEquals(_defaultVerifier.Value, verifier);

    internal SdJwtVerifier Create(SdJwtVerificationOptions options) => _create.Value(options);
}
