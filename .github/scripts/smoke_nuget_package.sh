#!/usr/bin/env bash
# Consumer verification against a local nupkg, never a ProjectReference.
set -euo pipefail
version="${1:?Provide a version}"
framework="${2:?Provide a target framework}"
case "$framework" in net8.0|net9.0|net10.0) ;; *) exit 2;; esac
package_dir="$(pwd)/src/HeroSdJwt/bin/Release"
package="$package_dir/HeroSD-JWT.$version.nupkg"
test -f "$package" || { echo "Missing: $package" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
dotnet new console --framework "$framework" --output "$tmp/consumer" --no-restore
dotnet add "$tmp/consumer/consumer.csproj" package HeroSD-JWT --version "$version" --no-restore

cat > "$tmp/NuGet.Config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear />
<add key="packed-artifact" value="$package_dir" />
<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
</packageSources></configuration>
EOF
cat > "$tmp/consumer/Program.cs" <<'EOF'
using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

var key = KeyGenerator.Instance.GenerateHmacKey();
var issued = SdJwtIssuerBuilder.Create()
    .WithClaim("sub", "external-consumer")
    .WithClaim("email", "hello@example.test")
    .MakeSelective("email")
    .SignWithHmac(key)
    .Build();
var presenter = new SdJwtPresenter();
var encoded = presenter.FormatPresentation(
    presenter.CreatePresentation(issued, new[] { "email" }));
var verifier = new SdJwtVerifier(
    new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
    new EcPublicKeyConverter(), new SignatureValidator(), new DigestValidator(),
    new KeyBindingValidator(), new ClaimValidator());
var valid = verifier.TryVerifyPresentation(encoded, key);
if (!valid.IsValid ||
    !valid.DisclosedClaims.TryGetValue("email", out var email) ||
    email.GetString() != "hello@example.test")
    throw new InvalidOperationException("Packaged issue/present/verify roundtrip failed");
if (verifier.TryVerifyPresentation(encoded, KeyGenerator.Instance.GenerateHmacKey()).IsValid)
    throw new InvalidOperationException("Packaged verifier accepted a wrong key");
Console.WriteLine("Packed package: valid disclosure and wrong-key rejection confirmed.");
EOF
dotnet restore "$tmp/consumer/consumer.csproj" --configfile "$tmp/NuGet.Config"
dotnet run --project "$tmp/consumer/consumer.csproj" --configuration Release --no-restore
