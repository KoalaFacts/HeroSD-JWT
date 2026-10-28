# Upgrade guide: 1.1.7 to 2.0 (forthcoming)

**Status: the 2.0 package has not been published.** This document describes the current development implementation, not a shipped NuGet release.

## Key-type verification

The verifier default changed from **Either** in 1.1.7 to **Asymmetric** in the development code. Applications signing with HS256 must explicitly configure ExpectedKeyType as VerificationKeyType.Symmetric (on SdJwtVerificationOptions or via SdJwtVerifierBuilder.WithExpectedKeyType). RSA/ECDSA use Asymmetric. Only use Either when accepting both kinds is an intentional, reviewed protocol decision. Never treat a public key as an HMAC secret.

## Authentication schemes and DI

ASP.NET authentication uses the full policy in each scheme's VerificationOptions, not unrelated settings from a separately constructed verifier. Move issuer, audiences, holder binding, clock skew and key-type requirements onto each scheme; see [authentication policy](authentication-policy.md).

A custom implementation used by authentication must implement ISdJwtVerifierFactory alongside ISdJwtVerifier and preserve its custom validation in CreateVerifier. Subclasses of SdJwtVerifier must override CreateVerifier. Direct calls outside ASP.NET authentication still accept the original verifier interface.

The default synchronous ISdJwtVerifier and asynchronous ISdJwtVerifierAsync services are scoped aliases to the same instance within a scope. Applications previously capturing the default verifier in a singleton should resolve it per request or inside an explicit scope. Custom registrations keep their declared lifetime.

## Audience and proof interoperability

A regular JWT aud array must contain strings only; mixed null, numeric, boolean or object values are rejected even if another element matches. A key-binding JWT, under RFC 9901, requires exactly **one string-valued aud**, not an array. ExpectedAudiences may contain multiple accepted values, but each holder proof chooses one string.

ES256 holder keys must use the NIST P-256 named curve. Keys on secp256k1 are rejected even when their coordinate size matches. Reissue nonconforming proofs and keys instead of disabling validation.

## Async and replay

ISdJwtVerifierAsync avoids synchronous blocking for asynchronous replay/revocation storage. The ASP.NET handler prefers the asynchronous path. A configured JTI replay cache must cover the accepted expiry window including allowed clock skew, subject to TTL bounds. Distributed replay admission must be atomic; IDistributedCache alone is not sufficient.

## Validate your upgrade

Test real issue/present/verify and authentication flows using the exact published package after the release. Include HS256, invalid signature, wrong issuer/audience, KB-JWT string audience, custom verifier factories and request scopes. The repository's package consumer smoke test installs a **locally packed** artifact on .NET 8/9/10; passing it does not establish that NuGet.org is already serving 2.0.

See [authentication policy details](authentication-policy.md) and [changelog](../../CHANGELOG.md).
