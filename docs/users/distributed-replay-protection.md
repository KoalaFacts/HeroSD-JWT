# Distributed replay protection

`IJtiCache.TryAddAsync` is a security boundary: for the same issuer and JWT ID,
exactly one concurrent caller may succeed while the marker remains live. Admission
and expiration must be a single atomic backend operation shared by every node.

## Compatibility requirement

`DistributedJtiCache(IDistributedCache, ...)` now rejects a cache that does not also
implement `IAtomicDistributedCache`, throwing `NotSupportedException` during
construction, before any cache operation. The distributed replay registration has
the same requirement when its `IJtiCache` is resolved. This is an intentional
security compatibility change: the former `GetAsync` followed by `SetAsync`
allowed concurrent requests to accept the same JWT ID.

Registering an ordinary Redis, SQL Server, or memory `IDistributedCache` does **not**
satisfy this requirement. A thread-safe client and a local lock do not supply
cross-process atomic admission. This package does not ship a Redis or SQL atomic
provider. The adapter tests use an in-process contract fixture; they do not certify
a production backend.

## Replay retention and credential expiry

Replay protection is safe only if a replay marker survives for as long as the
credential could still be admitted. Enabled `JtiValidator` now **requires a
valid integer Unix `exp`**, and rejects a credential if the full remaining
lifetime **plus `ClockSkewTolerance`** exceeds `MaximumTtl`. It does **not**
silently cap the marker at `MaximumTtl`, or use `DefaultTtl` for missing or
malformed expiry claims. Invalid/oversized expiries are rejected **before**
calling the cache. This is a security compatibility change.

For a credential that must be accepted for 48 hours, configure
`MaximumTtl` longer than 48 hours **plus** your marker skew allowance,
and ensure the backend can retain the marker for that period. Otherwise
issue shorter-lived credentials. Existing `DefaultTtl` configuration is
retained as a public compatibility property, but cannot make an unbounded
credential safe. The general claim verifier also requires a valid `exp`.

The JTI validator itself rejects claims once `exp` has elapsed; it can be
stricter than the scheme's separate temporal `ClockSkew`. `RequireJtiClaim
= false` deliberately skips replay tracking when no JTI exists, so do not
use it when every accepted presentation must be one-time. Plan the migration
for long-lived credentials before deploying; clients that previously succeeded
with a capped marker will now fail authentication rather than receive a
misleading replay guarantee.

## Marker-key migration

The adapter now uses a versioned, length-prefixed encoding of the prefix, issuer,
and JWT ID. Colons inside these values cannot alias another tuple (for example,
issuer `a:b` with ID `c` versus issuer `a` with ID `b:c`). All adapter operations
use that same encoding.

Existing unversioned `prefix:issuer:jti` markers are not read by the new adapter.
Changing versions without a migration can therefore allow a previously consumed
identifier to be accepted again. Coordinate the switch across every node; do not
mix old and new key formats while accepting replay-protected traffic. Either
pause that traffic until all existing markers reach their original expiration,
or migrate live markers with their original remaining TTL and known tuple
identity before switching. The old delimiter format is ambiguous, so blindly
splitting existing keys is not a safe migration. Changing a configured key prefix
has the same marker-reset risk.

## Integrate an atomic cache provider

Implement `HeroSdJwt.AspNetCore.Verification.ReplayProtection.IAtomicDistributedCache`
in your provider, using its supported client library. Its `TryAddAsync` must:

- Create a missing marker and attach the requested positive TTL atomically.
- Return `true` only when that creation succeeds, and `false` only when a live
  marker already exists. Duplicate attempts must not refresh or shorten its TTL.
- Treat an expired marker as absent. All clients and application nodes must use
  the same authoritative namespace and expiration semantics.
- Propagate cancellation and backend failures. Never convert a timeout or an
  uncertain result into successful admission, and never fall back to local state.

For example, a provider can use a backend's atomic conditional insert with
expiration. Do not emulate it with independent reads and writes or with a
conditional insert followed by a separate expiration command. Configure marker
retention so eviction or failover cannot silently discard live replay markers.
Cancellation or a lost response can occur after the backend committed an insert;
a retry must conservatively treat the retained marker as already used.

Register your implementation as `IDistributedCache`:

```csharp
// ApplicationAtomicCache is your implementation, verified against your backend.
builder.Services.AddSingleton<IDistributedCache, ApplicationAtomicCache>();
builder.Services.AddSdJwtServices()
    .AddSdJwtDistributedReplayProtection();
```

`AddSdJwtDistributedReplayProtection` registers the adapter and `JtiValidator`
with scoped lifetimes. It supplies enabled `ReplayProtectionOptions` by default
and preserves explicitly registered cache, validator, and options services.
Resolve scoped services from a request or an explicit DI scope. To customize
retention or claim requirements, register `ReplayProtectionOptions` before this
extension and explicitly set `Enabled = true`.

## Use a direct IJtiCache integration

An existing backend integration may implement `IJtiCache` directly, without
implementing the general-purpose distributed cache API:

```csharp
// ApplicationJtiCache implements atomic issuer/JTI admission in your backend.
builder.Services.AddScoped<IJtiCache, ApplicationJtiCache>();
builder.Services.AddSdJwtServices()
    .AddSdJwtDistributedReplayProtection();
```

The registration preserves that `IJtiCache` and wires the enabled validator; no
`IDistributedCache` is required for this path. Custom implementations must also
keep issuer/JTI pairs distinct, implement non-mutating `ExistsAsync`, and support
explicit `RemoveAsync`. Only use removal for deliberate administrative actions,
as it permits the identifier to be admitted again.

Outside ASP.NET Core, attach the validator explicitly:

```csharp
var validator = new JtiValidator(applicationJtiCache,
    new ReplayProtectionOptions { Enabled = true });
var verifier = SdJwtVerifierBuilder.Create()
    .WithReplayProtection(validator)
    // Configure issuer, audience and verification-key policy here.
    .Build();
```

Before deploying any provider, test it against the real backend with independent
clients: many simultaneous admissions must yield exactly one winner; rejected
duplicates must preserve the original TTL; the key must become admissible after
expiry; failures and cancellation must never yield successful admission without
a confirmed atomic insert. Test the backend's persistence, eviction, and failover
configuration as part of deployment acceptance.

Distributed revocation remains a separate adapter and does not require the
atomic replay capability. Register it with `AddSdJwtDistributedRevocation()` when
needed.

## Single-instance in-memory cache capacity

`InMemoryJtiCache` is suitable only for a single live process. It does not retain
markers across restarts or share them with other nodes. **At `MaxCacheEntries`
it now fails closed:** after reclaiming genuinely expired records, it throws
`InvalidOperationException` for a new identifier rather than evicting any
still-live replay marker. Duplicate identifiers continue to be rejected even
when full. The default verifier converts a capacity failure into unsuccessful
verification; applications using `IJtiCache` directly must also reject the
operation on this exception. **Do not catch the exception and accept a token.**

This intentionally replaces the older eviction-on-capacity behavior, which
could make a used, still-valid JWT admissible again. Choose enough capacity
for peak unique-JTI traffic across the *full* marker retention window, issue
shorter-lived credentials when appropriate, and alert on capacity failures.
Expired markers are reclaimed before refusing new entries; a cleanup timer
also removes expired entries periodically. Changing `MaxCacheEntries` after
constructing the cache does not change that instance's capacity.

For multi-instance, restart-safe or failover-sensitive operation use a verified
shared atomic `IJtiCache` or `IAtomicDistributedCache` backend instead.
An in-process stress test cannot establish cross-instance replay safety.
