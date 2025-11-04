# Ed25519 Implementation Status

## Overview
This directory contains an Ed25519 implementation being ported from Chaos.NaCl.

**Current Status**: 🚧 IN PROGRESS - Framework created, core operations needed

## What's Implemented
- ✅ Ed25519.cs - Main API with proper signatures
- ✅ THIRD-PARTY-NOTICES.txt - License attribution
- ✅ Integration points defined

## What's Needed (From Chaos.NaCl)

### Critical Files (~2,000 LOC to port)

**1. Core Operations** (Priority 1):
- [ ] Ed25519Operations.cs - Main crypto operations
  - crypto_sign_keypair
  - crypto_sign
  - crypto_sign_verify

**2. Field Element Operations** (Priority 1):
- [ ] FieldElement.cs - 10-element int32 array representing field elements
- [ ] FieldOperations.cs - Field arithmetic (fe_add, fe_sub, fe_mul, fe_sq, etc.)
  - ~30 operation methods needed

**3. Group Element Operations** (Priority 1):
- [ ] GroupElement.cs - Point representations (P2, P3, P1xP1, PreComp, Cached)
- [ ] GroupOperations.cs - Point operations (ge_add, ge_double, ge_scalarmult, etc.)
  - ~15-20 operations needed

**4. Scalar Operations** (Priority 2):
- [ ] ScalarOperations.cs - Scalar arithmetic
  - sc_reduce
  - sc_muladd
  - sc_clamp

**5. Tables and Constants** (Priority 2):
- [ ] base.cs - Precomputed base point tables (speeds up operations)
- [ ] d.cs - Curve constant d
- [ ] sqrtm1.cs - sqrt(-1) constant

## Porting Strategy

### Phase 1: Core Structure (DONE ✅)
-Created directory and attribution
- Created Ed25519.cs API wrapper

### Phase 2: Minimal Implementation (CURRENT 🚧)
Need to port these files from Chaos.NaCl:
```
Chaos.NaCl/Internal/Ed25519Ref10/
├── Ed25519Operations.cs
├── FieldElement.cs
├── FieldOperations.cs
├── GroupElement.cs
├── GroupOperations.cs
└── ScalarOperations.cs
```

### Phase 3: Complete Implementation
Port remaining support files (tables, additional operations)

### Phase 4: Testing
- RFC 8032 test vectors
- Cross-validation with Chaos.NaCl
- Interoperability tests

## Key Simplifications

1. **SHA-512**: Use `System.Security.Cryptography.SHA512` instead of custom implementation
2. **Key Format**: Add PKCS#8 import/export for JWT compatibility
3. **Namespace**: Simplified to `HeroSdJwt.Internal.Ed25519`

## Files from Chaos.NaCl

All files ported from:
- Repository: https://github.com/CodesInChaos/Chaos.NaCl
- Path: Chaos.NaCl/Internal/Ed25519Ref10/
- License: Public Domain
- Original Author: Dan Bernstein (curve operations), Christian Winnerlein (C# port)

## Next Steps

1. Port Ed25519Operations.cs with crypto_sign_keypair, crypto_sign, crypto_sign_verify
2. Port FieldElement and FieldOperations (field arithmetic)
3. Port GroupElement and GroupOperations (point arithmetic)
4. Port ScalarOperations
5. Test with RFC 8032 vectors
6. Integrate with KeyGenerator/JwtSigner/SignatureValidator

## Estimated Effort
- Lines of Code: ~1,500-2,000 LOC
- Time: 4-6 hours of careful porting and testing
- Files: ~15-20 core files

## References
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- Chaos.NaCl: https://github.com/CodesInChaos/Chaos.NaCl
- SUPERCOP Ref10: Original Ed25519 reference implementation
