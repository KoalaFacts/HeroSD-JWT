window.BENCHMARK_DATA = {
  "lastUpdate": 1780315504861,
  "repoUrl": "https://github.com/KoalaFacts/HeroSD-JWT",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "ldsenow@gmail.com",
            "name": "ldsenow",
            "username": "ldsenow"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c1d5f2e384a67685a6a358d3bd7bf3b7d40fd097",
          "message": "docs: add CLAUDE.md for AI assistant guidance (#54)\n\n* docs: add CLAUDE.md for AI assistant guidance\n\nTrack CLAUDE.md in-repo so codebase guidance is shared with all\ncontributors; remove it from .gitignore.\n\n* docs: fix test-filter examples to match namespace-based organization\n\nTests are grouped by folder/namespace, not xUnit traits, so the\n\"Category=...\" filter examples matched no tests. Use FullyQualifiedName\nfilters instead, and correct the coverage command to the collector-based\n--collect:\"XPlat Code Coverage\" that the project actually references.\n\n* fix(build): repair CI break from SDK/advisory drift on stale base\n\n- Bump Microsoft.Bcl.Memory 10.0.0 -> 10.0.8 (CVE-2026-26127, NU1903)\n- Regenerate packages.lock.json (stale vs current ILLink.Tasks, NU1004)\n- Resolve IDE0270/IDE0370 analyzer errors surfaced by the newer SDK\n  (treated as errors via TreatWarningsAsErrors/EnforceCodeStyleInBuild)\n\nRestore (locked mode), Release build (all TFMs), dotnet format, and the\nfull test suite (1064 passed) all pass locally.\n\n* ci: pin third-party GitHub Actions to commit SHAs\n\nPin all external actions (checkout, setup-dotnet, upload/download-artifact,\ndependency-review, attest-build-provenance, codecov, publish-unit-test-result,\ngithub-action-benchmark, NuGet/login, security-devops, codeql-action) to full\ncommit SHAs with version comments, hardening against mutable-tag supply-chain\nrisk. Local composite actions (./.github/actions/*) are left as path refs.\n\n* ci: update pinned actions to latest releases\n\nBump to newest majors: checkout v6.0.2, upload-artifact v7.0.1,\ndownload-artifact v8.0.1, dependency-review-action v5.0.0,\nattest-build-provenance v4.1.0, codecov-action v6.0.1, and\nsecurity-devops-action v1.12.0. All remain pinned to commit SHAs.\n\n* ci: drop EnricoMi/publish-unit-test-result-action\n\nRemove the third-party test-result publisher. Test failures still fail the\njob via 'dotnet test', and TRX files remain available as build artifacts.\nDrop the now-unused 'checks: write' permission (least privilege).\n\n* ci: drop unused checks:write permission from integration workflow\n\nThe nightly integration workflow declared checks:write but never calls the\nChecks API (it only writes job summaries and handles artifacts). Reduce to\ncontents:read per least privilege.\n\n* ci: add native test-result summary (no third-party action)\n\nReplace the removed third-party publisher with an inline bash step that\nparses the TRX output into $GITHUB_STEP_SUMMARY (pass/fail counts + failed\ntest names). No external action, no added permissions, no fork-PR token\nexposure. Mirrors the existing pattern in run-integrations.yml.\n\n* ci: make test-result summary portable to macOS bash 3.2\n\nThe summary step used 'shopt -s globstar' and '**', which are invalid in\nbash 3.2 (the default on GitHub macOS runners) and aborted under 'set -e',\nfailing all macOS legs. Replace globbing with 'find' and drop bash-4-only\nfeatures so it runs on bash 3.2/4/5 and BSD/GNU userland alike.\n\n* fix(benchmarks): set Symmetric key type for HMAC verification benchmark\n\nVerifyWithoutKeyBinding verifies an HS256 (HMAC) presentation, but the\nverifier defaults ExpectedKeyType to Asymmetric (alg/key-confusion guard).\nThe throwing VerifyPresentation therefore raised every iteration, so\nBenchmarkDotNet produced no statistics for it. The resulting null Statistics\ncrashed the github-action-benchmark step (Cannot read properties of null\n(reading 'Mean')) and failed the Perform Benchmarks workflow. Setting\nExpectedKeyType = Symmetric makes the benchmark verify successfully.\n\n* style(benchmarks): use using-alias for VerificationKeyType (fix IDE0002)\n\nThe fully-qualified HeroSdJwt.Primitives.VerificationKeyType.Symmetric\ntripped IDE0002 (name can be simplified), failing 'dotnet format\n--verify-no-changes' in the Code Quality job. Use a using-alias to match\nthe file's existing SdJwtHashAlgorithm pattern.\n\n* docs(ci): note gh-pages baseline requirement for benchmark step\n\nDocument that the Perform Benchmarks workflow needs the 'gh-pages' branch\nto exist; the action hard-fails ('couldn't find remote ref gh-pages')\notherwise. (Re-triggers the workflow now that gh-pages has been seeded.)\n\n---------\n\nCo-authored-by: Claude <noreply@anthropic.com>",
          "timestamp": "2026-06-01T21:59:27+10:00",
          "tree_id": "8052b1acd893d8c85daacd13ebc5dbf2be76c21d",
          "url": "https://github.com/KoalaFacts/HeroSD-JWT/commit/c1d5f2e384a67685a6a358d3bd7bf3b7d40fd097"
        },
        "date": 1780315501444,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 10)",
            "value": 34715.74818115235,
            "unit": "ns",
            "range": "± 341.85359710135396"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 10)",
            "value": 1978751.0807291667,
            "unit": "ns",
            "range": "± 2357.906759318679"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 10)",
            "value": 263026.9043511285,
            "unit": "ns",
            "range": "± 409.516851200459"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 10)",
            "value": 34691.40840657552,
            "unit": "ns",
            "range": "± 233.80125775625206"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 10)",
            "value": 1960548.3177083333,
            "unit": "ns",
            "range": "± 25938.3630703105"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 10)",
            "value": 262719.28043619794,
            "unit": "ns",
            "range": "± 1132.7608954567515"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 50)",
            "value": 206014.1846923828,
            "unit": "ns",
            "range": "± 1597.2090539148044"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 50)",
            "value": 2123298.0872395835,
            "unit": "ns",
            "range": "± 3238.8540725564862"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 50)",
            "value": 440646.71929253475,
            "unit": "ns",
            "range": "± 1449.093027518329"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 50)",
            "value": 239807.73502604166,
            "unit": "ns",
            "range": "± 37897.18715153353"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 50)",
            "value": 2164849.60546875,
            "unit": "ns",
            "range": "± 68477.73824802494"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 50)",
            "value": 453029.9658203125,
            "unit": "ns",
            "range": "± 3130.101996718476"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 100)",
            "value": 426767.5808105469,
            "unit": "ns",
            "range": "± 7515.100027412512"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 100)",
            "value": 2347133.8676757812,
            "unit": "ns",
            "range": "± 2160.1475207209446"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 100)",
            "value": 657002.5354003906,
            "unit": "ns",
            "range": "± 4913.82860673846"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 100)",
            "value": 477802.884765625,
            "unit": "ns",
            "range": "± 76974.5320395127"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 100)",
            "value": 2425334.98046875,
            "unit": "ns",
            "range": "± 17997.22755971249"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 100)",
            "value": 728602.771484375,
            "unit": "ns",
            "range": "± 65040.729396441486"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.VerifyWithoutKeyBinding",
            "value": 16488.824408637152,
            "unit": "ns",
            "range": "± 99.84363832324651"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.VerifyWithKeyBinding",
            "value": 975736.1340332031,
            "unit": "ns",
            "range": "± 1276.0148216181701"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.TryVerifyWithoutKeyBinding",
            "value": 16473.58285217285,
            "unit": "ns",
            "range": "± 53.4785957694929"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.VerifyWithoutKeyBinding",
            "value": 16853.853515625,
            "unit": "ns",
            "range": "± 110.60825665059605"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.VerifyWithKeyBinding",
            "value": 994942.3815104166,
            "unit": "ns",
            "range": "± 19032.443319307215"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.TryVerifyWithoutKeyBinding",
            "value": 16367.534052530924,
            "unit": "ns",
            "range": "± 14.524024466547335"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationFewClaims",
            "value": 931.0663763046265,
            "unit": "ns",
            "range": "± 18.393398384734176"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationManyClaims",
            "value": 2929.1434783935547,
            "unit": "ns",
            "range": "± 8.963926527763022"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationAllClaims",
            "value": 1407.9779663085938,
            "unit": "ns",
            "range": "± 6.880544957029458"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationWithKeyBinding",
            "value": 974.4835905075073,
            "unit": "ns",
            "range": "± 8.460513712034642"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationFewClaims",
            "value": 899.5081411997477,
            "unit": "ns",
            "range": "± 9.17751240034823"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationManyClaims",
            "value": 2958.213247934977,
            "unit": "ns",
            "range": "± 46.21902207829307"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationAllClaims",
            "value": 1422.3911692301433,
            "unit": "ns",
            "range": "± 47.993158074228894"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationWithKeyBinding",
            "value": 961.3637479146322,
            "unit": "ns",
            "range": "± 14.07615164261264"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "ldsenow@gmail.com",
            "name": "ldsenow",
            "username": "ldsenow"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c1d5f2e384a67685a6a358d3bd7bf3b7d40fd097",
          "message": "docs: add CLAUDE.md for AI assistant guidance (#54)\n\n* docs: add CLAUDE.md for AI assistant guidance\n\nTrack CLAUDE.md in-repo so codebase guidance is shared with all\ncontributors; remove it from .gitignore.\n\n* docs: fix test-filter examples to match namespace-based organization\n\nTests are grouped by folder/namespace, not xUnit traits, so the\n\"Category=...\" filter examples matched no tests. Use FullyQualifiedName\nfilters instead, and correct the coverage command to the collector-based\n--collect:\"XPlat Code Coverage\" that the project actually references.\n\n* fix(build): repair CI break from SDK/advisory drift on stale base\n\n- Bump Microsoft.Bcl.Memory 10.0.0 -> 10.0.8 (CVE-2026-26127, NU1903)\n- Regenerate packages.lock.json (stale vs current ILLink.Tasks, NU1004)\n- Resolve IDE0270/IDE0370 analyzer errors surfaced by the newer SDK\n  (treated as errors via TreatWarningsAsErrors/EnforceCodeStyleInBuild)\n\nRestore (locked mode), Release build (all TFMs), dotnet format, and the\nfull test suite (1064 passed) all pass locally.\n\n* ci: pin third-party GitHub Actions to commit SHAs\n\nPin all external actions (checkout, setup-dotnet, upload/download-artifact,\ndependency-review, attest-build-provenance, codecov, publish-unit-test-result,\ngithub-action-benchmark, NuGet/login, security-devops, codeql-action) to full\ncommit SHAs with version comments, hardening against mutable-tag supply-chain\nrisk. Local composite actions (./.github/actions/*) are left as path refs.\n\n* ci: update pinned actions to latest releases\n\nBump to newest majors: checkout v6.0.2, upload-artifact v7.0.1,\ndownload-artifact v8.0.1, dependency-review-action v5.0.0,\nattest-build-provenance v4.1.0, codecov-action v6.0.1, and\nsecurity-devops-action v1.12.0. All remain pinned to commit SHAs.\n\n* ci: drop EnricoMi/publish-unit-test-result-action\n\nRemove the third-party test-result publisher. Test failures still fail the\njob via 'dotnet test', and TRX files remain available as build artifacts.\nDrop the now-unused 'checks: write' permission (least privilege).\n\n* ci: drop unused checks:write permission from integration workflow\n\nThe nightly integration workflow declared checks:write but never calls the\nChecks API (it only writes job summaries and handles artifacts). Reduce to\ncontents:read per least privilege.\n\n* ci: add native test-result summary (no third-party action)\n\nReplace the removed third-party publisher with an inline bash step that\nparses the TRX output into $GITHUB_STEP_SUMMARY (pass/fail counts + failed\ntest names). No external action, no added permissions, no fork-PR token\nexposure. Mirrors the existing pattern in run-integrations.yml.\n\n* ci: make test-result summary portable to macOS bash 3.2\n\nThe summary step used 'shopt -s globstar' and '**', which are invalid in\nbash 3.2 (the default on GitHub macOS runners) and aborted under 'set -e',\nfailing all macOS legs. Replace globbing with 'find' and drop bash-4-only\nfeatures so it runs on bash 3.2/4/5 and BSD/GNU userland alike.\n\n* fix(benchmarks): set Symmetric key type for HMAC verification benchmark\n\nVerifyWithoutKeyBinding verifies an HS256 (HMAC) presentation, but the\nverifier defaults ExpectedKeyType to Asymmetric (alg/key-confusion guard).\nThe throwing VerifyPresentation therefore raised every iteration, so\nBenchmarkDotNet produced no statistics for it. The resulting null Statistics\ncrashed the github-action-benchmark step (Cannot read properties of null\n(reading 'Mean')) and failed the Perform Benchmarks workflow. Setting\nExpectedKeyType = Symmetric makes the benchmark verify successfully.\n\n* style(benchmarks): use using-alias for VerificationKeyType (fix IDE0002)\n\nThe fully-qualified HeroSdJwt.Primitives.VerificationKeyType.Symmetric\ntripped IDE0002 (name can be simplified), failing 'dotnet format\n--verify-no-changes' in the Code Quality job. Use a using-alias to match\nthe file's existing SdJwtHashAlgorithm pattern.\n\n* docs(ci): note gh-pages baseline requirement for benchmark step\n\nDocument that the Perform Benchmarks workflow needs the 'gh-pages' branch\nto exist; the action hard-fails ('couldn't find remote ref gh-pages')\notherwise. (Re-triggers the workflow now that gh-pages has been seeded.)\n\n---------\n\nCo-authored-by: Claude <noreply@anthropic.com>",
          "timestamp": "2026-06-01T21:59:27+10:00",
          "tree_id": "8052b1acd893d8c85daacd13ebc5dbf2be76c21d",
          "url": "https://github.com/KoalaFacts/HeroSD-JWT/commit/c1d5f2e384a67685a6a358d3bd7bf3b7d40fd097"
        },
        "date": 1780315504094,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 10)",
            "value": 43404.43369140625,
            "unit": "ns",
            "range": "± 410.90876719363496"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 10)",
            "value": 2125700.2447916665,
            "unit": "ns",
            "range": "± 3846.025086420759"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 10)",
            "value": 242588.27016601563,
            "unit": "ns",
            "range": "± 1476.6379640019063"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 10)",
            "value": 42749.61083984375,
            "unit": "ns",
            "range": "± 342.20781400393"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 10)",
            "value": 2130632.33203125,
            "unit": "ns",
            "range": "± 22616.5785195159"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 10)",
            "value": 243998.6512044271,
            "unit": "ns",
            "range": "± 3419.4291681504587"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 50)",
            "value": 269544.8565429688,
            "unit": "ns",
            "range": "± 2041.7739602600625"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 50)",
            "value": 2372380.9796006945,
            "unit": "ns",
            "range": "± 6114.0052318687185"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 50)",
            "value": 472402.1203342014,
            "unit": "ns",
            "range": "± 1318.53675052357"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 50)",
            "value": 272777.6126302083,
            "unit": "ns",
            "range": "± 3378.7730423009752"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 50)",
            "value": 2387673.4518229165,
            "unit": "ns",
            "range": "± 22747.914840727106"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 50)",
            "value": 472889.0055338542,
            "unit": "ns",
            "range": "± 2745.838553896347"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 100)",
            "value": 559762.6857638889,
            "unit": "ns",
            "range": "± 2388.646361143645"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 100)",
            "value": 2668564.89453125,
            "unit": "ns",
            "range": "± 7783.339564832089"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 100)",
            "value": 766980.6440972222,
            "unit": "ns",
            "range": "± 2737.326152343168"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithHmac(claimCount: 100)",
            "value": 565952.1634114584,
            "unit": "ns",
            "range": "± 1289.0746709672428"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithRsa(claimCount: 100)",
            "value": 2673612.1640625,
            "unit": "ns",
            "range": "± 17657.063288353413"
          },
          {
            "name": "HeroSdJwt.Benchmarks.IssuanceBenchmarks.IssueWithEcdsa(claimCount: 100)",
            "value": 770660.578125,
            "unit": "ns",
            "range": "± 7028.7195064314"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.VerifyWithoutKeyBinding",
            "value": 21403.058697509765,
            "unit": "ns",
            "range": "± 100.51946610840906"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.VerifyWithKeyBinding",
            "value": 1025219.318359375,
            "unit": "ns",
            "range": "± 903.0304836703519"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.TryVerifyWithoutKeyBinding",
            "value": 21535.740060424803,
            "unit": "ns",
            "range": "± 252.17167697905214"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.VerifyWithoutKeyBinding",
            "value": 21891.86382039388,
            "unit": "ns",
            "range": "± 63.88985356836704"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.VerifyWithKeyBinding",
            "value": 1039128.212890625,
            "unit": "ns",
            "range": "± 13880.905971646547"
          },
          {
            "name": "HeroSdJwt.Benchmarks.VerificationBenchmarks.TryVerifyWithoutKeyBinding",
            "value": 21590.574442545574,
            "unit": "ns",
            "range": "± 85.79862333938779"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationFewClaims",
            "value": 1185.7769222259521,
            "unit": "ns",
            "range": "± 23.20713958774644"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationManyClaims",
            "value": 4396.897715250651,
            "unit": "ns",
            "range": "± 34.75607577062209"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationAllClaims",
            "value": 1581.9490865071614,
            "unit": "ns",
            "range": "± 31.5515365239796"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationWithKeyBinding",
            "value": 1301.1950735516018,
            "unit": "ns",
            "range": "± 12.662495454276748"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationFewClaims",
            "value": 1150.447027206421,
            "unit": "ns",
            "range": "± 53.20115618383643"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationManyClaims",
            "value": 4536.377703348796,
            "unit": "ns",
            "range": "± 13.723682742864103"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationAllClaims",
            "value": 1574.0412489573162,
            "unit": "ns",
            "range": "± 37.71784835121512"
          },
          {
            "name": "HeroSdJwt.Benchmarks.PresentationBenchmarks.CreatePresentationWithKeyBinding",
            "value": 1286.292739868164,
            "unit": "ns",
            "range": "± 18.24144411310303"
          }
        ]
      }
    ]
  }
}