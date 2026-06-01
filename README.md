# gh-pages — benchmark history

This branch stores continuous performance-benchmark results for HeroSD-JWT.

It is **managed automatically** by [`benchmark-action/github-action-benchmark`](https://github.com/benchmark-action/github-action-benchmark)
via the `Perform Benchmarks` workflow (`.github/workflows/perform-benchmarks.yml`).
On pushes to `main`, benchmark data is appended under `dev/bench/` and a dashboard
is published from this branch. Do not edit by hand.
