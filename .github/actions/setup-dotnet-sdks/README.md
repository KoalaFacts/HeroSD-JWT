# Setup .NET SDKs Action

A reusable composite action that automatically installs all .NET SDK versions defined in `Directory.Build.props`.

## Usage

```yaml
- name: Setup .NET SDKs
  uses: ./.github/actions/setup-dotnet-sdks
```

With caching disabled:

```yaml
- name: Setup .NET SDKs
  uses: ./.github/actions/setup-dotnet-sdks
  with:
    cache: false
```

## How It Works

1. Extracts `<SupportedSdkVersions>` from the repository's `Directory.Build.props`
2. Installs all SDK versions using `actions/setup-dotnet@v5`
3. Enables NuGet package caching by default

## Benefits

- **Explicit SDK baseline**: CI installs the exact versions in `Directory.Build.props`
- **No duplication**: All workflows use the same action
- **Reproducible restore**: `global.json` selects the pinned build SDK on developer machines and CI
- **Consistent**: All workflows use identical SDK setup

## Outputs

- `versions`: The extracted SDK versions (newline-separated string)
- `frameworks`: The extracted target frameworks as JSON array (e.g., `["net8.0","net9.0","net10.0"]`)

## Requirements

- Repository must have a `Directory.Build.props` file at the root
- The file must contain a `<SupportedSdkVersions>` element with semicolon-separated versions
- Example: `<SupportedSdkVersions>8.0.426;9.0.319;10.0.402</SupportedSdkVersions>`

When updating the SDK baseline, update `global.json` to the matching build SDK,
run `dotnet restore --force-evaluate` to regenerate the package locks, then verify
`dotnet restore --locked-mode` and build and test all supported target frameworks.
SDK servicing updates can change implicit `Microsoft.NET.ILLink.Tasks` dependencies.
