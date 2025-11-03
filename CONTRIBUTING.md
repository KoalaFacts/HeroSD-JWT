# Contributing to HeroSD-JWT

Thank you for your interest in contributing to HeroSD-JWT! We welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Feature Requests](#feature-requests)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

### Our Standards

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/HeroSD-JWT.git
   cd HeroSD-JWT
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/KoalaFacts/HeroSD-JWT.git
   ```

## Development Setup

### Prerequisites

- .NET 8.0 SDK or .NET 9.0 SDK
- Your favorite C# IDE (Visual Studio, VS Code, Rider)
- Git

### Building the Project

```bash
# Restore dependencies
dotnet restore

# Build the project
dotnet build

# Run tests
dotnet test

# Build in release mode
dotnet build -c Release
```

### Project Structure

```
HeroSD-JWT/
├── src/
│   ├── Core/               # Domain models
│   ├── Common/             # Shared utilities
│   ├── Issuance/          # SD-JWT creation
│   ├── Presentation/      # Presentation creation
│   └── Verification/      # Verification logic
├── tests/
│   ├── Unit/              # Unit tests
│   ├── Integration/       # Integration tests
│   ├── Contract/          # API contract tests
│   └── Security/          # Security tests
└── docs/                  # Documentation
```

## Making Changes

### Branching Strategy

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   # or
   git checkout -b fix/my-bugfix
   ```

2. **Branch naming conventions**:
   - `feature/description` - New features
   - `fix/description` - Bug fixes
   - `docs/description` - Documentation updates
   - `refactor/description` - Code refactoring
   - `test/description` - Test improvements

### Development Workflow

1. **Make your changes** following our code style guidelines
2. **Write tests** for your changes (TDD encouraged)
3. **Run tests** to ensure everything passes:
   ```bash
   dotnet test
   ```
4. **Build in release mode** to ensure no warnings:
   ```bash
   dotnet build -c Release
   ```

### Commit Messages

Write clear, concise commit messages following these guidelines:

```
type(scope): subject

body (optional)

footer (optional)
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `style` - Code style changes (formatting, etc.)
- `refactor` - Code refactoring
- `test` - Adding or updating tests
- `chore` - Maintenance tasks

**Examples:**
```
feat(issuance): add support for array element disclosure

fix(verification): correct digest validation for nested claims

docs(readme): update installation instructions

test(security): add timing attack resistance tests
```

## Testing

### Running Tests

```bash
# Run all tests
dotnet test

# Run with verbose output
dotnet test --verbosity normal

# Run specific test category
dotnet test --filter Category=Security

# Run tests with code coverage
dotnet test /p:CollectCoverage=true
```

### Test Categories

- **Unit Tests** - Test individual components in isolation
- **Integration Tests** - Test end-to-end flows
- **Contract Tests** - Test public API behavior
- **Security Tests** - Test security-critical functionality

### Writing Tests

Follow these principles:

1. **Test-Driven Development (TDD)** - Write tests first when possible
2. **One assertion per test** - Keep tests focused
3. **Arrange-Act-Assert pattern** - Structure tests clearly
4. **Descriptive test names** - Use `Should_ExpectedBehavior_When_Condition` format

**Example:**
```csharp
[Fact]
public void Should_ThrowException_When_ClaimIsNull()
{
    // Arrange
    var builder = SdJwtBuilder.Create();

    // Act & Assert
    Assert.Throws<ArgumentNullException>(() =>
        builder.WithClaim(null, "value"));
}
```

### Test Coverage

We aim for high test coverage:
- Critical paths: 100%
- Security features: 100%
- Public APIs: 90%+
- Overall: 80%+

## Code Style

### General Guidelines

1. **Follow .NET conventions** - Use standard C# naming conventions
2. **XML documentation** - Document all public APIs
3. **No warnings** - Build must be warning-free
4. **EditorConfig** - Follow the `.editorconfig` settings

### Naming Conventions

- **Classes**: PascalCase (`SdJwtBuilder`)
- **Methods**: PascalCase (`CreateSdJwt`)
- **Parameters**: camelCase (`claimName`)
- **Private fields**: camelCase with underscore (`_signingKey`)
- **Constants**: PascalCase (`MaxClaimSize`)

### XML Documentation

All public APIs must have XML documentation:

```csharp
/// <summary>
/// Creates an SD-JWT with the specified claims.
/// </summary>
/// <param name="claims">The claims to include in the SD-JWT.</param>
/// <returns>The created SD-JWT instance.</returns>
/// <exception cref="ArgumentNullException">
/// Thrown when <paramref name="claims"/> is null.
/// </exception>
public SdJwt CreateSdJwt(Dictionary<string, object> claims)
{
    // Implementation
}
```

### Code Organization

1. **Single Responsibility** - Each class should have one clear purpose
2. **Dependency Injection** - Use interfaces for testability
3. **Immutability** - Prefer immutable types when possible
4. **No third-party dependencies** - Use only .NET BCL

### Security Guidelines

1. **Constant-time operations** - Use `CryptographicOperations.FixedTimeEquals` for comparisons
2. **Secure random generation** - Use `RandomNumberGenerator`
3. **Input validation** - Validate all inputs rigorously
4. **No hardcoded secrets** - Never include keys or secrets in code

## Submitting Changes

### Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new functionality
3. **Run all tests** and ensure they pass
4. **Update CHANGELOG.md** if appropriate
5. **Push to your fork**:
   ```bash
   git push origin feature/my-feature
   ```
6. **Create a Pull Request** on GitHub

### Pull Request Template

When creating a PR, include:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All tests pass
- [ ] New tests added
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Tests added/updated
```

### Review Process

1. A maintainer will review your PR
2. Address any feedback or requested changes
3. Once approved, a maintainer will merge your PR

## Reporting Issues

### Bug Reports

Include the following information:

1. **Description** - Clear description of the bug
2. **Reproduction steps** - Minimal steps to reproduce
3. **Expected behavior** - What should happen
4. **Actual behavior** - What actually happens
5. **Environment**:
   - .NET version
   - OS version
   - HeroSD-JWT version

**Example:**
```markdown
**Description:**
VerifyPresentation throws NullReferenceException with nested claims

**Steps to reproduce:**
1. Create SD-JWT with nested object
2. Make nested claim selective
3. Create presentation
4. Verify presentation

**Expected:** Verification succeeds
**Actual:** NullReferenceException thrown

**Environment:**
- .NET 9.0
- Ubuntu 22.04
- HeroSD-JWT 1.0.3
```

### Security Issues

**Do NOT report security issues publicly!**

1. Email security concerns to the maintainers
2. Include detailed description and reproduction steps
3. Allow time for a fix before public disclosure

## Feature Requests

We welcome feature suggestions! Please include:

1. **Use case** - What problem does this solve?
2. **Proposed solution** - How should it work?
3. **Alternatives** - Other approaches you've considered
4. **Additional context** - Any other relevant information

## Recognition

Contributors will be recognized in:
- GitHub contributors page
- CHANGELOG.md for significant contributions
- Release notes for major features

## Questions?

- **GitHub Discussions** - For general questions
- **GitHub Issues** - For bug reports and feature requests
- **Pull Requests** - For code contributions

Thank you for contributing to HeroSD-JWT! 🎉

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
