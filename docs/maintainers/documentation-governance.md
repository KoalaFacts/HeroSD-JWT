# Documentation Governance Guide

**Purpose:** Establish standards for creating, organizing, and maintaining documentation in HeroSD-JWT
**Status:** Active
**Last Updated:** 2025-11-06

---

## Table of Contents

- [Principles](#principles)
- [Documentation Structure](#documentation-structure)
- [Naming Conventions](#naming-conventions)
- [File Placement Rules](#file-placement-rules)
- [Content Guidelines](#content-guidelines)
- [Review Process](#review-process)
- [Templates](#templates)
- [Maintenance](#maintenance)

---

## Principles

### 1. Single Source of Truth
- **Never duplicate content** - If information exists, link to it instead of copying
- **Consolidate, don't fragment** - One comprehensive guide beats three partial ones
- **Use canonical locations** - Each type of documentation has a designated home

### 2. Audience-First Organization
- **Organize by reader, not by topic** - Users, Operations, Contributors, Maintainers
- **Clear separation** - Each audience has their own space
- **Easy navigation** - Readers find their docs without hunting

### 3. Discoverability
- **Clear navigation** from docs/README.md
- **Consistent naming** - No guessing if it's `SECURITY.md` or `security.md`
- **Search-friendly** - Descriptive filenames and headers

### 4. Maintainability
- **Keep docs near code** - Technical docs live with implementation
- **Regular reviews** - Quarterly documentation audits
- **Automated checks** - CI validates links and structure

### 5. Always Up-to-Date
- **Update docs with code** - Documentation is part of the definition of done
- **No stale content** - Delete outdated docs, don't leave them to rot
- **Version appropriately** - Indicate which version docs apply to

---

## Documentation Structure

### Folder Layout

```
HeroSD-JWT/
├── README.md                          # Project overview
├── CHANGELOG.md                       # Version history
├── LICENSE                            # License file
├── SECURITY.md                        # Security policy
│
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md      # PR template
│   └── ISSUE_TEMPLATE/                # Issue templates
│
├── docs/
│   ├── README.md                      # Documentation hub
│   │
│   ├── users/                         # 👤 USER DOCUMENTATION
│   │   ├── getting-started.md
│   │   ├── examples.md
│   │   ├── api-reference.md
│   │   └── security.md
│   │
│   ├── operations/                    # 🚀 OPERATIONAL DOCUMENTATION
│   │   ├── observability.md
│   │   ├── deployment.md
│   │   ├── operations.md
│   │   ├── troubleshooting.md
│   │   └── production-readiness.md
│   │
│   ├── contributors/                  # 🛠️ CONTRIBUTOR DOCUMENTATION
│   │   ├── contributing.md
│   │   ├── development.md
│   │   ├── testing.md
│   │   └── roadmap.md
│   │
│   └── maintainers/                   # 🔧 MAINTAINER DOCUMENTATION
│       ├── publishing-guide.md
│       ├── release-checklist.md
│       └── architecture.md
│
├── examples/
│   └── {ExampleName}/
│       └── README.md                  # Example-specific docs
│
└── src/
    └── {ProjectName}/
        └── Internal/
            └── README.md               # Implementation notes
```

### Audience Categories

| Audience | Folder | Purpose | Examples |
|----------|--------|---------|----------|
| **Users** | `docs/users/` | End-user documentation for consuming the library | Getting started, API reference, examples |
| **Operations** | `docs/operations/` | DevOps/SRE documentation for running in production | Deployment, monitoring, troubleshooting |
| **Contributors** | `docs/contributors/` | Developer documentation for contributing code | Contributing guidelines, development setup |
| **Maintainers** | `docs/maintainers/` | Core team documentation for publishing/releases | Publishing guide, release workflow |

---

## Naming Conventions

### Root Level Files

**Use UPPERCASE.md ONLY for GitHub-standard files:**

| Filename | Purpose | Required? |
|----------|---------|-----------|
| `README.md` | Project overview | ✅ Yes |
| `CHANGELOG.md` | Version history | ✅ Yes |
| `LICENSE` | License file | ✅ Yes |
| `SECURITY.md` | Security policy | ✅ Recommended |
| `CONTRIBUTING.md` | Contribution guide | ⚠️ Can move to docs/contributors/ |

**Everything else:** Use lowercase-with-dashes.md

### Documentation Files

**All documentation files use lowercase-with-dashes:**

```
✅ CORRECT:
docs/users/getting-started.md
docs/operations/deployment.md
docs/contributors/contributing.md

❌ WRONG:
docs/users/Getting-Started.md
docs/operations/DEPLOYMENT.md
docs/contributors/CONTRIBUTING.md
```

### Naming Patterns

| Document Type | Pattern | Example |
|---------------|---------|---------|
| Guide/Tutorial | `{topic}.md` | `getting-started.md` |
| Reference | `{topic}-reference.md` | `api-reference.md` |
| Operational | `{topic}.md` | `deployment.md`, `operations.md` |
| Process/Workflow | `{topic}-guide.md` or `{topic}-workflow.md` | `publishing-guide.md` |
| Checklist | `{topic}-checklist.md` | `release-checklist.md` |
| Example README | Always `README.md` | `examples/SerilogExample/README.md` |

---

## File Placement Rules

### Decision Tree

```
Is it a GitHub-standard file (README, LICENSE, CHANGELOG)?
├─ YES → Root level
└─ NO → Continue...

Is it for end users of the library?
├─ YES → docs/users/
└─ NO → Continue...

Is it for DevOps/SRE operating in production?
├─ YES → docs/operations/
└─ NO → Continue...

Is it for developers contributing code?
├─ YES → docs/contributors/
└─ NO → Continue...

Is it for maintainers publishing releases?
├─ YES → docs/maintainers/
└─ NO → Continue...

Is it example-specific documentation?
├─ YES → examples/{ExampleName}/README.md
└─ NO → Continue...

Is it technical implementation notes?
├─ YES → src/{ProjectName}/README.md
└─ NO → Consult with team for placement
```

### Specific Rules

#### DO ✅

- **Put user guides** in `docs/users/`
- **Put deployment guides** in `docs/operations/`
- **Put contributing guides** in `docs/contributors/`
- **Put release workflows** in `docs/maintainers/`
- **Use README.md** for examples
- **Keep implementation notes** near code in `src/`

#### DON'T ❌

- **Don't put user docs** in root (unless GitHub standard)
- **Don't put operational docs** in `docs/users/`
- **Don't put contributor docs** in `docs/operations/`
- **Don't create standalone release notes** (use GitHub Releases)
- **Don't duplicate content** across files

---

## Content Guidelines

### What to Include

#### User Documentation (`docs/users/`)

**Focus:** How to use the library

- Installation instructions
- Quick start guides
- Code examples
- API reference
- Common use cases
- Best practices
- Security guidelines

**Tone:** Friendly, tutorial-style, assumes basic .NET knowledge

#### Operational Documentation (`docs/operations/`)

**Focus:** How to run in production

- Deployment guides (Docker, Kubernetes, Azure, AWS)
- Configuration management
- Monitoring and observability
- Performance tuning
- Troubleshooting
- Security hardening
- Disaster recovery

**Tone:** Technical, prescriptive, assumes DevOps/SRE knowledge

#### Contributor Documentation (`docs/contributors/`)

**Focus:** How to contribute code

- Development environment setup
- Building and testing locally
- Code style guidelines
- Testing requirements
- Pull request process
- Architectural decisions
- Future roadmap

**Tone:** Technical, collaborative, assumes software development knowledge

#### Maintainer Documentation (`docs/maintainers/`)

**Focus:** How to maintain the project

- Publishing to NuGet
- Release workflow
- Version management
- Dependency updates
- Security response
- Governance policies

**Tone:** Process-oriented, detailed, assumes maintainer privileges

### What to Avoid

❌ **Don't:**

- Duplicate content (link instead)
- Include code examples in multiple places (single source of truth)
- Write outdated content without version indicators
- Mix audiences (e.g., publishing guide in user docs)
- Create standalone release notes (use GitHub Releases)
- Include internal-only information in public docs

---

## Review Process

### Documentation Changes

**All documentation changes must:**

1. ✅ **Follow naming conventions** defined in this guide
2. ✅ **Use correct folder** based on audience
3. ✅ **Update docs/README.md** if adding new top-level doc
4. ✅ **Check all links** are valid
5. ✅ **Follow markdown style** (see Templates section)
6. ✅ **Be reviewed** in pull request process

### Pull Request Checklist

When submitting documentation changes:

- [ ] Documentation follows naming conventions
- [ ] File is in correct audience folder
- [ ] No duplicate content
- [ ] All links are valid
- [ ] Code examples are tested
- [ ] Navigation updated (docs/README.md)
- [ ] Spell-checked
- [ ] Follows markdown style guide

### Quarterly Documentation Audit

**Every quarter, review:**

1. ✅ **All links** - Check for broken links (automated)
2. ✅ **Outdated content** - Verify accuracy with current version
3. ✅ **Missing docs** - Identify gaps in coverage
4. ✅ **Duplicate content** - Consolidate any new duplicates
5. ✅ **Naming compliance** - Ensure all files follow conventions
6. ✅ **Navigation** - Verify docs/README.md is up-to-date

---

## Templates

### Document Header Template

All documents should start with a clear header:

```markdown
# {Document Title}

**Purpose:** {One sentence describing purpose}
**Audience:** {User | Operations | Contributors | Maintainers}
**Last Updated:** YYYY-MM-DD

---

## Table of Contents

- [Section 1](#section-1)
- [Section 2](#section-2)

---

{Content starts here}
```

### User Guide Template

```markdown
# {Feature Name}

**What this guide covers:** {Brief description}

---

## Prerequisites

Before you begin, ensure you have:

- Prerequisite 1
- Prerequisite 2

---

## Quick Start

{Minimal example to get started}

---

## Detailed Guide

### Step 1: {First Step}

{Detailed instructions}

### Step 2: {Second Step}

{Detailed instructions}

---

## Examples

### Example 1: {Use Case}

{Code example with explanation}

---

## Troubleshooting

**Problem:** {Common issue}
**Solution:** {How to fix}

---

## Next Steps

- Link to related guide
- Link to API reference
```

### Operational Guide Template

```markdown
# {Operational Topic}

**Purpose:** {What this guide helps you accomplish}
**Target Environment:** {Production | Staging | Development}

---

## Prerequisites

- [ ] Prerequisite 1
- [ ] Prerequisite 2

---

## Configuration

### Step 1: {Configuration Step}

{Detailed configuration instructions}

---

## Deployment

### Option 1: {Platform Name}

{Platform-specific deployment steps}

---

## Monitoring

### Metrics to Track

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| Metric 1 | Description | Threshold |

---

## Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues.

---

## Best Practices

1. ✅ Best practice 1
2. ✅ Best practice 2
```

---

## Maintenance

### Automation

**Automated checks in CI:**

1. ✅ **Link validation** - Check for broken links
2. ✅ **Markdown linting** - Enforce markdown style
3. ✅ **Spell checking** - Catch typos
4. ✅ **TOC generation** - Auto-generate table of contents

**GitHub Actions workflow:**

```yaml
name: Documentation Checks

on:
  pull_request:
    paths:
      - '**.md'

jobs:
  check-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check broken links
        uses: gaurav-nelson/github-action-markdown-link-check@v1

      - name: Lint markdown
        uses: avto-dev/markdown-lint@v1

      - name: Spell check
        uses: streetsidesoftware/cspell-action@v2
```

### Manual Review Schedule

| Frequency | Task | Responsible |
|-----------|------|-------------|
| **Every PR** | Review doc changes | PR Reviewer |
| **Monthly** | Check for broken links | Any Contributor |
| **Quarterly** | Full documentation audit | Maintainer |
| **Every Release** | Update version references | Release Manager |

### Ownership

| Documentation Area | Owner | Backup |
|--------------------|-------|--------|
| docs/users/ | Lead Maintainer | Contributors |
| docs/operations/ | DevOps Lead | Maintainers |
| docs/contributors/ | Lead Maintainer | Contributors |
| docs/maintainers/ | Lead Maintainer | Senior Contributors |
| examples/ | Example Author | Maintainers |

---

## Enforcement

### Pull Request Requirements

**Documentation PRs must:**

1. ✅ Pass all automated checks (links, linting, spelling)
2. ✅ Be reviewed by documentation owner
3. ✅ Follow all conventions in this guide
4. ✅ Update navigation if adding new files

**Code PRs should:**

1. ⚠️ Update documentation if API changes
2. ⚠️ Add examples for new features
3. ⚠️ Update troubleshooting for new error cases

### Exceptions

**To request an exception to these rules:**

1. Open an issue explaining why the exception is needed
2. Tag with `documentation` label
3. Get approval from two maintainers
4. Document the exception in this guide

---

## Examples

### Good Documentation Structure

```
✅ CORRECT:

docs/users/getting-started.md
- Installation
- Quick start
- Next steps

docs/operations/deployment.md
- Docker deployment
- Kubernetes deployment
- Azure deployment

docs/contributors/contributing.md
- Development setup
- Testing guidelines
- PR process
```

### Bad Documentation Structure

```
❌ WRONG:

ROOT/GETTING_STARTED.md              # Wrong location and naming
ROOT/deployment-guide.md              # Wrong location
docs/publishing.md                    # Wrong audience folder
docs/OPERATIONS/Troubleshooting.MD    # Wrong case
docs/user-and-contributor-guide.md    # Mixed audiences
```

---

## Frequently Asked Questions

### Q: Where do I put a guide that applies to multiple audiences?

**A:** Choose the **primary audience** and link from other relevant docs. Example: Security best practices go in `docs/users/security.md`, but link from `docs/operations/operations.md`.

### Q: Can I use UPPERCASE.md for my new doc?

**A:** Only if it's a **GitHub-standard file** (README, LICENSE, CHANGELOG, SECURITY, CONTRIBUTING). Everything else uses lowercase-with-dashes.

### Q: What if my document doesn't fit any category?

**A:** Discuss with maintainers. Most docs fit into user/operations/contributors/maintainers. If truly unique, may need new category.

### Q: Should examples have their own docs folder?

**A:** No. Each example has ONE README.md in its own folder: `examples/{ExampleName}/README.md`

### Q: Where do architectural decision records (ADRs) go?

**A:** `docs/maintainers/architecture/` (create subfolder if needed)

### Q: Can I create a blog post or tutorial?

**A:** External blog posts are great! Link to them from `docs/users/` but don't duplicate content.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-06 | Initial documentation governance guide |

---

## References

- [Keep a Changelog](https://keepachangelog.com/) - Changelog format
- [GitHub Standard Files](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions) - GitHub standards
- [CommonMark](https://commonmark.org/) - Markdown specification
- [Google Developer Documentation Style Guide](https://developers.google.com/style) - Style reference

---

**Questions or suggestions?** Open an issue with the `documentation` label.
