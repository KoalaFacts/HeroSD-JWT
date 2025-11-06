# HeroSD-JWT Documentation

Welcome to the HeroSD-JWT documentation! This directory contains comprehensive guides and references organized by audience.

---

## Documentation Index

### 👤 User Documentation (`users/`)

For developers using HeroSD-JWT in their applications:

- **[Getting Started Guide](users/getting-started.md)** - Installation and first steps with HeroSD-JWT
- **[Examples](users/examples.md)** - Detailed code examples for various scenarios
- **[API Reference](users/api-reference.md)** - Complete API documentation
- **[Security Best Practices](users/security.md)** - Important security considerations and recommendations

### 🚀 Operations Documentation (`operations/`)

For DevOps/SRE teams deploying and operating HeroSD-JWT in production:

- **[Deployment Guide](operations/deployment.md)** - Step-by-step deployment instructions for Docker, Kubernetes, Azure, AWS, IIS, and CI/CD integration
- **[Operations Guide](operations/operations.md)** - Comprehensive production operations manual covering deployment architecture, configuration management, monitoring, performance tuning, security hardening, high availability, and disaster recovery
- **[Observability](operations/observability.md)** - Complete guide to logging, metrics, distributed tracing, and monitoring with Prometheus, Grafana, Application Insights, and Serilog
- **[Troubleshooting Guide](operations/troubleshooting.md)** - Detailed problem resolution for verification failures, performance issues, authentication problems, key management, and observability
- **[Production Readiness](operations/production-readiness.md)** - Comprehensive production readiness assessment and roadmap

### 🛠️ Contributor Documentation (`contributors/`)

For developers contributing code to HeroSD-JWT:

- **[Roadmap](contributors/roadmap.md)** - Future improvements and architectural plans

### 🔧 Maintainer Documentation (`maintainers/`)

For package maintainers managing releases and publishing:

- **[Publishing Guide](maintainers/publishing-guide.md)** - Complete guide for publishing NuGet packages, versioning strategy, and release workflow

### 📚 Governance & Standards

- **[Documentation Governance](maintainers/documentation-governance.md)** - Standards and conventions for documentation

### 📋 Project Resources

- **[Main README](../README.md)** - Project overview and quick start
- **[CHANGELOG](../CHANGELOG.md)** - Version history and changes
- **[CONTRIBUTING](../CONTRIBUTING.md)** - How to contribute to the project
- **[LICENSE](../LICENSE)** - MIT License details

---

## Quick Links

### For New Users
1. Read the [Getting Started Guide](users/getting-started.md)
2. Try the basic examples from [Examples](users/examples.md)
3. Review [Security Best Practices](users/security.md)

### For Production Deployment
1. Review [Production Readiness](operations/production-readiness.md) to understand requirements
2. Follow the [Deployment Guide](operations/deployment.md) for your platform
3. Set up [Observability](operations/observability.md) (logging, metrics, tracing)
4. Configure monitoring using the [Operations Guide](operations/operations.md)
5. Keep [Troubleshooting Guide](operations/troubleshooting.md) handy for issue resolution

### For Developers
1. Explore detailed [Examples](users/examples.md)
2. Reference the [API Documentation](users/api-reference.md)
3. Check [Security Best Practices](users/security.md)
4. Implement [Observability](operations/observability.md) for production visibility

### For Operations Teams
1. Start with the [Operations Guide](operations/operations.md) for comprehensive operational procedures
2. Use the [Deployment Guide](operations/deployment.md) for infrastructure setup
3. Configure monitoring dashboards from [Observability](operations/observability.md)
4. Follow runbooks in the [Operations Guide](operations/operations.md)
5. Refer to [Troubleshooting Guide](operations/troubleshooting.md) when issues arise

### For Contributors
1. Read [CONTRIBUTING.md](../CONTRIBUTING.md)
2. Review the [API Reference](users/api-reference.md)
3. Run the test suite
4. Check [Roadmap](contributors/roadmap.md) for planned improvements

### For Maintainers
1. Follow the [Publishing Guide](maintainers/publishing-guide.md) for releases
2. Review [Documentation Governance](maintainers/documentation-governance.md) for standards
3. Check [Production Readiness](operations/production-readiness.md) for improvement tracking

---

## Documentation Structure

```
docs/
├── README.md                          # This file - documentation hub
│
├── users/                             # 👤 USER DOCUMENTATION
│   ├── getting-started.md             # Installation and quick start
│   ├── examples.md                    # Code examples
│   ├── api-reference.md               # API documentation
│   └── security.md                    # Security best practices
│
├── operations/                        # 🚀 OPERATIONAL DOCUMENTATION
│   ├── deployment.md                  # Platform deployment guides
│   ├── operations.md                  # Production operations manual
│   ├── observability.md               # Logging, metrics, tracing
│   ├── troubleshooting.md             # Problem resolution
│   └── production-readiness.md        # Production readiness analysis
│
├── contributors/                      # 🛠️ CONTRIBUTOR DOCUMENTATION
│   └── roadmap.md                     # Future improvements
│
└── maintainers/                       # 🔧 MAINTAINER DOCUMENTATION
    ├── publishing-guide.md            # Publishing and release workflow
    └── documentation-governance.md    # Documentation standards
```

---

## External Resources

- **IETF Specification**: [draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- **RFC 7800**: [Proof-of-Possession Key Semantics for JWTs](https://www.rfc-editor.org/rfc/rfc7800.html)
- **GitHub Repository**: https://github.com/KoalaFacts/HeroSD-JWT
- **NuGet Package**: https://www.nuget.org/packages/HeroSD-JWT

---

## Contributing to Documentation

Found an issue or want to improve the documentation? Contributions are welcome!

1. Review [Documentation Governance](maintainers/documentation-governance.md) for standards
2. Follow naming conventions (lowercase-with-dashes.md)
3. Place docs in appropriate audience folder
4. Update this README.md if adding new files
5. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for more details.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/KoalaFacts/HeroSD-JWT/issues)
- **Discussions**: [GitHub Discussions](https://github.com/KoalaFacts/HeroSD-JWT/discussions)
