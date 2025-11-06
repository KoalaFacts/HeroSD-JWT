# HeroSD-JWT Documentation

Welcome to the HeroSD-JWT documentation! This directory contains comprehensive guides and references for using the library.

## Documentation Index

### Getting Started
- **[Getting Started Guide](getting-started.md)** - Installation and first steps with HeroSD-JWT
- **[Examples](examples.md)** - Detailed code examples for various scenarios

### Production Operations
- **[Operations Guide](OPERATIONS.md)** - **NEW!** Comprehensive production operations manual covering deployment architecture, configuration management, monitoring, performance tuning, security hardening, high availability, and disaster recovery
- **[Deployment Guide](DEPLOYMENT.md)** - **NEW!** Step-by-step deployment instructions for Docker, Kubernetes, Azure, AWS, IIS, and CI/CD integration
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - **NEW!** Detailed problem resolution for verification failures, performance issues, authentication problems, key management, and observability
- **[Observability](OBSERVABILITY.md)** - **NEW!** Complete guide to logging, metrics, distributed tracing, and monitoring with Prometheus, Grafana, Application Insights, and Serilog

### In-Depth Guides
- **[Security Best Practices](security.md)** - Important security considerations and recommendations
- **[API Reference](api-reference.md)** - Complete API documentation

### Additional Resources
- **[Main README](../README.md)** - Project overview and quick start
- **[CHANGELOG](../CHANGELOG.md)** - Version history and changes
- **[CONTRIBUTING](../CONTRIBUTING.md)** - How to contribute to the project
- **[Production Readiness Analysis](../PRODUCTION_READINESS_ANALYSIS.md)** - Comprehensive production readiness assessment and roadmap
- **[LICENSE](../LICENSE)** - MIT License details

## Quick Links

### For New Users
1. Read the [Getting Started Guide](getting-started.md)
2. Try the basic examples from [Examples](examples.md)
3. Review [Security Best Practices](security.md)

### For Production Deployment
1. Review [Production Readiness Analysis](../PRODUCTION_READINESS_ANALYSIS.md) to understand requirements
2. Follow the [Deployment Guide](DEPLOYMENT.md) for your platform
3. Set up [Observability](OBSERVABILITY.md) (logging, metrics, tracing)
4. Configure monitoring using the [Operations Guide](OPERATIONS.md)
5. Keep [Troubleshooting Guide](TROUBLESHOOTING.md) handy for issue resolution

### For Developers
1. Explore detailed [Examples](examples.md)
2. Reference the [API Documentation](api-reference.md)
3. Check [Security Best Practices](security.md)
4. Implement [Observability](OBSERVABILITY.md) for production visibility

### For Operations Teams
1. Start with the [Operations Guide](OPERATIONS.md) for comprehensive operational procedures
2. Use the [Deployment Guide](DEPLOYMENT.md) for infrastructure setup
3. Configure monitoring dashboards from [Observability](OBSERVABILITY.md)
4. Follow runbooks in the [Operations Guide](OPERATIONS.md)
5. Refer to [Troubleshooting Guide](TROUBLESHOOTING.md) when issues arise

### For Contributors
1. Read [CONTRIBUTING.md](../CONTRIBUTING.md)
2. Review the [API Reference](api-reference.md)
3. Run the test suite
4. Check [Production Readiness Analysis](../PRODUCTION_READINESS_ANALYSIS.md) for planned improvements

## Documentation Sections

### Getting Started Guide
- Prerequisites
- Installation methods
- Your first SD-JWT
- Three-party model explanation
- Signature algorithms overview

### Examples
- Basic SD-JWT creation and verification
- Nested object selective disclosure
- Array element selective disclosure
- Key binding (proof of possession)
- Different signature algorithms
- Error handling
- Real-world scenarios:
  - Driver's license
  - Medical records
  - Employee credentials

### Security Best Practices
- Built-in security features
- Key management
- Algorithm selection guidelines
- Key binding implementation
- Critical claims handling
- Privacy considerations
- Common security pitfalls
- Security testing

### API Reference
- Complete namespace documentation
- Class and method references
- Parameter descriptions
- Code examples for each API
- Extension methods
- Type support details

## External Resources

- **IETF Specification**: [draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- **RFC 7800**: [Proof-of-Possession Key Semantics for JWTs](https://www.rfc-editor.org/rfc/rfc7800.html)
- **GitHub Repository**: https://github.com/KoalaFacts/HeroSD-JWT
- **NuGet Package**: https://www.nuget.org/packages/HeroSD-JWT

## Contributing to Documentation

Found an issue or want to improve the documentation? Contributions are welcome!

1. Fork the repository
2. Make your changes
3. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for more details.

## Support

- **Issues**: [GitHub Issues](https://github.com/KoalaFacts/HeroSD-JWT/issues)
- **Discussions**: [GitHub Discussions](https://github.com/KoalaFacts/HeroSD-JWT/discussions)
