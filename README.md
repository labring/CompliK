# CompliK - Kubernetes Compliance and Security Platform

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.19+-326CE5?logo=kubernetes)](https://kubernetes.io/)

**CompliK** is a comprehensive Kubernetes compliance and security platform built with a Monorepo architecture. It provides three powerful tools for monitoring, managing, and securing your Kubernetes clusters.

## 🚀 Quick Links

- **[📚 Documentation Hub](DOCUMENTATION.md)** - Complete documentation index for all components
- **[Installation](#installation)** - Quick start guides
- **[Contributing](CONTRIBUTING.md)** - How to contribute
- **[License](#license)** - Apache 2.0

## 📦 Components

This repository adopts a **Monorepo + Multi-module** architecture, organizing three completely independent and equal sub-projects:

### 1. CompliK Platform
**Comprehensive compliance and security monitoring platform with plugin architecture**

- Event-driven plugin system for extensibility
- Automated service discovery for Kubernetes resources
- Browser-based compliance checking
- Integration with Lark/Feishu for alerts
- PostgreSQL storage for compliance records

[➡️ Learn more](complik/README.md)

### 2. Block Controller
**Kubernetes namespace block controller**

- Watches the namespace lock label `block.sealos.io/locked=true`
- Applies default-deny NetworkPolicy and ResourceQuota rules
- Cleans up blocking resources when the label is removed
- Runs as a lightweight in-cluster controller

[➡️ Learn more](block-controller/README.md)

### 3. ProcScan
**Lightweight security scanning DaemonSet for process monitoring**

- Real-time /proc filesystem monitoring
- Blacklist/whitelist rule engine
- Cryptocurrency mining detection
- Automatic labeling of suspicious pods
- Comprehensive Prometheus metrics

[➡️ Learn more](procscan/README.md)

### 4. Keyword Analyzer
**Data analysis tool for compliance detection keywords**

- MySQL database integration
- Frequency analysis with top-N statistics
- Histogram visualization with Chinese font support
- Cross-platform compatibility

[➡️ Learn more](analyze/README.md)

## 🎯 Key Features

- **Unified Monorepo**: All components in one repository with independent modules
- **Cloud-Native**: Built for Kubernetes with CRDs, operators, and DaemonSets
- **Extensible**: Plugin architecture for custom compliance checks
- **Production-Ready**: Comprehensive logging, metrics, and monitoring
- **Open Source**: Apache 2.0 licensed for community contributions

## 🏗️ Architecture Overview

**Important**: The sub-projects are completely equal in structure and organization, with no primary-secondary distinction, all located in independent subdirectories under the root directory.

## Directory Structure

```
CompliK/                                # Monorepo root directory
├── README.md                           # Project overview and quick start
├── MONOREPO.md                         # This document (architecture guide)
├── Makefile                            # Unified build system
├── .git/                               # Git repository
├── .github/                            # GitHub configuration (CI/CD, etc.)
│
├── complik/                            # Sub-project 1: Compliance monitoring platform
│   ├── go.mod                          # Independent module
│   │                                   # module: github.com/bearslyricattack/CompliK/complik
│   ├── go.sum
│   ├── cmd/complik/                    # Main program entry
│   │   └── main.go
│   ├── internal/                       # Internal implementation
│   │   └── app/
│   ├── plugins/                        # Plugin system
│   │   ├── compliance/
│   │   ├── discovery/
│   │   └── handle/
│   ├── pkg/                            # Public packages
│   ├── deploy/                         # K8s deployment configuration
│   ├── config.yml                      # Configuration file
│   ├── Dockerfile                      # Docker image build
│   └── bin/                            # Build artifacts
│       └── manager
│
├── block-controller/                   # Sub-project 2: Namespace manager
│   ├── go.mod                          # Independent module
│   │                                   # module: github.com/bearslyricattack/CompliK/block-controller
│   ├── go.sum
│   ├── cmd/                            # Entry program
│   │   └── main.go                     # Controller main entry
│   ├── internal/                       # Internal implementation
│   │   ├── config/                     # Controller configuration
│   │   └── controller/                 # Namespace lock reconciler
│   ├── deploy/                         # Kubernetes deployment manifests
│   ├── Dockerfile                      # Docker image build
│   └── README.md
│
└── procscan/                           # Sub-project 3: Process scanning tool
    ├── go.mod                          # Independent module
    │                                   # module: github.com/bearslyricattack/CompliK/procscan
    ├── go.sum
    ├── cmd/procscan/                   # Main program entry
    │   └── main.go
    ├── internal/                       # Internal implementation
    │   ├── core/
    │   │   ├── alert/
    │   │   ├── k8s/
    │   │   ├── processor/
    │   │   └── scanner/
    │   ├── container/
    │   └── notification/
    ├── pkg/                            # Public packages
    │   ├── config/
    │   ├── logger/
    │   ├── metrics/
    │   └── models/
    ├── deploy/                         # DaemonSet deployment configuration
    ├── config.yaml                     # Configuration file
    ├── Dockerfile                      # Docker image build
    ├── CLAUDE.md                       # Development guide
    └── bin/                            # Build artifacts
        └── procscan
```

## Architecture Design Principles

### 1. Completely Equal Sub-projects

The three sub-projects are **completely equal** in structure and organization:

| Feature | complik | block-controller | procscan |
|---------|---------|-----------------|----------|
| **Directory Location** | Under root | Under root | Under root |
| **go.mod** | Independent module | Independent module | Independent module |
| **Code Structure** | cmd/internal/pkg | cmd/internal/api | cmd/internal/pkg |
| **Deployment Config** | deploy/ | deploy/ | deploy/ |
| **Docker** | Dockerfile | Dockerfile | Dockerfile |
| **Build Artifacts** | bin/ | bin/ | bin/ |

### 2. Multi-module Architecture

Each sub-project has its own independent `go.mod`, forming independent Go modules:

```go
// complik/go.mod
module github.com/bearslyricattack/CompliK/complik

// block-controller/go.mod
module github.com/bearslyricattack/CompliK/block-controller

// procscan/go.mod
module github.com/bearslyricattack/CompliK/procscan
```

**Advantages**:
- Independent dependency management (can use different versions of k8s.io, etc.)
- Independent build and test
- Clear module boundaries
- Avoid dependency conflicts

### 3. Unified Build System

The `Makefile` in the root directory provides a unified build entry point, but each sub-project can also be built independently.

## Module Division

| Project | Module Path | Go Version | Main Dependencies |
|---------|------------|------------|------------------|
| **complik** | `github.com/bearslyricattack/CompliK/complik` | 1.24.5 | k8s.io v0.33.4, gorm, go-rod |
| **block-controller** | `github.com/bearslyricattack/CompliK/block-controller` | 1.24.5 | k8s.io v0.34.0, controller-runtime v0.22.1 |
| **procscan** | `github.com/bearslyricattack/CompliK/procscan` | 1.24.5 | k8s.io v0.33.4, prometheus client |

## Unified Build System (Makefile)

The `Makefile` in the root directory provides unified management for the three sub-projects.

### View All Available Commands

```bash
make help
```

### Build Commands

```bash
# Build all projects
make build-all

# Build individual projects
make build-complik           # CompliK platform
make build-block-controller  # Block Controller
make build-procscan         # ProcScan

# Clean all build artifacts
make clean-all
```

### Test Commands

```bash
# Run tests for all projects
make test-all

# Test individual projects
make test-complik
make test-block-controller
make test-procscan
```

### Development Tool Commands

```bash
# Tidy dependencies for all projects
make tidy-all

# Format code for all projects
make fmt-all

# Run go vet checks
make vet-all
```

### Docker Image Build

```bash
# Build Docker images
make docker-build-complik
make docker-build-block-controller
make docker-build-procscan
```

### Kubernetes Deployment

```bash
# Deploy all projects to Kubernetes
make deploy-all
```

## Independent Usage of Each Sub-project

Each sub-project can be built, tested, and deployed completely independently.

### CompliK

```bash
cd complik
go build -o bin/manager cmd/complik/main.go
./bin/manager --config=config.yml
```

### Block Controller

```bash
cd block-controller
go build -o bin/manager cmd/main.go
./bin/manager

kubectl apply -f deploy/manifests/
```

### ProcScan

```bash
cd procscan
go build -o bin/procscan cmd/procscan/main.go
./bin/procscan --config=config.yaml
```

## Inter-project Integration

Although the three sub-projects are completely independent in code (no cross-references), they can work together at runtime:

### Threat Response Workflow

```
1. CompliK or ProcScan detects a violation
   ↓
   Reports the violation to sealos-complik-admin

2. Admin stores the violation and evaluates autoban_policy
   ↓
   Creates an audit ban record and labels the namespace:
   "block.sealos.io/locked=true"

3. Block Controller listens to label changes
   ↓
   Automatically blocks namespace (limit resources and isolate network)

4. CompliK and ProcScan continue collecting security events
   ↓
   Sends alert notifications (Feishu, DingTalk, Email)
```

### Recommended Deployment Architecture

```
┌─────────────────────────────────────────┐
│           Kubernetes Cluster            │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  complik (Deployment)              │ │
│  │  Replicas: 2                       │ │
│  │  - Compliance detection            │ │
│  │  - Service discovery               │ │
│  │  - Alert notifications             │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  block-controller (Deployment)     │ │
│  │  Replicas: 1                       │ │
│  │  - Watch namespace lock labels     │ │
│  │  - Enforce blocking resources      │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  procscan (DaemonSet)              │ │
│  │  One instance per node             │ │
│  │  - Scan container processes        │ │
│  │  - Real-time threat detection      │ │
│  └────────────────────────────────────┘ │
│                                          │
└─────────────────────────────────────────┘
```

## Development Workflow

### 1. Clone Repository

```bash
git clone https://github.com/bearslyricattack/CompliK.git
cd CompliK
```

### 2. Build All Projects

```bash
make build-all
```

### 3. Modify a Sub-project

```bash
# Enter sub-project directory
cd complik  # or block-controller, procscan

# Modify code
vim cmd/complik/main.go

# Build and test
go build -o bin/manager cmd/complik/main.go
./bin/manager
```

### 4. Tidy Dependencies

```bash
# In sub-project directory
go mod tidy

# Or tidy all projects from root directory
cd ..
make tidy-all
```

### 5. Commit Code

```bash
git add .
git commit -m "feat(complik): add new feature"
git push origin main
```

## Dependency Management Notes

### 1. Do Not Cross-reference Projects

**Incorrect Example**:
```go
// Referencing complik code in block-controller (❌ Don't do this)
import "github.com/bearslyricattack/CompliK/complik/pkg/logger"
```

**Correct Approach**:
- Keep each sub-project independent
- If code sharing is needed, consider creating an independent shared library

### 2. Use go.work (Optional)

If you need to develop multiple sub-projects locally simultaneously, you can create `go.work`:

```bash
go work init
go work use complik
go work use block-controller
go work use procscan
```

### 3. Run tidy-all Regularly

```bash
make tidy-all
```

## Migration Guide

### Migrating from Old Structure

**Old Structure** (v1.x):
```
CompliK/
├── go.mod                    # CompliK code directly in root directory
├── cmd/complik/
├── internal/
├── pkg/
├── procscan/                 # procscan as subdirectory
│   └── go.mod
└── block-controller/         # block-controller as subdirectory
    └── go.mod
```

**New Structure** (v2.0):
```
CompliK/
├── complik/                  # CompliK also became a sub-project
│   └── go.mod
├── block-controller/         # Remains as sub-project
│   └── go.mod
└── procscan/                 # Remains as sub-project
    └── go.mod
```

**Main Changes**:
1. CompliK main project code moved to `complik/` subdirectory
2. Module path changed from `github.com/bearslyricattack/CompliK` to `github.com/bearslyricattack/CompliK/complik`
3. All import paths updated accordingly
4. Makefile adjusted to uniformly manage three equal sub-projects

### Old Code Backup

- `procscan.old.backup/` - Old procscan code from original CompliK project
- Can be deleted after confirmation: `rm -rf procscan.old.backup`

## FAQ

### Q: Why make the main project also a sub-project?

**A**: For architectural consistency and clarity:
- Three projects are completely equal in structure
- Clearer module boundaries
- Easier to understand and maintain
- Follows Monorepo best practices

### Q: Import paths became longer, will there be any impact?

**A**: Impact is minimal:
- Just one more level in path: `/complik`, `/block-controller`, `/procscan`
- No impact on compilation speed or runtime performance
- IDE auto-completion still works normally

### Q: How to add a new sub-project?

**A**:
1. Create new sub-project directory in root
2. Initialize independent go.mod
   ```bash
   mkdir newproject
   cd newproject
   go mod init github.com/bearslyricattack/CompliK/newproject
   ```
3. Create standard Go project structure (cmd/, internal/, pkg/)
4. Add build targets in root Makefile
5. Update README.md and MONOREPO.md

### Q: What to do if build fails?

**A**: Common troubleshooting:
1. Ensure Go version >= 1.24.5
2. Run `make tidy-all` to update all dependencies
3. Check if import paths are correct (should include `/complik`, `/block-controller`, or `/procscan`)
4. Review specific error logs

### Q: How to release Docker image for a single sub-project?

**A**:
```bash
cd <project>
docker build -t <registry>/<project>:<tag> .
docker push <registry>/<project>:<tag>
```

Or use Makefile:
```bash
make docker-build-complik
make docker-build-block-controller
make docker-build-procscan
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build All Projects

on: [push, pull_request]

jobs:
  build-complik:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.24.5'
      - run: make build-complik

  build-block-controller:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.24.5'
      - run: make build-block-controller

  build-procscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.24.5'
      - run: make build-procscan
```

## 📚 Documentation

Each component has comprehensive documentation:

- **[CompliK Platform](complik/README.md)** - Plugin architecture, configuration, deployment
- **[CompliK Logging](complik/docs/LOGGING.md)** - Advanced logging system documentation
- **[CompliK Security](complik/docs/SECURITY.md)** - Security configuration guide
- **[Block Controller](block-controller/README.md)** - Namespace lock enforcement and architecture
- **[ProcScan](procscan/README.md)** - Configuration, rules, deployment
- **[ProcScan Metrics](procscan/docs/PROMETHEUS_METRICS.md)** - Complete metrics reference
- **[Keyword Analyzer](analyze/README.md)** - Database setup, customization, troubleshooting

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Code of conduct
- Development setup
- Contribution workflow
- Coding standards
- Pull request process

## 📄 License

Copyright 2025 CompliK Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See [LICENSE](LICENSE) for the full license text.

## 🙏 Acknowledgments

- Built with [Kubernetes](https://kubernetes.io/)
- Powered by [Go](https://go.dev/)
- Inspired by cloud-native security best practices

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/bearslyricattack/CompliK/issues)
- **Discussions**: [GitHub Discussions](https://github.com/bearslyricattack/CompliK/discussions)
- **Labels**: Use labels to identify which component your issue relates to
  - `complik` - CompliK platform issues
  - `block-controller` - Block Controller issues
  - `procscan` - ProcScan issues
  - `analyze` - Keyword Analyzer issues
  - `monorepo` - Repository structure issues
  - `documentation` - Documentation improvements

## 📋 Version History

### v2.0.0 (2025-11-24)
- Completely equal three-project Monorepo architecture
- CompliK main project changed to sub-project structure
- All sub-projects are now independent and equal
- Updated all module paths and import paths
- Unified build system with Makefile
- Apache 2.0 license applied to all components
- Full English documentation and internationalization

### v1.x.x
- Hybrid structure (CompliK in root directory)
- Block-controller and procscan as subdirectories

---

**Project Status**: Active Development
**Kubernetes Compatibility**: 1.19+
**Go Version**: 1.24+
**Last Updated**: 2025-11-26
