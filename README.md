# ☁️ Cloud Guard — Cloud Security Posture Management Platform

[![CI/CD Pipeline](https://github.com/osamacs7/cloud-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/osamacs7/cloud-guard/actions/workflows/ci.yml)
[![Security Scan](https://github.com/osamacs7/cloud-guard/actions/workflows/security.yml/badge.svg?branch=master)](https://github.com/osamacs7/cloud-guard/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

**Cloud Guard** is an enterprise-grade Cloud Security Posture Management (CSPM) platform that continuously monitors your cloud infrastructure for security misconfigurations, compliance violations, and threat indicators across AWS, Azure, and GCP.

## Architecture

### System Overview

```mermaid
graph TB
    subgraph Users["Users & Integrations"]
        CLI["CLI Tool"]
        API_Client["API Clients"]
        CI_CD["CI/CD Pipelines"]
        Schedule["Scheduled Jobs"]
    end

    subgraph Platform["Cloud Guard Platform"]
        direction TB
        API["REST API<br/><i>FastAPI + JWT Auth</i>"]
        
        subgraph Engines["Core Engines"]
            Scanner["Scanner Engine"]
            Compliance["Compliance Engine"]
            Remediation["Remediation Engine"]
        end

        subgraph Notifications["Alerting System"]
            Slack["Slack"]
            PD["PagerDuty"]
            Webhook["Webhooks"]
            Email["Email"]
        end
    end

    subgraph Providers["Cloud Providers"]
        AWS["AWS"]
        Azure["Azure"]
        GCP["GCP"]
        K8s["Kubernetes"]
    end

    subgraph Storage["Data Layer"]
        PG[("PostgreSQL")]
        Redis[("Redis<br/><i>Cache & Queue</i>")]
    end

    CLI --> API
    API_Client --> API
    CI_CD --> API
    Schedule --> API

    API --> Scanner
    API --> Compliance
    API --> Remediation

    Scanner --> AWS
    Scanner --> Azure
    Scanner --> GCP
    Scanner --> K8s

    Scanner --> Compliance
    Compliance --> Notifications

    API --> PG
    API --> Redis

    style Platform fill:#1a1a2e,stroke:#16213e,color:#fff
    style Engines fill:#0f3460,stroke:#16213e,color:#fff
    style Notifications fill:#533483,stroke:#16213e,color:#fff
    style Providers fill:#e94560,stroke:#16213e,color:#fff
    style Storage fill:#0f3460,stroke:#16213e,color:#fff
    style Users fill:#16213e,stroke:#16213e,color:#fff
```

### Scanning Flow

```mermaid
sequenceDiagram
    participant U as User / CI Pipeline
    participant API as Cloud Guard API
    participant S as Scanner Engine
    participant C as Compliance Engine
    participant P as Cloud Provider
    participant N as Alerting System
    participant DB as PostgreSQL

    U->>API: POST /api/v1/scans
    API->>DB: Create scan record (PENDING)
    API-->>U: 201 Scan Created

    API->>S: Trigger scan
    S->>DB: Update status (RUNNING)

    loop For each security check
        S->>P: Query resource configuration
        P-->>S: Resource metadata
        S->>S: Evaluate against rules
    end

    S->>C: Evaluate compliance
    C->>C: Map findings to controls
    C-->>S: Compliance report

    S->>DB: Store findings
    S->>DB: Update status (COMPLETED)

    alt Critical findings found
        S->>N: Send alerts
        N->>N: Slack + PagerDuty + Webhook
    end

    U->>API: GET /api/v1/scans/{id}/findings
    API->>DB: Query findings
    DB-->>API: Finding records
    API-->>U: Findings + compliance score
```

### CI/CD Security Pipeline

```mermaid
graph LR
    subgraph CI["CI/CD Pipeline"]
        direction LR
        Lint["Lint<br/><i>Ruff</i>"] --> Test["Test<br/><i>Pytest</i>"]
        Test --> SAST["SAST<br/><i>Bandit + Semgrep</i>"]
        SAST --> Build["Docker<br/>Build"]
        Build --> ContainerScan["Container Scan<br/><i>Trivy</i>"]
        ContainerScan --> Deploy["Deploy"]
    end

    subgraph Weekly["Weekly Security Scan"]
        direction LR
        DepAudit["Dependency<br/>Audit<br/><i>Safety + pip-audit</i>"]
        CodeQL["CodeQL<br/>Analysis"]
        Secrets["Secret Scan<br/><i>TruffleHog</i>"]
    end

    style Lint fill:#28a745,stroke:#1e7e34,color:#fff
    style Test fill:#28a745,stroke:#1e7e34,color:#fff
    style SAST fill:#fd7e14,stroke:#e36209,color:#fff
    style Build fill:#007bff,stroke:#0056b3,color:#fff
    style ContainerScan fill:#fd7e14,stroke:#e36209,color:#fff
    style Deploy fill:#6f42c1,stroke:#5a32a3,color:#fff
    style DepAudit fill:#fd7e14,stroke:#e36209,color:#fff
    style CodeQL fill:#fd7e14,stroke:#e36209,color:#fff
    style Secrets fill:#dc3545,stroke:#bd2130,color:#fff
```

### Infrastructure Deployment

```mermaid
graph TB
    subgraph AWS_Cloud["AWS Cloud"]
        subgraph VPC["VPC (10.0.0.0/16)"]
            subgraph Public["Public Subnets"]
                ALB["Application<br/>Load Balancer"]
                NAT["NAT Gateway"]
            end

            subgraph Private["Private Subnets"]
                subgraph ECS["ECS Cluster"]
                    Task1["Cloud Guard<br/>Container #1"]
                    Task2["Cloud Guard<br/>Container #2"]
                end
                RDS[("RDS PostgreSQL<br/><i>Encrypted, Multi-AZ</i>")]
                ElastiCache[("ElastiCache Redis")]
            end
        end

        CloudWatch["CloudWatch<br/>Monitoring"]
        FlowLogs["VPC Flow Logs"]
    end

    Internet["Internet"] --> ALB
    ALB --> Task1
    ALB --> Task2
    Task1 --> RDS
    Task2 --> RDS
    Task1 --> ElastiCache
    Task2 --> ElastiCache
    VPC --> FlowLogs
    ECS --> CloudWatch

    style AWS_Cloud fill:#232f3e,stroke:#ff9900,color:#fff
    style VPC fill:#1a1a2e,stroke:#ff9900,color:#fff
    style Public fill:#0f3460,stroke:#ff9900,color:#fff
    style Private fill:#16213e,stroke:#ff9900,color:#fff
    style ECS fill:#533483,stroke:#ff9900,color:#fff
```

### Data Model

```mermaid
erDiagram
    USERS {
        uuid id PK
        string username UK
        string email UK
        string hashed_password
        enum role "admin | auditor | viewer"
        bool is_active
        timestamp created_at
    }

    SCANS {
        uuid id PK
        string provider
        string compliance_framework
        enum status "pending | running | completed | failed"
        timestamp created_at
        timestamp completed_at
        uuid created_by FK
        int total_findings
        int critical_count
        int high_count
    }

    FINDINGS {
        uuid id PK
        uuid scan_id FK
        string rule_id
        string title
        text description
        enum severity "critical | high | medium | low | info"
        string resource_type
        string resource_id
        string region
        text remediation
        string compliance_control
        bool is_resolved
        timestamp created_at
    }

    AUDIT_LOGS {
        uuid id PK
        uuid user_id FK
        string action
        string resource_type
        string resource_id
        text details
        string ip_address
        timestamp timestamp
    }

    USERS ||--o{ SCANS : creates
    SCANS ||--o{ FINDINGS : contains
    USERS ||--o{ AUDIT_LOGS : generates
```

## Features

- **Multi-Cloud Scanning** — Audit AWS, Azure, GCP, and Kubernetes for misconfigurations
- **Compliance Frameworks** — CIS Benchmarks, NIST 800-53, SOC 2, PCI-DSS, HIPAA, ISO 27001
- **Real-Time Alerting** — Webhook, Slack, PagerDuty, and email notifications
- **Policy-as-Code** — Define custom security policies in YAML/Rego
- **REST API** — Full API with OpenAPI docs for integration into CI/CD pipelines
- **RBAC** — Role-based access control with JWT authentication
- **Audit Logging** — Immutable audit trail for all actions
- **Scheduled Scans** — Cron-based automated scanning
- **Remediation Playbooks** — Automated and guided remediation for common findings
- **Extensible Plugin System** — Write custom scanners and compliance checks

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Cloud provider credentials (AWS/Azure/GCP)

### Installation

```bash
# Clone the repository
git clone https://github.com/osamacs7/cloud-guard.git
cd cloud-guard

# Start with Docker Compose
docker compose up -d

# Or install locally
pip install -e ".[dev]"
cloud-guard init
cloud-guard scan --provider aws --profile default
```

### Configuration

```bash
cp .env.example .env
# Edit .env with your settings
```

### Run a Scan

```bash
# Scan AWS infrastructure
cloud-guard scan --provider aws --compliance cis-aws-1.5

# Scan Kubernetes cluster
cloud-guard scan --provider k8s --kubeconfig ~/.kube/config

# Generate compliance report
cloud-guard report --format pdf --framework nist-800-53
```

## API Usage

```python
import requests

# Authenticate
token = requests.post("http://localhost:8000/api/v1/auth/login", json={
    "username": "admin",
    "password": "changeme"
}).json()["access_token"]

# Trigger a scan
scan = requests.post(
    "http://localhost:8000/api/v1/scans",
    headers={"Authorization": f"Bearer {token}"},
    json={"provider": "aws", "compliance_framework": "cis-aws-1.5"}
).json()
```

## Project Structure

```
cloud-guard/
├── src/cloud_guard/
│   ├── api/              # FastAPI routes and middleware
│   ├── core/             # Core framework (config, auth, logging)
│   ├── scanners/         # Cloud provider scanners
│   ├── compliance/       # Compliance framework engines
│   ├── alerting/         # Notification integrations
│   ├── models/           # SQLAlchemy models
│   ├── policies/         # Policy-as-code definitions
│   └── remediation/      # Automated remediation playbooks
├── tests/                # Unit, integration, and e2e tests
├── policies/             # Custom policy definitions (YAML)
├── docker/               # Docker and compose files
├── helm/                 # Kubernetes Helm chart
├── terraform/            # Infrastructure as Code
├── .github/workflows/    # CI/CD pipelines
└── docs/                 # Documentation
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest --cov=cloud_guard

# Linting
ruff check src/ tests/
ruff format src/ tests/

# Type checking
mypy src/

# Security scanning
bandit -r src/
safety check
```

## Deployment

See [docs/deployment.md](docs/deployment.md) for production deployment guides including:
- Docker Compose (single node)
- Kubernetes with Helm
- Terraform for cloud infrastructure

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
