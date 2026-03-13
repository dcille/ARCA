# D-ARCA — Asset Risk & Cloud Analysis

**Cloud & SaaS Security Posture Management Platform**

D-ARCA is a comprehensive CSPM platform that combines cloud infrastructure security scanning (AWS, Azure, GCP, Kubernetes) with SaaS application security assessment (ServiceNow, Microsoft 365, Salesforce, Snowflake). It provides a unified dashboard for monitoring, analyzing, and improving the security posture of your entire technology stack.

---

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Features](#features)
- [Cloud Security Scanning](#cloud-security-scanning)
- [SaaS Security Scanning](#saas-security-scanning)
- [API Reference](#api-reference)
- [Frontend Pages](#frontend-pages)
- [Compliance Frameworks](#compliance-frameworks)
- [Configuration](#configuration)
- [Project Structure](#project-structure)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         D-ARCA Platform                         │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│    UI (3000) │  API (8080)  │   Worker     │   Worker-Beat      │
│   Next.js 14 │   FastAPI    │   Celery     │   Celery Beat      │
│   React 18   │   Gunicorn   │   (scans)    │   (scheduled)      │
│   Tailwind   │              │              │                    │
├──────────────┴──────┬───────┴──────────────┴────────────────────┤
│                     │                                           │
│   PostgreSQL 16     │            Valkey 7 (Redis)               │
│   (5432)            │            (6379)                         │
│   Data store        │            Message broker + cache         │
└─────────────────────┴───────────────────────────────────────────┘
```

| Service        | Technology                  | Port | Purpose                           |
|----------------|-----------------------------|------|-----------------------------------|
| **api**        | Python 3.12 / FastAPI       | 8080 | REST API, authentication, CRUD    |
| **ui**         | Node 20 / Next.js 14        | 3000 | Web dashboard                     |
| **worker**     | Celery 5.4                  | —    | Background scan execution         |
| **worker-beat**| Celery Beat                 | —    | Scheduled/periodic tasks          |
| **postgres**   | PostgreSQL 16 Alpine        | 5432 | Relational data store             |
| **valkey**     | Valkey 7 Alpine (Redis)     | 6379 | Task queue broker + result cache  |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose v2
- 4 GB+ available RAM

### 1. Clone and configure

```bash
git clone <repository-url> && cd ARCA
cp .env.example .env
# Edit .env — at minimum set a strong SECRET_KEY:
#   openssl rand -hex 32
```

### 2. Launch all services

```bash
docker compose up -d --build
```

### 3. Access the platform

| Component | URL                          |
|-----------|------------------------------|
| Dashboard | http://localhost:3000         |
| API Docs  | http://localhost:8080/docs    |
| Health    | http://localhost:8080/api/v1/health |

### 4. Create your first account

Open http://localhost:3000 and click **Create account**. The first user gets the `admin` role automatically.

### 5. Stop the platform

```bash
docker compose down
# To also remove volumes (data):
docker compose down -v
```

---

## Development Setup

For development with hot-reload on the backend:

```bash
# Start DB + Redis + API + Worker (with source mounts)
docker compose -f docker-compose.dev.yml up -d

# Start the frontend dev server separately
cd ui
npm install --legacy-peer-deps
npm run dev
```

The API reloads on file changes automatically. The frontend runs on http://localhost:3000 with Next.js fast refresh.

---

## Features

### Dashboard Overview
- Total cloud providers and SaaS connections at a glance
- Aggregate findings count with pass rate
- Severity breakdown (Critical / High / Medium / Low / Informational)
- Top services by finding count
- Recent scan history with status and pass/fail counts

### Cloud Provider Management
- Add/remove cloud providers (AWS, Azure, GCP, Kubernetes)
- Credential storage with encryption at rest
- Connection status tracking
- Per-provider scan configuration

### SaaS Security Hub
- Dedicated SaaS security section with three views:
  - **Overview**: Aggregate stats, per-provider breakdown, severity distribution
  - **Connections**: Add/test/scan/delete SaaS connections
  - **Findings**: Filterable table of all SaaS findings
- Credential validation on connection creation
- Connection testing before scanning
- One-click scan initiation

### Scan Management
- Cloud and SaaS scan types
- Background execution via Celery workers
- Real-time progress tracking
- Pass/fail summary per scan

### Findings Browser
- Filter by severity, status, service, region
- Paginated results (up to 500 per page)
- Remediation guidance and compliance mapping
- Statistics endpoint with aggregation

### Compliance Assessment
- 10 compliance frameworks with check mapping
- Per-framework pass rate calculation
- Visual progress rings
- Framework descriptions and metadata

---

## Cloud Security Scanning

### AWS (20 services, 50+ checks)

| Service          | Checks                                                   |
|------------------|----------------------------------------------------------|
| **IAM**          | Root MFA, password policy, user MFA, access key rotation |
| **S3**           | Public access block, encryption, versioning, logging     |
| **EC2**          | Security groups (22/3389/all), EBS encryption, IMDSv2    |
| **RDS**          | Encryption, public access, Multi-AZ, backups             |
| **CloudTrail**   | Enabled, multi-region, log validation, KMS encryption    |
| **KMS**          | Key rotation for customer-managed keys                   |
| **VPC**          | Flow logs enabled                                        |
| **Lambda**       | Runtime deprecation, VPC configuration                   |
| **ECS**          | Container Insights enabled                               |
| **GuardDuty**    | Detector enabled per region                              |
| **Config**       | Configuration recorder enabled                           |
| **SNS**          | Topic encryption (KMS)                                   |
| **SQS**          | Queue encryption (KMS/SSE)                               |
| **SecretsManager** | Secret rotation enabled                                |
| **Elasticsearch** | Encryption at rest, node-to-node encryption             |
| **CloudWatch**   | Log group encryption, retention policy                   |
| **DynamoDB**     | KMS encryption, PITR enabled                             |
| **EFS**          | Encryption at rest                                       |
| **EKS**          | API logging, public endpoint access                      |
| **ElastiCache**  | Encryption in transit, encryption at rest                |

**Required credentials**: `access_key_id`, `secret_access_key` (+ optional `session_token`)

### Azure (8 services, 20+ checks)

| Service         | Checks                                              |
|-----------------|------------------------------------------------------|
| **Identity**    | Subscription owner count                             |
| **Storage**     | HTTPS only, TLS 1.2, public blob access              |
| **Network**     | NSG open ports (22/3389), Network Watcher            |
| **Compute**     | VM disk encryption                                   |
| **Database**    | SQL auditing, TLS 1.2                                |
| **Key Vault**   | Soft delete, purge protection                        |
| **Monitor**     | Activity log profile                                 |
| **App Service** | HTTPS only, TLS 1.2                                  |

**Required credentials**: `subscription_id`, `tenant_id`, `client_id`, `client_secret`

### GCP (8 services, 15+ checks)

| Service          | Checks                                              |
|------------------|------------------------------------------------------|
| **IAM**          | No public access (allUsers/allAuthenticatedUsers)    |
| **Compute**      | External IP, OS Login                                |
| **Storage**      | Uniform bucket access, versioning                    |
| **Cloud SQL**    | Public IP, SSL required, backups                     |
| **Logging**      | Log sinks configured                                 |
| **KMS**          | Key rotation <= 90 days                              |
| **GKE**          | Private nodes, network policy                        |
| **Networking**   | Firewall rules (22/3389 open to 0.0.0.0/0)          |

**Required credentials**: `project_id`, `service_account_key` (JSON)

### Kubernetes (4 categories, 10+ checks)

| Category           | Checks                                             |
|--------------------|-----------------------------------------------------|
| **Pods**           | Privileged containers, runAsNonRoot, readOnlyRootFS, resource limits |
| **RBAC**           | cluster-admin bound to broad groups                 |
| **Network Policies** | Namespace network policies                        |
| **Namespaces**     | Workload pods in default namespace                  |

**Required credentials**: `kubeconfig` (YAML)

---

## SaaS Security Scanning

SaaS security checks are inspired by [ElectricEye](https://github.com/jonrau1/ElectricEye) patterns and adapted for the D-ARCA platform.

### ServiceNow (50+ checks across 9 areas)

| Area                        | Examples                                                     |
|-----------------------------|--------------------------------------------------------------|
| **Users**                   | MFA enforcement, account lockout, password complexity, failed logins |
| **Access Control**          | Script sandbox, CSRF tokens, strict elevation, ACL rules, REST API auth |
| **Attachments**             | MIME validation, file extension filtering, type checking      |
| **Email Security**          | HTML sanitization, trusted domains                           |
| **Input Validation**        | Script escaping, CSP, XXE prevention, formula injection protection |
| **Secure Communications**   | Certificate validation, TLS version, hostname verification   |
| **Security Inclusion Listing** | URL allowlists, X-Frame-Options, HSTS, nosniff           |
| **Session Management**      | Session timeout (<=30min), CSRF, HTTPOnly cookies, secure cookies, SameSite |
| **Security Plugins**        | Explicit Roles, File Security, High Security Settings, IP Filter |

**Required credentials:**

| Field                  | Description                                         |
|------------------------|-----------------------------------------------------|
| `instance_name`        | ServiceNow instance (e.g., `dev12345`)              |
| `username`             | Dedicated admin user (e.g., `darca_sspm`)           |
| `password`             | User password                                       |
| `instance_region`      | `us`, `eu`, or `ap`                                 |

### Microsoft 365 (37 checks across 4 areas)

| Area                        | Examples                                                     |
|-----------------------------|--------------------------------------------------------------|
| **AAD Users**               | MFA registration, phishing-resistant MFA (FIDO2), risky user detection |
| **Conditional Access**      | Legacy auth blocking, MFA requirement, compliant devices, sign-in risk |
| **Defender Recommendations** | Platform-specific security controls (up to 25 recommendations) |
| **Defender for Endpoint**   | Sensor health, machine risk score, exposure level            |

**Required credentials:**

| Field             | Description                                              |
|-------------------|----------------------------------------------------------|
| `client_id`       | Azure AD Application (Client) ID                        |
| `client_secret`   | Client Secret Value                                      |
| `tenant_id`       | Directory (Tenant) ID                                    |
| `tenant_location` | `US`, `EU`, or `AP`                                      |

**Prerequisites:** Azure AD Enterprise Application with Graph API permissions + Global Administrator consent. M365 E5 license recommended for full coverage.

### Salesforce (18 checks across 3 areas)

| Area                  | Examples                                                     |
|-----------------------|--------------------------------------------------------------|
| **Users**             | MFA enablement, inactive users (90+ days), never-logged-in users, failed login rate |
| **Threat Detection**  | Transaction Security Policies, session hijacking, credential stuffing, report/API anomalies |
| **SSO**               | SAML SSO configuration, SAML version 2.0, JIT provisioning, My Domain |

**Required credentials:**

| Field                  | Description                                         |
|------------------------|-----------------------------------------------------|
| `client_id`            | Connected App Client ID                             |
| `client_secret`        | Connected App Client Secret                         |
| `username`             | API-enabled user email                              |
| `password`             | User password                                       |
| `security_token`       | Salesforce security token (Reset My Security Token) |
| `instance_location`    | Instance code (e.g., `NA224`)                       |
| `api_version`          | API version (default: `v58.0`)                      |

### Snowflake (21 checks across 2 areas)

| Area         | Examples                                                              |
|--------------|-----------------------------------------------------------------------|
| **Users**    | MFA for password users, RSA keys for service accounts, inactive users (90+ days), admin email, default role restrictions, password rotation, admin count (2-10) |
| **Account**  | SSO/SAML config, SCIM integration, network policies, session timeouts (<=15min), password policy (min 14 chars), task/procedure ownership |

**Required credentials:**

| Field                        | Description                                     |
|------------------------------|-------------------------------------------------|
| `username`                   | Service account username                        |
| `password`                   | Account password                                |
| `account_id`                 | Snowflake account ID (e.g., `XXXX-YYYY`)        |
| `warehouse_name`             | Warehouse for queries                           |
| `region`                     | Account region                                  |
| `service_account_usernames`  | (Optional) List of service accounts to exempt   |

**Prerequisites:** Custom role (e.g., `DARCA_AUDITOR`) with `IMPORTED PRIVILEGES` on `SNOWFLAKE` database.

---

## API Reference

Base URL: `http://localhost:8080`

Interactive API documentation: http://localhost:8080/docs (Swagger UI)

### Authentication

| Method | Endpoint               | Description          |
|--------|------------------------|----------------------|
| POST   | `/api/v1/auth/register`| Create new account   |
| POST   | `/api/v1/auth/login`   | Login, get JWT token |
| GET    | `/api/v1/auth/me`      | Get current user     |

All other endpoints require `Authorization: Bearer <token>` header.

### Dashboard

| Method | Endpoint                  | Description                 |
|--------|---------------------------|-----------------------------|
| GET    | `/api/v1/dashboard/overview` | Aggregate stats & recent scans |

### Cloud Providers

| Method | Endpoint                        | Description            |
|--------|---------------------------------|------------------------|
| GET    | `/api/v1/providers/`            | List providers         |
| POST   | `/api/v1/providers/`            | Add provider           |
| GET    | `/api/v1/providers/{id}`        | Get provider details   |
| DELETE | `/api/v1/providers/{id}`        | Remove provider        |

### Scans

| Method | Endpoint                | Description         |
|--------|-------------------------|---------------------|
| GET    | `/api/v1/scans/`        | List scans          |
| POST   | `/api/v1/scans/`        | Start new scan      |
| GET    | `/api/v1/scans/{id}`    | Get scan status     |

### Cloud Findings

| Method | Endpoint                  | Description                     |
|--------|---------------------------|---------------------------------|
| GET    | `/api/v1/findings/`       | List findings (filterable)      |
| GET    | `/api/v1/findings/stats`  | Aggregated finding statistics   |

Query parameters: `severity`, `status`, `service`, `region`, `scan_id`, `limit`, `offset`

### Compliance

| Method | Endpoint                       | Description                |
|--------|--------------------------------|----------------------------|
| GET    | `/api/v1/compliance/frameworks`| List all frameworks        |
| GET    | `/api/v1/compliance/summary`   | Pass/fail summary          |

### SaaS Security

| Method | Endpoint                                      | Description              |
|--------|-----------------------------------------------|--------------------------|
| GET    | `/api/v1/saas/connections`                    | List SaaS connections    |
| POST   | `/api/v1/saas/connections`                    | Add SaaS connection      |
| GET    | `/api/v1/saas/connections/{id}`               | Get connection details   |
| DELETE | `/api/v1/saas/connections/{id}`               | Remove connection        |
| POST   | `/api/v1/saas/connections/{id}/test`          | Test connectivity        |
| GET    | `/api/v1/saas/findings`                       | List SaaS findings       |
| GET    | `/api/v1/saas/overview`                       | SaaS aggregate stats     |
| GET    | `/api/v1/saas/findings/stats`                 | SaaS finding statistics  |

---

## Frontend Pages

| Page                | Path                       | Description                                    |
|---------------------|----------------------------|------------------------------------------------|
| **Sign In**         | `/auth/sign-in`            | JWT authentication login                       |
| **Sign Up**         | `/auth/sign-up`            | Account registration                           |
| **Overview**        | `/darca/overview`          | Main dashboard with aggregate metrics          |
| **Findings**        | `/darca/findings`          | Cloud findings browser with filters            |
| **Compliance**      | `/darca/compliance`        | Compliance frameworks with progress rings      |
| **Scans**           | `/darca/scans`             | Scan management (create, monitor, history)     |
| **Cloud Providers** | `/darca/providers`         | Cloud provider management (AWS/Azure/GCP/K8s)  |
| **SaaS Security**   | `/darca/saas-security`     | SaaS hub: overview, connections, findings      |

### Color Palette

| Color         | Hex       | Usage                                  |
|---------------|-----------|----------------------------------------|
| Green         | `#86BC25` | Primary actions, pass status, branding |
| Navy          | `#012169` | Headings, sidebar, dark backgrounds    |
| Blue          | `#0076A8` | Links, accents, cloud badges           |
| Teal          | `#00A3E0` | SaaS badges, secondary accents         |
| Black         | `#000000` | Text                                   |
| Gray 100      | `#F2F2F2` | Page backgrounds                       |
| Gray 200      | `#E6E6E6` | Borders                                |

---

## Compliance Frameworks

D-ARCA maps security checks to the following compliance frameworks:

| Framework       | Full Name                                              | Coverage          |
|-----------------|--------------------------------------------------------|-------------------|
| CIS-AWS-1.5     | CIS Amazon Web Services Foundations Benchmark v1.5     | 23 checks         |
| CIS-Azure-2.0   | CIS Microsoft Azure Foundations Benchmark v2.0         | 15 checks         |
| CIS-GCP-2.0     | CIS Google Cloud Platform Foundation Benchmark v2.0    | 11 checks         |
| NIST-800-53     | NIST SP 800-53 Rev. 5                                  | All cloud checks  |
| NIST-CSF        | NIST Cybersecurity Framework                           | All SaaS checks   |
| ISO-27001       | ISO/IEC 27001:2022                                     | All SaaS checks   |
| PCI-DSS-3.2.1   | Payment Card Industry Data Security Standard v3.2.1    | 12 checks         |
| HIPAA           | HIPAA Security Rule                                    | 9 checks          |
| SOC2            | SOC 2 Type II                                          | 6 checks          |
| GDPR            | General Data Protection Regulation                     | 4 checks          |

---

## Configuration

### Environment Variables

| Variable               | Default                                             | Description                          |
|------------------------|-----------------------------------------------------|--------------------------------------|
| `SECRET_KEY`           | `change-me-...`                                     | JWT signing key (use `openssl rand -hex 32`) |
| `DATABASE_URL`         | `postgresql+asyncpg://darca:darca@postgres:5432/darca` | PostgreSQL connection string      |
| `REDIS_URL`            | `redis://valkey:6379/0`                             | Redis/Valkey URL                     |
| `CELERY_BROKER_URL`    | `redis://valkey:6379/0`                             | Celery message broker                |
| `CELERY_RESULT_BACKEND`| `redis://valkey:6379/1`                             | Celery results backend               |
| `CORS_ORIGINS`         | `["http://localhost:3000"]`                         | Allowed CORS origins (JSON array)    |
| `NEXT_PUBLIC_API_URL`  | `http://localhost:8080`                             | API URL for the frontend             |

### Security Notes

- **Credentials encryption**: Provider and SaaS credentials are base64-encoded before storage. For production, integrate with a proper KMS (e.g., AWS KMS, Azure Key Vault, HashiCorp Vault).
- **JWT tokens**: Expire after 24 hours by default (`ACCESS_TOKEN_EXPIRE_MINUTES=1440`).
- **CORS**: Restricted to configured origins. Update `CORS_ORIGINS` for your deployment domain.
- **Password hashing**: bcrypt via passlib.

---

## Project Structure

```
ARCA/
├── api/                              # Backend (Python / FastAPI)
│   ├── main.py                       # FastAPI application entry point
│   ├── config.py                     # Settings (env vars)
│   ├── database.py                   # SQLAlchemy async engine setup
│   ├── celery_app.py                 # Celery configuration
│   ├── requirements.txt              # Python dependencies
│   ├── models/                       # SQLAlchemy ORM models
│   │   ├── user.py                   # User model (auth)
│   │   ├── provider.py               # Cloud provider model
│   │   ├── scan.py                   # Scan model (cloud + SaaS)
│   │   ├── finding.py                # Cloud finding model
│   │   ├── saas_connection.py        # SaaS connection model
│   │   └── saas_finding.py           # SaaS finding model
│   ├── schemas/                      # Pydantic request/response schemas
│   │   ├── auth.py                   # Auth DTOs
│   │   ├── provider.py               # Provider DTOs
│   │   ├── scan.py                   # Scan DTOs
│   │   ├── finding.py                # Finding DTOs
│   │   ├── saas.py                   # SaaS DTOs + credential validators
│   │   └── dashboard.py              # Dashboard DTOs
│   ├── routers/                      # API route handlers
│   │   ├── auth.py                   # POST /register, /login, GET /me
│   │   ├── providers.py              # CRUD cloud providers
│   │   ├── scans.py                  # Create/list/get scans
│   │   ├── findings.py               # List/filter/stats findings
│   │   ├── compliance.py             # Frameworks & summary
│   │   ├── saas.py                   # SaaS connections, findings, overview
│   │   └── dashboard.py              # Aggregate overview
│   ├── services/                     # Business logic
│   │   └── auth_service.py           # JWT, password hashing, encryption
│   └── tasks/                        # Celery background tasks
│       ├── scan_tasks.py             # Cloud scan execution
│       └── saas_tasks.py             # SaaS scan execution
│
├── scanner/                          # Security scanning engine
│   ├── providers/                    # Cloud provider scanners
│   │   ├── cloud_scanner.py          # Scanner dispatcher
│   │   ├── base_check.py             # CheckResult dataclass
│   │   ├── aws/
│   │   │   └── aws_scanner.py        # AWS checks (20 services)
│   │   ├── azure/
│   │   │   └── azure_scanner.py      # Azure checks (8 services)
│   │   ├── gcp/
│   │   │   └── gcp_scanner.py        # GCP checks (8 services)
│   │   └── kubernetes/
│   │       └── k8s_scanner.py        # K8s checks (4 categories)
│   ├── saas/                         # SaaS application scanners
│   │   ├── saas_scanner.py           # SaaS scanner factory
│   │   ├── base_saas_check.py        # SaaSCheckResult dataclass
│   │   ├── connection_tester.py      # Connection test functions
│   │   ├── servicenow/
│   │   │   └── servicenow_scanner.py # ServiceNow checks (50+)
│   │   ├── m365/
│   │   │   └── m365_scanner.py       # Microsoft 365 checks (37)
│   │   ├── salesforce/
│   │   │   └── salesforce_scanner.py # Salesforce checks (18)
│   │   └── snowflake/
│   │       └── snowflake_scanner.py  # Snowflake checks (21)
│   └── compliance/
│       └── frameworks.py             # Framework definitions & mappings
│
├── ui/                               # Frontend (Next.js / React / Tailwind)
│   ├── app/
│   │   ├── layout.tsx                # Root layout
│   │   ├── page.tsx                  # Root redirect
│   │   ├── globals.css               # Tailwind + custom styles
│   │   ├── auth/
│   │   │   ├── sign-in/page.tsx      # Login page
│   │   │   └── sign-up/page.tsx      # Registration page
│   │   └── darca/
│   │       ├── layout.tsx            # Authenticated layout + sidebar
│   │       ├── overview/page.tsx     # Main dashboard
│   │       ├── findings/page.tsx     # Cloud findings browser
│   │       ├── compliance/page.tsx   # Compliance frameworks
│   │       ├── scans/page.tsx        # Scan management
│   │       ├── providers/page.tsx    # Cloud provider management
│   │       └── saas-security/page.tsx# SaaS security hub
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx           # Navigation sidebar
│   │   │   └── Header.tsx            # Page header
│   │   └── ui/
│   │       ├── StatCard.tsx          # Metric stat card
│   │       ├── Badge.tsx             # Severity/status badge
│   │       └── DataTable.tsx         # Reusable data table
│   ├── lib/
│   │   ├── api.ts                    # API client (fetch wrapper)
│   │   └── utils.ts                  # Utility functions
│   ├── store/
│   │   └── auth.ts                   # Zustand auth store (persisted)
│   ├── public/
│   │   └── logo.svg                  # D-ARCA logo
│   ├── package.json                  # Node.js dependencies
│   ├── next.config.js                # Next.js configuration
│   ├── tailwind.config.ts            # Tailwind CSS (corporate colors)
│   ├── tsconfig.json                 # TypeScript config
│   └── postcss.config.js             # PostCSS config
│
├── docker-compose.yml                # Production deployment (6 services)
├── docker-compose.dev.yml            # Development (hot-reload)
├── Dockerfile.api                    # API container image
├── Dockerfile.worker                 # Worker container image
├── Dockerfile.ui                     # UI container image (multi-stage)
├── .env.example                      # Environment template
├── .gitignore                        # Git ignore rules
└── .dockerignore                     # Docker build ignore rules
```

---

## Troubleshooting

### Docker build fails on `pip install`
Ensure you have network access. The API image installs ~40 Python packages including AWS, Azure, GCP, and Snowflake SDKs. On slower connections, increase the Docker build timeout or build with `--progress=plain` for detailed logs.

### UI build fails on "public not found"
The `ui/public/` directory must exist. Run `mkdir -p ui/public` if missing.

### Database connection errors on startup
PostgreSQL may take a few seconds to initialize. The API container has a health check dependency on Postgres, so it will wait automatically. If issues persist, check `docker compose logs postgres`.

### Scans stuck in "pending"
Ensure the `worker` container is running: `docker compose logs worker`. The worker processes scans asynchronously via Celery.

---

## License

See [LICENSE](LICENSE) for details.
