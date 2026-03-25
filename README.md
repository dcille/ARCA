# D-ARCA — Asset Risk & Cloud Analysis

**Cloud & SaaS Security Posture Management Platform**

D-ARCA is a comprehensive CSPM platform that combines cloud infrastructure security scanning (AWS, Azure, GCP, OCI, Alibaba Cloud, Kubernetes) with SaaS application security assessment (ServiceNow, Microsoft 365, Salesforce, Snowflake, GitHub, Google Workspace, Cloudflare, OpenStack). It provides a unified dashboard for monitoring, analyzing, and improving the security posture of your entire technology stack — including compliance mapping, MITRE ATT&CK analysis, attack path analysis, data security posture management (DSPM), ransomware readiness assessment, interactive security graph, automated scheduling, audit logging, and executive reporting with embedded charts.

---

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Features](#features)
- [Cloud Security Scanning](#cloud-security-scanning)
  - [AWS](#aws-20-services-50-checks)
  - [Azure](#azure-8-services-20-checks)
  - [GCP](#gcp-8-services-15-checks)
  - [Kubernetes](#kubernetes-4-categories-10-checks)
  - [OCI](#oci--oracle-cloud-infrastructure-18-services-60-checks)
  - [Alibaba Cloud](#alibaba-cloud-12-services-70-checks)
- [SaaS Security Scanning](#saas-security-scanning)
- [Advanced Security Modules](#advanced-security-modules)
  - [Attack Path Analysis](#attack-path-analysis)
  - [Security Graph](#security-graph)
  - [Data Security Posture Management (DSPM)](#data-security-posture-management-dspm)
  - [Ransomware Readiness](#ransomware-readiness)
  - [MITRE ATT&CK Analysis](#mitre-attck-analysis)
  - [Drift Detection](#drift-detection)
- [Operations & Management](#operations--management)
  - [Scan Scheduling](#scan-scheduling)
  - [Notifications](#notifications)
  - [Audit Log](#audit-log)
  - [API Key Management](#api-key-management)
  - [Integrations](#integrations)
  - [Reports & Data Export](#reports--data-export)
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
- Add/remove cloud providers (AWS, Azure, GCP, OCI, Alibaba Cloud, Kubernetes)
- Credential storage with encryption at rest
- Connection status tracking
- Per-provider scan configuration

### SaaS Security Hub
- Dedicated SaaS security section with three views:
  - **Overview**: Aggregate stats, per-provider breakdown, severity distribution
  - **Connections**: Add/test/scan/delete SaaS connections
  - **Findings**: Filterable table of all SaaS findings
- 8 SaaS platforms: ServiceNow, Microsoft 365, Salesforce, Snowflake, GitHub, Google Workspace, Cloudflare, OpenStack
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
- 15+ compliance frameworks with control-level hierarchy (CIS, NIST, PCI-DSS, HIPAA, SOC2, GDPR, ISO-27001)
- Per-framework pass rate calculation (per-unique-check, not per-resource)
- Visual progress rings and Check Library with control descriptions
- Framework descriptions, metadata, and per-cloud check mappings

### MITRE ATT&CK Analysis
- Interactive MITRE ATT&CK matrix visualization
- Technique coverage mapping from scan findings
- Run Analysis workflow with phased loading animation
- Tactic/technique breakdown with protection status

### Ransomware Readiness
- 105 ransomware readiness rules across 7 domains
- Scoring engine with weighted domain assessments
- Protection, Detection, Recovery, and Governance categories
- Executive-level readiness dashboard

### Reports & Data Export
- Executive and technical PDF report generation with **embedded charts** (severity donut, top services bar)
- Chart service: matplotlib-based generation (donut, horizontal bar, radar, line, stacked bar charts)
- MITRE ATT&CK and compliance sections in reports
- Attack path analysis and ransomware readiness reporting
- Severity breakdown, top findings, and remediation guidance
- Downloadable PDF reports with filters (provider, account, severity, service)
- **Data export**: CSV and JSON export of findings for SIEM integration

### Inventory
- Cloud resource inventory with friendly service labels
- Per-provider resource aggregation
- Account summary with resource type breakdown
- Resource-level findings drill-down

### Attack Path Analysis
- Automated discovery of multi-step attack chains across resources
- Graph-based path finding with risk scoring and prioritization
- Choke point identification for optimal remediation
- Run comparison to track security posture changes over time
- Severity classification (critical, high, medium, low)
- Entry point and target identification with technique mapping

### Security Graph
- Interactive resource relationship visualization
- Relationship inference across cloud services
- Blast radius analysis from any compromised resource
- Path finding between any two resources
- Node search and filtering by type/service
- Findings panel per resource node
- Edge visualization with relationship types

### Data Security Posture Management (DSPM)
- **Data Store Discovery**: Inventory of all data stores across cloud providers
- **PII Scanner**: Detection of personally identifiable information in data stores
- **Permission Analyzer**: IAM/RBAC permission analysis for data access
- **Shadow Data Detection**: Discovery of unmanaged/unknown data stores
- **Content Sampling**: Data content analysis for classification
- **Data Classifier**: Automated sensitivity classification
- **Native Integrations**: Cloud-native data platform connectors

### Scan Scheduling
- Automated recurring scans with configurable frequency (daily, weekly, monthly)
- Per-provider and per-service scope control
- Pause/resume schedule management
- Next run and last run tracking
- Full CRUD UI for schedule management

### Notifications
- Real-time notification center for scan completions, critical findings, and system events
- Read/unread filtering with badge indicators in sidebar
- Mark individual or all notifications as read
- Severity-tagged notifications with contextual links
- Notification count polling in sidebar

### Audit Log
- Complete activity tracking for all platform actions
- Filterable by action type (create, update, delete, login, scan, export)
- Filterable by resource type (provider, scan, schedule, integration, report)
- Configurable time period (7-90 days)
- Aggregate statistics by action and resource type
- IP address tracking per event

### API Key Management
- Programmatic API access via secure API keys
- Key generation with `darca_` prefix and SHA-256 hashing
- One-time key display at creation (never stored in plain text)
- Key listing with prefix visibility and usage tracking
- Key revocation with immediate effect
- Settings tab integration with clipboard copy

### Integrations
- Third-party webhook and notification integrations
- Slack, Microsoft Teams, Jira, and custom webhook support
- Connection testing and validation
- Event-driven notifications on scan completion and critical findings

### Organizations & Multi-Tenancy
- Organization creation and management
- Team member invitation by email
- Role-based access: Owner, Admin, Member, Viewer
- Member role management and removal

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

### OCI — Oracle Cloud Infrastructure (18 services, 60+ checks)

| Service               | Checks                                                    |
|-----------------------|-----------------------------------------------------------|
| **IAM**               | MFA, password policy (length/expiry/reuse), API key rotation, admin controls, unused credentials |
| **Networking**        | Security lists (SSH/RDP), NSG unrestricted ingress, default SL restrict, VCN flow logs |
| **Compute**           | IMDSv2, Secure Boot, in-transit encryption                |
| **Object Storage**    | Public access, CMK encryption, versioning, event emission |
| **Block/Boot Volume** | CMK encryption for block and boot volumes                 |
| **File Storage**      | CMK encryption, export privileged ports, mount target NSG |
| **Database**          | Autonomous DB private endpoint, autoscaling, CMK; DB System backups |
| **MySQL**             | Backups, crash recovery, deletion protection, HA, PITR   |
| **Vault**             | Key rotation, private vault type                          |
| **Cloud Guard**       | Enabled in root compartment                               |
| **Events**            | Event rules configured (IdP, IAM, VCN, route, SL, NSG, gateway changes) |
| **Notifications**     | Topics and security subscriptions configured              |
| **Logging**           | Log groups, audit retention                               |
| **Load Balancer**     | HTTPS listeners, NSG assigned, backend health             |
| **OKE (Kubernetes)**  | Public endpoint, NSG, image verification, K8s version     |
| **Container Registry**| Public repos, immutable artifacts                         |
| **Container Instances**| Restart policy, graceful shutdown                        |
| **Functions**         | NSG assigned, tracing enabled, provisioned concurrency    |

**Required credentials**: `user_ocid`, `tenancy_ocid`, `fingerprint`, `key_content` (PEM), `region`

### Alibaba Cloud (12 services, 70+ checks)

| Service               | Checks                                                    |
|-----------------------|-----------------------------------------------------------|
| **RAM**               | MFA, password policy (uppercase/lowercase/symbol/number/length/reuse/expiry/lockout), access key rotation, unused users, wildcard policies, groups-only attachments |
| **ECS**               | Public IP, VPC network, deletion protection, disk encryption, security groups (all/SSH/RDP) |
| **RDS**               | Public access, whitelist, TDE encryption, SSL, backup retention, SQL audit, PostgreSQL log parameters |
| **OSS**               | Public access, encryption, logging, versioning, HTTPS-only, lifecycle rules |
| **VPC**               | Flow logs, NACL association                               |
| **KMS**               | Key rotation, CMK enabled state                           |
| **ActionTrail**       | Enabled, multi-region, active logging, OSS bucket public access |
| **SLB**               | HTTPS listeners, access logs                              |
| **WAF**               | Instance active, protected domains                        |
| **Security Center**   | Enabled, advanced edition, agents installed, notifications, vulnerability scanning |
| **ACK (Kubernetes)**  | Log service, cloud monitor, RBAC, basic auth, network policy, private cluster |
| **SLS (Log Service)** | 13 monitoring alert categories (CIS 2.10-2.22), log retention |

**Required credentials**: `access_key_id`, `access_key_secret`

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

### GitHub (~30 checks)

| Area          | Examples                                                            |
|---------------|---------------------------------------------------------------------|
| **Repos**     | Branch protection, signed commits, vulnerability alerts, secret scanning |
| **Org**       | 2FA enforcement, member privileges, base permissions               |
| **Actions**   | Workflow permissions, allowed actions, fork PR approvals            |

**Required credentials:** `personal_access_token` with `admin:org` + `repo` scopes.

### Google Workspace (~30 checks)

| Area                | Examples                                                     |
|---------------------|--------------------------------------------------------------|
| **Admin**           | 2-Step Verification enforcement, session controls, admin roles |
| **Gmail**           | SPF, DKIM, DMARC, attachment security, phishing protection   |
| **Drive**           | External sharing, link sharing defaults, DLP rules           |

**Required credentials:** `service_account_key` (JSON) with domain-wide delegation + `admin_email`.

### Cloudflare (~25 checks)

| Area                | Examples                                                     |
|---------------------|--------------------------------------------------------------|
| **DNS**             | DNSSEC, exposed records, CAA records                         |
| **SSL/TLS**         | TLS version, HSTS, Always Use HTTPS, certificate validity   |
| **Firewall**        | WAF rules, rate limiting, bot management, IP access rules    |

**Required credentials:** `api_token` with Zone Read + Firewall Read permissions.

### OpenStack (~30 checks)

| Area                | Examples                                                     |
|---------------------|--------------------------------------------------------------|
| **Identity (Keystone)** | Password policy, token expiry, MFA, service accounts     |
| **Compute (Nova)**  | Security groups, metadata service, encrypted volumes         |
| **Network (Neutron)** | Security group rules, floating IPs, port security          |
| **Storage (Swift)** | Container ACLs, encryption, versioning                       |

**Required credentials:** `auth_url`, `username`, `password`, `project_name`, `user_domain_name`.

---

## Advanced Security Modules

### Attack Path Analysis

D-ARCA discovers multi-step attack paths that chain together individual misconfigurations into exploitable routes through your infrastructure.

| Component           | Description                                                    |
|---------------------|----------------------------------------------------------------|
| **Graph Engine**    | Builds a resource dependency graph and discovers attack chains (2,523 lines) |
| **Path Scoring**    | Risk scoring based on severity, blast radius, and exploitability (174 lines) |
| **Choke Points**    | Identifies optimal remediation points to break multiple paths  |
| **Run Comparison**  | Compare analysis runs to track posture improvement over time   |

### Security Graph

Interactive visualization of cloud resource relationships and security posture.

| Feature              | Description                                                   |
|----------------------|---------------------------------------------------------------|
| **Resource Nodes**   | Visual representation of all cloud resources with health status |
| **Relationship Edges** | Inferred connections (IAM roles, network, storage, compute) |
| **Blast Radius**     | Impact analysis from any compromised resource                 |
| **Path Finding**     | Discover all paths between any two resources                  |
| **Search**           | Full-text search across resource nodes                        |
| **Findings Panel**   | Per-resource security findings overlay                        |

### Data Security Posture Management (DSPM)

Complete data security lifecycle management across cloud providers (~7,800 lines).

| Module                  | Lines | Description                                           |
|-------------------------|-------|-------------------------------------------------------|
| **Router/Orchestrator** | 976   | Orchestration and routing of DSPM workflows           |
| **Permission Analyzer** | 1,065 | IAM/RBAC permission analysis for data access          |
| **Data Store Checks**   | 452   | Security validation of data stores                    |
| **PII Scanner**         | 710   | Personally identifiable information detection         |
| **Shadow Detector**     | 987   | Discovery of unmanaged/unknown data stores            |
| **Content Sampler**     | 680   | Data content sampling for classification              |
| **Data Classifier**     | 465   | Automated sensitivity and compliance classification   |
| **Native Integrations** | 703   | Cloud-native data platform connectors                 |

### Ransomware Readiness

Comprehensive ransomware preparedness assessment with 105 rules across 7 domains.

| Domain             | Weight | Focus Areas                                                |
|--------------------|--------|------------------------------------------------------------|
| **Protection**     | High   | Encryption, access controls, network segmentation          |
| **Detection**      | High   | Monitoring, alerting, anomaly detection                    |
| **Recovery**       | High   | Backup strategy, RTO/RPO, disaster recovery                |
| **Governance**     | Medium | Policies, procedures, training, executive ownership        |
| **Identity**       | High   | MFA, privileged access, credential hygiene                 |
| **Data**           | Medium | Classification, encryption, DLP                           |
| **Infrastructure** | Medium | Patching, hardening, segmentation                          |

Features: Knowledge base side panel, domain drill-down, account-level assessment, score history, governance controls, executive PDF reports.

### MITRE ATT&CK Analysis

Maps all security findings to the MITRE ATT&CK framework for threat-centric visibility.

| Feature                 | Description                                              |
|-------------------------|----------------------------------------------------------|
| **Matrix Visualization** | Interactive tactic/technique heatmap                    |
| **Coverage Gaps**       | Identifies unassessed and at-risk techniques             |
| **Technique Detail**    | Per-technique evidence with mapped checks                |
| **Navigator Layer**     | Export to MITRE ATT&CK Navigator format                  |
| **Attack Path Coverage** | Cross-reference with discovered attack paths            |

### Drift Detection

Point-in-time configuration drift detection and change tracking (697 lines).

| Feature               | Description                                               |
|-----------------------|-----------------------------------------------------------|
| **State Snapshots**   | Capture resource configuration at scan time               |
| **Change Detection**  | Identify configuration changes between snapshots          |
| **Drift Scoring**     | Classify drift severity based on security impact          |
| **Remediation**       | Recommendations to restore compliant state                |

### Check Library

Centralized registry of all security checks across all providers (701 lines).

| Feature               | Description                                               |
|-----------------------|-----------------------------------------------------------|
| **Check Registry**    | Central catalog of all security checks                    |
| **Search & Filter**   | Find checks by provider, service, severity, framework     |
| **Compliance Mapping** | Per-check compliance framework associations              |
| **Remediation Guidance** | Step-by-step remediation for each check                |

---

## Operations & Management

### Scan Scheduling

Automated recurring scans via the Schedules management page.

| Feature             | Description                                                 |
|---------------------|-------------------------------------------------------------|
| **Frequency**       | Daily, weekly, or monthly schedules                         |
| **Scope Control**   | Filter by provider, services, and regions                   |
| **Pause/Resume**    | Toggle schedules without deleting them                      |
| **Next/Last Run**   | Track execution history and upcoming runs                   |

**API Endpoints:**

| Method | Endpoint                    | Description          |
|--------|---------------------------  |----------------------|
| GET    | `/api/v1/schedules`         | List all schedules   |
| POST   | `/api/v1/schedules`         | Create schedule      |
| PUT    | `/api/v1/schedules/{id}`    | Update schedule      |
| DELETE | `/api/v1/schedules/{id}`    | Delete schedule      |

### Notifications

Real-time notification center for platform events.

| Feature               | Description                                             |
|-----------------------|---------------------------------------------------------|
| **Event Types**       | Scan complete, critical finding, schedule, system       |
| **Severity Tags**     | Critical, high, medium, low, info                       |
| **Read/Unread**       | Filter and manage notification state                    |
| **Sidebar Badge**     | Live unread count with polling (30s interval)           |

**API Endpoints:**

| Method | Endpoint                          | Description              |
|--------|-----------------------------------|--------------------------|
| GET    | `/api/v1/notifications`           | List notifications       |
| GET    | `/api/v1/notifications/count`     | Get unread count         |
| PUT    | `/api/v1/notifications/{id}/read` | Mark as read             |
| PUT    | `/api/v1/notifications/read-all`  | Mark all as read         |

### Audit Log

Complete platform activity tracking for compliance and forensics.

| Feature                | Description                                            |
|------------------------|--------------------------------------------------------|
| **Action Tracking**    | Create, update, delete, login, scan, export, download  |
| **Resource Types**     | Provider, scan, schedule, integration, finding, report |
| **Time Filtering**     | Configurable lookback period (7-90 days)               |
| **Statistics**         | Aggregate counts by action and resource type            |
| **IP Tracking**        | Source IP address recorded per event                    |

**API Endpoints:**

| Method | Endpoint                  | Description              |
|--------|---------------------------|--------------------------|
| GET    | `/api/v1/audit-log`       | List audit log entries   |
| GET    | `/api/v1/audit-log/stats` | Aggregate statistics     |

### API Key Management

Programmatic API access via secure, revocable API keys.

| Feature              | Description                                              |
|----------------------|----------------------------------------------------------|
| **Key Format**       | `darca_` prefix + 48 hex characters                      |
| **Security**         | SHA-256 hashed storage; plain text shown only at creation |
| **Management**       | Create, list (prefix only), revoke via Settings page     |
| **Usage Tracking**   | Last used timestamp per key                              |

**API Endpoints:**

| Method | Endpoint                     | Description          |
|--------|------------------------------|----------------------|
| GET    | `/api/v1/auth/api-keys`      | List API keys        |
| POST   | `/api/v1/auth/api-keys`      | Create new key       |
| DELETE | `/api/v1/auth/api-keys/{id}` | Revoke key           |

### Integrations

Third-party service integrations for notifications and workflow automation.

| Integration    | Description                                              |
|----------------|----------------------------------------------------------|
| **Slack**      | Channel notifications on scan completion and findings    |
| **Teams**      | Microsoft Teams webhook integration                      |
| **Jira**       | Automatic ticket creation for critical findings          |
| **Webhooks**   | Custom HTTP webhook for any event type                   |

### Reports & Data Export

| Feature               | Description                                             |
|-----------------------|---------------------------------------------------------|
| **Executive PDF**     | High-level summary with charts, metrics, recommendations |
| **Technical PDF**     | Detailed findings with remediation, compliance, MITRE   |
| **Chart Embedding**   | Severity donut chart + top services bar chart in PDFs   |
| **CSV Export**        | Tabular findings export for spreadsheets                |
| **JSON Export**       | Structured findings export for SIEM/API integration     |
| **Ransomware Report** | Dedicated ransomware readiness executive report         |

---

## API Reference

Base URL: `http://localhost:8080`

Interactive API documentation: http://localhost:8080/docs (Swagger UI)

### Authentication & API Keys

| Method | Endpoint                      | Description              |
|--------|-------------------------------|--------------------------|
| POST   | `/api/v1/auth/register`       | Create new account       |
| POST   | `/api/v1/auth/login`          | Login, get JWT token     |
| GET    | `/api/v1/auth/me`             | Get current user         |
| GET    | `/api/v1/auth/api-keys`       | List API keys            |
| POST   | `/api/v1/auth/api-keys`       | Create new API key       |
| DELETE | `/api/v1/auth/api-keys/{id}`  | Revoke API key           |

All other endpoints require `Authorization: Bearer <token>` header.

### Dashboard

| Method | Endpoint                             | Description                        |
|--------|--------------------------------------|------------------------------------|
| GET    | `/api/v1/dashboard/overview`         | Aggregate stats & recent scans     |
| GET    | `/api/v1/dashboard/trends`           | Historical trend data              |
| GET    | `/api/v1/dashboard/account/{id}`     | Per-provider dashboard metrics     |

### Cloud Providers

| Method | Endpoint                                    | Description             |
|--------|---------------------------------------------|-------------------------|
| GET    | `/api/v1/providers`                         | List providers          |
| POST   | `/api/v1/providers`                         | Add provider            |
| PUT    | `/api/v1/providers/{id}`                    | Update provider         |
| DELETE | `/api/v1/providers/{id}`                    | Remove provider         |
| POST   | `/api/v1/providers/{id}/discover-accounts`  | Discover sub-accounts   |
| GET    | `/api/v1/providers/{id}/accounts`           | List child accounts     |

### Scans

| Method | Endpoint                | Description         |
|--------|-------------------------|---------------------|
| GET    | `/api/v1/scans`         | List scans          |
| POST   | `/api/v1/scans`         | Start new scan      |
| GET    | `/api/v1/scans/{id}`    | Get scan status     |

### Cloud Findings

| Method | Endpoint                              | Description                    |
|--------|---------------------------------------|--------------------------------|
| GET    | `/api/v1/findings`                    | List findings (filterable)     |
| GET    | `/api/v1/findings/stats`              | Aggregated finding statistics  |
| POST   | `/api/v1/findings/{id}/exception`     | Create finding exception       |
| POST   | `/api/v1/findings/{id}/remediate`     | Mark finding as remediated     |
| GET    | `/api/v1/findings/{id}/actions`       | Get finding action history     |

Query parameters: `severity`, `status`, `service`, `region`, `scan_id`, `limit`, `offset`

### Compliance

| Method | Endpoint                                         | Description                    |
|--------|--------------------------------------------------|--------------------------------|
| GET    | `/api/v1/compliance/frameworks`                  | List all frameworks            |
| GET    | `/api/v1/compliance/summary`                     | Pass/fail summary              |
| GET    | `/api/v1/compliance/accounts`                    | List compliant accounts        |
| GET    | `/api/v1/compliance/frameworks/{id}/checks`      | Framework checks detail        |
| GET    | `/api/v1/compliance/frameworks/{id}/stats`       | Framework statistics           |
| GET    | `/api/v1/compliance/frameworks/{id}/library`     | Framework control library      |
| GET    | `/api/v1/compliance/frameworks/{id}/controls`    | Control-level drill-down       |

### SaaS Security

| Method | Endpoint                                      | Description              |
|--------|-----------------------------------------------|--------------------------|
| GET    | `/api/v1/saas/connections`                    | List SaaS connections    |
| POST   | `/api/v1/saas/connections`                    | Add SaaS connection      |
| DELETE | `/api/v1/saas/connections/{id}`               | Remove connection        |
| POST   | `/api/v1/saas/connections/{id}/test`          | Test connectivity        |
| GET    | `/api/v1/saas/findings`                       | List SaaS findings       |
| GET    | `/api/v1/saas/overview`                       | SaaS aggregate stats     |
| GET    | `/api/v1/saas/findings/stats`                 | SaaS finding statistics  |

### Attack Paths

| Method | Endpoint                               | Description                    |
|--------|----------------------------------------|--------------------------------|
| POST   | `/api/v1/attack-paths/analyze`         | Run attack path analysis       |
| GET    | `/api/v1/attack-paths`                 | List discovered attack paths   |
| GET    | `/api/v1/attack-paths/summary`         | Aggregate path statistics      |
| GET    | `/api/v1/attack-paths/{id}`            | Get path details               |
| GET    | `/api/v1/attack-paths/runs`            | List analysis runs             |
| GET    | `/api/v1/attack-paths/choke-points`    | Get remediation choke points   |
| GET    | `/api/v1/attack-paths/compare`         | Compare two analysis runs      |

### Security Graph

| Method | Endpoint                                        | Description                  |
|--------|-------------------------------------------------|------------------------------|
| GET    | `/api/v1/security-graph/graph`                  | Get resource graph           |
| GET    | `/api/v1/security-graph/stats`                  | Graph statistics             |
| GET    | `/api/v1/security-graph/nodes/{id}`             | Node detail + findings       |
| GET    | `/api/v1/security-graph/blast-radius/{id}`      | Blast radius analysis        |
| GET    | `/api/v1/security-graph/paths`                  | Path finding (source/target) |
| GET    | `/api/v1/security-graph/search`                 | Search nodes by query        |

### MITRE ATT&CK

| Method | Endpoint                                 | Description                       |
|--------|------------------------------------------|-----------------------------------|
| GET    | `/api/v1/mitre/matrix`                   | MITRE ATT&CK matrix with coverage |
| GET    | `/api/v1/mitre/technique/{id}`           | Technique detail with evidence    |
| GET    | `/api/v1/mitre/technique/{id}/checks`    | Checks mapped to technique        |
| GET    | `/api/v1/mitre/coverage-gaps`            | Identify coverage gaps            |
| GET    | `/api/v1/mitre/navigator-layer`          | Export Navigator layer JSON       |
| GET    | `/api/v1/mitre/attack-paths`             | Attack path technique coverage    |

### DSPM

| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| GET    | `/api/v1/dspm/overview`      | DSPM posture overview          |
| GET    | `/api/v1/dspm/checks`        | Data security checks           |
| GET    | `/api/v1/dspm/data-stores`   | Discovered data stores         |

### Reports & Export

| Method | Endpoint                               | Description                         |
|--------|----------------------------------------|-------------------------------------|
| GET    | `/api/v1/reports/executive`            | Download executive PDF report       |
| GET    | `/api/v1/reports/technical`            | Download technical PDF report       |
| GET    | `/api/v1/reports/export/findings`      | Export findings as CSV or JSON      |
| GET    | `/api/v1/reports/ransomware-readiness` | Ransomware readiness PDF report     |

### Inventory

| Method | Endpoint                                | Description                          |
|--------|-----------------------------------------|--------------------------------------|
| GET    | `/api/v1/inventory/resources`           | List cloud resources                 |
| GET    | `/api/v1/inventory/summary`             | Resource summary by service          |
| GET    | `/api/v1/inventory/summary/by-account`  | Summary grouped by account           |
| GET    | `/api/v1/inventory/resources/findings`  | Findings for a specific resource     |

### Ransomware Readiness

| Method | Endpoint                                         | Description                    |
|--------|--------------------------------------------------|--------------------------------|
| GET    | `/api/v1/ransomware-readiness/score`             | Get readiness score            |
| GET    | `/api/v1/ransomware-readiness/score/history`     | Score history over time        |
| GET    | `/api/v1/ransomware-readiness/domains`           | Domain breakdown               |
| GET    | `/api/v1/ransomware-readiness/domains/{id}/rules`| Rules per domain               |
| GET    | `/api/v1/ransomware-readiness/findings`          | Ransomware findings            |
| GET    | `/api/v1/ransomware-readiness/accounts`          | Per-account assessment         |
| GET    | `/api/v1/ransomware-readiness/rules`             | All ransomware rules           |
| GET    | `/api/v1/ransomware-readiness/governance`        | Governance controls            |
| PUT    | `/api/v1/ransomware-readiness/governance`        | Update governance settings     |
| POST   | `/api/v1/ransomware-readiness/evaluate`          | Trigger new evaluation         |

### Schedules

| Method | Endpoint                    | Description          |
|--------|-----------------------------|----------------------|
| GET    | `/api/v1/schedules`         | List all schedules   |
| POST   | `/api/v1/schedules`         | Create schedule      |
| PUT    | `/api/v1/schedules/{id}`    | Update schedule      |
| DELETE | `/api/v1/schedules/{id}`    | Delete schedule      |

### Notifications

| Method | Endpoint                          | Description          |
|--------|-----------------------------------|----------------------|
| GET    | `/api/v1/notifications`           | List notifications   |
| GET    | `/api/v1/notifications/count`     | Unread count         |
| PUT    | `/api/v1/notifications/{id}/read` | Mark as read         |
| PUT    | `/api/v1/notifications/read-all`  | Mark all as read     |

### Integrations

| Method | Endpoint                            | Description            |
|--------|-------------------------------------|------------------------|
| GET    | `/api/v1/integrations`              | List integrations      |
| POST   | `/api/v1/integrations`              | Create integration     |
| PUT    | `/api/v1/integrations/{id}`         | Update integration     |
| DELETE | `/api/v1/integrations/{id}`         | Delete integration     |
| POST   | `/api/v1/integrations/{id}/test`    | Test integration       |

### Organizations

| Method | Endpoint                                         | Description          |
|--------|--------------------------------------------------|----------------------|
| POST   | `/api/v1/organizations`                          | Create organization  |
| GET    | `/api/v1/organizations/current`                  | Get current org      |
| PUT    | `/api/v1/organizations/current`                  | Update org           |
| GET    | `/api/v1/organizations/current/members`          | List members         |
| POST   | `/api/v1/organizations/current/members/invite`   | Invite member        |
| PUT    | `/api/v1/organizations/current/members/{id}/role`| Update member role   |
| DELETE | `/api/v1/organizations/current/members/{id}`     | Remove member        |

### Audit Log

| Method | Endpoint                  | Description              |
|--------|---------------------------|--------------------------|
| GET    | `/api/v1/audit-log`       | List audit log entries   |
| GET    | `/api/v1/audit-log/stats` | Audit log statistics     |

---

## Frontend Pages

| Page                    | Path                               | Description                                              |
|-------------------------|-------------------------------------|----------------------------------------------------------|
| **Sign In**             | `/auth/sign-in`                     | JWT authentication login                                 |
| **Sign Up**             | `/auth/sign-up`                     | Account registration                                     |
| **Overview**            | `/darca/overview`                   | Main dashboard with aggregate metrics                    |
| **Attack Paths**        | `/darca/attack-paths`               | Attack path visualization and analysis                   |
| **Findings**            | `/darca/findings`                   | Cloud findings browser with filters and actions          |
| **Compliance**          | `/darca/compliance`                 | Compliance frameworks with control-level library         |
| **MITRE ATT&CK**       | `/darca/mitre-attack`               | MITRE ATT&CK matrix and technique analysis               |
| **Ransomware Readiness**| `/darca/ransomware-readiness`       | Readiness dashboard with domains, findings, governance   |
| **Security Graph**      | `/darca/security-graph`             | Interactive resource relationship graph                  |
| **Inventory**           | `/darca/inventory`                  | Cloud resource inventory and account summary             |
| **Cloud Providers**     | `/darca/providers`                  | Provider management (AWS/Azure/GCP/OCI/Alibaba/K8s)     |
| **Data Security**       | `/darca/dspm`                       | Data Security Posture Management module                  |
| **SaaS Security**       | `/darca/saas-security`              | SaaS hub: overview, connections, findings                |
| **Scans**               | `/darca/scans`                      | Scan management (create, monitor, history)               |
| **Schedules**           | `/darca/schedules`                  | Automated scan scheduling (daily/weekly/monthly)         |
| **Notifications**       | `/darca/notifications`              | Notification center with read/unread management          |
| **Reports**             | `/darca/reports`                    | PDF reports (executive/technical) + CSV/JSON export      |
| **Integrations**        | `/darca/integrations`               | Third-party integrations (Slack, Teams, Jira, webhooks)  |
| **Audit Log**           | `/darca/audit-log`                  | Platform activity tracking with filters and statistics   |
| **Settings**            | `/darca/settings`                   | Profile, organization management, API keys               |

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

D-ARCA maps security checks to compliance frameworks at the **control level** — each framework defines theoretical controls (the actual standard's requirements) with mapped check IDs per cloud provider.

### CIS Benchmarks

| Framework          | Full Name                                                      | Controls | Platform      |
|--------------------|----------------------------------------------------------------|----------|---------------|
| CIS-AWS-1.5        | CIS Amazon Web Services Foundations Benchmark v1.5             | 11       | AWS           |
| CIS-AWS-3.0        | CIS Amazon Web Services Foundations Benchmark v3.0             | 32       | AWS           |
| CIS-AWS-6.0        | CIS Amazon Web Services Foundations Benchmark v6.0             | 56       | AWS           |
| CIS-Azure-2.0      | CIS Microsoft Azure Foundations Benchmark v2.0                 | 12       | Azure         |
| CIS-Azure-4.0      | CIS Microsoft Azure Foundations Benchmark v4.0                 | 58       | Azure         |
| CIS-GCP-2.0        | CIS Google Cloud Platform Foundation Benchmark v2.0            | 6        | GCP           |
| CIS-GCP-3.0        | CIS Google Cloud Platform Foundation Benchmark v3.0            | 64       | GCP           |
| CIS-OCI-2.0        | CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0     | 9        | OCI           |
| CIS-OCI-3.1        | CIS Oracle Cloud Infrastructure Foundations Benchmark v3.1.0   | 50       | OCI           |
| CIS-Alibaba-1.0    | CIS Alibaba Cloud Foundation Benchmark v1.0                    | 8        | Alibaba       |
| CIS-Alibaba-2.0    | CIS Alibaba Cloud Foundation Benchmark v2.0.0                  | 85       | Alibaba       |
| CIS-K8s-1.8        | CIS Kubernetes Benchmark v1.8                                  | 14       | Kubernetes    |
| CIS-M365-3.0       | CIS Microsoft 365 Foundations Benchmark v3.0                   | 21       | Microsoft 365 |

### Regulatory & Industry Frameworks

| Framework        | Full Name                                              | Controls | Scope           |
|------------------|--------------------------------------------------------|----------|-----------------|
| PCI-DSS-3.2.1    | Payment Card Industry Data Security Standard v3.2.1    | 9        | Multi-cloud     |
| PCI-DSS-v4       | Payment Card Industry Data Security Standard v4.0      | 12       | Multi-cloud     |
| HIPAA            | HIPAA Security Rule                                    | 4        | Multi-cloud     |
| SOC2             | SOC 2 Type II (Trust Service Criteria)                 | 5        | Multi-cloud     |
| GDPR             | General Data Protection Regulation                     | 4        | Multi-cloud     |
| NIST-800-53      | NIST SP 800-53 Rev. 5                                  | 7        | Multi-cloud     |
| NIST-CSF         | NIST Cybersecurity Framework v1.1                      | 6        | Multi-cloud     |
| ISO-27001        | ISO/IEC 27001:2022 Annex A                             | 6        | Multi-cloud     |
| MCSB-Azure-1.0   | Microsoft Cloud Security Benchmark (MCSB) v2 - Azure  | 84       | Azure           |
| CCM-4.1          | CSA Cloud Controls Matrix v4.1                         | 207      | Multi-cloud     |
| ENS              | Esquema Nacional de Seguridad (Spain)                  | 10       | Multi-cloud     |

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
- **API keys**: Prefixed with `darca_`, stored as SHA-256 hashes. Full key displayed only at creation time.
- **CORS**: Restricted to configured origins. Update `CORS_ORIGINS` for your deployment domain.
- **Password hashing**: bcrypt via passlib.
- **Audit logging**: All significant user actions are recorded with timestamps, IP addresses, and resource details.

---

## Project Structure

```
ARCA/
├── api/                              # Backend (Python / FastAPI)
│   ├── main.py                       # FastAPI application entry point (20 routers)
│   ├── config.py                     # Settings (env vars)
│   ├── database.py                   # SQLAlchemy async engine setup
│   ├── celery_app.py                 # Celery configuration
│   ├── requirements.txt              # Python dependencies
│   ├── models/                       # SQLAlchemy ORM models (17 tables)
│   │   ├── user.py                   # User model (auth)
│   │   ├── provider.py               # Cloud provider model
│   │   ├── scan.py                   # Scan model (cloud + SaaS)
│   │   ├── finding.py                # Cloud finding model
│   │   ├── finding_action.py         # Finding exception/remediation actions
│   │   ├── saas_connection.py        # SaaS connection model
│   │   ├── saas_finding.py           # SaaS finding model
│   │   ├── attack_path.py            # Attack path model
│   │   ├── scan_schedule.py          # Scan schedule model
│   │   ├── notification.py           # Notification model
│   │   ├── integration.py            # Third-party integration model
│   │   ├── organization.py           # Organization & membership model
│   │   ├── audit_log.py              # Audit log model (activity tracking)
│   │   ├── api_key.py                # API key model (programmatic access)
│   │   ├── rr_score.py               # Ransomware readiness scores
│   │   ├── rr_finding.py             # Ransomware readiness findings
│   │   └── rr_governance.py          # Ransomware readiness governance
│   ├── schemas/                      # Pydantic request/response schemas
│   │   ├── auth.py                   # Auth DTOs
│   │   ├── provider.py               # Provider DTOs
│   │   ├── scan.py                   # Scan DTOs
│   │   ├── finding.py                # Finding DTOs
│   │   ├── saas.py                   # SaaS DTOs + credential validators
│   │   └── dashboard.py              # Dashboard DTOs
│   ├── routers/                      # API route handlers (20 modules)
│   │   ├── auth.py                   # Auth + API key management
│   │   ├── providers.py              # CRUD cloud providers
│   │   ├── scans.py                  # Create/list/get scans
│   │   ├── findings.py               # List/filter/stats/actions findings
│   │   ├── compliance.py             # Frameworks, summary, control library
│   │   ├── saas.py                   # SaaS connections, findings, overview
│   │   ├── dashboard.py              # Aggregate overview + trends
│   │   ├── attack_paths.py           # Attack path analysis + choke points
│   │   ├── security_graph.py         # Security graph + blast radius (938 lines)
│   │   ├── reports.py                # PDF reports + CSV/JSON export
│   │   ├── mitre.py                  # MITRE ATT&CK matrix + navigator
│   │   ├── dspm.py                   # Data Security Posture Management
│   │   ├── inventory.py              # Cloud resource inventory
│   │   ├── ransomware_readiness.py   # Ransomware readiness assessment
│   │   ├── schedules.py              # Scan scheduling (CRUD)
│   │   ├── notifications.py          # Notification management
│   │   ├── integrations.py           # Third-party integrations
│   │   ├── organizations.py          # Multi-tenancy + membership
│   │   └── audit_log.py              # Audit log + statistics
│   ├── services/                     # Business logic
│   │   ├── auth_service.py           # JWT, password hashing, encryption
│   │   ├── report_service.py         # PDF report builder with chart embedding
│   │   ├── chart_service.py          # Matplotlib chart generation (donut, bar, radar, line, stacked)
│   │   ├── rr_report_service.py      # Ransomware readiness report builder
│   │   ├── notification_service.py   # Notification dispatch
│   │   └── audit_service.py          # Audit log recording
│   └── tasks/                        # Celery background tasks
│       ├── scan_tasks.py             # Cloud scan execution
│       └── saas_tasks.py             # SaaS scan execution
│
├── scanner/                          # Security scanning engine
│   ├── providers/                    # Cloud provider scanners
│   │   ├── cloud_scanner.py          # Scanner dispatcher
│   │   ├── base_check.py             # CheckResult dataclass
│   │   ├── aws/
│   │   │   └── aws_scanner.py        # AWS checks (20 services, 50+ checks)
│   │   ├── azure/
│   │   │   └── azure_scanner.py      # Azure checks (8 services, 20+ checks)
│   │   ├── gcp/
│   │   │   └── gcp_scanner.py        # GCP checks (8 services, 15+ checks)
│   │   ├── oci/
│   │   │   └── oci_scanner.py        # OCI checks (18 services, 60+ checks)
│   │   ├── alibaba/
│   │   │   └── alibaba_scanner.py    # Alibaba checks (12 services, 70+ checks)
│   │   └── kubernetes/
│   │       └── k8s_scanner.py        # K8s checks (4 categories)
│   ├── saas/                         # SaaS application scanners (8 platforms)
│   │   ├── saas_scanner.py           # SaaS scanner factory
│   │   ├── base_saas_check.py        # SaaSCheckResult dataclass
│   │   ├── connection_tester.py      # Connection test functions
│   │   ├── servicenow/               # ServiceNow checks (50+)
│   │   ├── m365/                     # Microsoft 365 checks (37)
│   │   ├── salesforce/               # Salesforce checks (18)
│   │   ├── snowflake/                # Snowflake checks (21)
│   │   ├── github/                   # GitHub checks (~30)
│   │   ├── google_workspace/         # Google Workspace checks (~30)
│   │   ├── cloudflare/               # Cloudflare checks (~25)
│   │   └── openstack/                # OpenStack checks (~30)
│   ├── compliance/
│   │   └── frameworks.py             # Framework definitions & control mappings (28+ frameworks)
│   ├── frameworks/                   # Regulatory framework definitions
│   │   ├── ens.py                    # Esquema Nacional de Seguridad (Spain)
│   │   ├── gdpr.py                   # GDPR compliance controls
│   │   ├── hipaa.py                  # HIPAA Security Rule controls
│   │   ├── pci_dss_v4.py            # PCI-DSS v4.0 controls
│   │   └── soc2.py                   # SOC 2 Type II controls
│   ├── mitre/
│   │   └── attack_mapping.py         # MITRE ATT&CK technique-to-check mapping
│   ├── attack_paths/                 # Attack path analysis engine (~3,025 lines)
│   │   ├── graph_engine.py           # Path finding and graph construction
│   │   ├── graph.py                  # Graph data structure
│   │   ├── scoring.py                # Path risk scoring
│   │   └── models.py                 # Attack path data models
│   ├── dspm/                         # Data Security Posture Management (~7,800 lines)
│   │   ├── router.py                 # DSPM orchestrator/router
│   │   ├── permission_analyzer.py    # IAM/RBAC permission analysis
│   │   ├── data_store_checks.py      # Data store security validation
│   │   ├── pii_scanner.py            # PII detection
│   │   ├── shadow_detector.py        # Unmanaged data store discovery
│   │   ├── content_sampler.py        # Data content sampling
│   │   ├── data_classifier.py        # Sensitivity classification
│   │   └── native_integrations.py    # Cloud-native data connectors
│   ├── check_library.py              # Centralized check registry (701 lines)
│   ├── drift_detection.py            # Configuration drift detection (697 lines)
│   └── ransomware/                   # Ransomware readiness module
│       ├── rules.py                  # 105 ransomware readiness rules
│       └── scoring.py                # Scoring engine with domain weights
│
├── ui/                               # Frontend (Next.js 14 / React 18 / Tailwind)
│   ├── app/
│   │   ├── layout.tsx                # Root layout
│   │   ├── page.tsx                  # Root redirect
│   │   ├── globals.css               # Tailwind + custom styles
│   │   ├── auth/
│   │   │   ├── sign-in/page.tsx      # Login page
│   │   │   └── sign-up/page.tsx      # Registration page
│   │   └── darca/                    # Authenticated pages (21 pages)
│   │       ├── layout.tsx            # Authenticated layout + sidebar
│   │       ├── overview/page.tsx     # Main dashboard
│   │       ├── attack-paths/page.tsx # Attack path visualization
│   │       ├── findings/page.tsx     # Cloud findings browser
│   │       ├── compliance/page.tsx   # Compliance frameworks + Check Library
│   │       ├── mitre-attack/page.tsx # MITRE ATT&CK matrix analysis
│   │       ├── ransomware-readiness/ # Ransomware readiness (4 sub-pages)
│   │       ├── security-graph/page.tsx# Interactive security graph
│   │       ├── inventory/page.tsx    # Cloud resource inventory
│   │       ├── providers/            # Provider management + dashboard
│   │       ├── dspm/page.tsx         # Data Security Posture Management
│   │       ├── saas-security/page.tsx# SaaS security hub
│   │       ├── scans/page.tsx        # Scan management
│   │       ├── schedules/page.tsx    # Scan scheduling UI
│   │       ├── notifications/page.tsx# Notification center
│   │       ├── reports/page.tsx      # PDF reports + data export
│   │       ├── integrations/page.tsx # Third-party integrations
│   │       ├── audit-log/page.tsx    # Activity audit log
│   │       └── settings/page.tsx     # Profile, organization, API keys
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx           # Navigation sidebar (collapsible, mobile-responsive)
│   │   │   └── Header.tsx            # Page header
│   │   └── ui/
│   │       ├── StatCard.tsx          # Metric stat card
│   │       ├── Badge.tsx             # Severity/status badge
│   │       └── DataTable.tsx         # Reusable data table
│   ├── lib/
│   │   ├── api.ts                    # API client (75+ methods)
│   │   └── utils.ts                  # Utility functions
│   ├── store/
│   │   └── auth.ts                   # Zustand auth store (persisted)
│   ├── package.json                  # Node.js dependencies
│   ├── next.config.js                # Next.js configuration
│   ├── tailwind.config.ts            # Tailwind CSS (corporate colors)
│   └── tsconfig.json                 # TypeScript config
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
