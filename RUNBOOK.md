# CloudGuardian MVP - Operational Runbook

---

## 📌 1. Purpose

This runbook provides a structured guide for setting up, running, and validating the CloudGuardian MVP.

It is intended for:
- Engineers onboarding to the project
- Reviewers assessing the system
- Demonstrations and reproducibility

---

## 🧭 2. Scope

This document covers:
- Local development setup (WSL2)
- Python environment configuration
- Dependency management
- AWS integration setup
- Application execution
- Troubleshooting and operational insights

---

## 🖥️ 3. Environment Overview

| Component        | Description                          |
|-----------------|--------------------------------------|
| OS              | Ubuntu (WSL2)                        |
| Workspace       | /home/peter/cloudguardian-mvp        |
| Language        | Python 3.x                           |
| Cloud Provider  | AWS                                  |
| Version Control | Git + GitHub (SSH authentication)    |
| Editor          | VS Code (WSL integration)            |

---

## ⚙️ 4. Prerequisites

Ensure the following are installed:

- WSL2 with Ubuntu
- Python 3.9+
- Git
- AWS CLI
- VS Code with WSL extension

---

## 📂 5. Project Structure

```bash
cloudguardian-mvp/
├── venv/                   # Python virtual environment
├── .gitignore
├── requirements.txt
├── README.md
├── RUNBOOK.md
├── ARCHITECTURE.md
├── backend/                # Application logic (to be expanded)
├── data/                   # YAML mappings (future)
└── output/                 # Generated reports (future)



## IAM + Live AWS Signal Integration

### Summary
CloudGuardian now evaluates live AWS signals instead of relying only on simulated data.

### Implemented Signals
- `S3_PUBLIC`
- `ROOT_MFA_DISABLED`
- `SG_SSH_OPEN` (placeholder for next phase)

### Implemented AWS Components
- `backend/scanners/aws_s3.py`
- `backend/scanners/aws_iam.py`

### Current Control Outcomes
- `CE_1_2` → Multi-Factor Authentication
- `CE_2_1` → Secure Configuration

### Validation Result
The engine successfully evaluated:
- Root MFA status from live AWS IAM metadata
- S3 public access from live AWS bucket configuration

### Example Output
- `CE_1_2 - Multi-Factor Authentication: PASS`
- `CE_2_1 - Secure Configuration: FAIL`

### Significance
This confirms CloudGuardian can evaluate real AWS infrastructure against machine-readable Cyber Essentials control logic.

## Network Scanner Integration (Phase 3)

### Summary
CloudGuardian now evaluates AWS network exposure using security group analysis.

### Implemented File
- backend/scanners/aws_network.py

### Signals Added
- SG_SSH_OPEN
- SG_RDP_OPEN
- SG_MYSQL_OPEN
- SG_POSTGRES_OPEN

### Control Added
- CE_3_1 – Boundary Firewalls and Internet Gateways

### Detection Logic
The scanner inspects inbound security group rules and detects exposure of critical ports to 0.0.0.0/0.

### Current Coverage
- SSH (22)
- RDP (3389)
- MySQL (3306)
- PostgreSQL (5432)

### Validation Result
System successfully detects open or secure network configurations and maps results to CE_3_1.

### Significance
This extends CloudGuardian’s capability from configuration and identity into network boundary protection, aligning with core Cyber Essentials requirements.


## Explanation Engine Integration

### Summary
CloudGuardian now produces control-level plain-English explanations in addition to PASS/FAIL evaluation.

### Design
Each control definition in `framework_controls.yaml` now includes:
- `plain_english_fail`
- `risk`
- `recommendation`

### Engine Enhancement
The framework engine now returns:
- control status
- triggered signals
- signal states
- explanation metadata

### Outcome
CloudGuardian can explain not only whether a control failed, but also:
- why it failed
- what business risk it creates
- what remediation is recommended

### Significance
This strengthens the platform’s differentiation by turning compliance logic into understandable regulatory advice for SMEs.

