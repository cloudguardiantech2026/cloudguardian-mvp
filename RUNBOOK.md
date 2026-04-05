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

### First-Run Behavior
If no previous snapshot exists, CloudGuardian initializes with an empty state and creates a baseline snapshot after the first scan.

## Conversational Compliance Engine

### Summary
CloudGuardian now includes a conversational query layer on top of the compliance engine.

### Implemented File
- `backend/engine/conversation_engine.py`

### Supported Queries
- show failed controls
- show passed controls
- why did CE_x_x fail
- what changed
- help

### Significance
The conversational engine does not replace the compliance model. It acts as an accessible interface to framework-level compliance reasoning, making control outcomes understandable to SMEs and reviewers.

## Compliance Scoring Engine

### Summary
CloudGuardian now calculates a weighted compliance score and overall risk level based on evaluated controls.

### Enhancements
Each control now contains:
- severity
- weight

### Output
The framework engine now produces:
- PASS / FAIL
- severity
- control weight
- overall compliance score
- overall risk level

### Scoring Logic
- Passed controls contribute their full weight
- Failed controls reduce the total score
- High-severity failures drive the overall risk level

### Significance
This shifts CloudGuardian from binary pass/fail reporting into risk-informed compliance intelligence, making the platform more useful for SME decision-making and reviewer assessment.

## IAM Depth Enhancement

### Summary
CloudGuardian now evaluates not only root account MFA, but also IAM user MFA coverage and direct administrator policy assignment.

### Signals Added
- IAM_USER_MFA_MISSING
- IAM_USER_ADMIN_POLICY

### Impact
This strengthens CE_1_2 by expanding the control from a single root-account signal to broader user access control validation.

### Significance
This makes CloudGuardian’s access-control modelling more aligned with real SME cloud identity risks.

## Advanced Network Detection

### Summary
CloudGuardian now evaluates not only security group exposure, but also higher-level public network reachability indicators.

### Signals Added
- IGW_ATTACHED
- PUBLIC_ROUTE_EXISTS
- EC2_PUBLIC_IP_PRESENT
- PUBLIC_EXPOSURE

### Logic
The scanner now correlates:
- internet gateway presence
- default public routing
- public IP assignment
- security group exposure

### Impact
This strengthens CE_3_1 by moving from simple port checks to broader internet-reachability modelling.

### Significance
This makes CloudGuardian’s network evaluation more realistic and more aligned with how cloud exposure actually occurs in AWS.
