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