---
doc_id: ce_2_1_s3_public_access_playbook
framework: cyber_essentials
control_id: CE_2_1
cloud: aws
signals: S3_PUBLIC
sector: general,legal
persona: executive,technical,legal
type: remediation_playbook
title: Remediation playbook for CE_2_1 public S3 exposure
---

CE_2_1 focuses on secure configuration.

Recommended remediation order:
1. Identify the affected bucket or buckets.
2. Enable S3 Block Public Access settings.
3. Review bucket policies for public principals such as "*".
4. Review object-level ACLs if used.
5. Confirm that only intended users, roles, or services retain access.
6. Re-run CloudGuardian scan to confirm the control passes.

Evidence to retain:
- Updated Block Public Access configuration
- Revised bucket policy
- Screenshot or exported proof of restricted access
- CloudGuardian post-remediation scan result

Common SME mistake:
Removing access too quickly without checking application dependencies can interrupt business systems.

Legal-sector relevance:
Public storage exposure may create confidentiality and client-data handling concerns where sensitive matter files or records are involved.
