---
doc_id: ce_3_1_public_exposure_playbook
framework: cyber_essentials
control_id: CE_3_1
cloud: aws
signals: SG_SSH_OPEN,SG_RDP_OPEN,SG_MYSQL_OPEN,SG_POSTGRES_OPEN,PUBLIC_EXPOSURE
sector: general,legal
persona: executive,technical,legal
type: remediation_playbook
title: Remediation playbook for CE_3_1 network exposure
---

CE_3_1 focuses on boundary firewalls and internet gateways.

Recommended remediation order:
1. Identify workloads with public IP exposure.
2. Review security groups for internet-open critical ports.
3. Remove unnecessary inbound access from 0.0.0.0/0.
4. Review route tables and internet gateway usage.
5. Confirm only intended internet-facing services remain public.
6. Re-run CloudGuardian scan to confirm the control passes.

Evidence to retain:
- Updated security group rules
- Public route table review
- Public IP review
- CloudGuardian post-remediation scan result

Common SME mistake:
Treating all public exposure as identical without confirming whether a service is intentionally public or accidentally exposed.

Legal-sector relevance:
Unnecessary internet exposure may increase the risk of unauthorized access to systems handling confidential client information.
