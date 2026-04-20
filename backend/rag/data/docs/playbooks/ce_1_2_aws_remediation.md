---
doc_id: ce_1_2_aws_remediation
framework: cyber_essentials
control_id: CE_1_2
cloud: aws
signals: ROOT_MFA_DISABLED,IAM_USER_MFA_MISSING,IAM_USER_ADMIN_POLICY
sector: general,legal
persona: executive,technical,legal
type: remediation_playbook
title: Remediation playbook for CE_1_2 in AWS
---

CE_1_2 focuses on multi-factor authentication and disciplined privileged access.

Recommended remediation order:
1. Confirm a fallback administrative access path exists before making changes.
2. Enable MFA on the AWS root account.
3. Review IAM users without MFA and enforce MFA for all privileged users.
4. Review users with direct AdministratorAccess policy attachment.
5. Replace direct user-level admin assignment with role-based access where possible.
6. Re-run CloudGuardian scan to confirm the control passes.

Evidence to retain:
- Proof that root MFA is enabled
- IAM user MFA status
- Updated policy assignments
- CloudGuardian post-remediation scan result

Common SME mistake:
Enforcing MFA without a recovery path can create avoidable access lockout issues.

Legal-sector relevance:
Where legal or professional services data is involved, weak identity controls may increase risk to confidentiality and accountability.
