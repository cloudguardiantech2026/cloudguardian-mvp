# ─────────────────────────────────────────────────────────────────────────────
# CloudGuardian Connect — Terraform Onboarding File
# ─────────────────────────────────────────────────────────────────────────────
#
# This file provisions a secure, read-only IAM role in your AWS account that
# allows CloudGuardian to perform Cyber Essentials compliance scans.
#
# No access keys are created. CloudGuardian uses AWS STS to assume this role
# and receives temporary, read-only credentials scoped to your account.
#
# HOW TO USE:
#   1. Install Terraform: https://developer.hashicorp.com/terraform/install
#   2. Ensure your AWS CLI is configured: aws configure
#   3. Run: terraform init && terraform apply
#   4. Copy the aws_role_arn output and paste it into CloudGuardian
#
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  # Uses your locally configured AWS credentials (aws configure)
  # Change this region if your primary AWS region is not eu-west-2
  region = "eu-west-2"
}

# ── Variables (pre-filled by CloudGuardian — do not edit) ─────────────────────

variable "cloudguardian_aws_account_id" {
  type        = string
  default     = "968477811670"
  description = "The CloudGuardian platform AWS account ID authorised to assume this role"
}

variable "cloudguardian_customer_id" {
  type        = string
  default     = "{{EXTERNAL_ID}}"
  description = "Your unique CloudGuardian customer ID — used as the STS External ID"
}

# ── IAM Role ──────────────────────────────────────────────────────────────────

resource "aws_iam_role" "cloudguardian_audit_role" {
  name        = "CloudGuardian-ReadOnly-AuditRole"
  description = "Read-only role for CloudGuardian Cyber Essentials compliance scanning"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.cloudguardian_aws_account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.cloudguardian_customer_id
          }
        }
      }
    ]
  })
}

# ── Policy attachments (read-only, no write permissions) ─────────────────────

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.cloudguardian_audit_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.cloudguardian_audit_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ── Output ────────────────────────────────────────────────────────────────────

output "aws_role_arn" {
  value       = aws_iam_role.cloudguardian_audit_role.arn
  description = "Paste this ARN into the CloudGuardian AWS Connection screen"
}
