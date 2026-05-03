# Enterprise Cloud Security Operations Platform

![AWS](https://img.shields.io/badge/AWS-Enterprise%20Security-orange?style=for-the-badge&logo=amazon-aws)
![Terraform](https://img.shields.io/badge/Terraform-IaC-purple?style=for-the-badge&logo=terraform)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![CIS](https://img.shields.io/badge/CIS-Benchmark%20v1.4.0-red?style=for-the-badge)
![Inspector](https://img.shields.io/badge/AWS-Inspector-green?style=for-the-badge&logo=amazon-aws)![Terraform Validate](https://github.com/MarioMM21/enterprise-cloud-security/actions/workflows/terraform-validate.yml/badge.svg)

## Overview

A production-grade Enterprise Cloud Security Operations Platform built entirely on AWS using Infrastructure as Code. This platform represents the evolution of cloud security from basic posture management to a fully automated, severity-intelligent security operations center — detecting threats, routing findings by severity, auto-remediating critical issues, creating Jira tickets for high-severity findings, and delivering executive compliance reports on a daily schedule.

**This is not a lab exercise. This is enterprise-grade security engineering deployed in a live AWS environment.**

> **Built as a progression from:** [AWS CSPM Pipeline](https://github.com/MarioMM21/aws-cspm-pipeline) — single account CSPM → **This project** — enterprise-grade multi-service security operations platform

---

## Architecture

---

## What Makes This Enterprise-Grade

### 🧠 Severity-Based Intelligent Remediation
Unlike basic CSPM tools that alert on everything equally, this platform routes findings through an intelligent decision engine:

| Severity | Action |
|---|---|
| **CRITICAL** | Auto-remediate immediately + SNS alert + Jira ticket |
| **HIGH** | SNS alert + Jira ticket (human review required) |
| **MEDIUM** | Log and include in daily report |
| **LOW/INFO** | Log only |

### 🔍 Multi-Source Threat Detection
- **GuardDuty** — ML-powered threat detection across S3, Kubernetes, and EC2 with malware protection
- **Security Hub** — Centralized findings aggregation with CIS v1.4.0 and AWS Foundational standards
- **AWS Config** — 8 CIS Benchmark rules with continuous compliance evaluation
- **AWS Inspector** — Vulnerability scanning across EC2, ECR, and Lambda functions

### 📋 Automated Jira Integration
HIGH and CRITICAL findings automatically create structured Jira tickets with full context — severity, affected resource, account, region, description, and remediation guidance. No manual triage required.

### 📊 Executive Compliance Dashboard
Daily compliance reports delivered via SNS every morning at 8AM UTC — overall CIS compliance score, severity breakdown, findings trends, and action items. CloudWatch metrics published for Grafana visualization.

### 🔐 Enterprise Security Controls
- KMS customer-managed key with automatic rotation
- S3 lifecycle management — 30-day IA transition, 90-day Glacier, 365-day expiration
- SSM Parameter Store for secure credential management
- Least-privilege IAM roles for every service

---

## Infrastructure — 52 AWS Resources

| Category | Resources |
|---|---|
| **Detection** | GuardDuty, AWS Config (8 rules), Security Hub, AWS Inspector |
| **Automation** | 3 Lambda functions, EventBridge (3 rules), CloudWatch (3 alarms) |
| **Alerting** | SNS Critical topic, SNS High topic, 2 email subscriptions |
| **Storage** | S3 bucket (encrypted + lifecycle), CloudTrail, CloudWatch logs |
| **Security** | KMS key + alias, 2 IAM roles, 3 IAM policies, SSM parameters |
| **Orchestration** | EventBridge targets, Lambda permissions |

---

## Lambda Functions

### 1. enterprise-severity-remediation
**Trigger:** EventBridge (GuardDuty findings + Security Hub findings)

The core intelligence engine. Receives every security finding, evaluates severity, and routes to the appropriate response:
- CRITICAL → auto-remediate S3 + SNS critical alert + Jira ticket
- HIGH → SNS high alert + Jira ticket
- MEDIUM → log for reporting
- LOW → log only

### 2. enterprise-jira-ticketing
**Trigger:** Called by severity-remediation or directly via EventBridge

Creates structured Jira tickets for HIGH and CRITICAL findings with full context including severity, resource details, remediation guidance, and auto-applied labels.

### 3. enterprise-compliance-dashboard
**Trigger:** EventBridge daily at 8AM UTC

Queries Config, Security Hub, and GuardDuty for current state. Calculates weighted CIS compliance score. Publishes 6 CloudWatch metrics for Grafana dashboards. Delivers executive report via SNS.

---

## CIS Benchmark Controls

| Control | Rule | Severity | Status |
|---|---|---|---|
| CIS 1.4 | Root account must not have active access keys | CRITICAL | ✅ |
| CIS 1.5 | MFA must be enabled for root account | CRITICAL | ✅ |
| CIS 1.10 | MFA must be enabled for all IAM console users | HIGH | ✅ |
| CIS 2.1.1 | S3 buckets must not allow public read | HIGH | ✅ |
| CIS 2.1.2 | S3 buckets must not allow public write | HIGH | ✅ |
| CIS 2.2.1 | EBS volumes must be encrypted | HIGH | ✅ |
| CIS 3.1 | CloudTrail must be enabled in all regions | CRITICAL | ✅ |
| CIS 3.9 | VPC flow logging must be enabled | MEDIUM | ✅ |

---
## IAM Architecture — Least Privilege Design

| Role | Purpose | Key Permissions |
|---|---|---|
| `enterprise-config-role` | AWS Config recorder | S3 PutObject to security logs bucket only |
| `enterprise-lambda-security-role` | All Lambda functions | Scoped S3, SNS, Config, SecHub, IAM read, SSM read |

### Design Decisions
- **No AdministratorAccess anywhere** — every role has explicit allow statements
- **S3 remediation scoped** — Lambda can only call `PutBucketPublicAccessBlock` and `ListAllMyBuckets` — cannot delete, read data, or modify bucket contents
- **SNS publish scoped** — Lambda can only publish to the two enterprise SNS topics — not any SNS topic
- **SecureString for secrets** — Jira API token stored as KMS-encrypted SSM SecureString — Lambda has GetParameter permission only

## Production Considerations

### Auto-Remediation Safety
- **Scope limiting:** S3 remediation only applies Block Public Access — it never deletes data or modifies bucket contents
- **Audit trail:** Every remediation action is logged to CloudWatch and triggers an SNS notification with full context before and after
- **Rollback:** All infrastructure is Terraform-managed — `terraform destroy` cleanly removes everything with zero orphaned resources

### False Positive Handling
- **Severity thresholds:** Only CRITICAL findings trigger auto-remediation — HIGH and above require human review via Jira ticket
- **Source validation:** Lambda validates finding source (GuardDuty vs Security Hub) and adjusts response accordingly
- **Simulation mode:** Jira integration falls back gracefully to SNS notification if credentials are not configured

### IAM Least Privilege Design
- **Role separation:** Config role, Lambda role, and remediation policies are completely separate with no shared permissions
- **No wildcards on destructive actions:** S3 remediation permissions are scoped to specific API actions only
- **SSM SecureString:** Jira credentials stored as encrypted SecureString — never in environment variables or code

### Logging & Auditability
- **CloudTrail:** Every API call logged across all regions — full audit trail of every action taken by every service
- **CloudWatch:** Remediation metrics published to Enterprise/Security namespace — queryable and alertable
- **SNS notifications:** Every auto-remediation sends a notification documenting what was changed, when, and why

## Test Scenarios — How to Validate the Platform

### Scenario 1 — S3 Public Access (CRITICAL)
```bash
# Create a public S3 bucket
aws s3api put-public-access-block \
  --bucket your-bucket \
  --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
```
**Expected:** Lambda detects via Config rule → auto-remediates → SNS CRITICAL alert sent → Jira ticket created → CloudTrail logs the remediation

### Scenario 2 — Root Account Activity (HIGH)
Simulate by logging into AWS console as root user and performing any API call.

**Expected:** GuardDuty detects root credential usage → EventBridge routes to severity Lambda → SNS HIGH alert → Jira ticket created for security team review

### Scenario 3 — MFA Not Enabled (HIGH)
Create an IAM user without MFA enabled.

**Expected:** Config rule `enterprise-mfa-enabled-iam-console` flags as NON_COMPLIANT → Security Hub aggregates finding → Daily compliance report score decreases → Finding appears in executive report

### Scenario 4 — CloudTrail Disabled (CRITICAL)
```bash
aws cloudtrail stop-logging --name enterprise-security-trail
```
**Expected:** Config rule `enterprise-cloudtrail-enabled` immediately flags NON_COMPLIANT → CRITICAL finding routed to auto-remediation Lambda → CloudTrail re-enabled → SNS CRITICAL alert sent

## Tech Stack

| Category | Technology |
|---|---|
| Cloud Platform | AWS (us-east-1) |
| Infrastructure as Code | Terraform v5.x |
| Scripting / Automation | Python 3.11 (boto3) |
| Threat Detection | GuardDuty, AWS Config, Security Hub |
| Vulnerability Scanning | AWS Inspector (EC2 + ECR + Lambda) |
| Incident Response | Lambda severity routing + auto-remediation |
| Ticketing Integration | Jira REST API v3 |
| Encryption | AWS KMS (customer-managed, auto-rotation) |
| Audit Logging | CloudTrail (multi-region) |
| Alerting | SNS (tiered — Critical + High) |
| Scheduling | EventBridge |
| Monitoring | CloudWatch metrics + alarms |
| Secure Config | SSM Parameter Store |
| Log Storage | S3 (AES-256 + lifecycle management) |

---

## Project Structure

---

## Deployment

### Prerequisites
- AWS account with IAM permissions
- Terraform v1.0+
- Python 3.11+
- AWS CLI configured
- Jira account (optional — ticketing works in simulation mode without it)

### Deploy
```bash
git clone https://github.com/MarioMM21/enterprise-cloud-security.git
cd enterprise-cloud-security

# Create your tfvars
cp terraform.tfvars.example terraform.tfvars
# Edit with your values

terraform init
terraform plan
terraform apply
```

### Destroy
```bash
terraform destroy
```

---

## Live Results

Upon deployment this platform immediately detected real security events:

- **24 non-compliant Config rules** across the account
- **GuardDuty finding:** Root credentials used to invoke AWS Config API — real behavioral detection
- **Inspector actively scanning** all 3 Lambda functions for package vulnerabilities
- **S3 auto-remediation** triggered and confirmed compliant
- **8 CIS controls** evaluated and reporting compliance status
- **Daily compliance report** scheduled — delivering executive-ready scoring every morning

---

## Key Skills Demonstrated

| Skill | Evidence |
|---|---|
| **Cloud Security Architecture** | 52-resource enterprise security platform designed from scratch |
| **Infrastructure as Code** | 798-line Terraform configuration — repeatable, auditable, production-ready |
| **Python Security Automation** | 3 Lambda functions totaling 859 lines of production Python/boto3 |
| **CIS Benchmark Implementation** | 8 controls mapped to CIS AWS Foundations Benchmark v1.4.0 |
| **Severity-Based Triage** | Intelligent CRITICAL/HIGH/MEDIUM/LOW routing — not just alerting on everything |
| **SIEM Integration** | Security Hub aggregating findings from multiple detection sources |
| **Vulnerability Management** | AWS Inspector scanning EC2, ECR, and Lambda in real time |
| **Incident Response Automation** | Detection to remediation to notification in seconds |
| **Jira Integration** | Automated ticket creation from security findings via REST API |
| **Executive Reporting** | Daily compliance scoring with CloudWatch metrics for dashboards |
| **IAM Least Privilege** | Every role scoped to minimum required permissions |
| **Encryption & Key Management** | Customer-managed KMS with automatic rotation |

---

## Project Progression

This project is the second in a series demonstrating cloud security engineering depth:

| Project | Focus | Resources |
|---|---|---|
| [AWS CSPM Pipeline](https://github.com/MarioMM21/aws-cspm-pipeline) | Single-account CSPM + basic remediation | 32 resources |
| **Enterprise Cloud Security Platform** (this) | Multi-service security ops + severity intelligence | 52 resources |

---

## Author

**Mario Myles**
Cloud Security Engineer | AWS | Terraform | Python | Security+

- GitHub: [github.com/MarioMM21](https://github.com/MarioMM21)
- LinkedIn: [linkedin.com/in/mario-myles](https://linkedin.com/in/mario-myles)

---

*Built and deployed May 2026*

