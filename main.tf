# ============================================================
# ENTERPRISE CLOUD SECURITY OPERATIONS PLATFORM
# Author: Mario Myles | github.com/MarioMM21
# Version: 2.0 | Built on AWS with Terraform IaC
# ============================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ============================================================
# S3 BUCKET — Centralized Security Log Storage
# ============================================================

resource "aws_s3_bucket" "security_logs" {
  bucket        = "enterprise-security-logs-${var.aws_account_id}"
  force_destroy = true

  tags = {
    Name        = "Enterprise Security Logs"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket_versioning" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  bucket                  = aws_s3_bucket.security_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    id     = "security-log-retention"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}


resource "aws_s3_bucket_policy" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::enterprise-security-logs-${var.aws_account_id}"
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::enterprise-security-logs-${var.aws_account_id}/AWSLogs/${var.aws_account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AWSConfigWrite"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::enterprise-security-logs-${var.aws_account_id}/AWSLogs/${var.aws_account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AWSConfigAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::enterprise-security-logs-${var.aws_account_id}"
      }
    ]
  })
}
# ============================================================
# SNS TOPICS — Tiered Security Alerting
# ============================================================

resource "aws_sns_topic" "critical_alerts" {
  name = "enterprise-critical-security-alerts"

  tags = {
    Name        = "Critical Security Alerts"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
    Severity    = "CRITICAL"
  }
}

resource "aws_sns_topic" "high_alerts" {
  name = "enterprise-high-security-alerts"

  tags = {
    Name        = "High Security Alerts"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
    Severity    = "HIGH"
  }
}

resource "aws_sns_topic_subscription" "critical_email" {
  topic_arn = aws_sns_topic.critical_alerts.arn
  protocol  = "email"
  endpoint  = var.email_address
}

resource "aws_sns_topic_subscription" "high_email" {
  topic_arn = aws_sns_topic.high_alerts.arn
  protocol  = "email"
  endpoint  = var.email_address
}

# ============================================================
# CLOUDTRAIL — Enterprise Audit Logging
# ============================================================

resource "aws_cloudtrail" "enterprise" {
  name                          = "enterprise-security-trail"
  s3_bucket_name                = aws_s3_bucket.security_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  tags = {
    Name        = "Enterprise Security Trail"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }

  depends_on = [aws_s3_bucket_policy.security_logs]
}

# ============================================================
# AWS KMS — Encryption Key Management
# ============================================================

resource "aws_kms_key" "security" {
  description             = "Enterprise Security Platform encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "Enterprise Security KMS Key"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_kms_alias" "security" {
  name          = "alias/enterprise-security"
  target_key_id = aws_kms_key.security.key_id
}
# ============================================================
# IAM ROLE — AWS Config
# ============================================================

resource "aws_iam_role" "config_role" {
  name = "enterprise-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })

  tags = {
    Name        = "Enterprise Config Role"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "enterprise-config-s3-policy"
  role = aws_iam_role.config_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:PutObject", "s3:GetBucketAcl"]
      Resource = [
        "arn:aws:s3:::enterprise-security-logs-${var.aws_account_id}",
        "arn:aws:s3:::enterprise-security-logs-${var.aws_account_id}/*"
      ]
    }]
  })
}

# ============================================================
# IAM ROLE — Lambda Remediation
# ============================================================

resource "aws_iam_role" "lambda_role" {
  name = "enterprise-lambda-security-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = {
    Name        = "Enterprise Lambda Security Role"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "enterprise-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketAcl"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["sns:Publish"]
        Resource = [
          aws_sns_topic.critical_alerts.arn,
          aws_sns_topic.high_alerts.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:UpdateFindings",
          "securityhub:BatchUpdateFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:DescribeConfigRules",
          "config:GetComplianceDetailsByResource"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetAccountSummary",
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================
# AWS CONFIG — Configuration Recorder
# ============================================================

resource "aws_config_configuration_recorder" "enterprise" {
  name     = "enterprise-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "enterprise" {
  name           = "enterprise-config-delivery"
  s3_bucket_name = aws_s3_bucket.security_logs.id

  depends_on = [aws_config_configuration_recorder.enterprise]
}

resource "aws_config_configuration_recorder_status" "enterprise" {
  name       = aws_config_configuration_recorder.enterprise.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.enterprise]
}
# ============================================================
# AWS CONFIG RULES — CIS Benchmark + Security Controls
# ============================================================

resource "aws_config_config_rule" "s3_public_read" {
  name        = "enterprise-s3-public-read-prohibited"
  description = "CIS 2.1.1 - S3 buckets must not allow public read"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.enterprise]

  tags = {
    Environment = var.environment
    CIS_Control = "2.1.1"
    Severity    = "HIGH"
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_config_config_rule" "s3_public_write" {
  name        = "enterprise-s3-public-write-prohibited"
  description = "CIS 2.1.2 - S3 buckets must not allow public write"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.enterprise]

  tags = {
    Environment = var.environment
    CIS_Control = "2.1.2"
    Severity    = "HIGH"
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_config_config_rule" "iam_root_access_key" {
  name        = "enterprise-iam-root-access-key-check"
  description = "CIS 1.4 - Root account must not have active access keys"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.enterprise]

  tags = {
    Environment = var.environment
    CIS_Control = "1.4"
    Severity    = "CRITICAL"
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_config_config_rule" "mfa_enabled" {
  name        = "enterprise-mfa-enabled-iam-console"
  description = "CIS 1.10 - MFA must be enabled for all IAM console users"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.enterprise]

  tags = {
    Environment = var.environment
    CIS_Control = "1.10"
    Severity    = "HIGH"
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "enterprise-cloudtrail-enabled"
  description = "CIS 3.1 - CloudTrail must be enabled in all regions"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.enterprise]

  tags = {
    Environment = var.environment
    CIS_Control = "3.1"
    Severity    = "CRITICAL"
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_config_config_rule" "root_mfa_enabled" {
  name        = "enterprise-root-mfa-enabled"
  description = "CIS 1.5 - MFA must be enabled for root account"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.enterprise]

  tags = {
    Environment = var.environment
    CIS_Control = "1.5"
    Severity    = "CRITICAL"
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_config_config_rule" "ebs_encryption" {
  name        = "enterprise-ebs-encryption-enabled"
  description = "CIS 2.2.1 - EBS volumes must be encrypted"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.enterprise]

  tags = {
    Environment = var.environment
    CIS_Control = "2.2.1"
    Severity    = "HIGH"
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_config_config_rule" "vpc_flow_logs" {
  name        = "enterprise-vpc-flow-logs-enabled"
  description = "CIS 3.9 - VPC flow logging must be enabled"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.enterprise]

  tags = {
    Environment = var.environment
    CIS_Control = "3.9"
    Severity    = "MEDIUM"
    Project     = "enterprise-cloud-security"
  }
}

# ============================================================
# AWS SECURITY HUB
# ============================================================

resource "aws_securityhub_account" "enterprise" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.enterprise]

  timeouts {
    create = "10m"
    delete = "10m"
  }
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.enterprise]

  timeouts {
    create = "10m"
    delete = "10m"
  }
}
# ============================================================
# AMAZON GUARDDUTY — Threat Detection
# ============================================================

resource "aws_guardduty_detector" "enterprise" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name        = "Enterprise GuardDuty"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

# ============================================================
# CLOUDWATCH — Security Monitoring & Alarms
# ============================================================

resource "aws_cloudwatch_log_group" "security_events" {
  name              = "/enterprise/security-events"
  retention_in_days = 90

  tags = {
    Name        = "Enterprise Security Events"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_cloudwatch_metric_alarm" "critical_findings" {
  alarm_name          = "enterprise-critical-security-findings"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityHubCriticalFindings"
  namespace           = "Enterprise/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Triggers when CRITICAL security findings are detected"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "Critical Findings Alarm"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_findings" {
  alarm_name          = "enterprise-high-security-findings"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityHubHighFindings"
  namespace           = "Enterprise/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Triggers when HIGH security findings exceed threshold"
  alarm_actions       = [aws_sns_topic.high_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "High Findings Alarm"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_cloudwatch_metric_alarm" "config_compliance" {
  alarm_name          = "enterprise-config-non-compliant"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "NonCompliantRules"
  namespace           = "AWS/Config"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Triggers when Config detects non-compliant resources"
  alarm_actions       = [aws_sns_topic.high_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Name        = "Config Compliance Alarm"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

# ============================================================
# EVENTBRIDGE — Automated Event Routing
# ============================================================

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "enterprise-guardduty-findings"
  description = "Routes GuardDuty findings to Lambda for severity-based processing"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = {
    Name        = "GuardDuty Findings Router"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  name        = "enterprise-securityhub-findings"
  description = "Routes Security Hub findings to Lambda for severity-based processing"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })

  tags = {
    Name        = "Security Hub Findings Router"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_cloudwatch_event_rule" "daily_report" {
  name                = "enterprise-daily-security-report"
  description         = "Triggers daily security compliance report at 8AM UTC"
  schedule_expression = "cron(0 8 * * ? *)"

  tags = {
    Name        = "Daily Security Report"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}
# ============================================================
# LAMBDA — Severity-Based Intelligent Remediation
# ============================================================

data "archive_file" "severity_remediation" {
  type        = "zip"
  source_file = "${path.module}/lambda/severity_remediation.py"
  output_path = "${path.module}/lambda/severity_remediation.zip"
}

data "archive_file" "jira_ticketing" {
  type        = "zip"
  source_file = "${path.module}/lambda/jira_ticketing.py"
  output_path = "${path.module}/lambda/jira_ticketing.zip"
}

data "archive_file" "compliance_dashboard" {
  type        = "zip"
  source_file = "${path.module}/lambda/compliance_dashboard.py"
  output_path = "${path.module}/lambda/compliance_dashboard.zip"
}

resource "aws_lambda_function" "severity_remediation" {
  filename         = data.archive_file.severity_remediation.output_path
  function_name    = "enterprise-severity-remediation"
  role             = aws_iam_role.lambda_role.arn
  handler          = "severity_remediation.lambda_handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.severity_remediation.output_base64sha256
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      CRITICAL_SNS_ARN = aws_sns_topic.critical_alerts.arn
      HIGH_SNS_ARN     = aws_sns_topic.high_alerts.arn
      ENVIRONMENT      = var.environment
      JIRA_URL         = var.jira_url
      JIRA_EMAIL       = var.jira_email
      JIRA_API_TOKEN   = var.jira_api_token
      JIRA_PROJECT_KEY = var.jira_project_key
    }
  }

  tags = {
    Name        = "Enterprise Severity Remediation"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_lambda_function" "jira_ticketing" {
  filename         = data.archive_file.jira_ticketing.output_path
  function_name    = "enterprise-jira-ticketing"
  role             = aws_iam_role.lambda_role.arn
  handler          = "jira_ticketing.lambda_handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.jira_ticketing.output_base64sha256
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      JIRA_URL         = var.jira_url
      JIRA_EMAIL       = var.jira_email
      JIRA_API_TOKEN   = var.jira_api_token
      JIRA_PROJECT_KEY = var.jira_project_key
      HIGH_SNS_ARN     = aws_sns_topic.high_alerts.arn
      ENVIRONMENT      = var.environment
    }
  }

  tags = {
    Name        = "Enterprise Jira Ticketing"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_lambda_function" "compliance_dashboard" {
  filename         = data.archive_file.compliance_dashboard.output_path
  function_name    = "enterprise-compliance-dashboard"
  role             = aws_iam_role.lambda_role.arn
  handler          = "compliance_dashboard.lambda_handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.compliance_dashboard.output_base64sha256
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      CRITICAL_SNS_ARN = aws_sns_topic.critical_alerts.arn
      HIGH_SNS_ARN     = aws_sns_topic.high_alerts.arn
      ENVIRONMENT      = var.environment
    }
  }

  tags = {
    Name        = "Enterprise Compliance Dashboard"
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

# ============================================================
# LAMBDA PERMISSIONS — EventBridge Triggers
# ============================================================

resource "aws_lambda_permission" "guardduty_invoke" {
  statement_id  = "AllowGuardDutyEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.severity_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

resource "aws_lambda_permission" "securityhub_invoke" {
  statement_id  = "AllowSecurityHubEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.severity_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_findings.arn
}

resource "aws_lambda_permission" "daily_report_invoke" {
  statement_id  = "AllowDailyReportEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_dashboard.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_report.arn
}

# ============================================================
# EVENTBRIDGE TARGETS — Wire Events to Lambda
# ============================================================

resource "aws_cloudwatch_event_target" "guardduty_to_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "GuardDutyToSeverityRemediation"
  arn       = aws_lambda_function.severity_remediation.arn
}

resource "aws_cloudwatch_event_target" "securityhub_to_lambda" {
  rule      = aws_cloudwatch_event_rule.securityhub_findings.name
  target_id = "SecurityHubToSeverityRemediation"
  arn       = aws_lambda_function.severity_remediation.arn
}

resource "aws_cloudwatch_event_target" "daily_report_to_lambda" {
  rule      = aws_cloudwatch_event_rule.daily_report.name
  target_id = "DailyReportToComplianceDashboard"
  arn       = aws_lambda_function.compliance_dashboard.arn
}

# ============================================================
# SSM PARAMETER STORE — Secure Configuration Storage
# ============================================================

resource "aws_ssm_parameter" "jira_url" {
  name  = "/enterprise-security/jira/url"
  type  = "String"
  value = var.jira_url != "" ? var.jira_url : "placeholder"

  tags = {
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}

resource "aws_ssm_parameter" "jira_token" {
  name  = "/enterprise-security/jira/token"
  type  = "SecureString"
  value = var.jira_api_token != "" ? var.jira_api_token : "placeholder"

  tags = {
    Environment = var.environment
    Project     = "enterprise-cloud-security"
  }
}
# ============================================================
# AWS INSPECTOR — Vulnerability Scanning
# ============================================================

resource "aws_inspector2_enabler" "enterprise" {
  account_ids    = [var.aws_account_id]
  resource_types = ["ECR", "EC2", "LAMBDA"]
}