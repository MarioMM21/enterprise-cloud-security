# ============================================================
# OUTPUTS — Enterprise Security Platform
# ============================================================

output "s3_bucket_name" {
  description = "Security logs S3 bucket"
  value       = aws_s3_bucket.security_logs.id
}

output "s3_bucket_arn" {
  description = "Security logs S3 bucket ARN"
  value       = aws_s3_bucket.security_logs.arn
}

output "critical_sns_arn" {
  description = "Critical alerts SNS topic ARN"
  value       = aws_sns_topic.critical_alerts.arn
}

output "high_sns_arn" {
  description = "High alerts SNS topic ARN"
  value       = aws_sns_topic.high_alerts.arn
}

output "cloudtrail_arn" {
  description = "Enterprise CloudTrail ARN"
  value       = aws_cloudtrail.enterprise.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.enterprise.id
}

output "kms_key_arn" {
  description = "Security KMS key ARN"
  value       = aws_kms_key.security.arn
}

output "lambda_remediation_arn" {
  description = "Severity remediation Lambda ARN"
  value       = aws_lambda_function.severity_remediation.arn
}

output "lambda_jira_arn" {
  description = "Jira ticketing Lambda ARN"
  value       = aws_lambda_function.jira_ticketing.arn
}

output "lambda_dashboard_arn" {
  description = "Compliance dashboard Lambda ARN"
  value       = aws_lambda_function.compliance_dashboard.arn
}

output "security_hub_id" {
  description = "Security Hub account ID"
  value       = aws_securityhub_account.enterprise.id
}

output "config_recorder_name" {
  description = "AWS Config recorder name"
  value       = aws_config_configuration_recorder.enterprise.name
}

output "inspector_status" {
  description = "AWS Inspector enabled resource types"
  value       = aws_inspector2_enabler.enterprise.resource_types
}