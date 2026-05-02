variable "aws_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "email_address" {
  description = "Email for security alerts"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "enterprise-security"
}

variable "jira_url" {
  description = "Jira instance URL"
  type        = string
  default     = ""
}

variable "jira_email" {
  description = "Jira account email"
  type        = string
  default     = ""
}

variable "jira_api_token" {
  description = "Jira API token"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jira_project_key" {
  description = "Jira project key"
  type        = string
  default     = "SEC"
}

variable "grafana_api_key" {
  description = "Grafana Cloud API key"
  type        = string
  default     = ""
  sensitive   = true
}