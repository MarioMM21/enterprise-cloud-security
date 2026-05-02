import boto3
import json
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

config_client = boto3.client('config')
securityhub_client = boto3.client('securityhub')
cloudwatch_client = boto3.client('cloudwatch')
sns_client = boto3.client('sns')
guardduty_client = boto3.client('guardduty')

CRITICAL_SNS_ARN = os.environ['CRITICAL_SNS_ARN']
HIGH_SNS_ARN = os.environ['HIGH_SNS_ARN']
ENVIRONMENT = os.environ['ENVIRONMENT']

ENTERPRISE_CONFIG_RULES = {
    'enterprise-s3-public-read-prohibited': {
        'control': 'CIS 2.1.1',
        'description': 'S3 buckets must not allow public read',
        'severity': 'HIGH'
    },
    'enterprise-s3-public-write-prohibited': {
        'control': 'CIS 2.1.2',
        'description': 'S3 buckets must not allow public write',
        'severity': 'HIGH'
    },
    'enterprise-iam-root-access-key-check': {
        'control': 'CIS 1.4',
        'description': 'Root account must not have active access keys',
        'severity': 'CRITICAL'
    },
    'enterprise-mfa-enabled-iam-console': {
        'control': 'CIS 1.10',
        'description': 'MFA must be enabled for all IAM console users',
        'severity': 'HIGH'
    },
    'enterprise-cloudtrail-enabled': {
        'control': 'CIS 3.1',
        'description': 'CloudTrail must be enabled in all regions',
        'severity': 'CRITICAL'
    },
    'enterprise-root-mfa-enabled': {
        'control': 'CIS 1.5',
        'description': 'MFA must be enabled for root account',
        'severity': 'CRITICAL'
    },
    'enterprise-ebs-encryption-enabled': {
        'control': 'CIS 2.2.1',
        'description': 'EBS volumes must be encrypted',
        'severity': 'HIGH'
    },
    'enterprise-vpc-flow-logs-enabled': {
        'control': 'CIS 3.9',
        'description': 'VPC flow logging must be enabled',
        'severity': 'MEDIUM'
    }
}


def lambda_handler(event, context):
    """
    Enterprise Compliance Dashboard Generator

    Runs daily at 8AM UTC via EventBridge.
    Collects metrics from Config, Security Hub, and GuardDuty.
    Publishes CloudWatch metrics for Grafana dashboards.
    Sends executive compliance report via SNS.
    """
    logger.info("Starting enterprise compliance dashboard generation...")
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    try:
        config_results = get_config_compliance()
        securityhub_results = get_securityhub_findings()
        guardduty_results = get_guardduty_findings()
        overall_score = calculate_compliance_score(config_results)
        publish_cloudwatch_metrics(
            config_results,
            securityhub_results,
            guardduty_results,
            overall_score
        )
        report = generate_executive_report(
            config_results,
            securityhub_results,
            guardduty_results,
            overall_score,
            timestamp
        )
        deliver_report(report, overall_score)

        logger.info(f"Dashboard generation complete. Score: {overall_score}%")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'overall_compliance_score': overall_score,
                'config_rules_evaluated': len(config_results),
                'securityhub_findings': securityhub_results['total'],
                'guardduty_findings': guardduty_results['total'],
                'timestamp': timestamp
            })
        }

    except Exception as e:
        logger.error(f"Dashboard generation failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def get_config_compliance():
    """Get compliance status for all enterprise Config rules"""
    results = []

    for rule_name, rule_info in ENTERPRISE_CONFIG_RULES.items():
        try:
            response = config_client.get_compliance_details_by_config_rule(
                ConfigRuleName=rule_name,
                ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT']
            )
            evaluations = response.get('EvaluationResults', [])
            compliant = sum(
                1 for e in evaluations
                if e['ComplianceType'] == 'COMPLIANT'
            )
            non_compliant = sum(
                1 for e in evaluations
                if e['ComplianceType'] == 'NON_COMPLIANT'
            )
            total = compliant + non_compliant
            score = round((compliant / total * 100) if total > 0 else 100, 2)

            results.append({
                'rule_name': rule_name,
                'control': rule_info['control'],
                'description': rule_info['description'],
                'severity': rule_info['severity'],
                'compliant': compliant,
                'non_compliant': non_compliant,
                'total': total,
                'score': score,
                'status': 'COMPLIANT' if non_compliant == 0 else 'NON_COMPLIANT'
            })

        except Exception as e:
            logger.error(f"Error getting compliance for {rule_name}: {str(e)}")
            results.append({
                'rule_name': rule_name,
                'control': rule_info['control'],
                'description': rule_info['description'],
                'severity': rule_info['severity'],
                'error': str(e),
                'score': 0,
                'status': 'ERROR'
            })

    return results


def get_securityhub_findings():
    """Get Security Hub findings summary by severity"""
    try:
        response = securityhub_client.get_findings(
            Filters={
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
            },
            MaxResults=100
        )

        findings = response.get('Findings', [])
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0
        }

        for f in findings:
            severity = f.get('Severity', {}).get('Label', 'INFORMATIONAL')
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            'total': len(findings),
            'by_severity': severity_counts,
            'critical': severity_counts['CRITICAL'],
            'high': severity_counts['HIGH'],
            'medium': severity_counts['MEDIUM'],
            'low': severity_counts['LOW']
        }

    except Exception as e:
        logger.error(f"Error getting Security Hub findings: {str(e)}")
        return {
            'total': 0,
            'by_severity': {},
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'error': str(e)
        }


def get_guardduty_findings():
    """Get GuardDuty active findings summary"""
    try:
        detectors = guardduty_client.list_detectors()
        detector_ids = detectors.get('DetectorIds', [])

        if not detector_ids:
            return {'total': 0, 'high_severity': 0, 'medium_severity': 0}

        detector_id = detector_ids[0]
        finding_ids_response = guardduty_client.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                'Criterion': {
                    'service.archived': {
                        'Eq': ['false']
                    }
                }
            },
            MaxResults=50
        )

        finding_ids = finding_ids_response.get('FindingIds', [])

        if not finding_ids:
            return {'total': 0, 'high_severity': 0, 'medium_severity': 0}

        findings_response = guardduty_client.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids[:50]
        )

        findings = findings_response.get('Findings', [])
        high_severity = sum(1 for f in findings if f.get('Severity', 0) >= 7.0)
        medium_severity = sum(
            1 for f in findings
            if 4.0 <= f.get('Severity', 0) < 7.0
        )

        return {
            'total': len(findings),
            'high_severity': high_severity,
            'medium_severity': medium_severity
        }

    except Exception as e:
        logger.error(f"Error getting GuardDuty findings: {str(e)}")
        return {
            'total': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'error': str(e)
        }


def calculate_compliance_score(config_results):
    """Calculate weighted overall compliance score"""
    severity_weights = {
        'CRITICAL': 3,
        'HIGH': 2,
        'MEDIUM': 1,
        'LOW': 0.5
    }

    total_weight = 0
    weighted_score = 0

    for rule in config_results:
        if 'error' not in rule:
            weight = severity_weights.get(rule['severity'], 1)
            total_weight += weight
            weighted_score += rule['score'] * weight

    if total_weight == 0:
        return 0

    return round(weighted_score / total_weight, 2)


def publish_cloudwatch_metrics(config_results, securityhub_results,
                               guardduty_results, overall_score):
    """Publish security metrics to CloudWatch for Grafana dashboards"""
    timestamp = datetime.now(timezone.utc)
    namespace = 'Enterprise/Security'

    metrics = [
        {
            'MetricName': 'OverallComplianceScore',
            'Value': overall_score,
            'Unit': 'Percent',
            'Timestamp': timestamp
        },
        {
            'MetricName': 'SecurityHubCriticalFindings',
            'Value': securityhub_results.get('critical', 0),
            'Unit': 'Count',
            'Timestamp': timestamp
        },
        {
            'MetricName': 'SecurityHubHighFindings',
            'Value': securityhub_results.get('high', 0),
            'Unit': 'Count',
            'Timestamp': timestamp
        },
        {
            'MetricName': 'SecurityHubTotalFindings',
            'Value': securityhub_results.get('total', 0),
            'Unit': 'Count',
            'Timestamp': timestamp
        },
        {
            'MetricName': 'GuardDutyHighFindings',
            'Value': guardduty_results.get('high_severity', 0),
            'Unit': 'Count',
            'Timestamp': timestamp
        },
        {
            'MetricName': 'NonCompliantConfigRules',
            'Value': sum(
                1 for r in config_results
                if r.get('status') == 'NON_COMPLIANT'
            ),
            'Unit': 'Count',
            'Timestamp': timestamp
        }
    ]

    cloudwatch_client.put_metric_data(
        Namespace=namespace,
        MetricData=metrics
    )

    logger.info(f"Published {len(metrics)} metrics to CloudWatch namespace: {namespace}")


def generate_executive_report(config_results, securityhub_results,
                               guardduty_results, overall_score, timestamp):
    """Generate executive-ready compliance report"""

    status_emoji = '✅' if overall_score >= 80 else '⚠️' if overall_score >= 60 else '🚨'
    status_text = 'PASSING' if overall_score >= 80 else 'NEEDS ATTENTION' if overall_score >= 60 else 'CRITICAL'

    critical_rules = [r for r in config_results if r.get('status') == 'NON_COMPLIANT' and r.get('severity') == 'CRITICAL']
    high_rules = [r for r in config_results if r.get('status') == 'NON_COMPLIANT' and r.get('severity') == 'HIGH']

    report = f"""
╔══════════════════════════════════════════════════════════════════╗
     ENTERPRISE CLOUD SECURITY COMPLIANCE REPORT
     Environment: {ENVIRONMENT.upper()}
     Generated: {timestamp}
╚══════════════════════════════════════════════════════════════════╝

{status_emoji} OVERALL COMPLIANCE SCORE: {overall_score}% — {status_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY HUB FINDINGS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Active Findings:  {securityhub_results.get('total', 0)}
Critical:               {securityhub_results.get('critical', 0)}
High:                   {securityhub_results.get('high', 0)}
Medium:                 {securityhub_results.get('medium', 0)}
Low:                    {securityhub_results.get('low', 0)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GUARDDUTY THREAT DETECTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Active Findings:  {guardduty_results.get('total', 0)}
High Severity:          {guardduty_results.get('high_severity', 0)}
Medium Severity:        {guardduty_results.get('medium_severity', 0)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CIS BENCHMARK CONTROL RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

    for rule in config_results:
        if 'error' in rule:
            status_icon = '❓'
            detail = f"Error: {rule['error']}"
        elif rule['status'] == 'COMPLIANT':
            status_icon = '✅'
            detail = f"All {rule.get('total', 0)} resources compliant"
        else:
            status_icon = '🚨' if rule['severity'] == 'CRITICAL' else '⚠️'
            detail = f"{rule.get('non_compliant', 0)} non-compliant of {rule.get('total', 0)} resources"

        report += f"""
{status_icon} [{rule['control']}] {rule['description']}
   Severity: {rule['severity']} | Score: {rule.get('score', 0)}% | {detail}"""

    if critical_rules or high_rules:
        report += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTION REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Critical Issues Requiring Immediate Action: {len(critical_rules)}
High Issues Requiring Prompt Remediation:   {len(high_rules)}"""

        for rule in critical_rules:
            report += f"\n🚨 CRITICAL: [{rule['control']}] {rule['description']}"
        for rule in high_rules:
            report += f"\n⚠️  HIGH:     [{rule['control']}] {rule['description']}"

    report += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Generated by Enterprise Cloud Security Platform
github.com/MarioMM21/enterprise-cloud-security
Framework: CIS AWS Foundations Benchmark v1.4.0
Metrics published to CloudWatch namespace: Enterprise/Security
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    return report


def deliver_report(report, overall_score):
    """Deliver report via SNS based on compliance score"""
    topic_arn = CRITICAL_SNS_ARN if overall_score < 60 else HIGH_SNS_ARN
    subject_prefix = '🚨 CRITICAL' if overall_score < 60 else '⚠️ ATTENTION' if overall_score < 80 else '✅ PASSING'

    sns_client.publish(
        TopicArn=topic_arn,
        Subject=f'{subject_prefix} — Daily Security Report — Score: {overall_score}% — {ENVIRONMENT.upper()}',
        Message=report
    )
    logger.info(f"Compliance report delivered via SNS. Score: {overall_score}%")