import boto3
import json
import os
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')

CRITICAL_SNS_ARN = os.environ['CRITICAL_SNS_ARN']
HIGH_SNS_ARN = os.environ['HIGH_SNS_ARN']
ENVIRONMENT = os.environ['ENVIRONMENT']
JIRA_URL = os.environ.get('JIRA_URL', '')
JIRA_EMAIL = os.environ.get('JIRA_EMAIL', '')
JIRA_API_TOKEN = os.environ.get('JIRA_API_TOKEN', '')
JIRA_PROJECT_KEY = os.environ.get('JIRA_PROJECT_KEY', 'SEC')


def lambda_handler(event, context):
    """
    Enterprise Severity-Based Intelligent Remediation Engine

    Severity routing:
    - CRITICAL: Auto-remediate immediately + SNS alert + Jira ticket
    - HIGH:     SNS alert + Jira ticket (no auto-remediation)
    - MEDIUM:   Log and report only
    - LOW:      Log only
    - INFO:     Ignore
    """
    logger.info(f"Received event: {json.dumps(event)}")

    source = event.get('source', '')
    findings = []

    # Extract findings from GuardDuty
    if source == 'aws.guardduty':
        finding = event.get('detail', {})
        severity_score = finding.get('severity', 0)
        severity_label = map_guardduty_severity(severity_score)
        findings.append({
            'id': finding.get('id', 'unknown'),
            'title': finding.get('title', 'GuardDuty Finding'),
            'description': finding.get('description', ''),
            'severity': severity_label,
            'source': 'GuardDuty',
            'type': finding.get('type', ''),
            'resource': finding.get('resource', {}),
            'region': finding.get('region', ''),
            'account': finding.get('accountId', '')
        })

    # Extract findings from Security Hub
    elif source == 'aws.securityhub':
        hub_findings = event.get('detail', {}).get('findings', [])
        for f in hub_findings:
            findings.append({
                'id': f.get('Id', 'unknown'),
                'title': f.get('Title', 'Security Hub Finding'),
                'description': f.get('Description', ''),
                'severity': f.get('Severity', {}).get('Label', 'INFORMATIONAL'),
                'source': 'SecurityHub',
                'type': f.get('Types', [''])[0],
                'resource': f.get('Resources', [{}])[0],
                'region': f.get('Region', ''),
                'account': f.get('AwsAccountId', '')
            })

    results = []
    for finding in findings:
        result = process_finding(finding)
        results.append(result)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'findings_processed': len(results),
            'results': results
        })
    }


def map_guardduty_severity(score):
    """Map GuardDuty numeric severity to label"""
    if score >= 7.0:
        return 'CRITICAL'
    elif score >= 4.0:
        return 'HIGH'
    elif score >= 1.0:
        return 'MEDIUM'
    else:
        return 'LOW'


def process_finding(finding):
    """Route finding based on severity"""
    severity = finding['severity'].upper()
    result = {
        'finding_id': finding['id'],
        'title': finding['title'],
        'severity': severity,
        'actions_taken': []
    }

    logger.info(f"Processing {severity} finding: {finding['title']}")

    if severity == 'CRITICAL':
        # Auto-remediate + Alert + Ticket
        remediation = attempt_auto_remediation(finding)
        result['actions_taken'].append(f"Auto-remediation: {remediation}")
        send_critical_alert(finding)
        result['actions_taken'].append("Critical SNS alert sent")
        if JIRA_URL:
            ticket = create_jira_ticket(finding, priority="Highest")
            result['actions_taken'].append(f"Jira ticket: {ticket}")

    elif severity == 'HIGH':
        # Alert + Ticket only — no auto-remediation
        send_high_alert(finding)
        result['actions_taken'].append("High SNS alert sent")
        if JIRA_URL:
            ticket = create_jira_ticket(finding, priority="High")
            result['actions_taken'].append(f"Jira ticket: {ticket}")

    elif severity == 'MEDIUM':
        # Log and report only
        logger.warning(f"MEDIUM finding logged: {finding['title']}")
        result['actions_taken'].append("Logged for reporting")

    else:
        # LOW/INFO — log only
        logger.info(f"LOW/INFO finding: {finding['title']}")
        result['actions_taken'].append("Logged only")

    return result


def attempt_auto_remediation(finding):
    """Attempt automatic remediation for CRITICAL findings"""
    finding_type = finding.get('type', '').lower()
    title = finding.get('title', '').lower()

    try:
        # S3 public access remediation
        if 's3' in finding_type or 's3' in title or 'public' in title:
            return remediate_s3_public_access(finding)

        # IAM access key remediation
        elif 'accesskey' in finding_type or 'access key' in title:
            return "IAM access key flagged for manual review — notification sent"

        # Default — flag for manual review
        else:
            return "Auto-remediation not available — escalated to security team"

    except Exception as e:
        logger.error(f"Auto-remediation failed: {str(e)}")
        return f"Auto-remediation failed: {str(e)}"


def remediate_s3_public_access(finding):
    """Block public access on S3 buckets"""
    remediated = []
    failed = []

    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                try:
                    access = s3_client.get_public_access_block(Bucket=bucket_name)
                    config = access['PublicAccessBlockConfiguration']
                    is_public = not all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ])
                except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    is_public = True

                if is_public:
                    s3_client.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    remediated.append(bucket_name)

            except Exception as e:
                failed.append(bucket_name)

        return f"S3 remediation complete — {len(remediated)} buckets secured"

    except Exception as e:
        return f"S3 remediation error: {str(e)}"


def send_critical_alert(finding):
    """Send CRITICAL severity SNS alert"""
    message = f"""
🚨 CRITICAL SECURITY FINDING — {ENVIRONMENT.upper()}

Title: {finding['title']}
Source: {finding['source']}
Severity: CRITICAL
Account: {finding['account']}
Region: {finding['region']}

Description:
{finding['description']}

Action Taken: Auto-remediation attempted
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Review finding in Security Hub immediately.
"""
    sns_client.publish(
        TopicArn=CRITICAL_SNS_ARN,
        Subject=f'[CRITICAL] Security Finding — {finding["title"][:50]}',
        Message=message
    )


def send_high_alert(finding):
    """Send HIGH severity SNS alert"""
    message = f"""
⚠️ HIGH SEVERITY SECURITY FINDING — {ENVIRONMENT.upper()}

Title: {finding['title']}
Source: {finding['source']}
Severity: HIGH
Account: {finding['account']}
Region: {finding['region']}

Description:
{finding['description']}

Action Required: Manual review and remediation needed
A Jira ticket has been created for tracking.
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
    sns_client.publish(
        TopicArn=HIGH_SNS_ARN,
        Subject=f'[HIGH] Security Finding — {finding["title"][:50]}',
        Message=message
    )


def create_jira_ticket(finding, priority="High"):
    """Create Jira ticket for HIGH and CRITICAL findings"""
    if not JIRA_URL or not JIRA_EMAIL or not JIRA_API_TOKEN:
        logger.warning("Jira credentials not configured")
        return "Jira not configured"

    try:
        import base64
        credentials = base64.b64encode(
            f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()
        ).decode()

        payload = json.dumps({
            "fields": {
                "project": {"key": JIRA_PROJECT_KEY},
                "summary": f"[{finding['severity']}] {finding['title'][:100]}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": f"Security Finding Details:\n\n"
                                   f"Severity: {finding['severity']}\n"
                                   f"Source: {finding['source']}\n"
                                   f"Account: {finding['account']}\n"
                                   f"Region: {finding['region']}\n\n"
                                   f"Description: {finding['description']}\n\n"
                                   f"Finding ID: {finding['id']}\n"
                                   f"Detected: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                        }]
                    }]
                },
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority},
                "labels": ["security", "cloud-security", finding['severity'].lower()]
            }
        }).encode()

        req = urllib.request.Request(
            f"{JIRA_URL}/rest/api/3/issue",
            data=payload,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/json"
            },
            method="POST"
        )

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read())
            ticket_key = result.get('key', 'Unknown')
            logger.info(f"Jira ticket created: {ticket_key}")
            return ticket_key

    except Exception as e:
        logger.error(f"Jira ticket creation failed: {str(e)}")
        return f"Ticket creation failed: {str(e)}"