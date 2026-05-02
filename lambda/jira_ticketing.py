import boto3
import json
import os
import logging
import urllib.request
import urllib.error
import base64
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns_client = boto3.client('sns')
config_client = boto3.client('config')
securityhub_client = boto3.client('securityhub')

JIRA_URL = os.environ.get('JIRA_URL', '')
JIRA_EMAIL = os.environ.get('JIRA_EMAIL', '')
JIRA_API_TOKEN = os.environ.get('JIRA_API_TOKEN', '')
JIRA_PROJECT_KEY = os.environ.get('JIRA_PROJECT_KEY', 'SEC')
HIGH_SNS_ARN = os.environ['HIGH_SNS_ARN']
ENVIRONMENT = os.environ['ENVIRONMENT']


def lambda_handler(event, context):
    """
    Enterprise Jira Ticketing Integration
    
    Creates structured Jira tickets for security findings
    with full context, severity, and remediation guidance.
    Triggered directly or called from severity_remediation.
    """
    logger.info(f"Jira ticketing event: {json.dumps(event)}")

    findings = event.get('findings', [])
    
    if not findings:
        findings = extract_findings_from_event(event)

    results = []
    for finding in findings:
        result = process_finding_ticket(finding)
        results.append(result)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'tickets_created': len([r for r in results if r.get('success')]),
            'tickets_failed': len([r for r in results if not r.get('success')]),
            'results': results
        })
    }


def extract_findings_from_event(event):
    """Extract findings from various AWS event formats"""
    findings = []
    source = event.get('source', '')

    if source == 'aws.securityhub':
        hub_findings = event.get('detail', {}).get('findings', [])
        for f in hub_findings:
            severity = f.get('Severity', {}).get('Label', 'INFORMATIONAL')
            if severity in ['CRITICAL', 'HIGH']:
                findings.append({
                    'id': f.get('Id', 'unknown'),
                    'title': f.get('Title', 'Security Finding'),
                    'description': f.get('Description', ''),
                    'severity': severity,
                    'source': 'SecurityHub',
                    'account': f.get('AwsAccountId', ''),
                    'region': f.get('Region', ''),
                    'resource_type': f.get('Resources', [{}])[0].get('Type', ''),
                    'resource_id': f.get('Resources', [{}])[0].get('Id', ''),
                    'remediation': f.get('Remediation', {}).get(
                        'Recommendation', {}).get('Text', 'See Security Hub for details')
                })

    elif source == 'aws.guardduty':
        detail = event.get('detail', {})
        severity_score = detail.get('severity', 0)
        if severity_score >= 4.0:
            findings.append({
                'id': detail.get('id', 'unknown'),
                'title': detail.get('title', 'GuardDuty Finding'),
                'description': detail.get('description', ''),
                'severity': 'CRITICAL' if severity_score >= 7.0 else 'HIGH',
                'source': 'GuardDuty',
                'account': detail.get('accountId', ''),
                'region': detail.get('region', ''),
                'resource_type': detail.get('resource', {}).get('resourceType', ''),
                'resource_id': detail.get('id', ''),
                'remediation': 'Review GuardDuty console for remediation steps'
            })

    return findings


def process_finding_ticket(finding):
    """Create a Jira ticket for a single finding"""
    try:
        if not JIRA_URL:
            return simulate_ticket(finding)

        ticket_key = create_jira_ticket(finding)
        
        logger.info(f"Ticket created for finding {finding['id']}: {ticket_key}")
        
        return {
            'finding_id': finding['id'],
            'title': finding['title'],
            'severity': finding['severity'],
            'ticket_key': ticket_key,
            'success': True
        }

    except Exception as e:
        logger.error(f"Failed to create ticket for {finding['id']}: {str(e)}")
        return {
            'finding_id': finding['id'],
            'title': finding['title'],
            'severity': finding['severity'],
            'error': str(e),
            'success': False
        }


def create_jira_ticket(finding):
    """Create ticket in Jira via REST API"""
    credentials = base64.b64encode(
        f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()
    ).decode()

    severity = finding['severity']
    priority_map = {
        'CRITICAL': 'Highest',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low'
    }
    priority = priority_map.get(severity, 'Medium')

    description_text = (
        f"SECURITY FINDING DETAILS\n\n"
        f"Severity: {severity}\n"
        f"Source: {finding.get('source', 'Unknown')}\n"
        f"Account: {finding.get('account', 'Unknown')}\n"
        f"Region: {finding.get('region', 'Unknown')}\n"
        f"Resource Type: {finding.get('resource_type', 'Unknown')}\n"
        f"Resource ID: {finding.get('resource_id', 'Unknown')}\n\n"
        f"DESCRIPTION\n{finding.get('description', 'No description available')}\n\n"
        f"REMEDIATION\n{finding.get('remediation', 'See security console for details')}\n\n"
        f"Finding ID: {finding.get('id', 'Unknown')}\n"
        f"Detected: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"Environment: {ENVIRONMENT}\n\n"
        f"This ticket was automatically created by the Enterprise Cloud Security Platform."
    )

    payload = json.dumps({
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"[{severity}] {finding['title'][:100]}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{
                        "type": "text",
                        "text": description_text
                    }]
                }]
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
            "labels": [
                "security",
                "cloud-security",
                "automated",
                severity.lower(),
                finding.get('source', 'unknown').lower()
            ]
        }
    }).encode()

    req = urllib.request.Request(
        f"{JIRA_URL}/rest/api/3/issue",
        data=payload,
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        result = json.loads(response.read())
        return result.get('key', 'Unknown')


def simulate_ticket(finding):
    """
    Simulate ticket creation when Jira is not configured.
    Logs what would have been created and sends SNS notification.
    """
    ticket_simulation = {
        'project': JIRA_PROJECT_KEY,
        'summary': f"[{finding['severity']}] {finding['title'][:100]}",
        'severity': finding['severity'],
        'priority': 'Highest' if finding['severity'] == 'CRITICAL' else 'High',
        'labels': ['security', 'cloud-security', 'automated'],
        'status': 'SIMULATED - Jira not configured'
    }

    logger.info(f"Simulated ticket: {json.dumps(ticket_simulation)}")

    message = f"""
📋 SECURITY TICKET CREATED — {ENVIRONMENT.upper()}

Title: {finding['title']}
Severity: {finding['severity']}
Source: {finding.get('source', 'Unknown')}
Account: {finding.get('account', 'Unknown')}
Region: {finding.get('region', 'Unknown')}

Description:
{finding.get('description', 'No description available')}

Remediation:
{finding.get('remediation', 'See security console for details')}

Finding ID: {finding.get('id', 'Unknown')}
Detected: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Note: Configure Jira integration for automatic ticket creation.
"""

    sns_client.publish(
        TopicArn=HIGH_SNS_ARN,
        Subject=f'[{finding["severity"]}] Security Ticket — {finding["title"][:50]}',
        Message=message
    )

    return {
        'finding_id': finding['id'],
        'title': finding['title'],
        'severity': finding['severity'],
        'ticket_key': 'SIMULATED',
        'success': True
    }