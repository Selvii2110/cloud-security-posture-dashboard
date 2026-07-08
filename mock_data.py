"""
mock_data.py

Provides realistic sample AWS security data so the dashboard can run in
"Demo Mode" without needing real AWS credentials. This lets anyone viewing
the project (recruiters, reviewers) run it instantly.

When real AWS credentials ARE configured, scanner.py pulls live data instead
and this module is not used.
"""

from datetime import datetime, timedelta
import random


def get_mock_iam_data():
    """Returns sample IAM users/roles with intentional security issues mixed in."""
    return [
        {
            "name": "admin-user",
            "type": "User",
            "mfa_enabled": False,
            "has_wildcard_policy": True,
            "access_key_age_days": 412,
            "last_used_days_ago": 2,
        },
        {
            "name": "deploy-bot",
            "type": "User",
            "mfa_enabled": False,
            "has_wildcard_policy": False,
            "access_key_age_days": 45,
            "last_used_days_ago": 1,
        },
        {
            "name": "readonly-analyst",
            "type": "User",
            "mfa_enabled": True,
            "has_wildcard_policy": False,
            "access_key_age_days": 20,
            "last_used_days_ago": 3,
        },
        {
            "name": "ec2-instance-role",
            "type": "Role",
            "mfa_enabled": None,  # roles don't use MFA directly
            "has_wildcard_policy": False,
            "access_key_age_days": None,
            "last_used_days_ago": 0,
        },
        {
            "name": "legacy-service-account",
            "type": "User",
            "mfa_enabled": False,
            "has_wildcard_policy": True,
            "access_key_age_days": 897,
            "last_used_days_ago": 210,
        },
    ]


def get_mock_s3_data():
    """Returns sample S3 buckets with mixed security configurations."""
    return [
        {
            "name": "company-app-assets",
            "public_access": False,
            "encryption_enabled": True,
            "versioning_enabled": True,
            "logging_enabled": True,
        },
        {
            "name": "customer-uploads-2026",
            "public_access": True,
            "encryption_enabled": False,
            "versioning_enabled": False,
            "logging_enabled": False,
        },
        {
            "name": "internal-backups",
            "public_access": False,
            "encryption_enabled": True,
            "versioning_enabled": True,
            "logging_enabled": False,
        },
        {
            "name": "legacy-static-site",
            "public_access": True,
            "encryption_enabled": False,
            "versioning_enabled": False,
            "logging_enabled": False,
        },
    ]


def get_mock_network_data():
    """Returns sample security groups with mixed rule configurations."""
    return [
        {
            "name": "web-sg",
            "open_ports": [80, 443],
            "open_to_world": [80, 443],
            "ssh_open_to_world": False,
            "rdp_open_to_world": False,
        },
        {
            "name": "db-sg",
            "open_ports": [5432],
            "open_to_world": [],
            "ssh_open_to_world": False,
            "rdp_open_to_world": False,
        },
        {
            "name": "legacy-admin-sg",
            "open_ports": [22, 3389, 8080],
            "open_to_world": [22, 3389],
            "ssh_open_to_world": True,
            "rdp_open_to_world": True,
        },
    ]


def get_mock_audit_events(n=25):
    """Generates sample audit log style events with a few suspicious ones mixed in."""
    users = ["admin-user", "deploy-bot", "readonly-analyst", "unknown-ip-actor"]
    actions = [
        "ConsoleLogin", "PutObject", "GetObject", "CreateUser",
        "AttachUserPolicy", "DeleteBucketPolicy", "AuthorizeSecurityGroupIngress",
    ]
    events = []
    now = datetime.utcnow()
    for i in range(n):
        suspicious = random.random() < 0.15
        events.append({
            "timestamp": now - timedelta(hours=random.randint(0, 240)),
            "user": "unknown-ip-actor" if suspicious else random.choice(users[:3]),
            "action": random.choice(actions),
            "source_ip": "203.0.113.77" if suspicious else "10.0.0." + str(random.randint(1, 254)),
            "flagged": suspicious,
        })
    return sorted(events, key=lambda e: e["timestamp"], reverse=True)
