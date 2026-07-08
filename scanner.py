"""
scanner.py

Core security scanning logic. If valid AWS credentials are found (via
environment variables, ~/.aws/credentials, or an IAM role), this module
queries live AWS IAM, S3, and EC2/VPC APIs using boto3.

If no credentials are found, it transparently falls back to mock_data.py
so the dashboard is always runnable — this is intentional so anyone
reviewing this project (e.g. a recruiter) can run it without needing
an AWS account.
"""

import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import mock_data


def credentials_available():
    """Checks whether boto3 can find usable AWS credentials."""
    try:
        session = boto3.Session()
        creds = session.get_credentials()
        if creds is None:
            return False
        # Confirm they actually work with a lightweight call
        sts = session.client("sts")
        sts.get_caller_identity()
        return True
    except (NoCredentialsError, ClientError, Exception):
        return False


def scan_iam():
    """Scans IAM users/roles for MFA status, wildcard policies, and stale keys."""
    if not credentials_available():
        return mock_data.get_mock_iam_data(), True  # (data, is_demo_mode)

    iam = boto3.client("iam")
    results = []
    try:
        for user in iam.list_users()["Users"]:
            username = user["UserName"]

            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            mfa_enabled = len(mfa_devices) > 0

            has_wildcard = False
            attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            for policy in attached:
                policy_doc = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
                version = iam.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=policy_doc["DefaultVersionId"]
                )["PolicyVersion"]["Document"]
                for statement in version.get("Statement", []):
                    if statement.get("Effect") == "Allow" and "*" in str(statement.get("Action", "")):
                        has_wildcard = True

            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            key_age = None
            if keys:
                from datetime import datetime, timezone
                key_age = (datetime.now(timezone.utc) - keys[0]["CreateDate"]).days

            results.append({
                "name": username,
                "type": "User",
                "mfa_enabled": mfa_enabled,
                "has_wildcard_policy": has_wildcard,
                "access_key_age_days": key_age,
                "last_used_days_ago": None,
            })
        return results, False
    except ClientError:
        # Fall back gracefully if permissions are insufficient
        return mock_data.get_mock_iam_data(), True


def scan_s3():
    """Scans S3 buckets for public access, encryption, versioning, and logging."""
    if not credentials_available():
        return mock_data.get_mock_s3_data(), True

    s3 = boto3.client("s3")
    results = []
    try:
        for bucket in s3.list_buckets()["Buckets"]:
            name = bucket["Name"]

            public_access = False
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl["Grants"]:
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "").endswith("AllUsers"):
                        public_access = True
            except ClientError:
                pass

            encryption_enabled = True
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                encryption_enabled = False

            versioning_enabled = False
            try:
                v = s3.get_bucket_versioning(Bucket=name)
                versioning_enabled = v.get("Status") == "Enabled"
            except ClientError:
                pass

            logging_enabled = False
            try:
                log = s3.get_bucket_logging(Bucket=name)
                logging_enabled = "LoggingEnabled" in log
            except ClientError:
                pass

            results.append({
                "name": name,
                "public_access": public_access,
                "encryption_enabled": encryption_enabled,
                "versioning_enabled": versioning_enabled,
                "logging_enabled": logging_enabled,
            })
        return results, False
    except ClientError:
        return mock_data.get_mock_s3_data(), True


def scan_network():
    """Scans EC2 security groups for overly permissive rules."""
    if not credentials_available():
        return mock_data.get_mock_network_data(), True

    ec2 = boto3.client("ec2")
    results = []
    try:
        for sg in ec2.describe_security_groups()["SecurityGroups"]:
            open_ports = []
            open_to_world = []
            ssh_open = False
            rdp_open = False

            for perm in sg.get("IpPermissions", []):
                port = perm.get("FromPort")
                if port is None:
                    continue
                open_ports.append(port)
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        open_to_world.append(port)
                        if port == 22:
                            ssh_open = True
                        if port == 3389:
                            rdp_open = True

            results.append({
                "name": sg.get("GroupName", sg["GroupId"]),
                "open_ports": open_ports,
                "open_to_world": open_to_world,
                "ssh_open_to_world": ssh_open,
                "rdp_open_to_world": rdp_open,
            })
        return results, False
    except ClientError:
        return mock_data.get_mock_network_data(), True


def get_audit_events():
    """Audit log events — always uses mock/simulated data in this demo project,
    since a real implementation would query CloudTrail + pay for Athena/S3 queries."""
    return mock_data.get_mock_audit_events()
