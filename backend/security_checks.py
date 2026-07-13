import boto3
from botocore.exceptions import NoCredentialsError, ClientError

def check_public_s3_buckets():
    """Check if any S3 buckets are public via ACLs or Policies."""
    findings = []
    try:
        s3 = boto3.client('s3')
        buckets = s3.list_buckets().get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                # Check Public Access Block
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab.get('PublicAccessBlockConfiguration', {})
                if not config.get('BlockPublicAcls') or not config.get('BlockPublicPolicy'):
                    findings.append({
                        "resource_name": bucket_name,
                        "category": "Storage",
                        "severity": "High",
                        "description": "S3 bucket may have public access allowed (PublicAccessBlock not fully enabled).",
                        "recommendation": "Enable all 'Block Public Access' settings for this bucket."
                    })
            except ClientError as e:
                # If NoSuchPublicAccessBlockConfiguration is thrown, it's not enabled
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    findings.append({
                        "resource_name": bucket_name,
                        "category": "Storage",
                        "severity": "High",
                        "description": "S3 bucket has no Public Access Block configuration.",
                        "recommendation": "Enable all 'Block Public Access' settings for this bucket."
                    })
    except NoCredentialsError:
        raise
    except Exception as e:
        print(f"Error checking S3: {e}")
        
    return findings

def check_iam_mfa():
    """Check if IAM users with console access have MFA enabled."""
    findings = []
    try:
        iam = boto3.client('iam')
        users = iam.list_users().get('Users', [])
        
        for user in users:
            user_name = user['UserName']
            
            # Check if user has a login profile (console access)
            try:
                iam.get_login_profile(UserName=user_name)
                # If we get here, they have console access
                mfa_devices = iam.list_mfa_devices(UserName=user_name).get('MFADevices', [])
                if len(mfa_devices) == 0:
                    findings.append({
                        "resource_name": user_name,
                        "category": "Identity",
                        "severity": "High",
                        "description": "IAM user has console access but no MFA enabled.",
                        "recommendation": "Enforce MFA for all IAM users with console access."
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    # User does not have a login profile (programmatic access only), safe to ignore for this check
                    pass
    except NoCredentialsError:
        raise
    except Exception as e:
        print(f"Error checking IAM MFA: {e}")
        
    return findings

def check_open_security_groups():
    """Check for security groups with 0.0.0.0/0 on port 22 or 3389."""
    findings = []
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1') # Defaulting to us-east-1 for example
        sgs = ec2.describe_security_groups().get('SecurityGroups', [])
        
        for sg in sgs:
            sg_name = sg['GroupName']
            sg_id = sg['GroupId']
            
            for permission in sg.get('IpPermissions', []):
                from_port = permission.get('FromPort')
                to_port = permission.get('ToPort')
                
                if from_port in [22, 3389] or to_port in [22, 3389] or (from_port is None and permission.get('IpProtocol') == '-1'):
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port_str = "All" if from_port is None else from_port
                            findings.append({
                                "resource_name": f"{sg_name} ({sg_id})",
                                "category": "Network",
                                "severity": "High",
                                "description": f"Security Group allows unrestricted inbound access (0.0.0.0/0) on port {port_str}.",
                                "recommendation": f"Restrict port {port_str} access to specific internal IPs or use a bastion/session manager."
                            })
    except NoCredentialsError:
        raise
    except Exception as e:
        print(f"Error checking Security Groups: {e}")
        
    return findings

def check_unused_access_keys():
    """Check for IAM access keys unused for > 90 days."""
    import datetime
    findings = []
    try:
        iam = boto3.client('iam')
        users = iam.list_users().get('Users', [])
        
        # 90 days ago
        threshold_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
        
        for user in users:
            user_name = user['UserName']
            keys = iam.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
            
            for key in keys:
                key_id = key['AccessKeyId']
                last_used_info = iam.get_access_key_last_used(AccessKeyId=key_id).get('AccessKeyLastUsed', {})
                last_used_date = last_used_info.get('LastUsedDate')
                
                if last_used_date:
                    if last_used_date < threshold_date:
                        findings.append({
                            "resource_name": f"Key {key_id} (User: {user_name})",
                            "category": "Identity",
                            "severity": "Medium",
                            "description": "Access key has not been used in the last 90 days.",
                            "recommendation": "Rotate or delete unused access keys."
                        })
                else:
                    # Key never used, check its creation date
                    create_date = key.get('CreateDate')
                    if create_date and create_date < threshold_date:
                         findings.append({
                            "resource_name": f"Key {key_id} (User: {user_name})",
                            "category": "Identity",
                            "severity": "Medium",
                            "description": "Access key is older than 90 days and has never been used.",
                            "recommendation": "Rotate or delete unused access keys."
                        })
    except NoCredentialsError:
        raise
    except Exception as e:
        print(f"Error checking Access Keys: {e}")
        
    return findings

def run_all_checks():
    """Run all AWS security checks and aggregate findings."""
    all_findings = []
    all_findings.extend(check_public_s3_buckets())
    all_findings.extend(check_iam_mfa())
    all_findings.extend(check_open_security_groups())
    all_findings.extend(check_unused_access_keys())
    return all_findings
