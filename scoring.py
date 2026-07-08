"""
scoring.py

Turns raw scan results into a security posture score (0-100) and a list of
findings with severity levels. Keeping this logic separate from the
Streamlit UI code makes it independently testable.
"""


def score_iam(iam_data):
    findings = []
    total_checks = 0
    passed_checks = 0

    for entry in iam_data:
        if entry["type"] != "User":
            continue

        total_checks += 1
        if entry["mfa_enabled"]:
            passed_checks += 1
        else:
            findings.append({
                "severity": "High",
                "area": "IAM",
                "resource": entry["name"],
                "issue": "MFA is not enabled for this user",
            })

        total_checks += 1
        if not entry["has_wildcard_policy"]:
            passed_checks += 1
        else:
            findings.append({
                "severity": "High",
                "area": "IAM",
                "resource": entry["name"],
                "issue": "User has a wildcard (overly permissive) policy attached",
            })

        if entry.get("access_key_age_days") is not None:
            total_checks += 1
            if entry["access_key_age_days"] <= 90:
                passed_checks += 1
            else:
                findings.append({
                    "severity": "Medium",
                    "area": "IAM",
                    "resource": entry["name"],
                    "issue": f"Access key is {entry['access_key_age_days']} days old (recommend rotating every 90 days)",
                })

    return passed_checks, total_checks, findings


def score_s3(s3_data):
    findings = []
    total_checks = 0
    passed_checks = 0

    for bucket in s3_data:
        total_checks += 1
        if not bucket["public_access"]:
            passed_checks += 1
        else:
            findings.append({
                "severity": "Critical",
                "area": "S3",
                "resource": bucket["name"],
                "issue": "Bucket allows public access",
            })

        total_checks += 1
        if bucket["encryption_enabled"]:
            passed_checks += 1
        else:
            findings.append({
                "severity": "High",
                "area": "S3",
                "resource": bucket["name"],
                "issue": "Bucket does not have default encryption enabled",
            })

        total_checks += 1
        if bucket["versioning_enabled"]:
            passed_checks += 1
        else:
            findings.append({
                "severity": "Low",
                "area": "S3",
                "resource": bucket["name"],
                "issue": "Bucket versioning is disabled",
            })

        total_checks += 1
        if bucket["logging_enabled"]:
            passed_checks += 1
        else:
            findings.append({
                "severity": "Medium",
                "area": "S3",
                "resource": bucket["name"],
                "issue": "Access logging is disabled",
            })

    return passed_checks, total_checks, findings


def score_network(network_data):
    findings = []
    total_checks = 0
    passed_checks = 0

    for sg in network_data:
        total_checks += 1
        if not sg["ssh_open_to_world"]:
            passed_checks += 1
        else:
            findings.append({
                "severity": "Critical",
                "area": "Network",
                "resource": sg["name"],
                "issue": "SSH (port 22) is open to 0.0.0.0/0",
            })

        total_checks += 1
        if not sg["rdp_open_to_world"]:
            passed_checks += 1
        else:
            findings.append({
                "severity": "Critical",
                "area": "Network",
                "resource": sg["name"],
                "issue": "RDP (port 3389) is open to 0.0.0.0/0",
            })

    return passed_checks, total_checks, findings


def calculate_overall_score(iam_data, s3_data, network_data):
    """Combines all three scan areas into a single 0-100 posture score."""
    iam_passed, iam_total, iam_findings = score_iam(iam_data)
    s3_passed, s3_total, s3_findings = score_s3(s3_data)
    net_passed, net_total, net_findings = score_network(network_data)

    total_passed = iam_passed + s3_passed + net_passed
    total_checks = iam_total + s3_total + net_total
    score = round((total_passed / total_checks) * 100) if total_checks else 100

    all_findings = iam_findings + s3_findings + net_findings
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 4))

    return {
        "score": score,
        "findings": all_findings,
        "breakdown": {
            "IAM": {"passed": iam_passed, "total": iam_total},
            "S3": {"passed": s3_passed, "total": s3_total},
            "Network": {"passed": net_passed, "total": net_total},
        },
    }
