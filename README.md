# Cloud Security Posture Dashboard

A Python + Streamlit dashboard that scans a cloud environment (AWS) for common security misconfigurations across **IAM, S3, and network/security groups**, then scores the overall security posture and lists prioritized findings.

Built as a hands-on project for my Cloud Technology & Information Security specialization.

## Features

- **Live AWS scanning** via Boto3 — checks IAM users for MFA and wildcard policies, S3 buckets for public access/encryption/versioning, and security groups for open SSH/RDP ports
- **Demo Mode** — if no AWS credentials are configured, the dashboard automatically falls back to realistic sample data so anyone can run it instantly without an AWS account
- **Security posture score (0–100)** with a visual gauge
- **Prioritized findings table** — Critical → High → Medium → Low
- **Simulated audit log view** flagging suspicious access events

## Tech Stack

`Python` · `Streamlit` · `Boto3 (AWS SDK)` · `Pandas` · `Plotly`

## Architecture

```
app.py         → Streamlit UI, renders scores/charts/tables
scanner.py     → Pulls live AWS data (IAM/S3/EC2) via boto3, or falls back to mock data
scoring.py     → Turns raw scan results into a 0-100 score + findings list
mock_data.py   → Realistic sample data used when no AWS credentials are present
```

## What it checks

| Area | Checks performed |
|---|---|
| IAM | MFA enabled, no wildcard (`*`) policies, access key age ≤ 90 days |
| S3 | No public access, encryption at rest enabled, versioning enabled, access logging enabled |
| Network | No SSH (22) or RDP (3389) open to `0.0.0.0/0` |

## Setup & Run

```bash
git clone https://github.com/YOUR_USERNAME/cloud-security-posture-dashboard.git
cd cloud-security-posture-dashboard
pip install -r requirements.txt
streamlit run app.py
```

The app opens in your browser. Without AWS credentials configured, it runs in **Demo Mode** automatically — no setup needed to try it out.

### To scan a real AWS account

Configure AWS credentials with **read-only** permissions (recommended: `SecurityAudit` managed policy):

```bash
aws configure
```

Then re-run `streamlit run app.py` — it will detect the credentials and scan your real account instead of using demo data.

## Why this project

Most cloud security incidents come from misconfigurations, not sophisticated attacks — a publicly exposed S3 bucket or an IAM user without MFA is a far more common real-world breach cause. This project turns the audit checklist a security analyst would manually work through into an automated, visual tool.

## Future improvements

- Add GCP and Azure scanning (currently AWS-only)
- Export findings report as PDF
- Historical scoring trend over time (store scan results in a database)

## Author

**Selvi Patel**
B.Tech Cloud Technology & Information Security, ITM Vocational University
[LinkedIn](https://linkedin.com/in/selvipatel)
