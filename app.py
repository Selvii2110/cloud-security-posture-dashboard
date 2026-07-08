"""
app.py

Cloud Security Posture Dashboard — Streamlit frontend.

Run with:
    streamlit run app.py

If AWS credentials are configured (env vars, ~/.aws/credentials, or an IAM
role), the dashboard scans your real AWS account. Otherwise it runs in
Demo Mode using realistic sample data, so anyone can try it instantly.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

import scanner
import scoring

st.set_page_config(page_title="Cloud Security Posture Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ Cloud Security Posture Dashboard")
st.caption("Scans IAM, S3, and network configuration for common security misconfigurations.")

# --- Run scans ---
with st.spinner("Scanning cloud environment..."):
    iam_data, iam_demo = scanner.scan_iam()
    s3_data, s3_demo = scanner.scan_s3()
    network_data, network_demo = scanner.scan_network()
    audit_events = scanner.get_audit_events()

is_demo_mode = iam_demo or s3_demo or network_demo

if is_demo_mode:
    st.info(
        "🔎 **Demo Mode** — no AWS credentials detected, showing sample data. "
        "Connect an AWS account (via `aws configure` or environment variables) to scan a real environment.",
        icon="ℹ️",
    )

results = scoring.calculate_overall_score(iam_data, s3_data, network_data)

# --- Top-level score ---
col1, col2, col3, col4 = st.columns(4)

with col1:
    score = results["score"]
    color = "green" if score >= 80 else "orange" if score >= 60 else "red"
    st.metric("Overall Security Score", f"{score}/100")

with col2:
    critical_count = sum(1 for f in results["findings"] if f["severity"] == "Critical")
    st.metric("Critical Findings", critical_count)

with col3:
    high_count = sum(1 for f in results["findings"] if f["severity"] == "High")
    st.metric("High Findings", high_count)

with col4:
    st.metric("Total Findings", len(results["findings"]))

# --- Score gauge ---
fig = go.Figure(go.Indicator(
    mode="gauge+number",
    value=results["score"],
    title={"text": "Security Posture Score"},
    gauge={
        "axis": {"range": [0, 100]},
        "bar": {"color": "darkblue"},
        "steps": [
            {"range": [0, 60], "color": "#f8d7da"},
            {"range": [60, 80], "color": "#fff3cd"},
            {"range": [80, 100], "color": "#d4edda"},
        ],
    },
))
fig.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20))
st.plotly_chart(fig, use_container_width=True)

# --- Breakdown by area ---
st.subheader("Score Breakdown by Area")
breakdown_cols = st.columns(3)
for i, (area, stats) in enumerate(results["breakdown"].items()):
    with breakdown_cols[i]:
        pct = round((stats["passed"] / stats["total"]) * 100) if stats["total"] else 100
        st.metric(area, f"{pct}%", f"{stats['passed']}/{stats['total']} checks passed")

# --- Findings table ---
st.subheader("Findings")
if results["findings"]:
    findings_df = pd.DataFrame(results["findings"])
    severity_colors = {
        "Critical": "background-color: #f8d7da",
        "High": "background-color: #fde2c8",
        "Medium": "background-color: #fff3cd",
        "Low": "background-color: #e2e3e5",
    }

    def highlight_severity(row):
        return [severity_colors.get(row["severity"], "")] * len(row)

    st.dataframe(
        findings_df.style.apply(highlight_severity, axis=1),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.success("No findings — environment passed all checks.")

# --- Tabs for raw scan data ---
st.subheader("Raw Scan Data")
tab1, tab2, tab3, tab4 = st.tabs(["IAM", "S3 Buckets", "Network / Security Groups", "Audit Log"])

with tab1:
    st.dataframe(pd.DataFrame(iam_data), use_container_width=True, hide_index=True)

with tab2:
    st.dataframe(pd.DataFrame(s3_data), use_container_width=True, hide_index=True)

with tab3:
    st.dataframe(pd.DataFrame(network_data), use_container_width=True, hide_index=True)

with tab4:
    events_df = pd.DataFrame(audit_events)
    flagged = events_df[events_df["flagged"] == True]
    if len(flagged) > 0:
        st.warning(f"⚠️ {len(flagged)} suspicious event(s) detected from unrecognized sources.")
    st.dataframe(events_df, use_container_width=True, hide_index=True)

st.divider()
st.caption("Built by Selvi Patel — Cloud Security Posture Dashboard | Python, Streamlit, Boto3, AWS SDK")
