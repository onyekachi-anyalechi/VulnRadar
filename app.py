import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.express as px
import streamlit as st

DATA_PATH = Path("data/radar_data.json")


def load_items(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return payload["items"]
    if isinstance(payload, list):
        return payload
    return []


def risk_bucket(row: pd.Series) -> str:
    if bool(row.get("in_patchthis")) and bool(row.get("watchlist_hit")):
        return "CRITICAL (PatchThis + Watchlist)"
    if bool(row.get("in_patchthis")):
        return "WARNING (PatchThis)"
    if bool(row.get("active_threat")):
        return "KEV"
    epss = row.get("probability_score")
    cvss = row.get("cvss_score")
    try:
        if epss is not None and float(epss) >= 0.7:
            return "High EPSS"
    except Exception:
        pass
    try:
        if cvss is not None and float(cvss) >= 9.0:
            return "Critical CVSS"
    except Exception:
        pass
    return "Other"


def risk_sort_key(row: pd.Series) -> float:
    # Higher is riskier; prioritize KEV, then EPSS, then CVSS.
    patch_watch = 1.0 if (bool(row.get("in_patchthis")) and bool(row.get("watchlist_hit"))) else 0.0
    patch_only = 1.0 if (bool(row.get("in_patchthis")) and not bool(row.get("watchlist_hit"))) else 0.0
    kev = 1.0 if bool(row.get("active_threat")) else 0.0
    epss = row.get("probability_score")
    cvss = row.get("cvss_score")
    try:
        epss_v = float(epss) if epss is not None else 0.0
    except Exception:
        epss_v = 0.0
    try:
        cvss_v = float(cvss) if cvss is not None else 0.0
    except Exception:
        cvss_v = 0.0
    return patch_watch * 1000.0 + patch_only * 900.0 + kev * 100.0 + epss_v * 10.0 + cvss_v


st.set_page_config(page_title="Vulnerability Radar", layout="wide")

st.title("Vulnerability Radar")
items = load_items(DATA_PATH)

if not items:
    st.warning("No data found. Run `python etl.py` to generate data/radar_data.json.")
    st.stop()

# Flatten for table display.
df = pd.json_normalize(items)

# Ensure expected columns exist.
for col in ["cve_id", "description", "cvss_score", "cvss_severity", "active_threat", "watchlist_hit", "probability_score"]:
    if col not in df.columns:
        df[col] = None
for col in ["in_patchthis", "priority_label", "in_watchlist"]:
    if col not in df.columns:
        df[col] = None

# Sidebar controls.
st.sidebar.header("Filters")
mode = st.sidebar.radio(
    "View mode",
    options=["Show Watchlist Only", "Show All Active Threats"],
    index=0,
)

filtered = df.copy()
if mode == "Show Watchlist Only":
    filtered = filtered[filtered["watchlist_hit"] == True]  # noqa: E712
else:
    filtered = filtered[filtered["active_threat"] == True]  # noqa: E712

filtered = filtered.copy()
filtered["risk_bucket"] = filtered.apply(risk_bucket, axis=1)
filtered["risk_score"] = filtered.apply(risk_sort_key, axis=1)
filtered = filtered.sort_values(by=["risk_score", "probability_score", "cvss_score"], ascending=[False, False, False])

# Metrics.
col1, col2, col3 = st.columns(3)
watch_hits = int(df["watchlist_hit"].fillna(False).sum())
kev_count = int(df["active_threat"].fillna(False).sum())
critical_kevs = int(
    df[(df["active_threat"].fillna(False) == True) & (df["cvss_score"].fillna(0).astype(float) >= 9.0)].shape[0]
)

col1.metric("Watchlist Hits", watch_hits)
col2.metric("Active Threats (KEV)", kev_count)
col3.metric("Critical KEVs (CVSS≥9)", critical_kevs)

st.subheader("Risk Overview")
chart_df = filtered[["risk_bucket"]].value_counts().reset_index(name="count")
fig = px.bar(chart_df, x="risk_bucket", y="count", title="Items by Risk Bucket")
st.plotly_chart(fig, use_container_width=True)

st.subheader("Radar Table")
show_cols = [
    "cve_id",
    "priority_label",
    "in_patchthis",
    "active_threat",
    "watchlist_hit",
    "probability_score",
    "cvss_score",
    "cvss_severity",
    "risk_bucket",
    "description",
]
for c in show_cols:
    if c not in filtered.columns:
        filtered[c] = None

st.dataframe(
    filtered[show_cols],
    use_container_width=True,
    hide_index=True,
)
