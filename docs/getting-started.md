# Getting Started

## Goal

Run the ETL to generate `data/radar_data.json`, then launch the Streamlit dashboard.

## Prerequisites

- Python 3.11+ recommended
- pip
- Optional: `GITHUB_TOKEN` (helps avoid GitHub API rate limits)

## Install

```bash
pip install -r requirements.txt
```

## Generate Data

```bash
python etl.py
```

## Run Dashboard

```bash
streamlit run app.py
```

## Verify

- `data/radar_data.json` exists
- Streamlit shows a table of CVEs
